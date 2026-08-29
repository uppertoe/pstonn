// Package parking is the per-app-user tenant client: everything about talking
// to a permit backend that is NOT the backend's protocol. It holds each user's
// sealed session material, keeps it fresh, caches plate readings, backs off per
// owner when the portal pushes back, pauses the whole fleet when the shared egress
// address is blocked, serialises credential logins, and counts every request —
// once, for every provider. The protocol itself (how to sign in, list permits,
// read and write the vehicle) is a provider.Provider; today the Orikan ePermits
// portal (internal/provider/orikan) and an in-memory fake (internal/provider/fake).
//
// Callers speak in app terms — an owner (the account's verified email), a
// model.Permit, a registration — and never see session material or wire shapes.
package parking

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/provider/orikan"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// The provider vocabulary, re-exported so the core keeps one import. See
// internal/provider for what each means.
var (
	ErrNotLinked             = provider.ErrNotLinked
	ErrSessionExpired        = provider.ErrSessionExpired
	ErrNoSavedPassword       = provider.ErrNoSavedPassword
	ErrLoginRejected         = provider.ErrLoginRejected
	ErrLoginFormUnrecognised = provider.ErrLoginFormUnrecognised
	ErrLoginOffHost          = provider.ErrLoginOffHost
	ErrNotCaptured           = provider.ErrNotCaptured
	// ErrCouncilBusy is provider.ErrUnavailable: the portal is pushing back or the
	// owner is in a backoff cooldown. Transient; the client already enforces an
	// exponential per-owner cooldown so it is not hammered.
	ErrCouncilBusy       = provider.ErrUnavailable
	ErrPermitListPartial = provider.ErrPermitListPartial
	ErrUnsupported       = provider.ErrUnsupported
)

type (
	FailureKind = provider.FailureKind
	TenantError = provider.Error
	PermitInfo  = provider.Permit
	Op          = provider.Op
)

const (
	FailTransient  = provider.FailTransient
	FailRejected   = provider.FailRejected
	FailUnexpected = provider.FailUnexpected
)

// FailureOf extracts the classification from an error (FailTransient for anything
// unclassified: an unclassified error is more likely a glitch than a refusal).
func FailureOf(err error) (FailureKind, Op) { return provider.FailureOf(err) }

// Client talks to one provider on behalf of app users. Safe for concurrent use.
type Client struct {
	p     provider.Provider
	store *store.Store
	box   *secretbox.Box
	// TenantID names the tenant this client serves; it keys the persisted
	// breaker state and is stamped on sessions this client links.
	TenantID string

	regCache   sync.Map // regKey -> cachedReg, to bound tenant reads
	regRefresh sync.Map // regKey -> struct{}, dedupes in-flight background plate refreshes
	regFail    sync.Map // regKey -> time.Time, start of the current refresh-failure streak
	// OnSessionExpired, when set (main wires it to the scheduler's reconnect queue),
	// is called whenever a BACKGROUND read discovers the session is dead. Called
	// from refresh goroutines: must be safe for concurrent use and cheap on repeats.
	OnSessionExpired func(owner, tenantID string, gen int64)
	// regGen is a per-key generation, bumped by ForgetPermit, so a plate read that
	// was already in flight when a permit was removed cannot resurrect the cache
	// entry afterwards. Guarded by regGenMu (writes only; reads stay lock-free).
	regGenMu sync.Mutex
	regGen   map[regKey]uint64
	traffic  *trafficCounters

	ownerLocks    sync.Map   // owner -> *sync.Mutex, serialises every tenant call per owner
	cooldownUntil sync.Map   // owner -> time.Time, soft-block backoff deadline
	strikes       sync.Map   // owner -> int, consecutive soft blocks (backoff growth)
	strikeMu      sync.Mutex // serialises the strike read-modify-write in penalize

	// breaker is the FLEET-level counterpart to the per-owner cooldown: it pauses
	// ALL traffic to this provider when several distinct owners are pushed back at
	// once, the signature of an edge block on our shared egress IP (see breaker.go).
	breaker *breaker
	// loginFlow serialises whole CREDENTIAL LOGIN flows to one at a time: the risk
	// pattern is many DISTINCT authentication flows from one IP at once.
	loginFlow chan struct{}

	// persist-health of the breaker-state write, surfaced on /status.
	persistMu  sync.Mutex
	persistErr error
	persistAt  time.Time

	// truncMu guards the last observed short permit list, surfaced on the status page.
	truncMu   sync.Mutex
	truncAt   time.Time
	truncGot  int
	truncWant int
}

type cachedReg struct {
	reg string
	at  time.Time
}

// regKey identifies a cached plate reading. The owner is part of the key because
// a tenant permit can change hands (a household permit is often visible to two
// tenant logins): keyed on the permit alone, the new holder was served the
// previous holder's cached plate — a wrong plate is a real parking fine.
type regKey struct {
	owner    string
	permitID string
}

// New builds a Client for the tenant the process is configured for — the Orikan
// provider from COUNCIL_* config, or the in-memory fake under COUNCIL_SANDBOX —
// with a governed transport sized from the same config. Multi-tenant wiring
// builds providers and clients explicitly via NewClient.
func New(cfg *config.Config, st *store.Store, box *secretbox.Box) *Client {
	tr := NewTransport(LimitsFromConfig(cfg.Council))
	var p provider.Provider
	if cfg.Council.Sandbox {
		p = fake.New()
	} else {
		p = orikan.New(orikan.Config{
			Issuer: cfg.Council.Issuer, APIBase: cfg.Council.APIBase, ClientID: cfg.Council.ClientID,
			RedirectURI: cfg.Council.RedirectURI, Scopes: cfg.Council.Scopes,
		}, tr)
	}
	return NewClient(p, st, box, tr)
}

// NewClient wires a provider to the store and cipher. tr is the transport the
// provider was built on (its traffic is what Stats reports); nil is fine for a
// provider that makes no requests.
func NewClient(p provider.Provider, st *store.Store, box *secretbox.Box, tr *Transport) *Client {
	return NewClientFor("", p, st, box, tr)
}

// NewClientFor is NewClient for a named tenant (see Client.TenantID).
func NewClientFor(tenantID string, p provider.Provider, st *store.Store, box *secretbox.Box, tr *Transport) *Client {
	c := &Client{
		TenantID: tenantID,
		p:        p,
		store:    st,
		box:      box,
		breaker: newBreaker(defaultBreakerThreshold, defaultBreakerWindow,
			defaultBreakerCooldown, defaultBreakerProbe),
		loginFlow: make(chan struct{}, 1),
	}
	if tr != nil {
		c.traffic = tr.traffic
	} else {
		c.traffic = newTrafficCounters()
	}
	// Restore a persisted breaker pause: if a block was in force when this process
	// last stopped, resume paused rather than resuming full traffic into the block.
	if st != nil {
		if bs, err := st.LoadBreakerState(context.Background(), tenantID); err == nil {
			c.breaker.restore(bs.OpenUntil, bs.LastPushback, bs.Generation)
			if bs.OpenUntil.After(time.Now()) {
				log.Printf("parking: fleet circuit restored OPEN from persisted state (paused %s) — a block survived a restart", time.Until(bs.OpenUntil).Round(time.Second))
			}
		} else {
			log.Printf("parking: load persisted breaker state: %v (starting closed)", err)
		}
	}
	return c
}

// Provider returns the provider this client drives.
func (c *Client) Provider() provider.Provider { return c.p }

// Capabilities reports what the provider supports.
func (c *Client) Capabilities() provider.Capabilities {
	if c.p == nil {
		return provider.Capabilities{}
	}
	return c.p.Capabilities()
}

// acquireLoginFlow blocks until no other credential login flow is running, then
// claims the single slot; the returned release frees it. A nil channel (tests
// constructing a bare Client) is a no-op. Bounded by ctx so a waiting flow fails
// cleanly rather than hanging.
func (c *Client) acquireLoginFlow(ctx context.Context) (func(), error) {
	if c.loginFlow == nil {
		return func() {}, nil
	}
	select {
	case c.loginFlow <- struct{}{}:
		return func() { <-c.loginFlow }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// persistBreaker writes the breaker's current pause to the store so a restart
// resumes from it. Best-effort: a failed write is logged, not fatal.
func (c *Client) persistBreaker() {
	if c.store == nil {
		return
	}
	openUntil, lastPushback, gen := c.breaker.snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.store.SaveBreakerState(ctx, c.TenantID, store.BreakerState{
		OpenUntil: openUntil, LastPushback: lastPushback, Generation: gen,
	})
	c.persistMu.Lock()
	c.persistErr, c.persistAt = err, time.Now()
	c.persistMu.Unlock()
	if err != nil {
		log.Printf("parking: persist breaker state: %v (restart-protection degraded)", err)
	}
}

// ---- session material ----

// sessionPrefix marks sealed session material written by this client (an opaque
// provider blob). A sealed value WITHOUT it is the pre-provider shape — a raw
// cookie header, with the token in its own column — and is imported once through
// the provider's legacy hook so existing accounts carry across without re-linking.
const sessionPrefix = "pstonn-session:"

// legacyImporter is implemented by a provider that can build session material from
// the pre-provider storage shape.
type legacyImporter interface {
	ImportLegacy(cookie, accessToken string, expiry time.Time) (provider.Session, error)
}

// Linked reports whether the app user has stored session material.
func (c *Client) Linked(ctx context.Context, owner string) bool {
	cs, err := c.store.GetTenantSessionIn(ctx, owner, c.TenantID)
	return err == nil && cs.Cookie != ""
}

// openSession unseals the stored material. A decrypt failure means the at-rest
// key no longer matches the sealed data (e.g. DATA_ENCRYPTION_KEY was rotated), so
// the material is permanently unusable: mapped to ErrSessionExpired, which retires
// the session and prompts a re-link rather than failing silently every tick.
func (c *Client) openSession(owner string, cs store.TenantSession) (provider.Session, error) {
	plain, legacy, err := c.box.OpenCtx(secretbox.TenantCookie(owner), cs.Cookie)
	if legacy {
		log.Printf("parking: session for %s is an unbound legacy ciphertext; it will be re-sealed on the next renew", redact.Email(owner))
	}
	if err != nil {
		log.Printf("parking: unseal session for %s failed (%v); treating as expired session (re-link required)", redact.Email(owner), err)
		return nil, ErrSessionExpired
	}
	if strings.HasPrefix(plain, sessionPrefix) {
		return provider.Session(plain[len(sessionPrefix):]), nil
	}
	// Pre-provider shape: cookie header here, cached token in its own column.
	imp, ok := c.p.(legacyImporter)
	if !ok {
		log.Printf("parking: session for %s is in the legacy shape and provider %s cannot import it; re-link required", redact.Email(owner), c.p.ID())
		return nil, ErrSessionExpired
	}
	token := ""
	if cs.AccessToken != "" {
		if at, _, err := c.box.OpenCtx(secretbox.TenantToken(owner), cs.AccessToken); err == nil {
			token = at
		}
	}
	return imp.ImportLegacy(plain, token, cs.TokenExpiry)
}

func (c *Client) sealSession(owner string, s provider.Session) (string, error) {
	return c.box.SealCtx(secretbox.TenantCookie(owner), sessionPrefix+string(s))
}

func (c *Client) ownerLock(owner string) *sync.Mutex {
	m, _ := c.ownerLocks.LoadOrStore(owner, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// withSession runs one provider operation for owner under the owner's lock: it
// loads and unseals the session, honours the owner's cooldown and the fleet
// breaker, hands the material to fn, classifies the outcome (push-back penalises
// the owner and feeds the breaker; success clears the penalty and may close the
// circuit; an expiry is tagged with the session generation it failed at), and
// re-seals and persists the material when the provider changed it — or always,
// when persist is set, because the write is keep-warm's freshness clock.
//
// Serialising EVERY call per owner (not only renews, as before) is deliberate: a
// provider rotates session material in place, and two calls racing on one
// session could otherwise rotate it out from under each other.
func (c *Client) withSession(ctx context.Context, owner string, persist bool, fn func(s *provider.Session) error) error {
	lock := c.ownerLock(owner)
	lock.Lock()
	defer lock.Unlock()

	cs, err := c.store.GetTenantSessionIn(ctx, owner, c.TenantID)
	if err != nil || cs.Cookie == "" {
		return ErrNotLinked
	}
	// This client speaks to ONE tenant. Session material stamped for another
	// must never be handed to this provider (a cookie or saved password replayed
	// at the wrong portal), however the routing above resolved the owner.
	if cs.TenantID != "" && c.TenantID != "" && cs.TenantID != c.TenantID {
		return ErrNotLinked
	}
	if d, blocked := c.cooldownFor(owner); blocked {
		return fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	permit, err := c.breakerGate()
	if err != nil {
		return err
	}
	sess, err := c.openSession(owner, cs)
	if err != nil {
		return withSessionGen(err, cs.Generation)
	}
	before := string(sess)
	opErr := fn(&sess)
	c.classify(owner, permit, opErr)
	if opErr != nil {
		// Never persist on a failure, even if the provider rotated material on the
		// way to it: a write bumps session_generation, and an expiry tagged with the
		// generation the operation STARTED from would then no longer match the row —
		// the scheduler's generation-checked retire/reconnect would read that as
		// "the user re-linked meanwhile" and leave a dead session in place. The old
		// client had the same rule (error paths wrote nothing). The tag binds the
		// recovery queue to THIS session, not to whatever the row holds later.
		return withSessionGen(opErr, cs.Generation)
	}
	if string(sess) != before || persist {
		sealed, err := c.sealSession(owner, sess)
		if err != nil {
			return err
		}
		// Conditioned on the generation the operation started from: a re-link that
		// landed meanwhile holds a DIFFERENT, valid session, and writing the older
		// material over it would silently undo the user's re-link.
		if err := c.store.UpdateTenantCookie(ctx, owner, c.TenantID, sealed, cs.Generation); err != nil {
			if errors.Is(err, store.ErrSessionSuperseded) {
				log.Printf("parking: session for %s was re-linked during an operation; keeping the newer one", redact.Email(owner))
				return nil
			}
			return err
		}
	}
	return nil
}

// classify applies the outcome of a provider call to the owner's backoff and the
// fleet breaker.
func (c *Client) classify(owner string, permit breakerPermit, err error) {
	var u *provider.Unavailable
	switch {
	case err == nil:
		c.clearPenalty(owner)
		c.noteTenantSuccess(owner, permit) // closes the circuit only if this was the probe
	case errors.As(err, &u):
		c.recordPushback(u)
		c.penalize(owner, u.RetryAfter)
	}
}

// ---- lifecycle ----

// Link signs owner in with the given credentials and stores the resulting session
// material; the password is kept (sealed) only when savePassword is set.
// interactive=true is a user-initiated link/re-link that advances the re-authorise
// clock (linked_at); a non-interactive call (auto-reconnect) keeps the clock
// anchored to the last real interactive link. expectedGen conditions the
// non-interactive save on the session generation observed when recovery was
// decided, so an in-flight reconnect cannot overwrite a session the user changed
// meanwhile; it is ignored for an interactive link.
func (c *Client) Link(ctx context.Context, owner, username, password string, savePassword, interactive bool, expectedGen int64) error {
	// Serialise the whole credential flow: only one login (or auto-reconnect) may
	// run at a time, so a reconnect storm cannot put many distinct authentication
	// flows on our shared IP at once. Acquired before the cooldown / breaker checks
	// so the entire real flow — including its breaker probe — is the atomic unit.
	releaseFlow, err := c.acquireLoginFlow(ctx)
	if err != nil {
		return err
	}
	defer releaseFlow()
	if d, blocked := c.cooldownFor(owner); blocked {
		return fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	permit, err := c.breakerGate()
	if err != nil {
		return err
	}
	sess, err := c.p.Login(ctx, provider.Credentials{Username: username, Password: password})
	c.classify(owner, permit, err)
	if err != nil {
		return err
	}
	sealed, err := c.sealSession(owner, sess)
	if err != nil {
		return err
	}
	var sealedPass string
	if savePassword {
		if sealedPass, err = c.box.SealCtx(secretbox.TenantPassword(owner), password); err != nil {
			return err
		}
	}
	cs := store.TenantSession{Owner: owner, TenantID: c.TenantID, TenantEmail: username, Cookie: sealed, Password: sealedPass}
	if interactive {
		return c.store.SaveTenantSession(ctx, cs) // stamps linked_at = now, bumps generation
	}
	// Auto-reconnect: persist ONLY if the session is still at expectedGen. If the user
	// relinked or opted out of saved-password recovery during our login, the write
	// lands nowhere and we report it superseded rather than clobbering their change.
	switch saved, err := c.store.SaveReconnectedSessionIfGen(ctx, cs, expectedGen); {
	case err != nil:
		return err
	case !saved:
		return store.ErrSessionSuperseded
	}
	return nil
}

// Reconnect re-establishes an expired session non-interactively using the sealed
// password the user opted to save, re-saving the (still opted-in) password.
// Returns ErrNoSavedPassword when none was saved.
func (c *Client) Reconnect(ctx context.Context, owner string) error {
	if c.Capabilities().LoginKind != "password" {
		return ErrUnsupported
	}
	cs, err := c.store.GetTenantSessionIn(ctx, owner, c.TenantID)
	if err != nil {
		return err
	}
	if cs.Password == "" {
		return ErrNoSavedPassword
	}
	if cs.TenantID != "" && c.TenantID != "" && cs.TenantID != c.TenantID {
		return ErrNotLinked // never replay a saved password at another tenant's portal
	}
	password, legacy, err := c.box.OpenCtx(secretbox.TenantPassword(owner), cs.Password)
	if legacy {
		log.Printf("parking: saved password for %s is an unbound legacy ciphertext; re-sealing on this reconnect", redact.Email(owner))
	}
	if err != nil {
		// A decrypt failure (e.g. DATA_ENCRYPTION_KEY rotated) is deterministic:
		// retrying it every scheduler pass never heals and never tells the user.
		// Map it to ErrNoSavedPassword so the retire-and-notify path fires.
		log.Printf("parking: unseal saved password for %s failed (%v); treating as no saved password (manual re-link required)", redact.Email(owner), err)
		return ErrNoSavedPassword
	}
	username := cs.TenantEmail
	if username == "" {
		username = owner // the tenant username is pinned to the owner's verified email
	}
	return c.Link(ctx, owner, username, password, true, false, cs.Generation)
}

// Refresh keeps an idle owner's session alive (keep-warm). Always persists, even
// when the provider rotated nothing: the write is keep-warm's freshness clock.
// Returns ErrNotLinked if there is no session and ErrSessionExpired if it is no
// longer accepted. A provider without SupportsRefresh reports success (there is
// nothing to keep warm).
func (c *Client) Refresh(ctx context.Context, owner string) error {
	if !c.Capabilities().SupportsRefresh {
		return nil
	}
	return c.withSession(ctx, owner, true, func(s *provider.Session) error {
		return c.p.Refresh(ctx, s)
	})
}

// ---- permits ----

func ref(p model.Permit) provider.PermitRef { return provider.PermitRef{ID: p.CouncilPermitID} }

// permitMine refuses a permit filed under another tenant: the ids overlap
// between portals, so acting on it here would address a stranger's permit.
func (c *Client) permitMine(p model.Permit) error {
	if p.TenantID != "" && c.TenantID != "" && p.TenantID != c.TenantID {
		return fmt.Errorf("%w: permit belongs to council %q, this client serves %q", ErrNotLinked, p.TenantID, c.TenantID)
	}
	return nil
}

// ListPermits returns the permits on the owner's linked account. Display callers
// use this and are content with a partial list.
func (c *Client) ListPermits(ctx context.Context, owner string) ([]PermitInfo, error) {
	ps, _, err := c.ListPermitsComplete(ctx, owner)
	return ps, err
}

// ListPermitsComplete returns the same rows as ListPermits, plus whether the list
// was the WHOLE account. Drift uses it: acting on a page is fine, but checking the
// owner off for another interval on the strength of one is not.
func (c *Client) ListPermitsComplete(ctx context.Context, owner string) ([]PermitInfo, bool, error) {
	var out []PermitInfo
	complete := false
	err := c.withSession(ctx, owner, false, func(s *provider.Session) error {
		ps, total, err := c.p.ListPermits(ctx, s)
		if err != nil {
			return err
		}
		out, complete = ps, len(ps) >= total
		if !complete {
			c.noteTruncatedGrid(len(ps), total)
		}
		return nil
	})
	return out, complete, err
}

// CurrentVehicle returns the registration currently on the permit, or "" if the
// permit genuinely has no vehicle.
func (c *Client) CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error) {
	if err := c.permitMine(p); err != nil {
		return "", err
	}
	var reg string
	err := c.withSession(ctx, owner, false, func(s *provider.Session) error {
		v, err := c.p.CurrentVehicle(ctx, s, ref(p))
		reg = v.Registration
		return err
	})
	return reg, err
}

// SetVehicle reallocates the permit to the given registration, the core action.
// The provider confirms the change against the portal's own record before
// reporting success, so every state we then show or store reflects what the
// tenant actually has.
func (c *Client) SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error {
	if err := c.permitMine(p); err != nil {
		return err
	}
	key := regKey{owner, p.CouncilPermitID}
	gen := c.regGeneration(key) // so a concurrent ForgetPermit invalidates the cache write below
	err := c.withSession(ctx, owner, false, func(s *provider.Session) error {
		return c.p.SetVehicle(ctx, s, ref(p), registration)
	})
	if err == nil {
		c.storeRegIfCurrent(key, gen, registration)
	}
	return err
}

// ClearVehicle removes the vehicle from a permit, leaving it with none. It is
// deliberately a SEPARATE, explicit operation, never something the scheduler does
// on its own — "nothing scheduled" leaves the last plate in place. ErrUnsupported
// when the provider cannot leave a permit empty.
func (c *Client) ClearVehicle(ctx context.Context, owner string, p model.Permit) error {
	if err := c.permitMine(p); err != nil {
		return err
	}
	if !c.Capabilities().CanClearVehicle {
		return ErrUnsupported
	}
	key := regKey{owner, p.CouncilPermitID}
	gen := c.regGeneration(key)
	err := c.withSession(ctx, owner, false, func(s *provider.Session) error {
		return c.p.ClearVehicle(ctx, s, ref(p))
	})
	if err == nil {
		c.storeRegIfCurrent(key, gen, "")
	}
	return err
}

// ---- expiry tagging ----

// SessionExpiredError is ErrSessionExpired carrying the generation of the session
// that failed. The async recovery queue needs the version it FAILED at: if it
// instead re-read the row when queueing, a re-link landing in between would make
// it bind to — and then potentially retire — the user's brand-new session.
type SessionExpiredError struct{ Gen int64 }

func (e *SessionExpiredError) Error() string { return ErrSessionExpired.Error() }
func (e *SessionExpiredError) Unwrap() error { return ErrSessionExpired }

// withSessionGen tags an expiry with the failing session's generation, passing any
// other error through untouched.
func withSessionGen(err error, gen int64) error {
	if err == nil {
		return nil
	}
	if _, tagged := SessionGenOf(err); tagged {
		return err
	}
	if errors.Is(err, ErrSessionExpired) {
		return &SessionExpiredError{Gen: gen}
	}
	return err
}

// SessionGenOf reports the generation an expiry failed at, and whether it was tagged.
func SessionGenOf(err error) (int64, bool) {
	var se *SessionExpiredError
	if errors.As(err, &se) {
		return se.Gen, true
	}
	return 0, false
}

// ---- plate cache ----

// ErrNoCachedPlate means no plate has been fetched from the tenant yet for this
// permit; a background refresh has been started and the caller should fall back
// to its stored belief for now.
var ErrNoCachedPlate = errors.New("parking: no cached plate yet")

// CurrentVehicleCached returns the permit's plate as last fetched from the tenant,
// refreshing in the background once the value is older than maxAge. It NEVER calls
// the tenant synchronously: a page render must not block on a slow portal. A stale
// value is served while one refresh per permit runs; fresh reports whether the value
// is within maxAge, and age is how old the reading actually is.
func (c *Client) CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (reg string, age time.Duration, fresh bool, err error) {
	v, ok := c.regCache.Load(regKey{owner, p.CouncilPermitID})
	if ok {
		age = time.Since(v.(cachedReg).at)
		if age < maxAge {
			return v.(cachedReg).reg, age, true, nil
		}
	}
	c.refreshCurrentVehicle(owner, p)
	if ok {
		return v.(cachedReg).reg, age, false, nil // stale but real; the refresh catches drift
	}
	return "", 0, false, ErrNoCachedPlate
}

// ForgetPermit drops an owner's cached plate for a permit. Call it when the app
// stops managing the permit: the cache is otherwise never evicted.
func (c *Client) ForgetPermit(owner, tenantPermitID string) {
	key := regKey{owner, tenantPermitID}
	c.regGenMu.Lock()
	if c.regGen == nil {
		c.regGen = map[regKey]uint64{}
	}
	c.regGen[key]++ // invalidate any refresh/write already in flight for this key
	c.regGenMu.Unlock()
	c.regCache.Delete(key)
	c.regFail.Delete(key) // a permit nobody manages has no failure streak worth reporting
}

func (c *Client) regGeneration(key regKey) uint64 {
	c.regGenMu.Lock()
	defer c.regGenMu.Unlock()
	return c.regGen[key]
}

// storeRegIfCurrent writes reg to the cache only if the key has not been forgotten
// since gen was captured.
func (c *Client) storeRegIfCurrent(key regKey, gen uint64, reg string) {
	c.regGenMu.Lock()
	defer c.regGenMu.Unlock()
	if c.regGen[key] != gen {
		return
	}
	c.regCache.Store(key, cachedReg{reg: reg, at: time.Now()})
}

// refreshCurrentVehicle fetches the permit's plate in the background, detached
// from any request context, deduplicating concurrent refreshes per permit. The
// failure STREAK is recorded so the UI can distinguish "the reading is old because
// nobody looked" from "we have been trying and failing".
func (c *Client) refreshCurrentVehicle(owner string, p model.Permit) {
	key := regKey{owner, p.CouncilPermitID}
	if _, inflight := c.regRefresh.LoadOrStore(key, struct{}{}); inflight {
		return
	}
	gen := c.regGeneration(key) // capture before the read; ForgetPermit bumps it
	go func() {
		defer c.regRefresh.Delete(key)
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		reg, err := c.CurrentVehicle(ctx, owner, p)
		if err != nil {
			log.Printf("parking: background plate refresh for permit %s: %v", p.CouncilPermitID, err)
			c.regFail.LoadOrStore(key, time.Now()) // keep the streak's START on repeats
			c.noteExpired(owner, err)
			return
		}
		c.regFail.Delete(key)
		c.storeRegIfCurrent(key, gen, reg)
	}()
}

// noteExpired reports a generation-tagged session expiry to OnSessionExpired.
func (c *Client) noteExpired(owner string, err error) {
	if c.OnSessionExpired == nil {
		return
	}
	if gen, ok := SessionGenOf(err); ok {
		c.OnSessionExpired(owner, c.TenantID, gen)
	}
}

// RefreshFailingFor reports how long background plate refreshes for this permit
// have been failing CONSECUTIVELY — zero when the last attempt succeeded.
func (c *Client) RefreshFailingFor(owner string, p model.Permit) time.Duration {
	if v, ok := c.regFail.Load(regKey{owner, p.CouncilPermitID}); ok {
		return time.Since(v.(time.Time))
	}
	return 0
}

// noteTruncatedGrid records that the tenant returned fewer permits than it
// claimed, for the status page. Last-one-wins: a shape signal, not a tally.
func (c *Client) noteTruncatedGrid(got, want int) {
	c.truncMu.Lock()
	c.truncAt, c.truncGot, c.truncWant = time.Now(), got, want
	c.truncMu.Unlock()
}

// Diagnose runs fn against the owner's live session material under the same
// lock, backoff and persistence discipline as every other operation. It exists
// for the env-gated live tooling (captures, session probes); the app never calls it.
func (c *Client) Diagnose(ctx context.Context, owner string, fn func(p provider.Provider, s *provider.Session) error) error {
	return c.withSession(ctx, owner, false, func(s *provider.Session) error { return fn(c.p, s) })
}
