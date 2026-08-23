// Package parking is the per-app-user client for the City of Stonnington
// ePermits system (multi-user).
//
// The council issues NO refresh tokens, its public SPA client `ePermits.ssp.web`
// is not granted offline_access. Instead the app mirrors the SPA's own
// mechanism: it holds each user's IdentityServer SESSION COOKIE and silent-renews
// (a prompt=none Authorization-Code + PKCE flow) to mint short-lived (~1h) access
// tokens on demand. Onboarding (Link) does a headless login with the user's
// council credentials to obtain that cookie. The password is discarded unless the
// user opted in to auto-reconnect (the default in the UI), in which case it is
// sealed at rest alongside the cookie so a lapsed session can be re-established
// without them. The cookie itself may rotate on renew and is re-persisted.
//
// The access token is a Bearer credential for the /ssp-svc/api permit endpoints.
// The request/response shapes mirror the portal's own SPA; an unexpected shape
// surfaces as a FailUnexpected operator alert (the signal that the council has
// changed its API and this client needs updating).
package parking

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

var (
	// ErrNotLinked means the app user has no stored council session.
	ErrNotLinked = errors.New("parking: council account not linked")
	// ErrSessionExpired means the stored session cookie is no longer valid; the
	// user must re-link (headless login) to obtain a fresh cookie.
	ErrSessionExpired = errors.New("parking: council session expired; re-link required")
	// ErrNoSavedPassword means an auto-reconnect was attempted but the user never
	// opted to save their council password, so a manual re-link is required.
	ErrNoSavedPassword = errors.New("parking: no saved council password for auto-reconnect")
	// ErrLoginRejected means a headless login completed but did NOT establish a
	// session — the credentials are wrong (as opposed to a transient/network fault).
	// A saved-password auto-reconnect that hits this must stop retrying and prompt a
	// manual re-link; any OTHER error is treated as transient and retried.
	ErrLoginRejected = errors.New("parking: login did not establish a session (check the username and password)")
	// ErrLoginFormUnrecognised means the council's sign-in page was fetched fine but
	// is not the form this client knows how to fill in (a missing or empty
	// antiforgery token, or no credential inputs). It is deliberately distinct from
	// ErrLoginRejected: the credentials were never even submitted, so nothing here
	// says anything about the user's password. It needs an operator to look at the
	// portal's HTML, and until they do, callers must keep the session and the saved
	// password intact.
	ErrLoginFormUnrecognised = errors.New("parking: council sign-in page shape not recognised (the portal's HTML changed?)")
	// ErrLoginOffHost means the login flow was asked to send the user's council
	// password somewhere the council configuration never named — an off-host form
	// action, an off-host redirect, or a scheme downgrade. The credentials are NOT
	// sent. Like ErrLoginFormUnrecognised this says nothing about the password, but
	// unlike it this is a security event and is logged as one.
	ErrLoginOffHost = errors.New("parking: council sign-in points off-host; refusing to send credentials")
	// ErrNotCaptured marks a call whose request/response shape is still unknown.
	ErrNotCaptured = errors.New("parking: endpoint not yet reverse-engineered (needs a capture)")
	// ErrCouncilBusy means the portal is pushing back (Azure Front Door 429/403/503) or the
	// owner is in a backoff cooldown. Callers should treat it as transient and NOT
	// retry immediately; the client already enforces an exponential per-owner
	// cooldown so it is not hammered.
	ErrCouncilBusy = errors.New("parking: council temporarily unavailable (rate-limited or blocked); backing off")
)

// Plain-English descriptions of what a council operation was trying to do,
// carried on a CouncilError so a notification can name it. Shared as constants
// where more than one function reports the same operation.
const (
	opLogin       = "sign in to your council account"
	opReadVehicle = "read the current vehicle on your permit"
)

// FailureKind classifies WHY a council operation failed, so callers can word the
// user's notification correctly and decide whether to retry quietly or ask the
// user to act.
type FailureKind int

const (
	// FailTransient: a network error or a 5xx from the council. A retry is likely
	// to succeed, so the user should not be alarmed on the first occurrence.
	FailTransient FailureKind = iota
	// FailRejected: the council refused the request (a 4xx, or the permit can't be
	// edited). This will not fix itself; the user needs to check or act.
	FailRejected
	// FailUnexpected: the council returned something we couldn't parse. Possibly a
	// one-off glitch, possibly an API change (worth an operator alert in bulk).
	FailUnexpected
)

// CouncilError wraps a failed council operation with its kind and a plain-English
// description of the operation ("read the current vehicle on your permit"), used
// to build human notifications. Unwraps to the underlying cause.
type CouncilError struct {
	Kind FailureKind
	Op   string
	Err  error
}

func (e *CouncilError) Error() string { return fmt.Sprintf("parking: %s: %v", e.Op, e.Err) }
func (e *CouncilError) Unwrap() error { return e.Err }

func councilErr(kind FailureKind, op string, err error) error {
	return &CouncilError{Kind: kind, Op: op, Err: err}
}

// FailureOf extracts the classification from an error. For anything that is not a
// CouncilError it defaults to FailTransient (retry, don't alarm) since an
// unclassified error is more likely a transient glitch than a permanent refusal.
func FailureOf(err error) (kind FailureKind, op string) {
	var ce *CouncilError
	if errors.As(err, &ce) {
		return ce.Kind, ce.Op
	}
	return FailTransient, ""
}

// Client talks to the council IdentityServer and permit API on behalf of app
// users. It is safe for concurrent use.
type Client struct {
	clientID    string
	redirectURI string // the SPA client's registered callback; we read the code from the 302
	scope       string // space-joined scopes (no offline_access)
	authURL     string // issuer + /connect/authorize
	tokenURL    string // issuer + /connect/token
	loginURL    string // issuer + /Account/Login
	apiBase     string // e.g. https://…/ssp-svc
	origin      string // scheme+host of the portal, for Origin/Referer headers
	store       *store.Store
	box         *secretbox.Box
	http        *http.Client // redirects handled manually; cookies passed per-user
	regCache    sync.Map     // regKey -> cachedReg, to bound council reads
	regRefresh  sync.Map     // regKey -> struct{}, dedupes in-flight background plate refreshes
	regFail     sync.Map     // regKey -> time.Time, start of the current refresh-failure streak (see RefreshFailingFor)
	// OnSessionExpired, when set (main.go wires it to the scheduler's reconnect
	// queue), is called whenever a BACKGROUND read discovers the session is dead.
	// Recovery used to be triggered only by the scheduler's own council touches
	// (keep-warm, applies) on the premise that keep-warm noticed deaths within
	// its interval — true at the original ~45-75m interval, silently false once
	// it was stretched to ~9h for traffic reduction. That left the dashboard
	// proving a session dead every few seconds while recovery slept for hours
	// (observed live 2026-08-11). Called from refresh goroutines: must be safe
	// for concurrent use, and cheap on repeats (the queue dedupes per owner).
	OnSessionExpired func(owner string, gen int64)
	// regGen is a per-key generation, bumped by ForgetPermit, so a plate read that was
	// already in flight when a permit was removed cannot resurrect the cache entry
	// afterwards. Guarded by regGenMu (writes only; regCache reads stay lock-free).
	regGenMu sync.Mutex
	regGen   map[regKey]uint64
	traffic  trafficCounters

	renewLocks    sync.Map   // owner -> *sync.Mutex, serialises silent-renew per owner
	cooldownUntil sync.Map   // owner -> time.Time, soft-block backoff deadline
	strikes       sync.Map   // owner -> int, consecutive soft blocks (backoff growth)
	strikeMu      sync.Mutex // serialises the strike read-modify-write in penalize

	// breaker is the FLEET-level counterpart to the per-owner cooldown: it pauses
	// ALL council traffic when several distinct owners are pushed back at once, the
	// signature of an Azure-Front-Door block on our shared egress IP (see breaker.go).
	breaker *breaker
	// gov bounds the rate and concurrency of outbound requests at the transport, to
	// keep our shared-IP traffic low and burst-free so a block is less likely to
	// start (the preventive counterpart to the reactive breaker; see governor.go).
	gov *governor
	// loginFlow serialises whole CREDENTIAL LOGIN flows (Link, and Reconnect which
	// calls it) to one at a time. The transport governor bounds individual requests,
	// but the risk pattern is many DISTINCT authentication flows from one IP at once
	// — several reconnects interleaving their login-page / credential-POST / callback
	// requests. A capacity-1 channel makes a headless login an atomic operation on
	// the wire: the next flow waits for the current one to finish.
	loginFlow chan struct{}

	// persist-health of the breaker-state write, surfaced on /status so the operator
	// knows whether restart-protection is intact during an incident (a failing write
	// means a restart could clear the pause). Nil error = last write succeeded (or
	// none needed yet).
	persistMu  sync.Mutex
	persistErr error

	// truncMu guards the last observed short permit grid, surfaced on the status page
	// so a paging change is visible to an operator rather than only in the journal.
	truncMu   sync.Mutex
	truncAt   time.Time
	truncGot  int
	truncWant int
	persistAt time.Time

	sandbox *councilSandbox // non-nil in COUNCIL_SANDBOX mode: fake the council in memory
}

type cachedReg struct {
	reg string
	at  time.Time
}

// regKey identifies a cached plate reading. The owner is part of the key because
// a council permit can change hands: a household permit is often visible to two
// council logins, and "stop managing" here plus "manage" from the other account is
// the ordinary way that happens. Keyed on the permit alone, the new holder was
// served the previous holder's cached plate as their permit's current state — a
// wrong plate is a real parking fine, so the cache must not be able to cross an
// account boundary at all.
type regKey struct {
	owner    string
	permitID string // the council's PKPermitID
}

// New builds a Client. Council OAuth endpoints follow the standard Duende
// IdentityServer layout under the issuer, so no boot-time discovery call is
// needed (keeps startup independent of council availability).
func New(cfg *config.Config, st *store.Store, box *secretbox.Box) *Client {
	issuer := strings.TrimRight(cfg.Council.Issuer, "/")
	apiBase := strings.TrimRight(cfg.Council.APIBase, "/")
	var sb *councilSandbox
	if cfg.Council.Sandbox {
		sb = newCouncilSandbox()
	}
	c := &Client{
		sandbox:     sb,
		clientID:    cfg.Council.ClientID, // public SPA client, no secret
		redirectURI: cfg.Council.RedirectURI,
		scope:       strings.Join(cfg.Council.Scopes, " "),
		authURL:     issuer + "/connect/authorize",
		tokenURL:    issuer + "/connect/token",
		loginURL:    issuer + "/Account/Login",
		apiBase:     apiBase,
		origin:      originOf(issuer, apiBase),
		store:       st,
		box:         box,
		breaker: newBreaker(defaultBreakerThreshold, defaultBreakerWindow,
			defaultBreakerCooldown, defaultBreakerProbe),
		gov: newGovernor(
			govOr(cfg.Council.GovRatePerMin, defaultGovTotalPerMin),
			govOr(cfg.Council.GovBurst, defaultGovTotalBurst),
			govOr(cfg.Council.GovLoginRatePerMin, defaultGovLoginPerMin),
			govOr(cfg.Council.GovLoginBurst, defaultGovLoginBurst),
			govIntOr(cfg.Council.GovConcurrency, defaultGovConcurrency)),
		loginFlow: make(chan struct{}, 1),
	}
	// Track request rate with headroom over the widest window Stats queries (5m):
	// the extra slots keep each in-window minute in its own bucket even if adds ever
	// arrive slightly out of order, so a just-aged-out minute can't collide with a
	// live one.
	c.traffic.rolling = newRollingCounter(8)
	// Restore a persisted breaker pause: if a block was in force when this process
	// last stopped, resume paused rather than resuming full traffic into the block
	// (which a container restart would otherwise do — the escalation this prevents).
	if bs, err := st.LoadBreakerState(context.Background()); err == nil {
		c.breaker.restore(bs.OpenUntil, bs.LastPushback, bs.Generation)
		if bs.OpenUntil.After(time.Now()) {
			log.Printf("parking: fleet circuit restored OPEN from persisted state (paused %s) — a block survived a restart", time.Until(bs.OpenUntil).Round(time.Second))
		}
	} else {
		log.Printf("parking: load persisted breaker state: %v (starting closed)", err)
	}
	c.http = &http.Client{
		Timeout: 30 * time.Second,
		// Present as a browser on every request (never Go's default UA), and
		// tally every outbound council request so traffic is measurable.
		Transport: browserTransport{base: http.DefaultTransport, traffic: &c.traffic, gov: c.gov},
		// We inspect 302s ourselves to read the auth code and rotated cookie.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c
}

// acquireLoginFlow blocks until no other credential login flow is running, then
// claims the single slot; the returned release frees it (deferred, so it survives
// panics and every error path). A nil channel (tests constructing a bare Client)
// is a no-op. Bounded by ctx so a waiting flow fails cleanly rather than hanging,
// and never deadlocks a user link behind a stuck reconnect — the loser just waits
// its turn or times out.
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
// resumes from it. Called on every open/close/pushback transition; breaker
// transitions are rare (only during a real block), so the write cost is negligible.
// Best-effort: a failed write is logged, not fatal — the in-memory breaker still
// works, we just lose the restart-survival guarantee for that one transition.
func (c *Client) persistBreaker() {
	if c.store == nil {
		return
	}
	// Ordering is enforced in SQL (SaveBreakerState only applies a generation >= the
	// stored one), so an older snapshot can no longer overwrite a newer one and this
	// does NOT need to hold a lock across the write. That matters: /status reads
	// persistErr under the same mutex, and a fleet block is when both are busiest.
	openUntil, lastPushback, gen := c.breaker.snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.store.SaveBreakerState(ctx, store.BreakerState{
		OpenUntil: openUntil, LastPushback: lastPushback, Generation: gen,
	})
	c.persistMu.Lock()
	c.persistErr, c.persistAt = err, time.Now()
	c.persistMu.Unlock()
	if err != nil {
		log.Printf("parking: persist breaker state: %v (restart-protection degraded)", err)
	}
}

// originOf returns the scheme://host to use as the browser Origin/Referer for
// council requests, derived from the API base (falling back to the issuer).
func originOf(issuer, apiBase string) string {
	for _, raw := range []string{apiBase, issuer} {
		if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

// Linked reports whether the app user has a stored council session cookie.
func (c *Client) Linked(ctx context.Context, owner string) bool {
	cs, err := c.store.GetCouncilSession(ctx, owner)
	return err == nil && cs.Cookie != ""
}

// openCookie decrypts the stored session cookie. A decrypt failure means the
// at-rest key no longer matches the sealed data (e.g. DATA_ENCRYPTION_KEY was
// rotated), so the cookie is permanently unusable. We map that to
// ErrSessionExpired: the scheduler retires the session and the dashboard prompts
// a re-link (and the user is notified), rather than failing silently every tick
// while still appearing "linked".
func (c *Client) openCookie(owner, sealed string) (string, error) {
	cookie, legacy, err := c.box.OpenCtx(secretbox.CouncilCookie(owner), sealed)
	if legacy {
		// Sealed before ciphertexts were bound to their owner and purpose. It still
		// opens, and the next renew re-seals it bound; nothing to do but note it.
		log.Printf("parking: cookie for %s is an unbound legacy ciphertext; it will be re-sealed on the next renew", redact.Email(owner))
	}
	if err != nil {
		log.Printf("parking: unseal cookie for %s failed (%v); treating as expired session (re-link required)", redact.Email(owner), err)
		return "", ErrSessionExpired
	}
	return cookie, nil
}

// accessToken returns a valid council access token for the app user, silent-
// renewing against the stored session cookie when the cached token is stale.
func (c *Client) accessToken(ctx context.Context, owner string) (string, error) {
	cs, err := c.store.GetCouncilSession(ctx, owner)
	if err != nil || cs.Cookie == "" {
		return "", ErrNotLinked
	}
	// Reuse a cached access token while it is comfortably unexpired.
	if cs.AccessToken != "" && time.Until(cs.TokenExpiry) > 60*time.Second {
		if at, _, err := c.box.OpenCtx(secretbox.CouncilToken(owner), cs.AccessToken); err == nil {
			return at, nil
		}
	}

	// Serialise renews per owner: a concurrent keep-warm pass may already be
	// renewing this session, and two silent-renews racing on one cookie can
	// rotate it out from under each other. Lock, then re-read in case the other
	// goroutine already produced a fresh token.
	lock := c.ownerLock(owner)
	lock.Lock()
	defer lock.Unlock()
	if cs, err = c.store.GetCouncilSession(ctx, owner); err != nil || cs.Cookie == "" {
		return "", ErrNotLinked
	}
	if cs.AccessToken != "" && time.Until(cs.TokenExpiry) > 60*time.Second {
		if at, _, err := c.box.OpenCtx(secretbox.CouncilToken(owner), cs.AccessToken); err == nil {
			return at, nil
		}
	}
	return c.renewLocked(ctx, owner, cs)
}

// renewLocked silent-renews the owner's session and persists the fresh token
// (and any rotated cookie). The caller must hold ownerLock(owner). The IDM
// endpoints sit behind the same per-owner cooldown as the API: they are the
// path most likely to attract Azure Front Door push-back, so hammering them while blocked
// is exactly the soft-block → hard-block escalation the backoff exists to stop.
func (c *Client) renewLocked(ctx context.Context, owner string, cs store.CouncilSession) (string, error) {
	if d, blocked := c.cooldownFor(owner); blocked {
		return "", fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	// No breakerGate here: renewLocked always runs INSIDE an already-gated operation
	// (apiRequest, or renewedToken on its 401 retry), and a second gate during
	// half-open would take the single probe slot and then block this very renew. The
	// per-owner cooldown above is still ours to check. The operation reports the
	// breaker success at its own level with the permit it holds.
	cookie, err := c.openCookie(owner, cs.Cookie)
	if err != nil {
		return "", err
	}
	at, expiry, newCookie, err := c.silentRenew(ctx, owner, cookie)
	if err != nil {
		return "", withSessionGen(err, cs.Generation) // see warmLocked
	}
	sealedAccess, err := c.box.SealCtx(secretbox.CouncilToken(owner), at)
	if err != nil {
		return "", err
	}
	sealedCookie := cs.Cookie
	if newCookie != "" && newCookie != cookie {
		// A Seal failure must not silently keep the OLD cookie: the rotation may
		// have invalidated it, and the next renew would then look like an expiry.
		sc, err := c.box.SealCtx(secretbox.CouncilCookie(owner), newCookie)
		if err != nil {
			return "", err
		}
		sealedCookie = sc
	}
	if err := c.store.UpdateCouncilToken(ctx, owner, sealedCookie, sealedAccess, expiry, cs.Generation); err != nil {
		return "", err
	}
	return at, nil
}

// renewedToken force-renews after the council rejected a token mid-life (401):
// the cached token is ignored and a fresh silent-renew runs under the owner
// lock, so a session kicked server-side (e.g. the user logged into the portal
// in a browser) recovers immediately instead of failing until natural expiry.
func (c *Client) renewedToken(ctx context.Context, owner string) (string, error) {
	lock := c.ownerLock(owner)
	lock.Lock()
	defer lock.Unlock()
	cs, err := c.store.GetCouncilSession(ctx, owner)
	if err != nil || cs.Cookie == "" {
		return "", ErrNotLinked
	}
	return c.renewLocked(ctx, owner, cs)
}

// Refresh slides the council session so an idle user's session does not lapse
// (keep-warm). It does an AUTHORIZE-ONLY renew: the authenticated authorize is the
// only request that touches the session (the IdentityServer slides it server-side),
// so warming needs neither the token exchange nor a token — one request instead of
// two, roughly halving the fleet's steady-state auth traffic. A real operation
// mints its token on demand via accessToken(). Returns ErrNotLinked if there is no
// session and ErrSessionExpired if the cookie is no longer accepted.
func (c *Client) Refresh(ctx context.Context, owner string) error {
	if c.sandbox != nil {
		return nil // sandbox sessions never lapse
	}
	// Serialise with accessToken so keep-warm and a reconcile write never renew
	// the same session concurrently.
	lock := c.ownerLock(owner)
	lock.Lock()
	defer lock.Unlock()

	cs, err := c.store.GetCouncilSession(ctx, owner)
	if err != nil || cs.Cookie == "" {
		return ErrNotLinked
	}
	return c.warmLocked(ctx, owner, cs)
}

// warmLocked performs an authorize-only keep-warm and persists the (re-sealed)
// cookie, bumping the freshness clock but leaving the access token untouched. The
// caller must hold ownerLock(owner). Like renewLocked it honours the per-owner
// cooldown and the fleet breaker: the /connect authorize is the surface most prone
// to edge push-back, so warming while blocked is exactly the escalation the backoff
// exists to prevent.
func (c *Client) warmLocked(ctx context.Context, owner string, cs store.CouncilSession) error {
	if d, blocked := c.cooldownFor(owner); blocked {
		return fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	permit, err := c.breakerGate()
	if err != nil {
		return err
	}
	cookie, err := c.openCookie(owner, cs.Cookie)
	if err != nil {
		return err
	}
	newCookie, err := c.warmRenew(ctx, owner, cookie)
	if err != nil {
		// Tag an expiry with the generation of the session that actually failed, so the
		// scheduler's recovery queue binds to THIS session and not to whatever the row
		// holds by the time it enqueues (a re-link can land in between).
		return withSessionGen(err, cs.Generation)
	}
	// The keep-warm probe's happy path: an authorize-only warm is the most common
	// half-open probe (the recovery tick fires it), so its success is what usually
	// closes the circuit.
	c.noteCouncilSuccess(owner, permit)
	// Re-seal and persist even when the cookie did not rotate: the write is what
	// resets updated_at, keep-warm's freshness clock, so the next pass doesn't renew
	// again immediately (see store.UpdateCouncilCookie). A Seal failure must surface,
	// not silently skip the freshness bump.
	sealed, err := c.box.SealCtx(secretbox.CouncilCookie(owner), newCookie)
	if err != nil {
		return err
	}
	return c.store.UpdateCouncilCookie(ctx, owner, sealed, cs.Generation)
}

// apiRequest issues an authenticated request to the permit API as the app user.
// It short-circuits while the owner is in a soft-block cooldown, and classifies
// Azure Front Door push-back (429/403/503) as ErrCouncilBusy with an exponential backoff so
// the scheduler stops re-hitting a portal that is already refusing us.
// op is a plain-English description of what the request is doing, used to build
// human notifications when it fails. On any non-2xx (other than the busy codes)
// or a transport error, apiRequest returns a classified CouncilError and no
// response; a 2xx returns the response for the caller to decode.
func (c *Client) apiRequest(ctx context.Context, owner, method, path, op string, query url.Values, body []byte) (*http.Response, error) {
	if d, blocked := c.cooldownFor(owner); blocked {
		return nil, fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	permit, err := c.breakerGate()
	if err != nil {
		return nil, err
	}
	at, err := c.accessToken(ctx, owner)
	if err != nil {
		return nil, err
	}
	resp, err := c.doAPI(ctx, at, method, path, query, body)
	if err != nil {
		// Transport error (DNS, dial, timeout, reset): transient by nature.
		return nil, councilErr(FailTransient, op, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The cached token was rejected mid-life (the council can kick a session
		// server-side, e.g. when the user logs into the portal in a browser).
		// Force one silent-renew and retry; if the renew itself fails the error
		// (ErrSessionExpired, ErrCouncilBusy, …) flows out and the retire/
		// reconnect machinery engages instead of the user seeing a false alarm.
		drainClose(resp)
		at, err = c.renewedToken(ctx, owner)
		if err != nil {
			return nil, err
		}
		resp, err = c.doAPI(ctx, at, method, path, query, body)
		if err != nil {
			return nil, councilErr(FailTransient, op, err)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			// A freshly-minted token is still refused: not a stale-token blip.
			drainClose(resp)
			return nil, councilErr(FailRejected, op, errors.New("council rejected a fresh access token (401)"))
		}
	}
	switch resp.StatusCode {
	case http.StatusForbidden:
		// Two very different things arrive as 403: Azure Front Door push-back (an HTML
		// challenge page — transient, back off) and a genuine API refusal (JSON,
		// e.g. permit access revoked — durable, will never self-heal). Treating
		// the latter as "busy" would cooldown-loop the owner forever with a
		// soothing "temporarily unavailable" message.
		if isJSONResponse(resp) {
			drainClose(resp)
			return nil, councilErr(FailRejected, op, errors.New("the council refused access (403)"))
		}
		fallthrough
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		ra := parseRetryAfter(resp)
		c.recordPushback(resp)
		drainClose(resp)
		c.penalize(owner, ra)
		return nil, fmt.Errorf("%w: council returned %d", ErrCouncilBusy, resp.StatusCode)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.clearPenalty(owner)
		c.noteCouncilSuccess(owner, permit) // closes the circuit only if this was the probe
		return resp, nil
	}
	// Other non-2xx: 5xx is a server-side blip (transient); 4xx is a refusal.
	// A refusal usually carries the council's OWN reason, and it is the only thing
	// that can tell a user what to actually do — "Vehicle Registration has invalid
	// pattern" is actionable where "council returned 400" is not. Read it before
	// discarding the body.
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	drainClose(resp)
	kind := FailRejected
	if resp.StatusCode >= 500 {
		kind = FailTransient
	}
	if msg := councilErrorMessage(errBody); msg != "" {
		return nil, councilErr(kind, op, fmt.Errorf("the council refused it: %s (%d)", msg, resp.StatusCode))
	}
	return nil, councilErr(kind, op, fmt.Errorf("council returned %d", resp.StatusCode))
}

// doAPI issues one authenticated permit-API request. Body is bytes (not a
// Reader) so the 401 path can replay it.
func (c *Client) doAPI(ctx context.Context, at, method, path string, query url.Values, body []byte) (*http.Response, error) {
	u := c.apiBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("Content-Type", "application/json")
	c.xhrHeaders(req)
	return c.http.Do(req)
}

// drainClose discards (a bounded amount of) the body and closes it, so the
// keep-alive connection is reusable.
func drainClose(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

// councilErrorPayload is the council's refusal body: a JSON ARRAY of message
// objects, e.g.
//
//	[{"Level":0,"Message":"Vehicle Registration has invalid pattern","ID":null,…}]
//
// Captured live on 2026-07-31 from a rejected manageVehicle POST.
type councilErrorPayload struct {
	Message       string `json:"Message"`
	CustomMessage string `json:"CustomMessage"`
}

// councilErrorMessage extracts a human-readable reason from a council refusal
// body, or "" if there is nothing usable. The result is portal-controlled text
// that flows into error strings, logs and user notifications, so it is passed
// through safeExcerpt — a refusal message must not be able to forge log lines.
//
// Multiple messages are joined: the council reports per-field validation, and
// showing only the first would hide the rest of what the user has to fix.
func councilErrorMessage(body []byte) string {
	var payload []councilErrorPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	var msgs []string
	for _, p := range payload {
		m := p.CustomMessage // the council's own user-facing wording, when it sets one
		if strings.TrimSpace(m) == "" {
			m = p.Message
		}
		if m = strings.TrimSpace(m); m != "" {
			msgs = append(msgs, m)
		}
	}
	if len(msgs) == 0 {
		return ""
	}
	return safeExcerpt(strings.Join(msgs, "; "))
}

// isJSONResponse reports whether the response declares a JSON body — the shape
// the council API itself speaks, as opposed to an Azure Front Door HTML challenge page.
func isJSONResponse(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "json")
}

// managedVehicleResp is the response of GET /ssp-svc/api/permits/managedVehicle.
//
// Verified against a live response. NOTE the casing is mixed: the top-level keys
// are camelCase, but the permitVehicles[] element keys are PascalCase. Within an
// element, PKPermitVehicleDetailID arrives as a bare JSON number while
// FKVehicleStateID arrives as a quoted string, hence the differing Go types.
type managedVehicleResp struct {
	PermitNumber string `json:"permitNumber"`
	// A POINTER so an OMITTED permitVehicleCount is distinguishable from a present
	// zero: emptyIsCredible must not accept a response that merely dropped the field.
	PermitVehicleCount *int `json:"permitVehicleCount"`
	MaxVehicles        int  `json:"maxVehicles"`
	// POINTER like CanEditOrDeleteVehicle: this now gates ADDING a vehicle to a
	// credibly-empty permit (the normal state of a freshly granted permit). Absent
	// decodes to false, which would turn a dropped/renamed field into "the council
	// won't let you add a vehicle" for EVERY new household at once — a durable
	// refusal that never self-heals. Absent must be UNEXPECTED (retry + alert), not
	// a plain false.
	CanAddVehicle *bool `json:"canAddVehicle"`
	// POINTER for the same reason as PermitVehicleCount: this one drives a DURABLE
	// refusal. Absent decodes to false, which would turn a dropped/renamed field into
	// "the council does not allow changing this permit's vehicle" for EVERY permit at
	// once — alarming every household with a false statement about their council
	// account, and never retrying (FailRejected).
	CanEditOrDeleteVehicle *bool           `json:"canEditOrDeleteVehicle"`
	PermitVehicles         []permitVehicle `json:"permitVehicles"`
}

// permitVehicle is one vehicle currently attached to the permit.
type permitVehicle struct {
	PKPermitVehicleDetailID json.Number `json:"PKPermitVehicleDetailID"`
	RegistrationNumber      string      `json:"RegistrationNumber"`
	FKVehicleStateID        string      `json:"FKVehicleStateID"`
}

// manageVehicleReq is the body of POST /ssp-svc/api/permits/manageVehicle.
// Field names, casing, and value types (note the string-typed IDs) mirror a
// captured, server-accepted request exactly.
type manageVehicleReq struct {
	PKPermitID          int64          `json:"PKPermitID"`
	SelectedVehicle     string         `json:"SelectedVehicle"`
	VehicleActionOption string         `json:"VehicleActionOption"`
	Vehicle             manageVehicleV `json:"Vehicle"`
}

type manageVehicleV struct {
	ChangeSetID             string  `json:"ChangeSetID"`
	FKPermitID              int64   `json:"FKPermitID"`
	FKVehicleColourID       *int64  `json:"FKVehicleColourID"`
	FKVehicleMakeID         *int64  `json:"FKVehicleMakeID"`
	FKVehicleModelID        *int64  `json:"FKVehicleModelID"`
	FKVehicleTypeID         *int64  `json:"FKVehicleTypeID"`
	FKVehicleStateID        string  `json:"FKVehicleStateID"`
	PKPermitVehicleDetailID string  `json:"PKPermitVehicleDetailID"`
	RegisteredAtAddress     bool    `json:"RegisteredAtAddress"`
	RegistrationNumber      string  `json:"RegistrationNumber"`
	VehicleColour           *string `json:"VehicleColour"`
	VehicleMake             *string `json:"VehicleMake"`
	VehicleModel            *string `json:"VehicleModel"`
	VehicleNotes            *string `json:"VehicleNotes"`
	VehicleState            *string `json:"VehicleState"`
	VehicleStatus           *string `json:"VehicleStatus"`
	VehicleType             *string `json:"VehicleType"`
}

// emptyIsCredible reports whether an EMPTY permitVehicles list can be believed.
//
// A JSON object that simply lacks the keys we expect decodes into a zero-valued
// struct, so "this permit has no vehicle" and "we did not understand this
// response" arrive looking identical. Treating the second as the first is not a
// harmless default: the scheduler writes an empty active registration and logs
// that the plate was "changed directly at the council portal" — a false claim
// about the user's council account — and SetVehicle turns it into a durable "the
// permit has no vehicle to change" refusal that never self-heals.
//
// So an empty list is believed only when the rest of the response corroborates
// it: the permit is identified (permitNumber came back) and the portal's own
// count agrees there are no vehicles. Anything else is an unexpected shape, which
// is the operator alert that says the council changed its API.
func (mv *managedVehicleResp) emptyIsCredible() bool {
	// Every corroborating signal must be EXPLICITLY present: the permit is identified,
	// the count field came back (not merely defaulted to zero by being absent) and
	// says zero, AND permitVehicles is an explicit empty array rather than an omitted
	// key. A shape change that drops any of these no longer masquerades as "no
	// vehicle" — it surfaces as the unexpected-shape operator alert instead.
	return mv.PermitNumber != "" &&
		mv.PermitVehicleCount != nil && *mv.PermitVehicleCount == 0 &&
		mv.PermitVehicles != nil
}

// errVehicleShape describes an empty vehicle list that nothing in the response
// corroborates.
func errVehicleShape(mv *managedVehicleResp) error {
	count := "absent"
	if mv.PermitVehicleCount != nil {
		count = fmt.Sprintf("%d", *mv.PermitVehicleCount)
	}
	return fmt.Errorf("the council returned no vehicles but the response does not look like a permit record (permitNumber=%q, permitVehicleCount=%s, permitVehiclesPresent=%t): API shape change?",
		mv.PermitNumber, count, mv.PermitVehicles != nil)
}

// maxAPIBody bounds a permit-API JSON response. The real ones are a few
// kilobytes; the bound exists so a hostile or broken portal cannot make a decode
// consume memory in proportion to what it chooses to send. Matches the 1 MiB cap
// the token exchange already applies.
const maxAPIBody = 1 << 20

// managedVehicle fetches the vehicle(s) currently on the permit.
func (c *Client) managedVehicle(ctx context.Context, owner string, p model.Permit) (*managedVehicleResp, error) {
	resp, err := c.apiRequest(ctx, owner, http.MethodGet, "/api/permits/managedVehicle", opReadVehicle,
		url.Values{"permitID": {p.CouncilPermitID}}, nil)
	if err != nil {
		return nil, err // already classified (or a busy/auth sentinel)
	}
	defer resp.Body.Close()
	var mv managedVehicleResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&mv); err != nil {
		return nil, councilErr(FailUnexpected, opReadVehicle, err)
	}
	return &mv, nil
}

// CurrentVehicle returns the registration currently allocated to the permit, or
// "" if the permit genuinely has no vehicle. An empty list the response does not
// corroborate is an error, not an empty plate — see emptyIsCredible.
func (c *Client) CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error) {
	if c.sandbox != nil {
		return c.sandboxCurrentVehicle(p)
	}
	mv, err := c.managedVehicle(ctx, owner, p)
	if err != nil {
		return "", err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return "", councilErr(FailUnexpected, opReadVehicle, errVehicleShape(mv))
		}
		return "", nil
	}
	if len(mv.PermitVehicles) != 1 {
		// The visitor-permit model is one managed vehicle per permit. More than one is
		// an unexpected shape: reading (or later editing) only [0] could act on the
		// wrong record, so refuse rather than guess — surfaced as a possible API change.
		return "", councilErr(FailUnexpected, opReadVehicle,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	if strings.TrimSpace(mv.PermitVehicles[0].RegistrationNumber) == "" {
		// A PRESENT vehicle record with a blank plate is not the same as "no vehicle":
		// returning "" here would cache and display an uncorroborated clearing (and the
		// empty-vs-missing guards above deliberately never reach this point for a
		// genuine empty). Treat it as an unexpected shape rather than a false clearing.
		return "", councilErr(FailUnexpected, opReadVehicle,
			errors.New("a managed vehicle record has an empty registration: API shape change?"))
	}
	return mv.PermitVehicles[0].RegistrationNumber, nil
}

// SessionExpiredError is ErrSessionExpired carrying the generation of the session
// that failed. The async recovery queue needs the version it FAILED at: if it instead
// re-read the row when queueing, a re-link landing in between would make it bind to —
// and then potentially retire — the user's brand-new session. Unwraps to
// ErrSessionExpired, so every existing errors.Is check is unaffected.
type SessionExpiredError struct{ Gen int64 }

func (e *SessionExpiredError) Error() string { return ErrSessionExpired.Error() }
func (e *SessionExpiredError) Unwrap() error { return ErrSessionExpired }

// withSessionGen tags an expiry with the failing session's generation, passing any
// other error through untouched.
func withSessionGen(err error, gen int64) error {
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

// ErrNoCachedPlate means no plate has been fetched from the council yet for
// this permit; a background refresh has been started and the caller should fall
// back to its stored belief for now.
var ErrNoCachedPlate = errors.New("parking: no cached plate yet")

// CurrentVehicleCached returns the permit's plate as last fetched from the
// council, refreshing in the background once the value is older than maxAge.
// It NEVER calls the council synchronously: a page render must not block on a
// slow portal (the council client's 30s timeout outlives the HTTP server's 20s
// WriteTimeout, so a sync call here turns a slow council into a dropped
// connection — a 502 at the proxy). A stale value is served while one refresh
// per permit runs; fresh reports whether the value is within maxAge, and age is
// how old the reading actually is — which matters because a stale entry has NO
// upper bound (refresh failures deliberately leave it in place), so "not fresh"
// alone hides the difference between six minutes and three days. Callers that
// show the plate to a person must show the age once it is stale. Keeps the
// dashboard's "on permit now" truthful and catches plates changed directly in
// the portal.
func (c *Client) CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (reg string, age time.Duration, fresh bool, err error) {
	if c.sandbox != nil {
		reg, err = c.sandboxCurrentVehicle(p) // in-memory: no cache needed
		return reg, 0, true, err
	}
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
// stops managing the permit: the cache is otherwise never evicted, so a permit
// that is removed and later re-added would answer from a reading taken before
// anyone stopped watching it.
//
// The in-flight-refresh marker is deliberately left alone — it is removed by the
// goroutine that owns it, and clearing it here would only let a second council
// request start for a permit nobody is managing any more.
func (c *Client) ForgetPermit(owner, councilPermitID string) {
	key := regKey{owner, councilPermitID}
	c.regGenMu.Lock()
	if c.regGen == nil {
		c.regGen = map[regKey]uint64{}
	}
	c.regGen[key]++ // invalidate any refresh/write already in flight for this key
	c.regGenMu.Unlock()
	c.regCache.Delete(key)
	c.regFail.Delete(key) // a permit nobody manages has no failure streak worth reporting
}

// regGeneration reads a key's current generation (0 if never forgotten).
func (c *Client) regGeneration(key regKey) uint64 {
	c.regGenMu.Lock()
	defer c.regGenMu.Unlock()
	return c.regGen[key]
}

// storeRegIfCurrent writes reg to the cache only if the key has not been forgotten
// since gen was captured — so a slow read that raced a ForgetPermit does not
// resurrect a stale entry.
func (c *Client) storeRegIfCurrent(key regKey, gen uint64, reg string) {
	c.regGenMu.Lock()
	defer c.regGenMu.Unlock()
	if c.regGen[key] != gen {
		return
	}
	c.regCache.Store(key, cachedReg{reg: reg, at: time.Now()})
}

// refreshCurrentVehicle fetches the permit's plate in the background, detached
// from any request context so a closed tab doesn't cancel it, deduplicating
// concurrent refreshes per permit. Failures are logged and the stale cache
// entry is left in place for the next attempt; the failure STREAK is recorded
// (regFail) so the UI can distinguish "the reading is old because nobody
// looked" from "we have been trying and failing" — only the second deserves
// the couldn't-confirm mark.
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
// Untagged errors are dropped on purpose: without the generation the receiver
// cannot bind recovery to the session that actually failed (a fresh re-link
// racing the report could be retired by mistake), which is the same rule the
// scheduler's own expiry branch follows.
func (c *Client) noteExpired(owner string, err error) {
	if c.OnSessionExpired == nil {
		return
	}
	if gen, ok := SessionGenOf(err); ok {
		c.OnSessionExpired(owner, gen)
	}
}

// RefreshFailingFor reports how long background plate refreshes for this permit
// have been failing CONSECUTIVELY — zero when the last attempt succeeded (or
// none has run). This, not the cache entry's age, is the honest input to the
// dashboard's couldn't-confirm clock: a healthy system's first visit of the day
// serves an hours-old reading while a refresh lands within seconds, and seeding
// the clock from raw age declared that visit unconfirmable before trying.
func (c *Client) RefreshFailingFor(owner string, p model.Permit) time.Duration {
	if c.sandbox != nil {
		return 0
	}
	if v, ok := c.regFail.Load(regKey{owner, p.CouncilPermitID}); ok {
		return time.Since(v.(time.Time))
	}
	return 0
}

// SetVehicle reallocates the permit to the given registration, the core action.
//
// The portal implements this as an in-place edit of the permit's single vehicle,
// so we first read the current vehicle to obtain its detail ID (and preserve its
// state), then POST the edit. A no-op edit (unchanged plate) is skipped, mirroring
// the portal, which sends no request when nothing changes. Success is any 2xx
// with an empty body — a 2026-07-31 capture confirmed a successful POST returns
// exactly that: 200, no Content-Type, zero bytes. It says nothing about the
// resulting state, which is why the confirmation read below is not optional.
//
// The pre-read is deliberately NOT cached away, though the same capture showed
// PKPermitVehicleDetailID is stable across an edit and so could be. Three reasons:
// writes are a small share of council traffic next to the keep-warm background
// load, so the saving is a few percent; the read also carries the
// CanEditOrDeleteVehicle check and the no-op short-circuit, both of which would
// have to be reproduced from cached state; and a stale cached ID turns one
// three-call change into a four-call one. The burst that actually matters is a
// shared roster rollover, and that is better fixed by spreading the writes than by
// shaving one call off each.
func (c *Client) SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error {
	const op = "change the vehicle on your permit"
	if c.sandbox != nil {
		return c.sandboxSetVehicle(p, registration)
	}
	key := regKey{owner, p.CouncilPermitID}
	gen := c.regGeneration(key) // so a concurrent ForgetPermit invalidates the cache writes below
	mv, err := c.managedVehicle(ctx, owner, p)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		// A response we failed to understand must never be taken as "empty permit",
		// so require corroboration first (retried + operator-alerted otherwise).
		if !mv.emptyIsCredible() {
			return councilErr(FailUnexpected, op, errVehicleShape(mv))
		}
		// A credibly-empty permit is the NORMAL state of a freshly granted permit
		// (confirmed live 2026-08-23: a new signup's only permit has no vehicle until
		// one is assigned). ADD one rather than refuse — the old "no vehicle to
		// change" durable refusal locked exactly the newest households out of their
		// first roster/one-off apply, forever.
		if mv.CanAddVehicle == nil {
			// Absent, not false: cannot tell "not permitted" from "field gone".
			return councilErr(FailUnexpected, op,
				errors.New("response has no canAddVehicle field: API shape change?"))
		}
		if !*mv.CanAddVehicle {
			return councilErr(FailRejected, op,
				errors.New("the council does not allow adding a vehicle to this permit"))
		}
		return c.addVehicle(ctx, owner, p, registration, key, gen)
	}
	if mv.CanEditOrDeleteVehicle == nil {
		// Absent, not false: we cannot tell "not permitted" from "field gone". Unexpected
		// (retried, operator alerted), never the durable refusal.
		return councilErr(FailUnexpected, op,
			errors.New("response has no canEditOrDeleteVehicle field: API shape change?"))
	}
	if !*mv.CanEditOrDeleteVehicle {
		return councilErr(FailRejected, op, errors.New("the council does not allow changing this permit's vehicle"))
	}
	if len(mv.PermitVehicles) != 1 {
		// One managed vehicle per permit is the model; editing [0] of several could
		// change the wrong record. Refuse as unexpected rather than guess.
		return councilErr(FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	cur := mv.PermitVehicles[0]
	// Every other field on the write below is validated or defaulted; this one was
	// taken on trust. An absent PKPermitVehicleDetailID yields json.Number("") and we
	// would POST an edit with empty SelectedVehicle/ChangeSetID/detail id. What the
	// council does with that is unknown, and this is the one code path that can put a
	// wrong plate on a real permit — so fail closed.
	if strings.TrimSpace(cur.PKPermitVehicleDetailID.String()) == "" {
		return councilErr(FailUnexpected, op,
			errors.New("managed vehicle has no PKPermitVehicleDetailID: API shape change?"))
	}
	if model.SamePlate(cur.RegistrationNumber, registration) {
		// Already allocated (the read above IS the confirmation). Refresh the cache
		// so callers reflect the council's own record, then report success.
		c.storeRegIfCurrent(key, gen, cur.RegistrationNumber)
		return nil
	}
	permitID, err := strconv.ParseInt(p.CouncilPermitID, 10, 64)
	if err != nil {
		return councilErr(FailRejected, op, fmt.Errorf("invalid council permit id %q", p.CouncilPermitID))
	}
	detailID := cur.PKPermitVehicleDetailID.String()
	state := cur.FKVehicleStateID
	if state == "" {
		state = "1" // VIC, if the current state is somehow absent
	}
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     detailID,
		VehicleActionOption: "edit",
		Vehicle: manageVehicleV{
			ChangeSetID:             detailID,
			FKPermitID:              permitID,
			FKVehicleStateID:        state,
			PKPermitVehicleDetailID: detailID,
			RegisteredAtAddress:     false,
			RegistrationNumber:      registration,
		},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := c.apiRequest(ctx, owner, http.MethodPost, "/api/permits/manageVehicle", op, nil, buf)
	if err != nil {
		return err // classified (non-2xx / transport) or a busy/auth sentinel
	}
	drainClose(resp)

	// Confirm the change against the council's OWN record before reporting success,
	// so every state we then show or store (the dashboard's "on permit now", a
	// guest's "your plate is on", the apply log) reflects what the council actually
	// has — not merely a write we sent, which a 2xx does not guarantee took effect.
	return c.confirmWrite(ctx, owner, p, registration, key, gen, op)
}

// confirmWrite re-reads the council's OWN record after a 2xx write and only
// reports success once it shows the plate we sent — a 2xx does not guarantee the
// change took. A mismatch is a durable refusal (act-now notice), an unreadable
// confirm is transient (retry). Shared by the edit and add paths so both make
// the same guarantee. registration "" means "expect the permit empty" (the clear
// path), matched by SamePlate("", "").
func (c *Client) confirmWrite(ctx context.Context, owner string, p model.Permit, registration string, key regKey, gen uint64, op string) error {
	confirmed, err := c.CurrentVehicle(ctx, owner, p)
	if err != nil {
		return councilErr(FailTransient, op, fmt.Errorf("change sent but could not be confirmed: %w", err))
	}
	if !model.SamePlate(confirmed, registration) {
		return councilErr(FailRejected, op, fmt.Errorf("change was accepted but the council still shows %q", confirmed))
	}
	c.storeRegIfCurrent(key, gen, confirmed)
	return nil
}

// addVehicle attaches a NEW vehicle to a permit that currently has none — the
// council's "add" action, distinct from "edit". The request shape was captured
// live (2026-08-23) against the empty test permit: VehicleActionOption "add",
// an empty SelectedVehicle, and a Vehicle with no prior detail id / change-set
// (the council assigns a fresh PKPermitVehicleDetailID). State defaults to VIC,
// as everywhere else in the app (SetVehicle takes a bare plate, no state).
func (c *Client) addVehicle(ctx context.Context, owner string, p model.Permit, registration string, key regKey, gen uint64) error {
	const op = "add a vehicle to your permit"
	permitID, err := strconv.ParseInt(p.CouncilPermitID, 10, 64)
	if err != nil {
		return councilErr(FailRejected, op, fmt.Errorf("invalid council permit id %q", p.CouncilPermitID))
	}
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     "",
		VehicleActionOption: "add",
		Vehicle: manageVehicleV{
			ChangeSetID:             "",
			FKPermitID:              permitID,
			FKVehicleStateID:        "1", // VIC; a bare-plate add carries no prior state
			PKPermitVehicleDetailID: "",  // new record — the council assigns the id
			RegisteredAtAddress:     false,
			RegistrationNumber:      registration,
		},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := c.apiRequest(ctx, owner, http.MethodPost, "/api/permits/manageVehicle", op, nil, buf)
	if err != nil {
		return err
	}
	drainClose(resp)
	return c.confirmWrite(ctx, owner, p, registration, key, gen, op)
}

// ClearVehicle removes the vehicle from a permit, leaving it with none — the
// council's "delete" action. Idempotent: an already-empty permit is success. It
// is deliberately a SEPARATE, explicit operation, never something the scheduler
// does on its own — "nothing scheduled" leaves the last plate in place, so the
// only way a plate comes OFF is a person asking for it here.
func (c *Client) ClearVehicle(ctx context.Context, owner string, p model.Permit) error {
	const op = "remove the vehicle from your permit"
	if c.sandbox != nil {
		return c.sandboxSetVehicle(p, "")
	}
	key := regKey{owner, p.CouncilPermitID}
	gen := c.regGeneration(key)
	mv, err := c.managedVehicle(ctx, owner, p)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		// Already empty. Believe it only when corroborated (see emptyIsCredible),
		// else it's an unexpected shape, not a done deal.
		if !mv.emptyIsCredible() {
			return councilErr(FailUnexpected, op, errVehicleShape(mv))
		}
		c.storeRegIfCurrent(key, gen, "")
		return nil
	}
	if len(mv.PermitVehicles) != 1 {
		return councilErr(FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	cur := mv.PermitVehicles[0]
	detailID := cur.PKPermitVehicleDetailID.String()
	if strings.TrimSpace(detailID) == "" {
		return councilErr(FailUnexpected, op,
			errors.New("managed vehicle has no PKPermitVehicleDetailID: API shape change?"))
	}
	permitID, err := strconv.ParseInt(p.CouncilPermitID, 10, 64)
	if err != nil {
		return councilErr(FailRejected, op, fmt.Errorf("invalid council permit id %q", p.CouncilPermitID))
	}
	state := cur.FKVehicleStateID
	if state == "" {
		state = "1"
	}
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     detailID,
		VehicleActionOption: "delete",
		Vehicle: manageVehicleV{
			ChangeSetID:             detailID,
			FKPermitID:              permitID,
			FKVehicleStateID:        state,
			PKPermitVehicleDetailID: detailID,
			RegisteredAtAddress:     false,
			RegistrationNumber:      cur.RegistrationNumber,
		},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := c.apiRequest(ctx, owner, http.MethodPost, "/api/permits/manageVehicle", op, nil, buf)
	if err != nil {
		return err
	}
	drainClose(resp)
	// Confirm the permit is now empty against the council's own record.
	return c.confirmWrite(ctx, owner, p, "", key, gen, op)
}

// PermitInfo summarises one permit on the account, for letting a user pick which
// permit the app should manage.
type PermitInfo struct {
	CouncilPermitID  string // PKPermitID, e.g. "14576"
	PermitTypeID     string // FKPermitTypeID, e.g. "14"
	PermitNumber     string // e.g. "VPP24714"
	PermitType       string // e.g. "(A) 1st Visitor Permit"
	Status           string // e.g. "Granted"
	CurrentRego      string // plate currently allocated
	StartDate        time.Time
	EndDate          time.Time
	CanChangeVehicle bool // holder is permitted to change the vehicle
	IsCoHolder       bool
}

// POINTERS, so an ABSENT key is distinguishable from a present zero/empty. Without
// that, `{}` decodes to (nil, 0) and reads as "this account has no permits" — the same
// missing-vs-zero trap already closed on managedVehicleResp, which this struct is the
// sibling of.
type gridResp struct {
	PermitGrid *[]gridRow `json:"PermitGrid"`
	TotalItems *int       `json:"TotalItems"`
}

// gridRow is decoded with POINTERS for every field drift acts on, so an omitted key
// is distinguishable from a legitimately empty value. With plain values the two are
// identical after decoding, and that is the dangerous direction: blank
// PermitStatus/EndDate would be written over good stored metadata. Absence is a
// shape change and must be reported as one, not silently coerced to "".
//
// VehicleRego is the one deliberate EXEMPTION: the council sends null for a permit
// that has never had a vehicle assigned (observed live 2026-08-22, a new signup's
// fresh permit), and a nil pointer cannot tell that from a dropped key — so
// requiring it locked the exact households most likely to be new out of the picker,
// with retry advice that burned real council logins. Treating it as "" is safe
// because the plate-clearing catastrophe the guard feared is prevented downstream:
// drift NEVER blanks a stored plate on the grid's word alone — an empty grid rego
// triggers a corroborating managedVehicle read first (see scheduler drift and
// parking.emptyIsCredible), even if a schema change blanked every row at once.
type gridRow struct {
	PKPermitID                            int64   `json:"PKPermitID"`
	FKPermitTypeID                        *int64  `json:"FKPermitTypeID"`
	PermitNumber                          *string `json:"PermitNumber"`
	PermitType                            *string `json:"PermitType"`
	PermitStatus                          *string `json:"PermitStatus"`
	VehicleRego                           *string `json:"VehicleRego"`
	StartDate                             *string `json:"StartDate"`
	EndDate                               *string `json:"EndDate"`
	PermitTypeAllowsVehicleChangeByHolder *bool   `json:"PermitTypeAllowsVehicleChangeByHolder"`
	IsCoHolder                            bool    `json:"IsCoHolder"`
}

// missingGridFields names the absent keys on a row, so the shape-change error says
// which field vanished rather than just that something did.
func (r gridRow) missingGridFields() []string {
	var missing []string
	for _, f := range []struct {
		name    string
		present bool
	}{
		{"FKPermitTypeID", r.FKPermitTypeID != nil},
		{"PermitNumber", r.PermitNumber != nil},
		{"PermitType", r.PermitType != nil},
		{"PermitStatus", r.PermitStatus != nil},
		// VehicleRego deliberately absent: null means "no vehicle assigned yet",
		// not schema drift — see the gridRow comment.
		{"StartDate", r.StartDate != nil},
		{"EndDate", r.EndDate != nil},
		{"PermitTypeAllowsVehicleChangeByHolder", r.PermitTypeAllowsVehicleChangeByHolder != nil},
	} {
		if !f.present {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// ListPermits returns the permits on the app user's linked council account. Display
// callers (the picker, addPermit) use this and are content with a partial list.
//
// ErrPermitListPartial is what a caller that must not act on a partial list checks
// for; see ListPermitsComplete.

func (c *Client) ListPermits(ctx context.Context, owner string) ([]PermitInfo, error) {
	ps, _, err := c.listPermits(ctx, owner)
	return ps, err
}

// listPermits is the single implementation. complete reports whether the rows are the
// WHOLE account rather than a page, determined at decode time so it cannot race with
// another owner's read.
// maxPermitPages bounds the paging loop. A household with more than this many permits
// does not exist; the cap is here so a council that ignores pageNumber cannot turn one
// read into an unbounded request loop against the shared egress IP.
const maxPermitPages = 20

// listPermits reads the owner's whole permit list, paging if the council gives us one.
// complete reports whether we ended up holding the entire account.
//
// We ask for pageSize=0 ("everything") and the council has always honoured it, so the
// loop below normally runs exactly once. It exists because the alternative — accepting
// whatever the first page held — was silently wrong in a way users felt: the picker
// showed a truncated list, and addPermit read absence from that page as "this permit is
// not yours" and returned 403 for a permit the household genuinely holds.
func (c *Client) listPermits(ctx context.Context, owner string) ([]PermitInfo, bool, error) {
	const op = "list your permits"
	if c.sandbox != nil {
		return c.sandboxListPermits(), true, nil
	}
	var all []PermitInfo
	seen := make(map[string]bool)
	expected := -1 // the account size the FIRST page claimed
	for page := 0; page < maxPermitPages; page++ {
		rows, total, err := c.permitPage(ctx, owner, page)
		if err != nil {
			return nil, false, err
		}
		if expected < 0 {
			expected = total
		} else if total != expected {
			// The account changed under us mid-read. Accepting the new count would let
			// stale rows collected earlier satisfy a smaller total while a permit that
			// exists right now was never returned — and drift would then check the owner
			// off as fully seen. A snapshot we cannot trust is reported incomplete; the
			// next pass reads it cleanly.
			c.noteTruncatedGrid(len(all), expected)
			log.Printf("parking: permit count for %s changed mid-read (%d -> %d at page %d); "+
				"treating this list as incomplete", redact.Email(owner), expected, total, page)
			return all, false, nil
		}
		added := 0
		for _, p := range rows {
			if seen[p.CouncilPermitID] {
				continue // a council that ignores pageNumber would repeat page 0 forever
			}
			seen[p.CouncilPermitID] = true
			all = append(all, p)
			added++
		}
		if len(all) >= expected {
			return all, true, nil
		}
		if added == 0 {
			// No progress and still short of the count: paging is not working the way we
			// assumed, so report what we have and let the caller decide. Drift declines
			// to check the owner off; the display paths show what they got.
			c.noteTruncatedGrid(len(all), expected)
			log.Printf("parking: permit list for %s stalled at %d of %d after %d page(s); "+
				"acting on a partial list", redact.Email(owner), len(all), expected, page+1)
			return all, false, nil
		}
	}
	c.noteTruncatedGrid(len(all), expected)
	log.Printf("parking: permit list for %s still incomplete after %d pages; acting on a partial list",
		redact.Email(owner), maxPermitPages)
	return all, false, nil
}

// permitPage reads ONE page of the grid and returns its rows plus the total the council
// says the account holds.
func (c *Client) permitPage(ctx context.Context, owner string, page int) (_ []PermitInfo, total int, err error) {
	const op = "list your permits"
	resp, err := c.apiRequest(ctx, owner, http.MethodGet, "/api/Index/grid", op,
		url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {"0"}}, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var g gridResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&g); err != nil {
		return nil, 0, councilErr(FailUnexpected, op, err)
	}
	// A 200 whose body decoded to nothing useful is an API-SHAPE failure, not "this
	// account has no permits". Believing the latter is expensive: the picker offers
	// nothing to add, a legitimate permit looks gone, and drift records a clean empty
	// snapshot over real state. So BOTH top-level fields must be explicitly present,
	// and the council's own count must agree with what it sent.
	if g.PermitGrid == nil || g.TotalItems == nil {
		return nil, 0, councilErr(FailUnexpected, op,
			fmt.Errorf("permit grid response is missing PermitGrid=%t/TotalItems=%t: API shape change?",
				g.PermitGrid == nil, g.TotalItems == nil))
	}
	rows, total := *g.PermitGrid, *g.TotalItems
	// Deliberately NOT exact equality. We request pageSize=0 meaning "everything", but
	// if the council ever applies a default page size, TotalItems becomes the unpaged
	// total and exact equality would hard-fail ListPermits for every account holding
	// more permits than one page — the picker, addPermit and drift all break at once.
	// What must never pass is the case this guard exists for: the council says there ARE
	// permits and sent us none.
	if len(rows) == 0 && total != 0 {
		return nil, 0, councilErr(FailUnexpected, op,
			fmt.Errorf("permit grid is empty but the response claims %d items: API shape change?", total))
	}
	if total < len(rows) {
		return nil, 0, councilErr(FailUnexpected, op,
			fmt.Errorf("permit grid has %d rows but the response claims only %d items: API shape change?", len(rows), total))
	}
	// A page shorter than the total is now NORMAL — it just means there is another
	// page — so the caller loops rather than treating it as a shape change. The two
	// guards above still stand: a claimed-nonempty account that sent nothing, and more
	// rows than the council says exist, are both impossible and refused.
	out := make([]PermitInfo, 0, len(rows))
	for _, r := range rows {
		// Every row must identify its permit; without a usable ID we cannot act on it,
		// and a zero/negative would be written into the store as "0"/"-1".
		if r.PKPermitID <= 0 {
			return nil, 0, councilErr(FailUnexpected, op,
				fmt.Errorf("a permit row has a non-positive PKPermitID (%d): API shape change?", r.PKPermitID))
		}
		// A date we cannot parse must not silently become the zero time: end_date drives
		// expiry, and drift writes it over the stored value, so a format change would
		// quietly retire live permits. Empty stays empty (genuinely "not set").
		if missing := r.missingGridFields(); len(missing) > 0 {
			return nil, 0, councilErr(FailUnexpected, op,
				fmt.Errorf("permit %d is missing %s: API shape change? Treating an absent field as empty "+
					"would blank the stored permit and clear its plate", r.PKPermitID, strings.Join(missing, ", ")))
		}
		start, serr := councilDate(*r.StartDate)
		end, eerr := councilDate(*r.EndDate)
		if serr != nil || eerr != nil {
			return nil, 0, councilErr(FailUnexpected, op,
				fmt.Errorf("permit %d has an unparseable date (start=%q end=%q): API shape change?",
					r.PKPermitID, safeExcerpt(*r.StartDate), safeExcerpt(*r.EndDate)))
		}
		out = append(out, PermitInfo{
			CouncilPermitID:  strconv.FormatInt(r.PKPermitID, 10),
			PermitTypeID:     strconv.FormatInt(*r.FKPermitTypeID, 10),
			PermitNumber:     *r.PermitNumber,
			PermitType:       *r.PermitType,
			Status:           *r.PermitStatus,
			CurrentRego:      strOrEmpty(r.VehicleRego),
			StartDate:        start,
			EndDate:          end,
			CanChangeVehicle: *r.PermitTypeAllowsVehicleChangeByHolder,
			IsCoHolder:       r.IsCoHolder,
		})
	}
	return out, total, nil
}

// strOrEmpty reads an optional grid string: nil (the council's null for a permit
// with no vehicle assigned) becomes "", which is what it means.
func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// councilDate parses a council date, reporting a malformed one instead of swallowing
// it. Empty means "not set" and is not an error.
func councilDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// noteTruncatedGrid records that the council returned fewer permits than it claimed,
// for the status page. Last-one-wins: this is a shape signal, not a tally.
func (c *Client) noteTruncatedGrid(got, want int) {
	c.truncMu.Lock()
	c.truncAt, c.truncGot, c.truncWant = time.Now(), got, want
	c.truncMu.Unlock()
}

// ErrPermitListPartial means the council returned fewer permits than it reported
// holding, so the list is a page rather than the account. The rows are still usable —
// callers that only display them may carry on — but any caller that would treat the
// list as the whole truth must not, and must not record the work as done.
var ErrPermitListPartial = errors.New("parking: the council returned only part of the permit list")

// ListPermitsComplete returns the same rows as ListPermits, plus whether the list was
// the WHOLE account. Drift uses it: acting on a page is fine, but checking the owner
// off for another interval on the strength of one is not — if the council settles into
// returning a stable first page, the permits behind it would never be read again, and
// their plate drift and expiry warnings would go missing indefinitely.
func (c *Client) ListPermitsComplete(ctx context.Context, owner string) ([]PermitInfo, bool, error) {
	return c.listPermits(ctx, owner)
}
