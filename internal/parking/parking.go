// Package parking is the per-app-user client for the City of Stonnington
// ePermits system (multi-user).
//
// The council issues NO refresh tokens, its public SPA client `ePermits.ssp.web`
// is not granted offline_access. Instead the app mirrors the SPA's own
// mechanism: it holds each user's IdentityServer SESSION COOKIE and silent-renews
// (a prompt=none Authorization-Code + PKCE flow) to mint short-lived (~1h) access
// tokens on demand. Onboarding (Link) does a headless login with the user's
// council credentials to obtain that cookie, then discards the password, we
// never store it. The cookie itself may rotate on renew and is re-persisted.
//
// The access token is a Bearer credential for the /ssp-svc/api permit endpoints;
// all request/response shapes are reverse-engineered from captured portal
// traffic (see docs/CAPTURE.md).
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
	// ErrNotCaptured marks a call whose request/response shape is still unknown.
	ErrNotCaptured = errors.New("parking: endpoint not yet reverse-engineered (needs a capture)")
	// ErrCouncilBusy means the portal is pushing back (Akamai 429/403/503) or the
	// owner is in a backoff cooldown. Callers should treat it as transient and NOT
	// retry immediately; the client already enforces an exponential per-owner
	// cooldown so it is not hammered.
	ErrCouncilBusy = errors.New("parking: council temporarily unavailable (rate-limited or blocked); backing off")
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
	regCache    sync.Map     // councilPermitID -> cachedReg, to bound council reads

	renewLocks    sync.Map // owner -> *sync.Mutex, serialises silent-renew per owner
	cooldownUntil sync.Map // owner -> time.Time, soft-block backoff deadline
	strikes       sync.Map // owner -> int, consecutive soft blocks (backoff growth)
}

type cachedReg struct {
	reg string
	at  time.Time
}

// New builds a Client. Council OAuth endpoints follow the standard Duende
// IdentityServer layout under the issuer, so no boot-time discovery call is
// needed (keeps startup independent of council availability).
func New(cfg *config.Config, st *store.Store, box *secretbox.Box) *Client {
	issuer := strings.TrimRight(cfg.Council.Issuer, "/")
	apiBase := strings.TrimRight(cfg.Council.APIBase, "/")
	return &Client{
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
		http: &http.Client{
			Timeout: 30 * time.Second,
			// Present as a browser on every request (never Go's default UA).
			Transport: browserTransport{base: http.DefaultTransport},
			// We inspect 302s ourselves to read the auth code and rotated cookie.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
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
	cookie, err := c.box.Open(sealed)
	if err != nil {
		log.Printf("parking: unseal cookie for %s failed (%v); treating as expired session (re-link required)", owner, err)
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
		if at, err := c.box.Open(cs.AccessToken); err == nil {
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
		if at, err := c.box.Open(cs.AccessToken); err == nil {
			return at, nil
		}
	}

	cookie, err := c.openCookie(owner, cs.Cookie)
	if err != nil {
		return "", err
	}
	at, expiry, newCookie, err := c.silentRenew(ctx, cookie)
	if err != nil {
		return "", err
	}
	sealedAccess, err := c.box.Seal(at)
	if err != nil {
		return "", err
	}
	sealedCookie := cs.Cookie
	if newCookie != "" && newCookie != cookie {
		if sc, err := c.box.Seal(newCookie); err == nil {
			sealedCookie = sc
		}
	}
	if err := c.store.UpdateCouncilToken(ctx, owner, sealedCookie, sealedAccess, expiry); err != nil {
		return "", err
	}
	return at, nil
}

// Refresh forces a silent-renew against the stored cookie even when the cached
// access token is still valid, sliding the council session cookie so an idle
// user's session does not lapse (keep-warm). Returns ErrNotLinked if there is no
// session and ErrSessionExpired if the cookie is no longer accepted.
func (c *Client) Refresh(ctx context.Context, owner string) error {
	// Serialise with accessToken so keep-warm and a reconcile write never renew
	// the same cookie concurrently.
	lock := c.ownerLock(owner)
	lock.Lock()
	defer lock.Unlock()

	cs, err := c.store.GetCouncilSession(ctx, owner)
	if err != nil || cs.Cookie == "" {
		return ErrNotLinked
	}
	cookie, err := c.openCookie(owner, cs.Cookie)
	if err != nil {
		return err
	}
	at, expiry, newCookie, err := c.silentRenew(ctx, cookie)
	if err != nil {
		return err
	}
	sealedAccess, err := c.box.Seal(at)
	if err != nil {
		return err
	}
	sealedCookie := cs.Cookie
	if newCookie != "" && newCookie != cookie {
		if sc, err := c.box.Seal(newCookie); err == nil {
			sealedCookie = sc
		}
	}
	return c.store.UpdateCouncilToken(ctx, owner, sealedCookie, sealedAccess, expiry)
}

// apiRequest issues an authenticated request to the permit API as the app user.
// It short-circuits while the owner is in a soft-block cooldown, and classifies
// Akamai push-back (429/403/503) as ErrCouncilBusy with an exponential backoff so
// the scheduler stops re-hitting a portal that is already refusing us.
// op is a plain-English description of what the request is doing, used to build
// human notifications when it fails. On any non-2xx (other than the busy codes)
// or a transport error, apiRequest returns a classified CouncilError and no
// response; a 2xx returns the response for the caller to decode.
func (c *Client) apiRequest(ctx context.Context, owner, method, path, op string, query url.Values, body io.Reader) (*http.Response, error) {
	if d, blocked := c.cooldownFor(owner); blocked {
		return nil, fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	at, err := c.accessToken(ctx, owner)
	if err != nil {
		return nil, err
	}
	u := c.apiBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+at)
	req.Header.Set("Content-Type", "application/json")
	c.xhrHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		// Transport error (DNS, dial, timeout, reset): transient by nature.
		return nil, councilErr(FailTransient, op, err)
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
		ra := parseRetryAfter(resp)
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		c.penalize(owner, ra)
		return nil, fmt.Errorf("%w: council returned %d", ErrCouncilBusy, resp.StatusCode)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.clearPenalty(owner)
		return resp, nil
	}
	// Other non-2xx: 5xx is a server-side blip (transient); 4xx is a refusal.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	kind := FailRejected
	if resp.StatusCode >= 500 {
		kind = FailTransient
	}
	return nil, councilErr(kind, op, fmt.Errorf("council returned %d", resp.StatusCode))
}

// managedVehicleResp is the response of GET /ssp-svc/api/permits/managedVehicle.
//
// Verified against a live response. NOTE the casing is mixed: the top-level keys
// are camelCase, but the permitVehicles[] element keys are PascalCase. Within an
// element, PKPermitVehicleDetailID arrives as a bare JSON number while
// FKVehicleStateID arrives as a quoted string, hence the differing Go types.
type managedVehicleResp struct {
	PermitNumber           string          `json:"permitNumber"`
	PermitVehicleCount     int             `json:"permitVehicleCount"`
	MaxVehicles            int             `json:"maxVehicles"`
	CanAddVehicle          bool            `json:"canAddVehicle"`
	CanEditOrDeleteVehicle bool            `json:"canEditOrDeleteVehicle"`
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

// managedVehicle fetches the vehicle(s) currently on the permit.
func (c *Client) managedVehicle(ctx context.Context, owner string, p model.Permit) (*managedVehicleResp, error) {
	const op = "read the current vehicle on your permit"
	resp, err := c.apiRequest(ctx, owner, http.MethodGet, "/api/permits/managedVehicle", op,
		url.Values{"permitID": {p.CouncilPermitID}}, nil)
	if err != nil {
		return nil, err // already classified (or a busy/auth sentinel)
	}
	defer resp.Body.Close()
	var mv managedVehicleResp
	if err := json.NewDecoder(resp.Body).Decode(&mv); err != nil {
		return nil, councilErr(FailUnexpected, op, err)
	}
	return &mv, nil
}

// CurrentVehicle returns the registration currently allocated to the permit, or
// "" if the permit has no vehicle.
func (c *Client) CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error) {
	mv, err := c.managedVehicle(ctx, owner, p)
	if err != nil {
		return "", err
	}
	if len(mv.PermitVehicles) == 0 {
		return "", nil
	}
	return mv.PermitVehicles[0].RegistrationNumber, nil
}

// CurrentVehicleCached returns the permit's actual current plate from the
// council, reusing a value fetched within maxAge so a council call isn't made on
// every page load. Keeps the dashboard's "on permit now" truthful and catches
// plates changed directly in the council portal.
func (c *Client) CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (string, error) {
	if v, ok := c.regCache.Load(p.CouncilPermitID); ok {
		if cr := v.(cachedReg); time.Since(cr.at) < maxAge {
			return cr.reg, nil
		}
	}
	reg, err := c.CurrentVehicle(ctx, owner, p)
	if err != nil {
		return "", err
	}
	c.regCache.Store(p.CouncilPermitID, cachedReg{reg: reg, at: time.Now()})
	return reg, nil
}

// SetVehicle reallocates the permit to the given registration, the core action.
//
// The portal implements this as an in-place edit of the permit's single vehicle,
// so we first read the current vehicle to obtain its detail ID (and preserve its
// state), then POST the edit. A no-op edit (unchanged plate) is skipped, mirroring
// the portal, which sends no request when nothing changes. Success is any 2xx
// with an empty body.
func (c *Client) SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error {
	const op = "change the vehicle on your permit"
	mv, err := c.managedVehicle(ctx, owner, p)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		return councilErr(FailRejected, op, errors.New("the permit has no vehicle to change"))
	}
	if !mv.CanEditOrDeleteVehicle {
		return councilErr(FailRejected, op, errors.New("the council does not allow changing this permit's vehicle"))
	}
	cur := mv.PermitVehicles[0]
	if strings.EqualFold(cur.RegistrationNumber, registration) {
		// Already allocated (the read above IS the confirmation). Refresh the cache
		// so callers reflect the council's own record, then report success.
		c.regCache.Store(p.CouncilPermitID, cachedReg{reg: cur.RegistrationNumber, at: time.Now()})
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
	resp, err := c.apiRequest(ctx, owner, http.MethodPost, "/api/permits/manageVehicle", op, nil, bytes.NewReader(buf))
	if err != nil {
		return err // classified (non-2xx / transport) or a busy/auth sentinel
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Confirm the change against the council's OWN record before reporting success,
	// so every state we then show or store (the dashboard's "on permit now", a
	// guest's "your plate is on", the apply log) reflects what the council actually
	// has — not merely a write we sent, which a 2xx does not guarantee took effect.
	// A mismatch or an unreadable confirmation is treated as not-yet-applied
	// (transient): the scheduler retries and the user sees "still applying" rather
	// than a false "done". The fresh read also refreshes the current-plate cache.
	confirmed, err := c.CurrentVehicle(ctx, owner, p)
	if err != nil {
		// Couldn't reach the council for the confirm — genuinely transient, retry.
		return councilErr(FailTransient, op, fmt.Errorf("change sent but could not be confirmed: %w", err))
	}
	if !strings.EqualFold(confirmed, registration) {
		// The POST was accepted (2xx) but the council's own record still shows a
		// different plate: the write did NOT take. This is a durable refusal (a
		// permission quirk or an API-shape change), not a blip — classify it as
		// rejected so the user gets an act-now "still shows X" notice rather than a
		// soothing "we'll keep trying" that never self-heals.
		return councilErr(FailRejected, op, fmt.Errorf("change was accepted but the council still shows %q", confirmed))
	}
	c.regCache.Store(p.CouncilPermitID, cachedReg{reg: confirmed, at: time.Now()})
	return nil
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

type gridResp struct {
	PermitGrid []gridRow `json:"PermitGrid"`
	TotalItems int       `json:"TotalItems"`
}

type gridRow struct {
	PKPermitID                            int64  `json:"PKPermitID"`
	FKPermitTypeID                        int64  `json:"FKPermitTypeID"`
	PermitNumber                          string `json:"PermitNumber"`
	PermitType                            string `json:"PermitType"`
	PermitStatus                          string `json:"PermitStatus"`
	VehicleRego                           string `json:"VehicleRego"`
	StartDate                             string `json:"StartDate"`
	EndDate                               string `json:"EndDate"`
	PermitTypeAllowsVehicleChangeByHolder bool   `json:"PermitTypeAllowsVehicleChangeByHolder"`
	IsCoHolder                            bool   `json:"IsCoHolder"`
}

// ListPermits returns the permits on the app user's linked council account.
func (c *Client) ListPermits(ctx context.Context, owner string) ([]PermitInfo, error) {
	const op = "list your permits"
	resp, err := c.apiRequest(ctx, owner, http.MethodGet, "/api/Index/grid", op,
		url.Values{"pageNumber": {"0"}, "pageSize": {"0"}}, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var g gridResp
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		return nil, councilErr(FailUnexpected, op, err)
	}
	out := make([]PermitInfo, 0, len(g.PermitGrid))
	for _, r := range g.PermitGrid {
		out = append(out, PermitInfo{
			CouncilPermitID:  strconv.FormatInt(r.PKPermitID, 10),
			PermitTypeID:     strconv.FormatInt(r.FKPermitTypeID, 10),
			PermitNumber:     r.PermitNumber,
			PermitType:       r.PermitType,
			Status:           r.PermitStatus,
			CurrentRego:      r.VehicleRego,
			StartDate:        parseCouncilDate(r.StartDate),
			EndDate:          parseCouncilDate(r.EndDate),
			CanChangeVehicle: r.PermitTypeAllowsVehicleChangeByHolder,
			IsCoHolder:       r.IsCoHolder,
		})
	}
	return out, nil
}

// parseCouncilDate parses the portal's zoneless local timestamps
// (e.g. "2026-07-13T00:00:00"), returning the zero time if unparseable.
func parseCouncilDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		return time.Time{}
	}
	return t
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
