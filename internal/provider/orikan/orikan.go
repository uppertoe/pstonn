// Package orikan is the provider for Orikan's ePermits self-service portal (the
// `/ssp` SPA, its Duende IdentityServer at `/idm`, and the `/ssp-svc` permit API)
// as run by the City of Stonnington and a dozen other registry.
//
// The portal issues NO refresh tokens: its public SPA client is not granted
// offline_access. So the provider mirrors the SPA's own mechanism — it holds the
// IdentityServer SESSION COOKIE and silent-renews (a prompt=none Authorization-Code
// + PKCE flow) to mint short-lived (~1h) access tokens on demand. Login replays the
// SPA's own sign-in form headlessly to obtain that cookie. The cookie may rotate on
// renew; the session material handed back to the generic client carries it.
//
// The request/response shapes mirror the portal's SPA; an unexpected shape
// surfaces as FailUnexpected (the signal that the portal changed its API and this
// provider needs updating). Nothing here composes words for a person: failures are
// the typed vocabulary in internal/provider.
package orikan

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// ID is the connector name a tenant descriptor refers to.
const ID = "orikan-ssp"

// auState is one Australian registration state as the portal enumerates it. The
// FKVehicleStateID tokens are an Orikan-wide constant (confirmed live against the
// GET /permits/vehicleStates lookup on 2026-08-29: VIC=1 ACT=2 NSW=3 WA=4 TAS=5
// QLD=6 SA=7 NT=8), so the connector carries the code↔token map rather than
// fetching it per tenant. The app stores the CODE; only this file knows the token.
type auState struct {
	Code  string
	Token string
}

var auStates = []auState{
	{"VIC", "1"}, {"ACT", "2"}, {"NSW", "3"}, {"WA", "4"},
	{"TAS", "5"}, {"QLD", "6"}, {"SA", "7"}, {"NT", "8"},
}

// regionToken maps a state code (case-insensitive) to its portal token; ok is
// false for a code the portal does not enumerate.
func regionToken(code string) (token string, ok bool) {
	for _, s := range auStates {
		if strings.EqualFold(s.Code, code) {
			return s.Token, true
		}
	}
	return "", false
}

// tokenRegion maps a portal token back to a state code ("" if unrecognised).
func tokenRegion(token string) string {
	for _, s := range auStates {
		if s.Token == token {
			return s.Code
		}
	}
	return ""
}

// Config parameterises one tenant of the portal.
type Config struct {
	Issuer      string   // …/idm
	APIBase     string   // …/ssp-svc
	ClientID    string   // the public SPA client, no secret
	RedirectURI string   // that client's REGISTERED callback; the code is read off the 302
	Scopes      []string // no offline_access — the client rejects it
	// HomeState is the tenant's own registration state as a CODE (e.g. "VIC"),
	// written when a plate carries no state of its own. Empty or unrecognised falls
	// back to VIC.
	HomeState string
}

// Client is the provider. Safe for concurrent use; sessions are never shared
// between concurrent calls by the generic client.
type Client struct {
	clientID    string
	redirectURI string
	scope       string
	authURL     string
	tokenURL    string
	loginURL    string
	apiBase     string
	origin      string
	homeCode    string            // the tenant's own state, as a code ("VIC")
	homeToken   string            // that state's portal FKVehicleStateID ("1")
	http        *http.Client      // redirects handled manually; cookies passed per call
	transport   http.RoundTripper // the governed/counted base, shared with the login-flow client
	authCircuit *authCircuit      // per-tenant breaker for the authorize (token-mint) surface
}

// New builds the provider. base is the transport the generic client governs and
// counts; nil means http.DefaultTransport (tests).
func New(cfg Config, base http.RoundTripper) *Client {
	if base == nil {
		base = http.DefaultTransport
	}
	issuer := strings.TrimRight(cfg.Issuer, "/")
	apiBase := strings.TrimRight(cfg.APIBase, "/")
	homeCode := strings.ToUpper(strings.TrimSpace(cfg.HomeState))
	homeToken, ok := regionToken(homeCode)
	if !ok {
		homeCode, homeToken = "VIC", "1"
	}
	tr := identityTransport{base: base}
	return &Client{
		clientID:    cfg.ClientID,
		redirectURI: cfg.RedirectURI,
		scope:       strings.Join(cfg.Scopes, " "),
		authURL:     issuer + "/connect/authorize",
		tokenURL:    issuer + "/connect/token",
		loginURL:    issuer + "/Account/Login",
		apiBase:     apiBase,
		origin:      originOf(issuer, apiBase),
		homeCode:    homeCode,
		homeToken:   homeToken,
		transport:   tr,
		authCircuit: &authCircuit{},
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
			// We inspect 302s ourselves to read the auth code and rotated cookie.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Client) ID() string { return ID }

func (c *Client) Capabilities() provider.Capabilities {
	return provider.Capabilities{
		CanClearVehicle: true,
		SupportsRefresh: true,
		NeedsKeepWarm:   true,
		// The Duende IdentityServer default CookieLifetime; an idle session was
		// observed dead somewhere between ~1h and ~13h, so this is the anchor the
		// keep-warm cadence is derived from.
		IdleWindow:     10 * time.Hour,
		SupportsExpiry: true,
		LoginKind:      "password",
		Regions:        c.regions(),
	}
}

// regions is the AU state set the UI offers, ordered with the tenant's own state
// first (the contract's "first entry is the default").
func (c *Client) regions() []provider.Region {
	out := make([]provider.Region, 0, len(auStates))
	out = append(out, provider.Region{Code: c.homeCode, Label: c.homeCode})
	for _, s := range auStates {
		if !strings.EqualFold(s.Code, c.homeCode) {
			out = append(out, provider.Region{Code: s.Code, Label: s.Code})
		}
	}
	return out
}

// writeToken resolves the FKVehicleStateID to POST for a plate carrying region
// code. An empty code means "no state of its own": prior is the state already on
// the permit (edit) or "" (add), and either way falls back to the tenant home. An
// unrecognised code (should not happen — the UI only offers regions()) also falls
// back to home rather than sending a token the portal would reject.
func (c *Client) writeToken(region, prior string) string {
	if region != "" {
		if tok, ok := regionToken(region); ok {
			return tok
		}
		log.Printf("orikan: unknown vehicle-state code %q; writing tenant home state %q", region, c.homeCode)
		return c.homeToken
	}
	if prior != "" {
		return prior
	}
	return c.homeToken
}

// originOf returns the scheme://host to use as the browser Origin/Referer for
// portal requests, derived from the API base (falling back to the issuer).
func originOf(issuer, apiBase string) string {
	for _, raw := range []string{apiBase, issuer} {
		if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

// ---- session material ----

// session is what this provider keeps per account: the IdentityServer cookie
// header and a cached access token with its expiry. Serialised as JSON into the
// opaque provider.Session the generic client seals.
type session struct {
	Cookie      string    `json:"cookie"`
	AccessToken string    `json:"access_token,omitempty"`
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
}

func load(s *provider.Session) (*session, error) {
	if s == nil || len(*s) == 0 {
		return nil, provider.ErrNotLinked
	}
	var ss session
	if err := json.Unmarshal(*s, &ss); err != nil {
		return nil, provider.Fail(provider.FailUnexpected, provider.OpUnknown, fmt.Errorf("orikan: session material unreadable: %w", err))
	}
	if ss.Cookie == "" {
		return nil, provider.ErrNotLinked
	}
	return &ss, nil
}

func save(s *provider.Session, ss *session) error {
	b, err := json.Marshal(ss)
	if err != nil {
		return err
	}
	*s = b
	return nil
}

// ImportLegacy builds session material from the pre-provider storage shape (a
// raw cookie header plus a cached token), so existing accounts carry across
// without re-linking. Implements the generic client's legacy import hook.
func (c *Client) ImportLegacy(cookie, accessToken string, expiry time.Time) (provider.Session, error) {
	if cookie == "" {
		return nil, provider.ErrNotLinked
	}
	return json.Marshal(session{Cookie: cookie, AccessToken: accessToken, TokenExpiry: expiry})
}

// do is c.http.Do with its failure sanitised. A *url.Error names the request URL
// in full — for the authorize step that is the state, nonce and PKCE challenge —
// and when a 3xx carries a Location url.Parse rejects, net/http quotes that raw
// header (query and all, so on a login-style bounce a return URL or state) before
// any redirect policy runs. Neither belongs in a log line, so keep the operation
// and the target's scheme/host/path and drop the rest.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	var ue *url.Error
	if err == nil || !errors.As(err, &ue) {
		return resp, err
	}
	inner := ue.Err
	if inner != nil && strings.Contains(inner.Error(), "failed to parse Location header") {
		inner = errors.New("unparseable Location header on a redirect")
	}
	return resp, fmt.Errorf("%s %s: %w", ue.Op, redirectTarget(ue.URL), inner)
}

// redirectTarget renders a Location for an error message: scheme, host and path
// only, so the query — which on a login-style bounce can carry a return URL or a
// state value — never lands in a log line.
func redirectTarget(loc string) string {
	if loc == "" {
		return "(no Location)"
	}
	u, err := url.Parse(loc)
	if err != nil {
		// The raw string is the one thing this function exists to keep out of the
		// log: an unparseable Location still carries its query verbatim.
		return "(unparseable Location)"
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return safeExcerpt(u.String())
}

// CookieOf returns the raw cookie header inside session material ("" if unreadable).
func CookieOf(s provider.Session) string {
	ss, err := load(&s)
	if err != nil {
		return ""
	}
	return ss.Cookie
}
