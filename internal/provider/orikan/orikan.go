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
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
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

// ---- push-back ----

// pushback returns the typed unavailable error when the response is edge/rate-limit
// push-back (429/403/503); nil otherwise. For the permit API the caller first
// separates a JSON 403 (a genuine refusal) from an HTML one (push-back).
func pushback(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
		path := ""
		if resp.Request != nil && resp.Request.URL != nil {
			path = resp.Request.URL.Path
		}
		return &provider.Unavailable{
			RetryAfter:  parseRetryAfter(resp),
			Status:      resp.StatusCode,
			Surface:     surfaceOfPath(path),
			ContentType: safeExcerpt(resp.Header.Get("Content-Type")),
			Ref:         safeExcerpt(resp.Header.Get("X-Azure-Ref")),
		}
	}
	return nil
}

func parseRetryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// ---- OIDC: silent renew / keep-warm ----

// tokenResponse is the subset of the /connect/token response we use. No
// refresh_token is ever present (the client lacks offline_access).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// Refresh keeps the session alive with an AUTHORIZE-ONLY renew: the authenticated
// authorize is the only request that touches the session (the IdentityServer
// slides it server-side), so warming needs neither the token exchange nor a token —
// one request instead of two. A token is minted on demand by the next operation.
func (c *Client) Refresh(ctx context.Context, s *provider.Session) error {
	ss, err := load(s)
	if err != nil {
		return err
	}
	_, _, newCookie, err := c.authorizeWithCookie(ctx, ss.Cookie)
	if err != nil {
		return err
	}
	ss.Cookie = newCookie
	return save(s, ss)
}

// silentRenew performs a prompt=none Authorization-Code + PKCE flow using the
// stored session cookie, returning a fresh access token, its expiry, and the
// (possibly rotated) cookie header. ErrSessionExpired when the cookie is no longer
// accepted (login_required); *provider.Unavailable when the IDM pushes back.
func (c *Client) silentRenew(ctx context.Context, cookie string) (string, time.Time, string, error) {
	code, verifier, newCookie, err := c.authorizeWithCookie(ctx, cookie)
	if err != nil {
		return "", time.Time{}, "", err
	}
	tok, err := c.exchangeCode(ctx, code, verifier)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second), newCookie, nil
}

// authorizeWithCookie performs the prompt=none authorize step shared by a full
// silent-renew and an authorize-only keep-warm, returning the auth code, the PKCE
// verifier that pairs with it, and the (possibly rotated) session cookie.
//
// This authenticated authorize is the ONLY part of a renew that touches the
// session: the IdentityServer slides its server-side session clock when it serves
// this request (a live 2026-08-01 probe showed the cookie itself does NOT rotate,
// so the sliding is server-side, not a new Set-Cookie), while the later token
// exchange is authenticated by the auth code and never touches the session.
func (c *Client) authorizeWithCookie(ctx context.Context, cookie string) (code, verifier, newCookie string, err error) {
	verifier, err = randToken()
	if err != nil {
		return "", "", "", err
	}
	authQuery, err := c.authorizeQuery(verifier)
	if err != nil {
		return "", "", "", err
	}
	authQuery.Set("prompt", "none")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authURL+"?"+authQuery.Encode(), nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Cookie", cookie)
	c.navHeaders(req) // iframe-style silent authorize
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", "", err
	}
	// Keep a bounded prefix of the body: it is the only way to tell an
	// IdentityServer page from any other 200, and the classification below turns
	// on that. 64 KiB, not 8: the expiry test looks for the antiforgery field
	// ANYWHERE in this prefix, so a sign-in page that grew past the limit (inline
	// CSS/JS is ordinary for a login page) would push the marker out of view and
	// make every genuine expiry on this path classify as transient — a session
	// that never gets recovered. Still trivially bounded against a hostile body.
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	drainClose(resp)

	newCookie = mergeSetCookie(cookie, resp.Cookies())

	if busy := pushback(resp); busy != nil {
		return "", "", "", busy
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		// A prompt=none authorize has exactly two honest answers, and both are
		// redirects: one carrying a code, one carrying an error. An HTML page in
		// their place means IdentityServer decided to show something to a HUMAN —
		// the sign-in form, a consent screen, a JS-driven bounce — and it only does
		// that when the session cookie is no longer accepted.
		//
		// The test is deliberately narrow. Push-back (429/403/503) has already been
		// classified above, a transport error returned earlier, and a 5xx or any
		// other status still falls through to the unexpected-status error below —
		// so a genuine transient is never mistaken for an expiry.
		if resp.StatusCode == http.StatusOK && looksLikeHTML(resp, head) {
			// Distinguish IdentityServer's OWN sign-in/consent page (a genuine expiry)
			// from an EDGE challenge page (Azure Front Door / WAF), which also arrives as
			// 200 HTML: only the former carries the ASP.NET antiforgery field. Without
			// that positive marker, treat it as a transient unexpected response rather
			// than retiring the session.
			if bytes.Contains(head, []byte(fieldAntiforgery)) {
				return "", "", "", provider.ErrSessionExpired
			}
			// An edge (WAF/challenge) interstitial. Typed as push-back so it feeds
			// the per-owner cooldown, the fleet breaker and the /status connector
			// state exactly like a 403-HTML would — an untyped error here degraded
			// to an unclassifiable transient that nothing counted, so a challenge
			// rollout was invisible until a user reported it.
			return "", "", "", &provider.Unavailable{
				RetryAfter:  parseRetryAfter(resp),
				Status:      resp.StatusCode,
				Surface:     provider.SurfaceAuth,
				ContentType: safeExcerpt(resp.Header.Get("Content-Type")),
				Ref:         safeExcerpt(resp.Header.Get("X-Azure-Ref")),
			}
		}
		return "", "", "", fmt.Errorf("orikan: silent-renew authorize: unexpected status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", "", "", fmt.Errorf("orikan: silent-renew: bad redirect: %w", err)
	}
	loc = req.URL.ResolveReference(loc) // a relative Location resolves against the authorize URL
	if code = loc.Query().Get("code"); code != "" {
		return code, verifier, newCookie, nil
	}
	// No code. The 200-HTML branch above demands a positive marker (the antiforgery
	// field) before it declares the session dead, and a redirect needs the same
	// discipline: ErrSessionExpired triggers a fleet-wide reconnect and UNLINKS
	// every owner without a saved password, so it must never be raised on a
	// redirect that merely lacks a code. IdentityServer's only no-code answer to a
	// prompt=none authorize is an error (login_required / interaction_required)
	// delivered to the registered redirect_uri, so that — same host and path,
	// carrying error= — is the one redirect that means expiry. Anything else (an
	// edge bounce to a challenge or maintenance page, a redirect to a login page
	// we never asked for, a bare redirect_uri with neither code nor error) is the
	// portal behaving in a way we do not recognise: an unexpected, retried
	// transient, exactly like a non-redirect status would be.
	if loc.Query().Get("error") != "" && c.isRedirectURI(loc) {
		return "", "", "", provider.ErrSessionExpired
	}
	return "", "", "", fmt.Errorf("orikan: silent-renew authorize: unexpected redirect (%d) to %s", resp.StatusCode, redirectTarget(loc.String()))
}

// isRedirectURI reports whether a Location is the client's registered redirect_uri
// (scheme, host and path; the query is where the code or error lives).
func (c *Client) isRedirectURI(loc *url.URL) bool {
	want, err := url.Parse(c.redirectURI)
	if err != nil {
		return false
	}
	return strings.EqualFold(loc.Scheme, want.Scheme) &&
		strings.EqualFold(loc.Host, want.Host) &&
		strings.TrimRight(loc.Path, "/") == strings.TrimRight(want.Path, "/")
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
		return safeExcerpt(loc)
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return safeExcerpt(u.String())
}

// looksLikeHTML reports whether a response is a rendered page rather than the
// machine answer its endpoint is supposed to give. The declared Content-Type is
// the primary signal; the body prefix is a fallback because a portal behind a WAF
// does not reliably label its interstitials.
func looksLikeHTML(resp *http.Response, head []byte) bool {
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}
	s := strings.ToLower(strings.TrimSpace(string(head)))
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html")
}

// authorizeQuery builds the common authorize parameters for a PKCE code flow.
func (c *Client) authorizeQuery(verifier string) (url.Values, error) {
	state, err := randToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randToken()
	if err != nil {
		return nil, err
	}
	return url.Values{
		"client_id":             {c.clientID},
		"redirect_uri":          {c.redirectURI},
		"response_type":         {"code"},
		"scope":                 {c.scope},
		"nonce":                 {nonce},
		"state":                 {state},
		"code_challenge":        {s256(verifier)},
		"code_challenge_method": {"S256"},
	}, nil
}

// exchangeCode swaps an authorization code for tokens at the token endpoint.
func (c *Client) exchangeCode(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.xhrHeaders(req) // fetch-style token exchange
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if busy := pushback(resp); busy != nil {
		return nil, busy
	}
	const op = provider.OpRefresh
	if resp.StatusCode != http.StatusOK {
		return nil, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, safeExcerpt(string(body))))
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		// The likeliest shape signal of all: a token endpoint returning HTML (an error
		// page, an edge interstitial). Bare, FailureOf would call it transient and every
		// owner would retry it forever instead of the operator being told.
		return nil, provider.Fail(provider.FailUnexpected, op, fmt.Errorf("token response was not JSON: %w", err))
	}
	if tok.AccessToken == "" {
		return nil, provider.Fail(provider.FailUnexpected, op, errors.New("token response had no access_token"))
	}
	// A 200 is not enough: the fields we DEPEND on must be sane, or the failure is
	// silent and expensive. A missing/zero expires_in makes the token look already
	// expired, so every single API call would mint a fresh one — multiplying auth
	// traffic on the shared egress IP for as long as the shape stays wrong. A
	// non-Bearer type means our Authorization header is malformed and every call
	// 401s. Treat both as an API-shape change rather than papering over them.
	if !strings.EqualFold(tok.TokenType, "Bearer") && tok.TokenType != "" {
		return nil, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("token response has unsupported token_type %q: API shape change?", safeExcerpt(tok.TokenType)))
	}
	if tok.ExpiresIn <= 0 || tok.ExpiresIn > 24*3600 {
		return nil, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("token response has implausible expires_in %d: API shape change?", tok.ExpiresIn))
	}
	return &tok, nil
}

// accessToken returns a valid access token for the session, silent-renewing
// against the cookie when the cached token is stale and writing the new token
// (and any rotated cookie) back into the session.
func (c *Client) accessToken(ctx context.Context, ss *session, force bool) (string, error) {
	if !force && ss.AccessToken != "" && time.Until(ss.TokenExpiry) > 60*time.Second {
		return ss.AccessToken, nil
	}
	at, expiry, newCookie, err := c.silentRenew(ctx, ss.Cookie)
	if err != nil {
		return "", err
	}
	ss.AccessToken, ss.TokenExpiry = at, expiry
	if newCookie != "" {
		ss.Cookie = newCookie
	}
	return at, nil
}

// ---- login ----

// loginHosts is the set of hosts the login flow may talk to, taken ENTIRELY from
// the configuration: the issuer the sign-in form lives on, the token endpoint, the
// portal origin, and the SPA callback the credential POST chain lands on. Nothing
// scraped from the page contributes to it, which is the whole point — the page is
// what we are guarding against.
func (c *Client) loginHosts() map[string]bool {
	hosts := map[string]bool{}
	for _, raw := range []string{c.authURL, c.loginURL, c.tokenURL, c.origin, c.redirectURI} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			hosts[strings.ToLower(u.Host)] = true
		}
	}
	return hosts
}

// linkShapeErr classifies a login page this provider cannot safely submit, and is
// deliberately NOT ErrLoginRejected: that would tell every affected user their
// password is wrong and make the scheduler delete their saved session over one
// cosmetic change to the portal's HTML. FailUnexpected means "the portal changed
// something and this provider needs updating"; every caller's fallback for it is
// safe (the session and saved password are kept). The log line is what the
// operator acts on.
func linkShapeErr(err error) error {
	log.Printf("orikan: sign-in page not usable: %v", err)
	return provider.Fail(provider.FailUnexpected, provider.OpLogin, err)
}

// Login performs a headless login with the person's portal credentials and
// returns the (unsealed) session material. The credentials are used only here.
//
// NOTE: this replays the SPA's own login form. The form-field harvesting is
// deliberately lenient about PRESENTATION (quoting style, attribute spacing) and
// deliberately strict about SUBSTANCE: where the credentials would go, and whether
// the page is the sign-in form at all.
func (c *Client) Login(ctx context.Context, creds provider.Credentials) (provider.Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	// Pin the whole flow to the portal's own hosts before it starts. This is the
	// one request in the app that carries a user's plaintext third-party password,
	// so where it goes must be decided by operator configuration and nothing else.
	hosts := c.loginHosts()
	if len(hosts) == 0 {
		return nil, linkShapeErr(fmt.Errorf("%w: no portal host is configured, so there is nothing to pin the credential POST to", provider.ErrLoginOffHost))
	}
	// The scheme the flow must not drop below. loginHosts pins WHERE the password may
	// go but discards the scheme, so a same-host https→http redirect would sail past
	// the host check and put the password on the wire in clear.
	wantScheme := "https"
	if u, err := url.Parse(c.authURL); err == nil && u.Scheme != "" {
		wantScheme = strings.ToLower(u.Scheme)
	}
	// A dedicated client that follows redirects and keeps a jar for this one
	// login flow (c.http handles redirects manually and shares no cookies). Same
	// governed, counted transport as everything else.
	lc := &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: c.transport,
		// Refuse to be walked off the portal's hosts. The credential POST target is
		// resolved against the URL this redirect chain ENDS at, so an open redirect
		// on the portal would otherwise be enough to move that base off-host and take
		// the password with it — no HTML injection needed.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !hosts[strings.ToLower(req.URL.Host)] {
				err := fmt.Errorf("%w: refused to follow the sign-in off-host to %q", provider.ErrLoginOffHost, safeExcerpt(req.URL.Host))
				log.Printf("orikan: SECURITY: %v", err)
				return err
			}
			// A right-host redirect can still be a scheme DOWNGRADE (https→http on the
			// same host), which the host check above cannot see. Refuse it.
			if !redirectSchemeOK(req.URL.Scheme, wantScheme) {
				err := fmt.Errorf("%w: refused a %q redirect on a %q sign-in flow (host %q)",
					provider.ErrLoginOffHost, safeExcerpt(req.URL.Scheme), wantScheme, safeExcerpt(req.URL.Host))
				log.Printf("orikan: SECURITY: %v", err)
				return err
			}
			// Setting CheckRedirect replaces Go's own 10-hop cap, so re-impose one.
			if len(via) >= 10 {
				return errors.New("orikan: sign-in: stopped after 10 redirects")
			}
			return nil
		},
	}

	verifier, err := randToken()
	if err != nil {
		return nil, err
	}
	authQuery, err := c.authorizeQuery(verifier)
	if err != nil {
		return nil, err
	}

	// 1. Authorize → redirects to the login page (sets the antiforgery cookie).
	//    A top-level, user-initiated navigation.
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authURL+"?"+authQuery.Encode(), nil)
	if err != nil {
		return nil, err
	}
	c.navHeaders(getReq)
	getReq.Header.Set("Sec-Fetch-Dest", "document")
	getReq.Header.Set("Sec-Fetch-Site", "none")
	getReq.Header.Set("Sec-Fetch-User", "?1")
	getReq.Header.Del("Referer")
	resp, err := lc.Do(getReq)
	if err != nil {
		return nil, err
	}
	loginPage, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if busy := pushback(resp); busy != nil {
		return nil, busy
	}
	loginURL := resp.Request.URL // final URL after redirects = the login form

	// 2. Harvest the form and settle BOTH questions — is this the sign-in form, and
	//    where would submitting it send the password — before the password is put
	//    into anything. If either answer is wrong, nothing was ever assembled.
	action, fields := parseLoginForm(string(loginPage))
	if err := checkLoginForm(fields); err != nil {
		return nil, linkShapeErr(err)
	}
	actionURL, err := resolveAction(loginURL, action, hosts)
	if err != nil {
		return nil, linkShapeErr(err)
	}
	fields[fieldUsername] = creds.Username
	fields[fieldPassword] = creds.Password
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	// 3. POST credentials; follow the redirect chain (ends at the SPA callback,
	//    which is static HTML) so the jar collects the session cookies.
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, actionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.navHeaders(postReq)
	postReq.Header.Set("Sec-Fetch-Dest", "document")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.Header.Set("Sec-Fetch-User", "?1")
	if c.origin != "" {
		postReq.Header.Set("Origin", c.origin)
	}
	postReq.Header.Set("Referer", loginURL.String())
	presp, err := lc.Do(postReq)
	if err != nil {
		// A CheckRedirect refusal arrives here wrapped in a *url.Error. Returning it
		// unclassified is the safe landing: every caller's fallback treats an
		// unrecognised error as transient, so nothing is unlinked and no user is told
		// their password is wrong. The refusal itself was already logged.
		return nil, err
	}
	drainClose(presp)
	if busy := pushback(presp); busy != nil {
		return nil, busy
	}

	// 4. Extract the session cookie (scoped to /idm) from the jar.
	authURLParsed, err := url.Parse(c.authURL)
	if err != nil {
		return nil, err
	}
	cookie := jarCookieHeader(jar, authURLParsed)
	if !hasCookieNamed(cookie, sessionCookie) {
		return nil, provider.ErrLoginRejected
	}
	return json.Marshal(session{Cookie: cookie})
}

// ---- permit API ----

// maxAPIBody bounds a permit-API JSON response. The real ones are a few
// kilobytes; the bound exists so a hostile or broken portal cannot make a decode
// consume memory in proportion to what it chooses to send.
const maxAPIBody = 1 << 20

// drainClose discards (a bounded amount of) the body and closes it, so the
// keep-alive connection is reusable.
func drainClose(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

// refusalPayload is the portal's refusal body: a JSON ARRAY of message objects,
// e.g. [{"Level":0,"Message":"Vehicle Registration has invalid pattern","ID":null,…}]
// (captured live 2026-07-31 from a rejected manageVehicle POST).
type refusalPayload struct {
	Message       string `json:"Message"`
	CustomMessage string `json:"CustomMessage"`
}

// refusalMessage extracts a human-readable reason from a refusal body, or "" if
// there is nothing usable. Portal-controlled text: passed through safeExcerpt.
// Multiple messages are joined: the portal reports per-field validation, and
// showing only the first would hide the rest of what the user has to fix.
func refusalMessage(body []byte) string {
	var payload []refusalPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	var msgs []string
	for _, p := range payload {
		m := p.CustomMessage // the portal's own user-facing wording, when it sets one
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
// the API itself speaks, as opposed to an edge HTML challenge page.
func isJSONResponse(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "json")
}

// apiRequest issues an authenticated request to the permit API. It classifies
// edge push-back (429/403-HTML/503) as *provider.Unavailable, a mid-life token
// rejection (401) is retried once after a forced renew, and any other non-2xx is
// a classified provider.Error carrying the portal's own reason when it gave one.
// A 2xx returns the response for the caller to decode.
func (c *Client) apiRequest(ctx context.Context, ss *session, method, path string, op provider.Op, query url.Values, body []byte) (*http.Response, error) {
	at, err := c.accessToken(ctx, ss, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.doAPI(ctx, at, method, path, query, body)
	if err != nil {
		// Transport error (DNS, dial, timeout, reset): transient by nature.
		return nil, provider.Fail(provider.FailTransient, op, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The cached token was rejected mid-life (the portal can kick a session
		// server-side, e.g. when the user logs into the portal in a browser).
		// Force one silent-renew and retry; if the renew itself fails the error
		// (ErrSessionExpired, Unavailable, …) flows out.
		drainClose(resp)
		at, err = c.accessToken(ctx, ss, true)
		if err != nil {
			return nil, err
		}
		resp, err = c.doAPI(ctx, at, method, path, query, body)
		if err != nil {
			return nil, provider.Fail(provider.FailTransient, op, err)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			// A freshly-minted token is still refused: not a stale-token blip.
			drainClose(resp)
			return nil, provider.Fail(provider.FailRejected, op, errors.New("portal rejected a fresh access token (401)"))
		}
	}
	switch resp.StatusCode {
	case http.StatusForbidden:
		// Two very different things arrive as 403: edge push-back (an HTML challenge
		// page — transient, back off) and a genuine API refusal (JSON, e.g. permit
		// access revoked — durable, will never self-heal).
		if isJSONResponse(resp) {
			drainClose(resp)
			return nil, provider.Fail(provider.FailRejected, op, errors.New("the portal refused access (403)"))
		}
		fallthrough
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		busy := pushback(resp)
		drainClose(resp)
		return nil, busy
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// The client never follows redirects, and the permit API never issues one:
		// a bearer-authenticated JSON endpoint answers with data or an error. A 3xx
		// here is therefore the EDGE speaking — a WAF interstitial, a maintenance
		// bounce, a portal relocation — and says nothing about this household's
		// permit. Left to the generic rule below it would classify as a refusal
		// (a 4xx-like "< 500"), which the scheduler parks for good and reports to
		// the household as the council not letting p.stonn make the change.
		// Transient instead: retried on the backoff path, and if the redirect
		// persists it surfaces as a degraded connector, not a parked permit.
		loc := resp.Header.Get("Location")
		drainClose(resp)
		return nil, provider.Fail(provider.FailTransient, op, fmt.Errorf("portal redirected (%d) to %s: edge interstitial or portal moved?", resp.StatusCode, redirectTarget(loc)))
	}
	// Other non-2xx: 5xx is a server-side blip (transient); 4xx is a refusal.
	// A refusal usually carries the portal's OWN reason, and it is the only thing
	// that can tell a user what to actually do — "Vehicle Registration has invalid
	// pattern" is actionable where "returned 400" is not. Read it before discarding.
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	drainClose(resp)
	kind := provider.FailRejected
	if resp.StatusCode >= 500 {
		kind = provider.FailTransient
	}
	if msg := refusalMessage(errBody); msg != "" {
		return nil, provider.FailDetail(kind, op, msg, fmt.Errorf("the portal refused it: %s (%d)", msg, resp.StatusCode))
	}
	return nil, provider.Fail(kind, op, fmt.Errorf("portal returned %d", resp.StatusCode))
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

// managedVehicleResp is the response of GET /ssp-svc/api/permits/managedVehicle.
//
// Verified against a live response. NOTE the casing is mixed: the top-level keys
// are camelCase, but the permitVehicles[] element keys are PascalCase. Within an
// element, PKPermitVehicleDetailID arrives as a bare JSON number while
// FKVehicleStateID arrives as a quoted string, hence the differing Go types.
// POINTERS wherever an absent key must be distinguishable from a present zero:
// an omitted field must surface as an unexpected shape, never as a durable "the
// portal does not allow…" refusal or as "this permit has no vehicle".
type managedVehicleResp struct {
	PermitNumber           string          `json:"permitNumber"`
	PermitVehicleCount     *int            `json:"permitVehicleCount"`
	MaxVehicles            int             `json:"maxVehicles"`
	CanAddVehicle          *bool           `json:"canAddVehicle"`
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
// harmless default: the scheduler would write an empty plate and SetVehicle would
// turn it into a durable refusal. So an empty list is believed only when the rest
// of the response corroborates it: the permit is identified, the portal's own
// count came back and says zero, AND permitVehicles is an explicit empty array.
func (mv *managedVehicleResp) emptyIsCredible() bool {
	return mv.PermitNumber != "" &&
		mv.PermitVehicleCount != nil && *mv.PermitVehicleCount == 0 &&
		mv.PermitVehicles != nil
}

// errVehicleShape describes an empty vehicle list that nothing corroborates.
func errVehicleShape(mv *managedVehicleResp) error {
	count := "absent"
	if mv.PermitVehicleCount != nil {
		count = fmt.Sprintf("%d", *mv.PermitVehicleCount)
	}
	return fmt.Errorf("the portal returned no vehicles but the response does not look like a permit record (permitNumber=%q, permitVehicleCount=%s, permitVehiclesPresent=%t): API shape change?",
		mv.PermitNumber, count, mv.PermitVehicles != nil)
}

// managedVehicle fetches the vehicle(s) currently on the permit.
func (c *Client) managedVehicle(ctx context.Context, ss *session, p provider.PermitRef, op provider.Op) (*managedVehicleResp, error) {
	resp, err := c.apiRequest(ctx, ss, http.MethodGet, "/api/permits/managedVehicle", op, url.Values{"permitID": {p.ID}}, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var mv managedVehicleResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&mv); err != nil {
		return nil, provider.Fail(provider.FailUnexpected, op, err)
	}
	return &mv, nil
}

// CurrentVehicle returns the registration currently on the permit, or "" if the
// permit genuinely has no vehicle. An empty list the response does not corroborate
// is an error, not an empty plate — see emptyIsCredible.
func (c *Client) CurrentVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) (provider.Vehicle, error) {
	ss, err := load(s)
	if err != nil {
		return provider.Vehicle{}, err
	}
	reg, stateToken, err := c.currentVehicle(ctx, ss, p, provider.OpReadVehicle)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return provider.Vehicle{Registration: reg, Region: tokenRegion(stateToken)}, err
}

// currentVehicle returns the plate on the permit and its state token ("" for a
// genuinely empty permit). The token is the portal's FKVehicleStateID; callers
// that only need the plate ignore it.
func (c *Client) currentVehicle(ctx context.Context, ss *session, p provider.PermitRef, op provider.Op) (reg, stateToken string, err error) {
	mv, err := c.managedVehicle(ctx, ss, p, op)
	if err != nil {
		return "", "", err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return "", "", provider.Fail(provider.FailUnexpected, op, errVehicleShape(mv))
		}
		return "", "", nil
	}
	if len(mv.PermitVehicles) != 1 {
		// The visitor-permit model is one managed vehicle per permit. More than one is
		// an unexpected shape: reading (or later editing) only [0] could act on the
		// wrong record, so refuse rather than guess.
		return "", "", provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	if strings.TrimSpace(mv.PermitVehicles[0].RegistrationNumber) == "" {
		// A PRESENT vehicle record with a blank plate is not "no vehicle": returning ""
		// would report an uncorroborated clearing.
		return "", "", provider.Fail(provider.FailUnexpected, op,
			errors.New("a managed vehicle record has an empty registration: API shape change?"))
	}
	return mv.PermitVehicles[0].RegistrationNumber, mv.PermitVehicles[0].FKVehicleStateID, nil
}

// SetVehicle reallocates the permit to the given registration, the core action.
//
// The portal implements this as an in-place edit of the permit's single vehicle,
// so we first read the current vehicle to obtain its detail ID (and preserve its
// state), then POST the edit. A no-op edit (unchanged plate) is skipped, mirroring
// the portal. A credibly-empty permit gets an ADD instead (the normal state of a
// freshly granted permit). Success is any 2xx with an empty body, which says
// nothing about the resulting state — so the change is confirmed by re-reading the
// portal's own record before success is reported.
func (c *Client) SetVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef, v provider.Vehicle) error {
	ss, err := load(s)
	if err != nil {
		return err
	}
	err = c.setVehicle(ctx, ss, p, v.Registration, v.Region)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return err
}

func (c *Client) setVehicle(ctx context.Context, ss *session, p provider.PermitRef, registration, region string) error {
	const op = provider.OpSetVehicle
	mv, err := c.managedVehicle(ctx, ss, p, op)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return provider.Fail(provider.FailUnexpected, op, errVehicleShape(mv))
		}
		if mv.CanAddVehicle == nil {
			// Absent, not false: cannot tell "not permitted" from "field gone".
			return provider.Fail(provider.FailUnexpected, op, errors.New("response has no canAddVehicle field: API shape change?"))
		}
		if !*mv.CanAddVehicle {
			return provider.Fail(provider.FailRejected, op, errors.New("the portal does not allow adding a vehicle to this permit"))
		}
		return c.addVehicle(ctx, ss, p, registration, region)
	}
	if mv.CanEditOrDeleteVehicle == nil {
		return provider.Fail(provider.FailUnexpected, op, errors.New("response has no canEditOrDeleteVehicle field: API shape change?"))
	}
	if !*mv.CanEditOrDeleteVehicle {
		return provider.Fail(provider.FailRejected, op, errors.New("the portal does not allow changing this permit's vehicle"))
	}
	if len(mv.PermitVehicles) != 1 {
		return provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	cur := mv.PermitVehicles[0]
	// An absent PKPermitVehicleDetailID yields json.Number("") and we would POST an
	// edit with empty ids. This is the one code path that can put a wrong plate on a
	// real permit — so fail closed.
	if strings.TrimSpace(cur.PKPermitVehicleDetailID.String()) == "" {
		return provider.Fail(provider.FailUnexpected, op, errors.New("managed vehicle has no PKPermitVehicleDetailID: API shape change?"))
	}
	// The desired state: an explicit region wins; otherwise keep the state already
	// on the permit, falling back to the tenant home. A same-plate write is skipped
	// only when the state is ALSO already what we want — so correcting just the state
	// on an already-active plate is still applied.
	state := c.writeToken(region, cur.FKVehicleStateID)
	if model.SamePlate(cur.RegistrationNumber, registration) && state == cur.FKVehicleStateID {
		return nil // plate and state already as desired; the read above IS the confirmation
	}
	permitID, err := strconv.ParseInt(p.ID, 10, 64)
	if err != nil {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("invalid permit id %q", p.ID))
	}
	detailID := cur.PKPermitVehicleDetailID.String()
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
	if err := c.postManage(ctx, ss, reqBody, op); err != nil {
		return err
	}
	return c.confirmWrite(ctx, ss, p, registration, op)
}

// postManage sends a manageVehicle request and discards the (empty) 2xx body.
func (c *Client) postManage(ctx context.Context, ss *session, reqBody manageVehicleReq, op provider.Op) error {
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := c.apiRequest(ctx, ss, http.MethodPost, "/api/permits/manageVehicle", op, nil, buf)
	if err != nil {
		return err
	}
	drainClose(resp)
	return nil
}

// confirmRetryDelay is the single pause confirmWrite takes when the first
// read-back after a 2xx write does not yet show the plate we sent, before it
// reads once more. A variable so tests can shorten it; the transport's governor
// still paces the request itself.
var confirmRetryDelay = 2 * time.Second

// confirmWrite re-reads the portal's OWN record after a 2xx write and only
// reports success once it shows the plate we sent. An unreadable confirm is
// transient (retry). A mismatch on the FIRST read is treated as the portal not
// having caught up yet (a 2xx followed by a stale read has been observed to be
// lag, not refusal): wait briefly and read once more. Only when that second
// read still disagrees is it a durable refusal (act-now notice) — at the cost of
// exactly one extra request, and only on the mismatch path.
// registration "" means "expect the permit empty" (the clear path).
func (c *Client) confirmWrite(ctx context.Context, ss *session, p provider.PermitRef, registration string, op provider.Op) error {
	confirmed, _, err := c.currentVehicle(ctx, ss, p, op)
	if err != nil {
		return provider.Fail(provider.FailTransient, op, fmt.Errorf("change sent but could not be confirmed: %w", err))
	}
	if model.SamePlate(confirmed, registration) {
		return nil
	}
	select {
	case <-ctx.Done():
		return provider.Fail(provider.FailTransient, op, fmt.Errorf("change sent but not yet confirmed (portal still shows %q): %w", confirmed, ctx.Err()))
	case <-time.After(confirmRetryDelay):
	}
	confirmed, _, err = c.currentVehicle(ctx, ss, p, op)
	if err != nil {
		return provider.Fail(provider.FailTransient, op, fmt.Errorf("change sent but could not be confirmed: %w", err))
	}
	if !model.SamePlate(confirmed, registration) {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("change was accepted but the portal still shows %q", confirmed))
	}
	return nil
}

// addVehicle attaches a NEW vehicle to a permit that currently has none — the
// portal's "add" action, distinct from "edit". Captured live 2026-08-23 against an
// empty permit: VehicleActionOption "add", an empty SelectedVehicle, and a Vehicle
// with no prior detail id / change-set (the portal assigns a fresh one).
func (c *Client) addVehicle(ctx context.Context, ss *session, p provider.PermitRef, registration, region string) error {
	const op = provider.OpAddVehicle
	permitID, err := strconv.ParseInt(p.ID, 10, 64)
	if err != nil {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("invalid permit id %q", p.ID))
	}
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     "",
		VehicleActionOption: "add",
		Vehicle: manageVehicleV{
			ChangeSetID:             "",
			FKPermitID:              permitID,
			FKVehicleStateID:        c.writeToken(region, ""), // a bare-plate add carries no prior state
			PKPermitVehicleDetailID: "",                       // new record — the portal assigns the id
			RegisteredAtAddress:     false,
			RegistrationNumber:      registration,
		},
	}
	if err := c.postManage(ctx, ss, reqBody, op); err != nil {
		return err
	}
	return c.confirmWrite(ctx, ss, p, registration, op)
}

// ClearVehicle removes the vehicle from a permit, leaving it with none — the
// portal's "delete" action. Idempotent: an already-empty permit is success.
func (c *Client) ClearVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) error {
	ss, err := load(s)
	if err != nil {
		return err
	}
	err = c.clearVehicle(ctx, ss, p)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return err
}

func (c *Client) clearVehicle(ctx context.Context, ss *session, p provider.PermitRef) error {
	const op = provider.OpClearVehicle
	mv, err := c.managedVehicle(ctx, ss, p, op)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return provider.Fail(provider.FailUnexpected, op, errVehicleShape(mv))
		}
		return nil // already empty, corroborated
	}
	if len(mv.PermitVehicles) != 1 {
		return provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	cur := mv.PermitVehicles[0]
	detailID := cur.PKPermitVehicleDetailID.String()
	if strings.TrimSpace(detailID) == "" {
		return provider.Fail(provider.FailUnexpected, op, errors.New("managed vehicle has no PKPermitVehicleDetailID: API shape change?"))
	}
	permitID, err := strconv.ParseInt(p.ID, 10, 64)
	if err != nil {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("invalid permit id %q", p.ID))
	}
	state := cur.FKVehicleStateID
	if state == "" {
		state = c.homeToken
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
	if err := c.postManage(ctx, ss, reqBody, op); err != nil {
		return err
	}
	return c.confirmWrite(ctx, ss, p, "", op)
}

// ---- permit list ----

// POINTERS, so an ABSENT key is distinguishable from a present zero/empty. Without
// that, `{}` decodes to (nil, 0) and reads as "this account has no permits".
type gridResp struct {
	PermitGrid *[]gridRow `json:"PermitGrid"`
	TotalItems *int       `json:"TotalItems"`
}

// gridRow is decoded with POINTERS for every field drift acts on, so an omitted key
// is distinguishable from a legitimately empty value: blank PermitStatus/EndDate
// would otherwise be written over good stored metadata.
//
// VehicleRego is the one deliberate EXEMPTION: the portal sends null for a permit
// that has never had a vehicle assigned (observed live 2026-08-22), and a nil
// pointer cannot tell that from a dropped key. Treating it as "" is safe because
// drift never blanks a stored plate on the grid's word alone — an empty grid rego
// triggers a corroborating managedVehicle read first.
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
		// VehicleRego deliberately absent: null means "no vehicle assigned yet".
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

// maxPermitPages bounds the paging loop. A household with more than this many
// permits does not exist; the cap is here so a portal that ignores pageNumber
// cannot turn one read into an unbounded request loop.
const maxPermitPages = 20

// ListPermits reads the account's whole permit list, paging if the portal gives us
// one, and returns the total the portal claims. len(permits) < total means we ended
// up holding a page rather than the account: the account changed mid-read, paging
// stalled, or the cap was hit. The rows are still usable; the generic client and
// the core decide what a partial list may be used for.
//
// We ask for pageSize=0 ("everything") and the portal has always honoured it, so
// the loop normally runs exactly once.
func (c *Client) ListPermits(ctx context.Context, s *provider.Session) ([]provider.Permit, int, error) {
	ss, err := load(s)
	if err != nil {
		return nil, 0, err
	}
	permits, total, err := c.listPermits(ctx, ss)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return permits, total, err
}

func (c *Client) listPermits(ctx context.Context, ss *session) ([]provider.Permit, int, error) {
	var all []provider.Permit
	seen := make(map[string]bool)
	expected := -1 // the account size the FIRST page claimed
	for page := 0; page < maxPermitPages; page++ {
		rows, total, err := c.permitPage(ctx, ss, page)
		if err != nil {
			return nil, 0, err
		}
		if expected < 0 {
			expected = total
		} else if total != expected {
			// The account changed under us mid-read. Accepting the new count would let
			// stale rows collected earlier satisfy a smaller total while a permit that
			// exists right now was never returned. A snapshot we cannot trust is
			// reported incomplete; the next pass reads it cleanly.
			// Reported as partial by construction (total > len), whichever way the
			// count moved, so a caller can never mistake it for the whole account.
			log.Printf("orikan: permit count changed mid-read (%d -> %d at page %d); treating this list as incomplete", expected, total, page)
			return all, max(expected, total, len(all)+1), nil
		}
		added := 0
		for _, p := range rows {
			if seen[p.CouncilPermitID] {
				continue // a portal that ignores pageNumber would repeat page 0 forever
			}
			seen[p.CouncilPermitID] = true
			all = append(all, p)
			added++
		}
		if len(all) >= expected {
			return all, expected, nil
		}
		if added == 0 {
			// No progress and still short of the count: paging is not working the way
			// we assumed, so report what we have as partial.
			log.Printf("orikan: permit list stalled at %d of %d after %d page(s); reporting a partial list", len(all), expected, page+1)
			return all, expected, nil
		}
	}
	log.Printf("orikan: permit list still incomplete after %d pages; reporting a partial list", maxPermitPages)
	return all, expected, nil
}

// permitPage reads ONE page of the grid and returns its rows plus the total the
// portal says the account holds.
func (c *Client) permitPage(ctx context.Context, ss *session, page int) (_ []provider.Permit, total int, err error) {
	const op = provider.OpListPermits
	resp, err := c.apiRequest(ctx, ss, http.MethodGet, "/api/Index/grid", op,
		url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {"0"}}, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var g gridResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&g); err != nil {
		return nil, 0, provider.Fail(provider.FailUnexpected, op, err)
	}
	// A 200 whose body decoded to nothing useful is an API-SHAPE failure, not "this
	// account has no permits". BOTH top-level fields must be explicitly present.
	if g.PermitGrid == nil || g.TotalItems == nil {
		return nil, 0, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("permit grid response is missing PermitGrid=%t/TotalItems=%t: API shape change?", g.PermitGrid == nil, g.TotalItems == nil))
	}
	rows, total := *g.PermitGrid, *g.TotalItems
	// Deliberately NOT exact equality (a default page size would make TotalItems the
	// unpaged total). What must never pass: the portal says there ARE permits and
	// sent none, or more rows than it says exist.
	if len(rows) == 0 && total != 0 {
		return nil, 0, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("permit grid is empty but the response claims %d items: API shape change?", total))
	}
	if total < len(rows) {
		return nil, 0, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("permit grid has %d rows but the response claims only %d items: API shape change?", len(rows), total))
	}
	out := make([]provider.Permit, 0, len(rows))
	for _, r := range rows {
		if r.PKPermitID <= 0 {
			return nil, 0, provider.Fail(provider.FailUnexpected, op,
				fmt.Errorf("a permit row has a non-positive PKPermitID (%d): API shape change?", r.PKPermitID))
		}
		if missing := r.missingGridFields(); len(missing) > 0 {
			return nil, 0, provider.Fail(provider.FailUnexpected, op,
				fmt.Errorf("permit %d is missing %s: API shape change? Treating an absent field as empty would blank the stored permit and clear its plate", r.PKPermitID, strings.Join(missing, ", ")))
		}
		start, serr := tenantDate(*r.StartDate)
		end, eerr := tenantDate(*r.EndDate)
		if serr != nil || eerr != nil {
			return nil, 0, provider.Fail(provider.FailUnexpected, op,
				fmt.Errorf("permit %d has an unparseable date (start=%q end=%q): API shape change?", r.PKPermitID, safeExcerpt(*r.StartDate), safeExcerpt(*r.EndDate)))
		}
		out = append(out, provider.Permit{
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

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// tenantDate parses a portal date, reporting a malformed one instead of
// swallowing it. Empty means "not set" and is not an error.
func tenantDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse("2006-01-02T15:04:05", s)
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

// ---- diagnostics (env-gated live tooling; not used by the app) ----

// SilentRenew runs one full silent-renew on a raw cookie header and returns the
// minted token, its expiry and the (possibly rotated) cookie.
func (c *Client) SilentRenew(ctx context.Context, cookie string) (token string, expiry time.Time, newCookie string, err error) {
	return c.silentRenew(ctx, cookie)
}

// Warm runs one authorize-only keep-warm on a raw cookie header.
func (c *Client) Warm(ctx context.Context, cookie string) (newCookie string, err error) {
	_, _, newCookie, err = c.authorizeWithCookie(ctx, cookie)
	return newCookie, err
}

// Do issues one authenticated raw permit-API request for the session (minting a
// token if needed) and returns the undecoded response, so a capture reports what
// the portal actually sent rather than what this provider's structs keep.
func (c *Client) Do(ctx context.Context, s *provider.Session, method, path string, query url.Values, body []byte) (*http.Response, error) {
	ss, err := load(s)
	if err != nil {
		return nil, err
	}
	at, err := c.accessToken(ctx, ss, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.doAPI(ctx, at, method, path, query, body)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return resp, err
}

// CookieOf returns the raw cookie header inside session material ("" if unreadable).
func CookieOf(s provider.Session) string {
	ss, err := load(&s)
	if err != nil {
		return ""
	}
	return ss.Cookie
}
