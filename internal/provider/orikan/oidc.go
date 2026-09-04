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
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// authBackoffErr is the fast-fail returned while the auth circuit is open. It wraps
// the ErrUnavailable SENTINEL — so callers that already handle a busy portal
// (errors.Is(err, ErrCouncilBusy)) get the right "the council's sign-in is busy, not
// your password" treatment — but is NOT a *provider.Unavailable STRUCT, so the
// parking client's classify() does not `errors.As` it and therefore does NOT feed
// the blunt fleet breaker. This keeps the backoff surface-scoped to auth.
func authBackoffErr(retry time.Duration) error {
	return fmt.Errorf("%w: council sign-in is temporarily unavailable, backing off (retry in %s)", provider.ErrUnavailable, retry.Round(time.Second))
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

	// AUTH-surface circuit: a council auth outage (5xx) is otherwise re-hit by every
	// keep-warm renew AND every API op whose cached token has gone stale, at each
	// path's own rate, for the whole outage. When the circuit is open, fast-fail here
	// WITHOUT touching the council — except for the single, escalating-backoff probe
	// that tests recovery. A valid-token API op never reaches this (accessToken
	// returns the cached token), so due schedule changes still apply.
	probe, ok, retry := c.authCircuit.allow(time.Now())
	if !ok {
		return "", "", "", authBackoffErr(retry)
	}
	code, newCookie, status, err := c.doAuthorize(ctx, cookie, verifier, authQuery)
	c.recordAuthorizeOutcome(probe, status, err)
	return code, verifier, newCookie, err
}

// AuthGate reports whether the auth-surface circuit is currently open (renews and
// stale-token ops are fast-failing) and how long until the next recovery probe. The
// parking client surfaces it on /status so the operator/watchdog can tell an
// auth-only council outage that the app is already shedding from a healthy connector.
func (c *Client) AuthGate() (open bool, retry time.Duration) {
	return c.authCircuit.state(time.Now())
}

// recordAuthorizeOutcome feeds the auth circuit the result of one authorize.
// A code or a genuine session-expiry both mean the upstream SERVED us, so the
// circuit closes. A transport error or an HTTP 5xx is the "upstream is down" signal
// that opens it (or escalates a failed probe). Everything else — edge push-back, an
// odd 4xx, an unrecognised redirect — is not upstream-down, so it neither opens nor
// closes the circuit (the fleet breaker owns the edge case).
func (c *Client) recordAuthorizeOutcome(probe bool, status int, err error) {
	now := time.Now()
	sig := provider.Classify(err)
	switch {
	case sig.OK, sig.Expiry:
		// A code, or a genuine expiry — the upstream served us. Close.
		c.authCircuit.onSuccess(probe)
	case sig.Pushback != nil, sig.Canceled:
		// Edge push-back (429/403/503 / WAF), routed by TYPE not status so a 503 the
		// fleet breaker owns is not double-counted here; or our own cancellation
		// (mirrors health.noteAt, which also ignores it). Inconclusive either way.
		c.authCircuit.onInconclusive(now, probe)
	case status == 0, status >= 500:
		// A transport failure (no response) or an origin 5xx: the upstream is down.
		c.authCircuit.onUpstreamFailure(now, probe)
	default:
		// An odd 4xx or an unrecognised redirect — not upstream-down.
		c.authCircuit.onInconclusive(now, probe)
	}
}

// doAuthorize is the network half of authorizeWithCookie: the prompt=none authorize
// GET and its response classification, returning the HTTP status so the caller can
// drive the auth circuit. Behaviour is otherwise identical to before the circuit was
// added.
func (c *Client) doAuthorize(ctx context.Context, cookie, verifier string, authQuery url.Values) (code, newCookie string, status int, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authURL+"?"+authQuery.Encode(), nil)
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Cookie", cookie)
	c.navHeaders(req) // iframe-style silent authorize
	resp, err := c.do(req)
	if err != nil {
		return "", "", 0, err
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
		return "", "", resp.StatusCode, busy
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
				return "", "", resp.StatusCode, provider.ErrSessionExpired
			}
			// An edge (WAF/challenge) interstitial. Typed as push-back so it feeds
			// the per-owner cooldown, the fleet breaker and the /status connector
			// state exactly like a 403-HTML would — an untyped error here degraded
			// to an unclassifiable transient that nothing counted, so a challenge
			// rollout was invisible until a user reported it.
			return "", "", resp.StatusCode, &provider.Unavailable{
				RetryAfter:  parseRetryAfter(resp),
				Status:      resp.StatusCode,
				Surface:     provider.SurfaceAuth,
				ContentType: safeExcerpt(resp.Header.Get("Content-Type")),
				Ref:         safeExcerpt(resp.Header.Get("X-Azure-Ref")),
			}
		}
		return "", "", resp.StatusCode, fmt.Errorf("orikan: silent-renew authorize: unexpected status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		// Not %w-wrapped: a *url.Error's message embeds the whole raw URL, query
		// and all, and a login-style bounce can carry a return URL or state there.
		return "", "", resp.StatusCode, fmt.Errorf("orikan: silent-renew: unparseable redirect (%d)", resp.StatusCode)
	}
	loc = req.URL.ResolveReference(loc) // a relative Location resolves against the authorize URL
	if code = loc.Query().Get("code"); code != "" {
		return code, newCookie, resp.StatusCode, nil
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
		return "", "", resp.StatusCode, provider.ErrSessionExpired
	}
	return "", "", resp.StatusCode, fmt.Errorf("orikan: silent-renew authorize: unexpected redirect (%d) to %s", resp.StatusCode, redirectTarget(loc.String()))
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
	resp, err := c.do(req)
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
