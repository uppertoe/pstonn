package parking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// tokenResponse is the subset of the /connect/token response we use. No
// refresh_token is ever present (the client lacks offline_access).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// silentRenew performs a prompt=none Authorization-Code + PKCE flow using the
// stored session cookie, returning a fresh access token, its expiry, and the
// (possibly rotated) cookie header. It returns ErrSessionExpired when the cookie
// is no longer accepted (login_required), which signals the user must re-link.
func (c *Client) silentRenew(ctx context.Context, cookie string) (string, time.Time, string, error) {
	verifier, err := randToken()
	if err != nil {
		return "", time.Time{}, "", err
	}
	authQuery, err := c.authorizeQuery(verifier)
	if err != nil {
		return "", time.Time{}, "", err
	}
	authQuery.Set("prompt", "none")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authURL+"?"+authQuery.Encode(), nil)
	if err != nil {
		return "", time.Time{}, "", err
	}
	req.Header.Set("Cookie", cookie)
	c.navHeaders(req) // iframe-style silent authorize
	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, "", err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	newCookie := mergeSetCookie(cookie, resp.Cookies())

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		return "", time.Time{}, "", fmt.Errorf("parking: silent-renew authorize: unexpected status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("parking: silent-renew: bad redirect: %w", err)
	}
	if loc.Query().Get("error") != "" {
		return "", time.Time{}, "", ErrSessionExpired // login_required / interaction_required
	}
	code := loc.Query().Get("code")
	if code == "" {
		return "", time.Time{}, "", ErrSessionExpired
	}

	tok, err := c.exchangeCode(ctx, code, verifier)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second), newCookie, nil
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("parking: token endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("parking: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("parking: token response had no access_token")
	}
	return &tok, nil
}

// Link performs a headless login with the app user's council credentials,
// obtains and stores their (sealed) session cookie, and discards the password.
// It is the per-user onboarding step; the credentials are used only here.
//
// NOTE: this replays the SPA's own login form. It is not yet validated against
// the live site from a server IP (see the Akamai spike in docs/CAPTURE.md); the
// form-field harvesting is deliberately lenient in case the page shifts.
// interactive=true is a user-initiated link/re-link that advances the
// re-authorise clock (linked_at); a non-interactive call (auto-reconnect) keeps
// the clock anchored to the last real interactive link, so the periodic
// "confirm you're still using this" bound still fires.
func (c *Client) Link(ctx context.Context, owner, username, password string, savePassword, interactive bool) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	// A dedicated client that follows redirects and keeps a jar for this one
	// login flow (c.http handles redirects manually and shares no cookies). The
	// browser transport presents a real Chrome UA and client hints throughout.
	lc := &http.Client{Timeout: 30 * time.Second, Jar: jar, Transport: browserTransport{base: http.DefaultTransport}}

	verifier, err := randToken()
	if err != nil {
		return err
	}
	authQuery, err := c.authorizeQuery(verifier)
	if err != nil {
		return err
	}

	// 1. Authorize → redirects to the login page (sets the antiforgery cookie).
	//    A top-level, user-initiated navigation.
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.authURL+"?"+authQuery.Encode(), nil)
	if err != nil {
		return err
	}
	c.navHeaders(getReq)
	getReq.Header.Set("Sec-Fetch-Dest", "document")
	getReq.Header.Set("Sec-Fetch-Site", "none")
	getReq.Header.Set("Sec-Fetch-User", "?1")
	getReq.Header.Del("Referer")
	resp, err := lc.Do(getReq)
	if err != nil {
		return err
	}
	loginPage, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil {
		return err
	}
	loginURL := resp.Request.URL // final URL after redirects = the login form

	// 2. Harvest the form (antiforgery token + all hidden fields); set creds.
	action, fields := parseLoginForm(string(loginPage))
	if _, ok := fields["__RequestVerificationToken"]; !ok {
		return errors.New("parking: login form missing antiforgery token (page shape changed?)")
	}
	fields["Username"] = username
	fields["Password"] = password
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}
	actionURL, err := resolveAction(loginURL, action)
	if err != nil {
		return err
	}

	// 3. POST credentials; follow the redirect chain (ends at the SPA callback,
	//    which is static HTML) so the jar collects the session cookies. A form
	//    submission navigation from the login page.
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, actionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
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
		return err
	}
	io.Copy(io.Discard, presp.Body)
	presp.Body.Close()

	// 4. Extract the council session cookie (scoped to /idm) from the jar.
	authURLParsed, err := url.Parse(c.authURL)
	if err != nil {
		return err
	}
	cookie := jarCookieHeader(jar, authURLParsed)
	if !strings.Contains(cookie, "Permits.IDM.Identity") {
		return ErrLoginRejected
	}

	// 5. Seal and store the session cookie. The password is sealed and kept only
	//    if the user opted in to auto-reconnect; otherwise it is dropped here and
	//    password_sealed is written empty (clearing any previously saved value).
	sealed, err := c.box.Seal(cookie)
	if err != nil {
		return err
	}
	var sealedPass string
	if savePassword {
		if sealedPass, err = c.box.Seal(password); err != nil {
			return err
		}
	}
	cs := store.CouncilSession{Owner: owner, Cookie: sealed, Password: sealedPass}
	if interactive {
		return c.store.SaveCouncilSession(ctx, cs) // stamps linked_at = now
	}
	return c.store.SaveReconnectedSession(ctx, cs) // preserves linked_at
}

// Reconnect re-establishes an expired session non-interactively using the sealed
// password the user opted to save. It replays the same headless login as Link,
// re-saving the (still opted-in) password. Returns ErrNoSavedPassword when the
// user has not saved one, in which case the caller must fall back to prompting
// for a manual re-link.
func (c *Client) Reconnect(ctx context.Context, owner string) error {
	cs, err := c.store.GetCouncilSession(ctx, owner)
	if err != nil {
		return err
	}
	if cs.Password == "" {
		return ErrNoSavedPassword
	}
	password, err := c.box.Open(cs.Password)
	if err != nil {
		return err
	}
	// The council username is pinned to the owner's verified email at link time,
	// so the owner doubles as the username here. interactive=false keeps the saved
	// password and does NOT advance the re-authorise clock.
	return c.Link(ctx, owner, owner, password, true, false)
}

var (
	reInputTag = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reNameAttr = regexp.MustCompile(`(?is)\bname="([^"]*)"`)
	reValAttr  = regexp.MustCompile(`(?is)\bvalue="([^"]*)"`)
	reFormAct  = regexp.MustCompile(`(?is)<form\b[^>]*\baction="([^"]*)"`)
)

// parseLoginForm extracts the form action and all <input> name/value pairs from
// the login page (values HTML-unescaped). It is intentionally lenient, a regex
// over a stable server-rendered ASP.NET form rather than a full HTML parse.
func parseLoginForm(page string) (action string, fields map[string]string) {
	fields = map[string]string{}
	if m := reFormAct.FindStringSubmatch(page); m != nil {
		action = html.UnescapeString(m[1])
	}
	for _, tag := range reInputTag.FindAllString(page, -1) {
		nm := reNameAttr.FindStringSubmatch(tag)
		if nm == nil || nm[1] == "" {
			continue
		}
		val := ""
		if vm := reValAttr.FindStringSubmatch(tag); vm != nil {
			val = html.UnescapeString(vm[1])
		}
		fields[nm[1]] = val
	}
	return action, fields
}

// resolveAction resolves a possibly-relative form action against the login page
// URL, returning an absolute URL string.
func resolveAction(base *url.URL, action string) (string, error) {
	if action == "" {
		return base.String(), nil
	}
	ref, err := url.Parse(action)
	if err != nil {
		return "", fmt.Errorf("parking: bad form action %q: %w", action, err)
	}
	return base.ResolveReference(ref).String(), nil
}

// jarCookieHeader serialises the cookies the jar would send to u.
func jarCookieHeader(jar http.CookieJar, u *url.URL) string {
	var parts []string
	for _, ck := range jar.Cookies(u) {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

// mergeSetCookie applies Set-Cookie values from a response onto an existing
// Cookie header, preserving order and returning the updated header. Used to
// carry forward a rotated session cookie after silent-renew.
func mergeSetCookie(existing string, set []*http.Cookie) string {
	if len(set) == 0 {
		return existing
	}
	var order []string
	vals := map[string]string{}
	for _, kv := range strings.Split(existing, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, val := kv, ""
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name, val = kv[:i], kv[i+1:]
		}
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = val
	}
	for _, ck := range set {
		if _, seen := vals[ck.Name]; !seen {
			order = append(order, ck.Name)
		}
		vals[ck.Name] = ck.Value
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		parts = append(parts, name+"="+vals[name])
	}
	return strings.Join(parts, "; ")
}
