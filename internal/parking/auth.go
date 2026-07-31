package parking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/secretbox"
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
// is no longer accepted (login_required), which signals the user must re-link,
// and ErrCouncilBusy (recording a per-owner penalty) when the IDM endpoint
// itself pushes back — the /idm path is the most bot-sensitive surface, so it
// gets the same backoff discipline as the permit API.
func (c *Client) silentRenew(ctx context.Context, owner, cookie string) (string, time.Time, string, error) {
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
	// Keep a bounded prefix of the body: it is the only way to tell an
	// IdentityServer page from any other 200, and the classification below turns
	// on that. Bounded because the rest of the body is of no interest and a
	// hostile or broken portal must not be able to make us read without limit.
	head, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	drainClose(resp)

	newCookie := mergeSetCookie(cookie, resp.Cookies())

	if busy := c.classifyPushback(owner, resp); busy != nil {
		return "", time.Time{}, "", busy
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		// A prompt=none authorize has exactly two honest answers, and both are
		// redirects: one carrying a code, one carrying an error. An HTML page in
		// their place means IdentityServer decided to show something to a HUMAN —
		// the sign-in form, a consent screen, a JS-driven bounce — and it only does
		// that when the session cookie is no longer accepted. Read as "transient"
		// (the old behaviour) it was the worst of both worlds: recoverOrRetire never
		// fired, so the session was never retired, no re-link was ever prompted, and
		// the user was told "trouble reaching the council" indefinitely while their
		// permit sat on the wrong plate.
		//
		// The test is deliberately narrow. Push-back (429/403/503) has already been
		// classified as busy above, a transport error returned earlier, and a 5xx or
		// any other status still falls through to the unexpected-status error below —
		// so a genuine transient is never mistaken for an expiry, which would retire
		// a session that was actually fine.
		if resp.StatusCode == http.StatusOK && looksLikeHTML(resp, head) {
			return "", time.Time{}, "", ErrSessionExpired
		}
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

	tok, err := c.exchangeCode(ctx, owner, code, verifier)
	if err != nil {
		return "", time.Time{}, "", err
	}
	return tok.AccessToken, time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second), newCookie, nil
}

// looksLikeHTML reports whether a response is a rendered page rather than the
// machine answer its endpoint is supposed to give. The declared Content-Type is
// the primary signal; the body prefix is a fallback because a portal behind a WAF
// does not reliably label its interstitials, and mislabelling one as JSON would
// hide exactly the case this exists to catch.
func looksLikeHTML(resp *http.Response, head []byte) bool {
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}
	s := strings.ToLower(strings.TrimSpace(string(head)))
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html")
}

// classifyPushback records a per-owner penalty and returns ErrCouncilBusy when
// the response is Akamai/rate-limit push-back (429/403/503); nil otherwise.
func (c *Client) classifyPushback(owner string, resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusForbidden, http.StatusServiceUnavailable:
		c.penalize(owner, parseRetryAfter(resp))
		return fmt.Errorf("%w: council returned %d", ErrCouncilBusy, resp.StatusCode)
	}
	return nil
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
func (c *Client) exchangeCode(ctx context.Context, owner, code, verifier string) (*tokenResponse, error) {
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
	if busy := c.classifyPushback(owner, resp); busy != nil {
		return nil, busy
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("parking: token endpoint status %d: %s", resp.StatusCode, safeExcerpt(string(body)))
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
// NOTE: this replays the SPA's own login form. The form-field harvesting is
// deliberately lenient about PRESENTATION (quoting style, attribute spacing) and
// deliberately strict about SUBSTANCE: where the credentials would go, and whether
// the page is the sign-in form at all. The IDM endpoints are the most bot-sensitive
// surface, so this path shares the per-owner backoff cooldown (classifyPushback /
// cooldownFor).
// interactive=true is a user-initiated link/re-link that advances the
// re-authorise clock (linked_at); a non-interactive call (auto-reconnect) keeps
// the clock anchored to the last real interactive link, so the periodic
// "confirm you're still using this" bound still fires.
func (c *Client) Link(ctx context.Context, owner, username, password string, savePassword, interactive bool) error {
	if c.sandbox != nil {
		return c.sandboxLink(ctx, owner, username) // any credentials link in sandbox mode
	}
	// Honour an existing push-back cooldown: retrying the login while Akamai is
	// already refusing this owner is how a soft block escalates to a hard one.
	if d, blocked := c.cooldownFor(owner); blocked {
		return fmt.Errorf("%w (retry in %s)", ErrCouncilBusy, d.Round(time.Second))
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	// Pin the whole flow to the council's own hosts before it starts. This is the
	// one request in the app that carries a user's plaintext third-party password,
	// so where it goes must be decided by operator configuration and nothing else.
	// An unconfigured client has no host to pin to, and posting a password to an
	// unpinned target is not a thing to do on a best effort.
	hosts := c.loginHosts()
	if len(hosts) == 0 {
		return c.linkShapeErr(fmt.Errorf("%w: no council host is configured, so there is nothing to pin the credential POST to", ErrLoginOffHost))
	}
	// A dedicated client that follows redirects and keeps a jar for this one
	// login flow (c.http handles redirects manually and shares no cookies). The
	// browser transport presents a real Chrome UA and client hints throughout.
	// Count this client's traffic too. It was previously uncounted, which left the
	// hourly traffic summary's "login" bucket permanently at zero and understated
	// every link/reconnect by its 4–6 round trips — an undercount we would not
	// want to be quoting to the council.
	lc := &http.Client{Timeout: 30 * time.Second, Jar: jar,
		Transport: browserTransport{base: http.DefaultTransport, traffic: &c.traffic},
		// Refuse to be walked off the council's hosts. The credential POST target is
		// resolved against the URL this redirect chain ENDS at, so an open redirect
		// on the portal would otherwise be enough to move that base off-host and take
		// the password with it — no HTML injection needed. Checking here also stops
		// the session cookies the jar collects from being handed to a third party.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !hosts[strings.ToLower(req.URL.Host)] {
				err := fmt.Errorf("%w: refused to follow the council login off-host to %q", ErrLoginOffHost, safeExcerpt(req.URL.Host))
				// Logged at the moment of refusal, not just where the error surfaces:
				// this is the signal that something is redirecting a credential flow
				// away from the council, and the operator must see it even if the
				// caller only reports "couldn't link your account" to the user.
				log.Printf("parking: SECURITY: %v", err)
				return err
			}
			// Setting CheckRedirect replaces Go's own 10-hop cap, so re-impose one: a
			// portal redirect loop would otherwise spin until the 30s client timeout.
			if len(via) >= 10 {
				return errors.New("parking: council login: stopped after 10 redirects")
			}
			return nil
		},
	}

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
	if busy := c.classifyPushback(owner, resp); busy != nil {
		return busy
	}
	loginURL := resp.Request.URL // final URL after redirects = the login form

	// 2. Harvest the form and settle BOTH questions — is this the sign-in form, and
	//    where would submitting it send the password — before the password is put
	//    into anything. If either answer is wrong, nothing was ever assembled.
	action, fields := parseLoginForm(string(loginPage))
	if err := checkLoginForm(fields); err != nil {
		return c.linkShapeErr(err)
	}
	actionURL, err := resolveAction(loginURL, action, hosts)
	if err != nil {
		return c.linkShapeErr(err)
	}
	fields[fieldUsername] = username
	fields[fieldPassword] = password
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
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
		// A CheckRedirect refusal arrives here wrapped in a *url.Error. Returning it
		// unclassified is the safe landing: every caller's fallback treats an
		// unrecognised error as transient, so nothing is unlinked and no user is told
		// their password is wrong. The refusal itself was already logged.
		return err
	}
	drainClose(presp)
	if busy := c.classifyPushback(owner, presp); busy != nil {
		return busy
	}

	// 4. Extract the council session cookie (scoped to /idm) from the jar.
	authURLParsed, err := url.Parse(c.authURL)
	if err != nil {
		return err
	}
	cookie := jarCookieHeader(jar, authURLParsed)
	if !hasCookieNamed(cookie, councilSessionCookie) {
		return ErrLoginRejected
	}

	// 5. Seal and store the session cookie. The password is sealed and kept only
	//    if the user opted in to auto-reconnect; otherwise it is dropped here and
	//    password_sealed is written empty (clearing any previously saved value).
	sealed, err := c.box.SealCtx(secretbox.CouncilCookie(owner), cookie)
	if err != nil {
		return err
	}
	var sealedPass string
	if savePassword {
		if sealedPass, err = c.box.SealCtx(secretbox.CouncilPassword(owner), password); err != nil {
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
	if c.sandbox != nil {
		return nil // sandbox sessions never expire, so there is nothing to re-establish
	}
	cs, err := c.store.GetCouncilSession(ctx, owner)
	if err != nil {
		return err
	}
	if cs.Password == "" {
		return ErrNoSavedPassword
	}
	password, legacy, err := c.box.OpenCtx(secretbox.CouncilPassword(owner), cs.Password)
	if legacy {
		// An unbound legacy ciphertext. It opens, and the re-login below re-seals it
		// bound, so this heals itself on the very next reconnect.
		log.Printf("parking: saved password for %s is an unbound legacy ciphertext; re-sealing on this reconnect", owner)
	}
	if err != nil {
		// A decrypt failure (e.g. DATA_ENCRYPTION_KEY rotated) is deterministic:
		// retrying it every scheduler pass never heals and never tells the user.
		// Map it to ErrNoSavedPassword so the retire-and-notify path fires and the
		// dashboard prompts a manual re-link — the same mapping openCookie applies
		// to the identical failure on the session cookie.
		log.Printf("parking: unseal saved password for %s failed (%v); treating as no saved password (manual re-link required)", owner, err)
		return ErrNoSavedPassword
	}
	// The council username is pinned to the owner's verified email at link time,
	// so the owner doubles as the username here. interactive=false keeps the saved
	// password and does NOT advance the re-authorise clock.
	return c.Link(ctx, owner, owner, password, true, false)
}

// The council's page double-quotes its attribute values today, but quoting style
// is cosmetic: a template tidy-up, a minifier, or a framework upgrade can switch
// to single quotes or drop the quotes entirely without changing the page's
// meaning. Matching only double quotes made such a change indistinguishable from
// a wrong password — every login would have failed as ErrLoginRejected, telling
// users their password was wrong, burning their attempt throttle, and driving
// recoverOrRetire to delete every saved session across the fleet. All three
// styles are therefore accepted.
//
// The attribute patterns require WHITESPACE before the attribute name rather than
// a word boundary, so `data-name=` can no longer be mistaken for `name=` and
// hijack a field (a `\b` matches after the hyphen).
var (
	reInputTag = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	reFormTag  = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	reNameAttr = regexp.MustCompile("(?is)\\sname\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'`=<>]+))")
	reValAttr  = regexp.MustCompile("(?is)\\svalue\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'`=<>]+))")
	reActAttr  = regexp.MustCompile("(?is)\\saction\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'`=<>]+))")
)

// The field names the council's sign-in form uses. Hardcoding them is fine —
// they are what a captured, server-accepted POST contained. Proceeding when they
// are ABSENT is not, which is what checkLoginForm is for.
const (
	fieldUsername    = "Username"
	fieldPassword    = "Password"
	fieldAntiforgery = "__RequestVerificationToken"
)

// parseLoginForm extracts the form action and all <input> name/value pairs from
// the login page (values HTML-unescaped). It is intentionally lenient, a regex
// over a stable server-rendered ASP.NET form rather than a full HTML parse; what
// it harvests is then checked by checkLoginForm before anything is submitted.
func parseLoginForm(page string) (action string, fields map[string]string) {
	fields = map[string]string{}
	for _, tag := range reFormTag.FindAllString(page, -1) {
		if v, ok := attrValue(reActAttr, tag); ok {
			action = html.UnescapeString(v)
			break
		}
	}
	for _, tag := range reInputTag.FindAllString(page, -1) {
		nm, ok := attrValue(reNameAttr, tag)
		if !ok || nm == "" {
			continue
		}
		val := ""
		if v, ok := attrValue(reValAttr, tag); ok {
			val = html.UnescapeString(v)
		}
		fields[nm] = val
	}
	return action, fields
}

// attrValue returns an attribute's value and whether the attribute was PRESENT.
// Presence is read from the submatch index rather than from the returned string,
// because value="" is a present-but-empty attribute and the antiforgery check
// turns on exactly that distinction.
func attrValue(re *regexp.Regexp, tag string) (string, bool) {
	loc := re.FindStringSubmatchIndex(tag)
	if loc == nil {
		return "", false
	}
	// Exactly one of the three quoting alternatives participates in a match; the
	// others report -1. A participating group of zero length is a real empty value.
	for g := 1; 2*g+1 < len(loc); g++ {
		if loc[2*g] >= 0 {
			return tag[loc[2*g]:loc[2*g+1]], true
		}
	}
	return "", true
}

// checkLoginForm rejects a harvested form that is not the credential form this
// client knows how to submit, so an unrecognised page shape fails as a page-shape
// problem instead of being submitted blind and coming back as "your password is
// wrong".
func checkLoginForm(fields map[string]string) error {
	// An antiforgery token that is present but EMPTY is as useless as one that is
	// absent: ASP.NET refuses the POST either way. The old presence-only check let
	// that case through, which meant the password was sent and the refusal was then
	// reported to the user as a bad password.
	if tok, ok := fields[fieldAntiforgery]; !ok || tok == "" {
		return fmt.Errorf("%w: no usable %s on the page (present=%v, empty=%v)",
			ErrLoginFormUnrecognised, fieldAntiforgery, ok, tok == "")
	}
	// The credential inputs are filled in by name, so a rename would have us POST
	// the password under a name the server ignores. Their absence is the earliest
	// and clearest evidence that this is not the form we think it is.
	for _, f := range []string{fieldUsername, fieldPassword} {
		if _, ok := fields[f]; !ok {
			return fmt.Errorf("%w: the page has no %q input, so it is not the sign-in form", ErrLoginFormUnrecognised, f)
		}
	}
	return nil
}

// linkShapeErr classifies a login page this client cannot safely submit, and is
// deliberately NOT ErrLoginRejected.
//
// ErrLoginRejected means "the credentials are wrong". Using it for a page-shape
// problem tells every affected user their password is wrong, spends one of their
// five throttled attempts, and makes the scheduler's recoverOrRetire delete their
// saved session — so one cosmetic change to the council's HTML would produce a
// fleet-wide unlink blamed on users. FailUnexpected is the classification that
// means "the council changed something and this client needs updating", and every
// caller's fallback for it is safe: the link handler says the problem is at our
// end rather than the password, and recoverOrRetire treats it as transient,
// keeping both the session and the saved password for a later pass. The log line
// is what the operator acts on.
func (c *Client) linkShapeErr(err error) error {
	log.Printf("parking: council login page not usable: %v", err)
	return councilErr(FailUnexpected, opLogin, err)
}

// loginHosts is the set of hosts the login flow may talk to, taken ENTIRELY from
// the council configuration: the issuer the sign-in form lives on, the token
// endpoint, the portal origin, and the SPA callback the credential POST chain
// lands on. Nothing scraped from the page contributes to it, which is the whole
// point — the page is what we are guarding against.
func (c *Client) loginHosts() map[string]bool {
	hosts := map[string]bool{}
	for _, raw := range []string{c.authURL, c.loginURL, c.tokenURL, c.origin, c.redirectURI} {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			hosts[strings.ToLower(u.Host)] = true
		}
	}
	return hosts
}

// resolveAction resolves a possibly-relative form action against the login page
// URL and returns an absolute URL string — but only if it stays on a configured
// council host and keeps the login page's scheme.
//
// This is the check that stops a plaintext password leaving the server. The login
// HTML is scraped, so its action attribute is portal-controlled: HTML injection
// on the council's sign-in page (or a stored XSS there) could set an absolute
// action and have this client POST fields["Password"] straight to a third party,
// while the user saw nothing but an ordinary failed login. The scheme is held
// constant for the same reason — an https page pointing its form at http:// would
// put the password on the wire in clear without changing host at all.
//
// The base URL is checked too, not just the resolved one: with a relative action
// the base IS the target, and it is the end of a redirect chain.
func resolveAction(base *url.URL, action string, allowed map[string]bool) (string, error) {
	if !allowed[strings.ToLower(base.Host)] {
		return "", fmt.Errorf("%w: the council sign-in page was served from %q, which is not a configured council host",
			ErrLoginOffHost, safeExcerpt(base.Host))
	}
	if action == "" {
		return base.String(), nil
	}
	ref, err := url.Parse(action)
	if err != nil {
		return "", fmt.Errorf("%w: unparseable form action %q: %v", ErrLoginFormUnrecognised, safeExcerpt(action), err)
	}
	u := base.ResolveReference(ref)
	if !allowed[strings.ToLower(u.Host)] {
		return "", fmt.Errorf("%w: the sign-in page asked us to post credentials to %q, which is not a configured council host (action %q)",
			ErrLoginOffHost, safeExcerpt(u.Host), safeExcerpt(action))
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) {
		return "", fmt.Errorf("%w: the sign-in page asked us to post credentials over %q from a %q page (action %q)",
			ErrLoginOffHost, safeExcerpt(u.Scheme), base.Scheme, safeExcerpt(action))
	}
	return u.String(), nil
}

// councilSessionCookie is the IdentityServer session cookie whose presence means
// a headless login actually established a session.
const councilSessionCookie = "Permits.IDM.Identity"

// hasCookieNamed reports whether a serialised Cookie header carries a cookie with
// exactly this name and a non-empty value.
//
// A substring test matched the PREFIXED siblings the IDM also sets on the way
// through a login — .External, .Nonce, .Antiforgery — so a login that FAILED but
// left one of those in the jar reported success: a useless cookie was sealed and
// the user's council password stored for a session that did not exist. The value
// must be non-empty too, since a name with no value is a cookie the server is
// clearing, not a session.
func hasCookieNamed(header, name string) bool {
	for _, kv := range strings.Split(header, ";") {
		n, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		if n == name && v != "" {
			return true
		}
	}
	return false
}

// maxPortalExcerpt bounds how much portal-controlled text may appear in an error
// string. The bound is about the log as much as the message: these errors reach
// log.Printf, and without it a broken portal writes up to the full megabyte we
// are willing to read into the journal on every attempt.
const maxPortalExcerpt = 200

// safeExcerpt renders portal-controlled text for an error message: control
// characters replaced with spaces, then truncated. Newlines are the reason this
// exists — an error string carrying one into log.Printf lets whoever controls the
// portal forge log lines, so a hostile response could bury its own traces under
// plausible-looking entries.
func safeExcerpt(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxPortalExcerpt {
		// Truncating by bytes can cut a rune in half; dropping the invalid tail keeps
		// the message printable.
		s = strings.ToValidUTF8(s[:maxPortalExcerpt], "") + "…(truncated)"
	}
	return s
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
		// A deletion (Max-Age<=0 or an Expires in the past) means the server wants
		// the cookie GONE; keeping "name=" would re-send a credential the IDM
		// meant to clear.
		if ck.MaxAge < 0 || (!ck.Expires.IsZero() && ck.Expires.Before(time.Now())) {
			delete(vals, ck.Name)
			continue
		}
		if _, seen := vals[ck.Name]; !seen {
			order = append(order, ck.Name)
		}
		vals[ck.Name] = ck.Value
	}
	parts := make([]string, 0, len(order))
	for _, name := range order {
		if v, ok := vals[name]; ok {
			parts = append(parts, name+"="+v)
		}
	}
	return strings.Join(parts, "; ")
}
