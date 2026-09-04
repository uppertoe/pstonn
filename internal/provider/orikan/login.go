package orikan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

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
	alog.Errorf("sign-in page not usable: %v", err)
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
				alog.Errorf("SECURITY: %v", err)
				return err
			}
			// A right-host redirect can still be a scheme DOWNGRADE (https→http on the
			// same host), which the host check above cannot see. Refuse it.
			if !redirectSchemeOK(req.URL.Scheme, wantScheme) {
				err := fmt.Errorf("%w: refused a %q redirect on a %q sign-in flow (host %q)",
					provider.ErrLoginOffHost, safeExcerpt(req.URL.Scheme), wantScheme, safeExcerpt(req.URL.Host))
				alog.Errorf("SECURITY: %v", err)
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
