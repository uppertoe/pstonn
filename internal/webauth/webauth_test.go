package webauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"golang.org/x/oauth2"

	"github.com/uppertoe/pstonn/internal/store"
)

// testAuthenticator builds an Authenticator without OIDC discovery. Login and the
// state check below never reach the provider, so a hand-built oauth2.Config is
// enough to exercise them.
func testAuthenticator(t *testing.T) (*Authenticator, *store.Store) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "webauth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &Authenticator{
		oauth: oauth2.Config{
			ClientID: "pstonn",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://idp.example.com/authorize",
				TokenURL: "https://idp.example.com/token",
			},
			RedirectURL: "https://p.stonn.example/auth/callback",
			Scopes:      []string{"openid", "email"},
		},
		store:        st,
		adminGroups:  map[string]bool{"pstonn-admin": true},
		cookieSecure: true,
	}, st
}

// startLogin runs Login and returns the issued state plus the state cookie.
func startLogin(t *testing.T, a *Authenticator) (state string, cookie *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	a.Login(w, httptest.NewRequest("GET", "/auth/login", nil))
	res := w.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("Login status = %d, want 302", res.StatusCode)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state = loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in the authorization redirect")
	}
	for _, c := range res.Cookies() {
		// A secure authenticator issues the state cookie under the __Host- name.
		if c.Name == hostStateCookie {
			cookie = c
		}
	}
	return state, cookie
}

func TestLoginBindsStateToTheBrowser(t *testing.T) {
	a, _ := testAuthenticator(t)
	state, cookie := startLogin(t, a)
	if cookie == nil {
		t.Fatal("Login must set the state cookie; without it nothing ties the flow to this browser")
	}
	if cookie.Value != state {
		t.Errorf("cookie value = %q, want the issued state %q", cookie.Value, state)
	}
	if !cookie.HttpOnly {
		t.Error("state cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Error("state cookie must be Secure when COOKIE_SECURE is on")
	}
	// Strict would withhold the cookie on the cross-site navigation back from the
	// identity provider and break every login.
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("state cookie SameSite = %v, want Lax", cookie.SameSite)
	}
}

func TestLoginSendsPKCEChallenge(t *testing.T) {
	a, _ := testAuthenticator(t)
	w := httptest.NewRecorder()
	a.Login(w, httptest.NewRequest("GET", "/auth/login", nil))
	loc, err := url.Parse(w.Result().Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	q := loc.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("expected an S256 PKCE challenge, got %v", q)
	}
	if q.Get("nonce") == "" {
		t.Error("expected a nonce so the ID token can be bound to this request")
	}
}

// This is the regression test for the login-CSRF finding. An attacker starts a
// login, authenticates as themselves, and hands the victim the resulting callback
// URL. The victim's browser has no matching state cookie, so the callback must be
// refused before the code is ever exchanged — otherwise the victim ends up signed
// in as the attacker and types their tenant password into the attacker's account.
func TestCallbackRefusesStateFromAnotherBrowser(t *testing.T) {
	a, st := testAuthenticator(t)
	attackerState, _ := startLogin(t, a)

	// The victim's browser: the attacker's state, but none of the attacker's cookies.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback?code=attacker-code&state="+url.QueryEscape(attackerState), nil)
	a.Callback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want 400", w.Code)
	}
	// The stored state must survive: rejecting must happen before it is consumed, so a
	// forced callback cannot also burn the victim's own pending login.
	if _, err := st.TakeOAuthState(r.Context(), attackerState); err != nil {
		t.Errorf("stored state was consumed by a rejected callback: %v", err)
	}
}

func TestCallbackRefusesMismatchedCookie(t *testing.T) {
	a, _ := testAuthenticator(t)
	state, _ := startLogin(t, a)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback?code=c&state="+url.QueryEscape(state), nil)
	r.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "some-other-flow"})
	a.Callback(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want 400 for a cookie that names a different flow", w.Code)
	}
}

func TestCallbackRefusesMissingState(t *testing.T) {
	a, _ := testAuthenticator(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback?code=c", nil)
	r.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "anything"})
	a.Callback(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("callback status = %d, want 400 when the state param is absent", w.Code)
	}
}

// A provider-reported error must be surfaced without touching the stored state.
func TestCallbackReportsProviderError(t *testing.T) {
	a, _ := testAuthenticator(t)
	w := httptest.NewRecorder()
	a.Callback(w, httptest.NewRequest("GET", "/auth/callback?error=access_denied", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestStateMatchesBrowser(t *testing.T) {
	a, _ := testAuthenticator(t)
	cases := []struct {
		name   string
		state  string
		cookie string
		set    bool
		want   bool
	}{
		{"match", "abc", "abc", true, true},
		{"mismatch", "abc", "xyz", true, false},
		{"no cookie", "abc", "", false, false},
		{"empty cookie", "abc", "", true, false},
		{"empty state", "", "abc", true, false},
		{"both empty", "", "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/auth/callback", nil)
			if c.set {
				r.AddCookie(&http.Cookie{Name: hostStateCookie, Value: c.cookie})
			}
			if got := a.stateMatchesBrowser(r, c.state); got != c.want {
				t.Errorf("stateMatchesBrowser = %v, want %v", got, c.want)
			}
		})
	}
}

// A secure authenticator reads ONLY the __Host- state cookie. The plain name is
// what a sibling subdomain can plant to seed a login-CSRF, and the fallback that
// once read it (for logins started before the rename) has nothing left to serve.
func TestStateMatchesBrowserIgnoresUnprefixedCookieWhenSecure(t *testing.T) {
	a, _ := testAuthenticator(t)
	r := httptest.NewRequest("GET", "/auth/callback", nil)
	r.AddCookie(&http.Cookie{Name: stateCookie, Value: "abc"})
	if a.stateMatchesBrowser(r, "abc") {
		t.Fatal("a matching state under the plain cookie name must not satisfy a secure authenticator")
	}
	// Over plain HTTP (local dev) the plain name IS the issued name and still works.
	a.cookieSecure = false
	if !a.stateMatchesBrowser(r, "abc") {
		t.Fatal("an insecure (dev) authenticator must still read the plain name it issues")
	}
}

func TestClearStateCookie(t *testing.T) {
	a, _ := testAuthenticator(t)
	w := httptest.NewRecorder()
	a.clearStateCookie(w)
	cookies := w.Result().Cookies()
	// Clears the __Host- name at / AND the legacy plain name at its old /auth/ path, so a
	// login started before the rename is still cleared on completion.
	if len(cookies) != 2 {
		t.Fatalf("expected the state cookie cleared under both names, got %+v", cookies)
	}
	var sawHost, sawLegacyAuthPath bool
	for _, c := range cookies {
		if c.MaxAge >= 0 || c.Value != "" {
			t.Fatalf("Clear must send immediately-expiring empty cookies, got %+v", c)
		}
		if c.Name == hostStateCookie && c.Path == "/" {
			sawHost = true
		}
		if c.Name == stateCookie && c.Path == "/auth/" {
			sawLegacyAuthPath = true
		}
	}
	if !sawHost || !sawLegacyAuthPath {
		t.Fatalf("clearStateCookie must expire __Host-@/ and legacy@/auth/, got %+v", cookies)
	}
}

func TestDeriveGroups(t *testing.T) {
	a, _ := testAuthenticator(t)
	cases := []struct {
		name      string
		in        []string
		wantAdmin bool
	}{
		{"no groups", nil, false},
		{"unrelated groups", []string{"staff", "everyone"}, false},
		{"admin group", []string{"staff", "pstonn-admin"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := a.deriveGroups(c.in)
			if len(got) == 0 || got[0] != "user" {
				t.Fatalf("every signed-in user should get the user group, got %v", got)
			}
			var admin bool
			for _, g := range got {
				if g == "admin" {
					admin = true
				}
			}
			if admin != c.wantAdmin {
				t.Errorf("admin = %v, want %v (groups %v)", admin, c.wantAdmin, got)
			}
		})
	}
}

func TestLowerAndFirstNonEmpty(t *testing.T) {
	if got := lower("User@Example.COM"); got != "user@example.com" {
		t.Errorf("lower = %q", got)
	}
	if got := firstNonEmpty("", "", "third"); got != "third" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("firstNonEmpty() = %q, want empty", got)
	}
}
