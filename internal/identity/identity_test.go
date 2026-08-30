package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// resolve runs the middleware and reports the identity it settled on.
func resolve(t *testing.T, devEmail string, decode Decoder, trustForwardAuth bool, prep func(*http.Request)) (User, bool) {
	t.Helper()
	var got User
	var ok bool
	h := Middleware(devEmail, decode, trustForwardAuth)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = FromContext(r.Context())
	}))
	r := httptest.NewRequest("GET", "/schedule", nil)
	if prep != nil {
		prep(r)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got, ok
}

// proxyPeer is what the far end of a container network looks like; publicPeer is a
// caller straight off the internet, which is the case that must be refused.
func proxyPeer(r *http.Request)  { r.RemoteAddr = "172.18.0.4:52000" }
func publicPeer(r *http.Request) { r.RemoteAddr = "203.0.113.9:52000" }

// TestForwardAuthPeerTrust is the regression test for the finding that mattered
// most here: the identity headers used to be believed from ANY peer, so an app
// whose port was published directly handed out any identity — including admin — to
// anyone willing to send two headers.
func TestForwardAuthPeerTrust(t *testing.T) {
	cases := []struct {
		name      string
		peer      func(*http.Request)
		wantEmail string
		wantAdmin bool
	}{
		{"proxy peer is trusted", proxyPeer, "user@example.com", true},
		{"public peer is refused", publicPeer, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, ok := resolve(t, "", nil, true, func(r *http.Request) {
				c.peer(r)
				r.Header.Set("Remote-Email", "user@example.com")
				r.Header.Set("Remote-Groups", "user,admin")
			})
			if u.Email != c.wantEmail {
				t.Errorf("email = %q, want %q", u.Email, c.wantEmail)
			}
			if ok != (c.wantEmail != "") {
				t.Errorf("authenticated = %v, want %v", ok, c.wantEmail != "")
			}
			if u.IsAdmin() != c.wantAdmin {
				t.Errorf("IsAdmin = %v, want %v", u.IsAdmin(), c.wantAdmin)
			}
		})
	}
}

func TestUnparseablePeerIsUntrusted(t *testing.T) {
	u, ok := resolve(t, "", nil, true, func(r *http.Request) {
		r.RemoteAddr = "not-an-address"
		r.Header.Set("Remote-Email", "user@example.com")
	})
	if ok || u.Email != "" {
		t.Fatalf("an unparseable peer must not be trusted, got %+v", u)
	}
}

// Loopback covers the host-network deployment, where the proxy shares the netns.
func TestLoopbackPeerIsTrusted(t *testing.T) {
	u, _ := resolve(t, "", nil, true, func(r *http.Request) {
		r.RemoteAddr = "127.0.0.1:9000"
		r.Header.Set("Remote-Email", "user@example.com")
	})
	if u.Email != "user@example.com" {
		t.Fatalf("loopback peer should be trusted, got %+v", u)
	}
}

// In OIDC mode the headers are ignored outright, so they cannot override a verified
// session cookie even when they arrive from the proxy itself.
func TestHeadersIgnoredWhenNotInForwardAuthMode(t *testing.T) {
	decode := func(http.ResponseWriter, *http.Request) (User, bool) {
		return User{Email: "cookie@example.com", Groups: []string{"user"}}, true
	}
	u, ok := resolve(t, "", decode, false, func(r *http.Request) {
		proxyPeer(r)
		r.Header.Set("Remote-Email", "header@example.com")
		r.Header.Set("Remote-Groups", "admin")
	})
	if !ok || u.Email != "cookie@example.com" {
		t.Fatalf("cookie identity must win, got %+v", u)
	}
	if u.IsAdmin() {
		t.Error("a Remote-Groups header must not confer admin in OIDC mode")
	}
}

func TestEmailIsNormalised(t *testing.T) {
	u, _ := resolve(t, "", nil, true, func(r *http.Request) {
		proxyPeer(r)
		r.Header.Set("Remote-Email", "  User@Example.COM  ")
	})
	if u.Email != "user@example.com" {
		t.Fatalf("email = %q, want it lowercased and trimmed", u.Email)
	}
}

// The header path takes precedence, but an EMPTY header must fall through to the
// cookie rather than resolving to an anonymous user.
func TestEmptyHeaderFallsThroughToCookie(t *testing.T) {
	decode := func(http.ResponseWriter, *http.Request) (User, bool) {
		return User{Email: "cookie@example.com"}, true
	}
	u, ok := resolve(t, "", decode, true, func(r *http.Request) {
		proxyPeer(r)
		r.Header.Set("Remote-Email", "   ")
	})
	if !ok || u.Email != "cookie@example.com" {
		t.Fatalf("want the cookie identity, got %+v", u)
	}
}

func TestDevIdentityIsLastResort(t *testing.T) {
	u, ok := resolve(t, "dev@example.com", nil, true, publicPeer)
	if !ok || u.Email != "dev@example.com" {
		t.Fatalf("want the dev identity, got %+v", u)
	}
	if !u.IsAdmin() {
		t.Error("the dev identity is documented as admin; config must keep it out of production")
	}
}

func TestSplitGroupsIgnoresBlanks(t *testing.T) {
	u, _ := resolve(t, "", nil, true, func(r *http.Request) {
		proxyPeer(r)
		r.Header.Set("Remote-Email", "u@example.com")
		r.Header.Set("Remote-Groups", " user , , admin ,")
	})
	want := []string{"user", "admin"}
	if len(u.Groups) != len(want) {
		t.Fatalf("groups = %v, want %v", u.Groups, want)
	}
	for i := range want {
		if u.Groups[i] != want[i] {
			t.Fatalf("groups = %v, want %v", u.Groups, want)
		}
	}
}

func TestFromContextRejectsEmptyEmail(t *testing.T) {
	if _, ok := resolve(t, "", nil, true, publicPeer); ok {
		t.Fatal("an anonymous request must report ok=false")
	}
}
