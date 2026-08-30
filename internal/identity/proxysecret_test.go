package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// resolveWith runs one request through the middleware and reports the resolved
// email ("" = no identity).
func resolveWith(t *testing.T, secretCfg, secretHdr, peer string) string {
	t.Helper()
	var got string
	h := Middleware("", nil, true, secretCfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := FromContext(r.Context()); ok {
			got = u.Email
		}
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = peer
	r.Header.Set("Remote-Email", "person@example.com")
	if secretHdr != "" {
		r.Header.Set("X-Proxy-Secret", secretHdr)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

// The shared secret is defence in depth on top of the private-peer test: with a
// secret configured, a private peer alone is no longer enough — the exact
// "compromised container on the same private network" scenario.
func TestProxySecretGatesIdentityHeaders(t *testing.T) {
	const secret = "s3cr3t-s3cr3t-s3cr3t"
	cases := []struct {
		name                 string
		cfg, hdr, peer, want string
	}{
		{"no secret configured: peer test stands alone", "", "", "10.0.0.2:1234", "person@example.com"},
		{"secret configured and presented", secret, secret, "10.0.0.2:1234", "person@example.com"},
		{"secret configured, absent: private peer refused", secret, "", "10.0.0.2:1234", ""},
		{"secret configured, wrong: refused", secret, "wrong", "10.0.0.2:1234", ""},
		{"right secret from a PUBLIC peer is still refused", secret, secret, "203.0.113.9:1234", ""},
		{"no secret, public peer refused (unchanged)", "", "", "203.0.113.9:1234", ""},
	}
	for _, c := range cases {
		if got := resolveWith(t, c.cfg, c.hdr, c.peer); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
