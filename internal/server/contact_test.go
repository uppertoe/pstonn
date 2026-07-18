package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSameOrigin(t *testing.T) {
	mk := func(method, host, origin, referer string) *http.Request {
		r := httptest.NewRequest(method, "https://p.stonn.org/permits/1/rules", nil)
		r.Host = host
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if referer != "" {
			r.Header.Set("Referer", referer)
		}
		return r
	}
	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"matching origin", mk("POST", "p.stonn.org", "https://p.stonn.org", ""), true},
		{"cross-site origin", mk("POST", "p.stonn.org", "https://evil.example", ""), false},
		{"referer fallback matches", mk("POST", "p.stonn.org", "", "https://p.stonn.org/schedule"), true},
		{"referer cross-site", mk("POST", "p.stonn.org", "", "https://evil.example/x"), false},
		{"no origin or referer rejected", mk("POST", "p.stonn.org", "", ""), false},
	}
	for _, c := range cases {
		if got := sameOrigin(c.r); got != c.want {
			t.Errorf("%s: sameOrigin = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestClientIPUsesRightmostXFF(t *testing.T) {
	r := httptest.NewRequest("POST", "/contact", nil)
	r.RemoteAddr = "10.0.0.1:5000"
	// Attacker prepends a spoofed value; Caddy appends the real peer on the right.
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.9")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want the rightmost trusted hop 203.0.113.9", got)
	}
}

func TestLooksLikeEmail(t *testing.T) {
	good := []string{"a@b.co", "user.name@example.com", "x+tag@sub.domain.io"}
	bad := []string{"", "nope", "a@b", "@b.com", "a@", "two@@x.com", "a b@c.com", "trailing@dot."}
	for _, s := range good {
		if !looksLikeEmail(s) {
			t.Errorf("looksLikeEmail(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if looksLikeEmail(s) {
			t.Errorf("looksLikeEmail(%q) = true, want false", s)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d for the same key should be allowed", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request within the window should be blocked")
	}
	// A different key is tracked independently.
	if !rl.allow("5.6.7.8") {
		t.Fatal("first request for a new key should be allowed")
	}
}

func TestRateLimiterWindowExpiry(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	if !rl.allow("k") {
		t.Fatal("first request should be allowed")
	}
	if rl.allow("k") {
		t.Fatal("second request within the window should be blocked")
	}
	// Backdate the recorded hit beyond the window; the next call should be allowed.
	rl.mu.Lock()
	rl.hits["k"] = []time.Time{time.Now().Add(-2 * time.Minute)}
	rl.mu.Unlock()
	if !rl.allow("k") {
		t.Fatal("request after the window has elapsed should be allowed")
	}
}
