package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/identity"
)

// identityMiddlewareFor wraps a handler in the same identity resolution the real
// router uses, so a test can exercise one wrapper without building the whole mux.
func identityMiddlewareFor(s *Server) func(http.Handler) http.Handler {
	return identity.Middleware(s.cfg.DevIdentityEmail, nil, s.auth == nil)
}

// Signed-in pages show household data — permits, plates, the activity log, who has
// access — and used to carry no cache directive at all, so a browser was free to
// keep them. On the shared family device this app is built for, that means signing
// out and pressing Back shows the previous person's dashboard.
func TestAuthenticatedPagesAreNotCacheable(t *testing.T) {
	s := newAuthzServer(t)
	for _, path := range []string{"/schedule", "/vehicles", "/activity", "/settings", "/guests"} {
		t.Run(path, func(t *testing.T) {
			w := s.doReq("GET", path, "user@example.com", "", nil)
			cc := w.Header().Get("Cache-Control")
			if !strings.Contains(cc, "no-store") {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
		})
	}
}

// The admin page is the densest collection of other people's data in the app. Tested
// through the wrapper rather than the page itself, because rendering /admin needs a
// live scheduler and the property under test belongs to requireAdmin.
func TestRequireAdminMarksResponsesUncacheable(t *testing.T) {
	s := newAuthzServer(t)
	var reached bool
	h := s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest("GET", "/admin", nil)
	r.RemoteAddr = "10.0.0.2:41000"
	r.Header.Set("Remote-Email", "admin@example.com")
	r.Header.Set("Remote-Groups", "user,admin")
	w := httptest.NewRecorder()
	identityMiddlewareFor(s)(h).ServeHTTP(w, r)

	if !reached {
		t.Fatalf("admin handler did not run (status %d)", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// Public marketing pages are the same for everyone, so they must NOT be swept up by
// the no-store rule — otherwise the fix costs every anonymous visitor a re-fetch.
func TestPublicPagesAreStillCacheable(t *testing.T) {
	s := newAuthzServer(t)
	for _, path := range []string{"/", "/about", "/why"} {
		w := s.doReq("GET", path, "", "", nil)
		if cc := w.Header().Get("Cache-Control"); strings.Contains(cc, "no-store") {
			t.Errorf("%s: public pages should not be marked no-store (got %q)", path, cc)
		}
	}
}

// Guarding the reason noStoreCache exists separately from the guest routes' noStore:
// that one also sets Referrer-Policy: no-referrer, which would strip the same-origin
// Referer that sameOrigin falls back on when a request carries no Origin. Fixing a
// caching bug must not quietly weaken the CSRF check.
func TestAuthenticatedPagesKeepSameOriginReferrerPolicy(t *testing.T) {
	s := newAuthzServer(t)
	w := s.doReq("GET", "/settings", "user@example.com", "", nil)
	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q, want same-origin so the CSRF Referer fallback still works", got)
	}
}

// The fallback itself: a mutation carrying only a same-origin Referer must pass, and
// one carrying neither header must not.
func TestCSRFRefererFallback(t *testing.T) {
	s := newAuthzServer(t)

	withReferer := func(ref string) int {
		r := httptest.NewRequest("POST", "/terms/accept", strings.NewReader(""))
		r.Host = "app.example.com"
		r.RemoteAddr = "10.0.0.2:41000"
		r.Header.Set("Remote-Email", "user@example.com")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if ref != "" {
			r.Header.Set("Referer", ref)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Code
	}

	if code := withReferer("https://app.example.com/settings"); code == http.StatusForbidden {
		t.Error("a same-origin Referer should satisfy the CSRF check")
	}
	if code := withReferer(""); code != http.StatusForbidden {
		t.Errorf("no Origin and no Referer = %d, want 403", code)
	}
	if code := withReferer("https://evil.example.com/"); code != http.StatusForbidden {
		t.Errorf("a cross-origin Referer = %d, want 403", code)
	}
}
