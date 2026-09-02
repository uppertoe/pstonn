package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/identity"
)

// identityMiddlewareFor wraps a handler in the same identity resolution the real
// router uses, so a test can exercise one wrapper without building the whole mux.
func identityMiddlewareFor(s *Server) func(http.Handler) http.Handler {
	return identity.Middleware(s.cfg.DevIdentityEmail, nil, s.auth == nil, s.cfg.ProxySecret)
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
	// The ACTUAL public routes (server.go): "/about" and "/why" 404, and a 404's empty
	// Cache-Control trivially satisfies the no-store check for reasons unrelated to
	// caching — so the guard has to hit real 200 pages, or it would stay green even if
	// one of them were later wrapped in noStoreCache (the regression it exists to catch).
	for _, path := range []string{"/", "/security", "/how"} {
		w := s.doReq("GET", path, "", "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: want 200 (a public page), got %d — the guard is testing the wrong route", path, w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); strings.Contains(cc, "no-store") {
			t.Errorf("%s: public pages should not be marked no-store (got %q)", path, cc)
		}
	}
}

// Guarding the reason noStoreCache exists separately from the guest routes' noStore:
// that one also sets Referrer-Policy: no-referrer, which would strip the same-origin
// Referer that sameOrigin falls back on when a request carries no Origin. Fixing a
// caching bug must not quietly weaken the CSRF check.
//
// The two signed-in pages that embed a guest token (the on-screen visitor QR and
// the printable door poster) once reached for the guest helper because of the
// token, and so shipped no-referrer to app pages; they are on the list so that
// cannot come back. Each sets its headers before any check that could 4xx, so
// the status is not asserted — only the policy that reached the wire.
func TestAuthenticatedPagesKeepSameOriginReferrerPolicy(t *testing.T) {
	s := newAuthzServer(t)
	const user = "user@example.com"
	const origin = "https://app.example.com"
	if err := s.store.RecordConsent(context.Background(), user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	permitID, grantID, _ := seedDoorQR(t, s, user, "Door")
	cases := []struct {
		name, method, path string
		form               url.Values
	}{
		{"settings", "GET", "/settings", nil},
		{"door poster", "GET", "/guests/door/" + itoa64(grantID) + "/view", nil},
		{"visitor QR", "POST", "/guests/qr", url.Values{"permit_id": {itoa64(permitID)}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := s.doReq(c.method, c.path, user, origin, c.form)
			if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
				t.Fatalf("Referrer-Policy = %q, want same-origin so the CSRF Referer fallback still works", got)
			}
		})
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
