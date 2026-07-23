package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/store"
)

// newAuthzServer builds a Server in forward-auth mode (auth == nil), so a request
// can present its identity via the Remote-Email header the way Caddy injects it.
// council/sched/etc. are nil: every case below asserts a guard that returns
// before those are ever touched (401/403/redirect), or a store-only path.
func newAuthzServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "authz.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{
		cfg:   &config.Config{DisplayLocation: time.UTC},
		store: st,
		terms: loadTerms(""),
	}
}

// req builds a request through the real routed handler. email "" is
// unauthenticated; origin "" omits the Origin header (a cross-site POST forges no
// Origin, so this is the CSRF-fail case).
func (s *Server) doReq(method, target, email, origin string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, target, body)
	r.Host = "app.example.com"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if email != "" {
		r.Header.Set("Remote-Email", email)
		r.Header.Set("Remote-Groups", "user")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestAuthorizationMatrix drives the real router with injected identities to lock
// in access control at the HTTP boundary: authentication gates, the CSRF
// same-origin check on mutations, the owner-only (secondary → 403) boundary, and
// cross-owner IDOR. Nothing here should ever depend on handler discipline alone.
func TestAuthorizationMatrix(t *testing.T) {
	ctx := context.Background()
	s := newAuthzServer(t)
	const owner, secondary, other = "owner@example.com", "second@example.com", "other@example.com"
	const goodOrigin = "http://app.example.com"

	// Consent for everyone (so withConsent reaches the handler's own authz), a
	// shared-access membership (secondary → owner), and a vehicle owned by `owner`.
	for _, e := range []string{owner, secondary, other} {
		if err := s.store.RecordConsent(ctx, e, s.terms.Version, s.terms.Hash()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.AddMemberCapped(ctx, owner, secondary, 2); err != nil {
		t.Fatal(err)
	}
	vehID, err := s.store.CreateVehicle(ctx, owner, "OWN111", "Owner car")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unauthenticated read is rejected", func(t *testing.T) {
		w := s.doReq("GET", "/settings", "", "", nil)
		if w.Code == http.StatusOK {
			t.Fatalf("unauthenticated GET /settings = 200, want a rejection")
		}
	})

	t.Run("unauthenticated mutation is rejected", func(t *testing.T) {
		w := s.doReq("POST", "/vehicles", "", goodOrigin, url.Values{"registration": {"NEW111"}})
		if w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
			t.Fatalf("unauthenticated POST /vehicles = %d, want a rejection", w.Code)
		}
	})

	t.Run("cross-origin mutation is CSRF-rejected", func(t *testing.T) {
		// A state-changing POST with no matching Origin/Referer is refused.
		w := s.doReq("POST", "/vehicles", owner, "", url.Values{"registration": {"NEW222"}})
		if w.Code != http.StatusForbidden {
			t.Fatalf("no-origin POST = %d, want 403", w.Code)
		}
		w = s.doReq("POST", "/vehicles", owner, "http://evil.example.com", url.Values{"registration": {"NEW222"}})
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-origin POST = %d, want 403", w.Code)
		}
	})

	t.Run("same-origin mutation is allowed", func(t *testing.T) {
		w := s.doReq("POST", "/vehicles", owner, goodOrigin, url.Values{"registration": {"NEW333"}, "label": {"Second"}})
		if w.Code != http.StatusSeeOther {
			t.Fatalf("same-origin POST /vehicles = %d, want 303", w.Code)
		}
	})

	t.Run("secondary is blocked from owner-only actions", func(t *testing.T) {
		for _, path := range []string{"/council/link", "/account/members", "/account/members/remove", "/council/unlink", "/council/forget-password", "/account/delete"} {
			w := s.doReq("POST", path, secondary, goodOrigin, url.Values{"email": {other}, "confirm": {"DELETE"}})
			if w.Code != http.StatusForbidden {
				t.Fatalf("secondary POST %s = %d, want 403", path, w.Code)
			}
		}
	})

	t.Run("cross-owner IDOR cannot delete another account's vehicle", func(t *testing.T) {
		w := s.doReq("POST", "/vehicles/"+strconv.FormatInt(vehID, 10)+"/delete", other, goodOrigin, url.Values{})
		if w.Code == http.StatusInternalServerError {
			t.Fatalf("cross-owner delete errored: %d", w.Code)
		}
		// The owner's vehicle must survive an unrelated account's delete attempt.
		vs, err := s.store.ListVehiclesFor(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, v := range vs {
			if v.ID == vehID {
				found = true
			}
		}
		if !found {
			t.Fatal("owner's vehicle was deleted by another account (IDOR)")
		}
	})

	t.Run("admin route rejects a non-admin user", func(t *testing.T) {
		w := s.doReq("GET", "/admin", owner, goodOrigin, nil) // groups = "user" only
		if w.Code != http.StatusForbidden {
			t.Fatalf("non-admin GET /admin = %d, want 403", w.Code)
		}
	})
}

// TestCombineDateTime covers the one-off booking date+time recombination: an
// empty date is unset, and a date with no time falls back to the default (start
// of day for "from", end of day for "until").
func TestCombineDateTime(t *testing.T) {
	cases := []struct{ date, tm, def, want string }{
		{"", "", "00:00", ""},
		{"", "09:30", "00:00", ""}, // time with no date is unset
		{"2026-07-15", "09:30", "00:00", "2026-07-15T09:30"},
		{"2026-07-15", "", "00:00", "2026-07-15T00:00"},          // from: default start of day
		{"2026-07-16", "", "23:59", "2026-07-16T23:59"},          // until: default end of day
		{" 2026-07-15 ", " 09:30 ", "00:00", "2026-07-15T09:30"}, // trimmed
	}
	for _, c := range cases {
		if got := combineDateTime(c.date, c.tm, c.def); got != c.want {
			t.Fatalf("combineDateTime(%q,%q,%q) = %q, want %q", c.date, c.tm, c.def, got, c.want)
		}
	}
}

// TestGuestPageBoostReturnsFullPage locks in the fix for the hx-boost bug: a
// boosted link click (HX-Request + HX-Boosted) is a navigation and must get the
// whole page — not the #gbody fragment, which htmx would swap into <body>,
// dropping the card wrapper (and its padding). An in-page htmx swap (activation
// POST / poll — HX-Request without HX-Boosted) still gets just the fragment.
func TestGuestPageBoostReturnsFullPage(t *testing.T) {
	ctx := context.Background()
	s := newAuthzServer(t)
	const owner = "owner@example.com"
	pid, err := s.store.UpsertPermit(ctx, owner, "VPP1", "1", "VPP1")
	if err != nil {
		t.Fatal(err)
	}
	raw := "boost-test-guest-token-000111222333"
	if _, err := s.store.CreateQRGrant(ctx, owner, pid, hashGuestToken(raw), time.Hour); err != nil {
		t.Fatal(err)
	}

	get := func(headers map[string]string) string {
		r := httptest.NewRequest("GET", "/g/"+raw, nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w.Body.String()
	}

	if body := get(nil); !strings.Contains(body, "guestwrap") {
		t.Fatal("full page load must render the card wrapper")
	}
	if body := get(map[string]string{"HX-Request": "true", "HX-Boosted": "true"}); !strings.Contains(body, "guestwrap") {
		t.Fatal("a boosted navigation must return the full page, not the bare fragment")
	}
	if body := get(map[string]string{"HX-Request": "true"}); strings.Contains(body, "guestwrap") {
		t.Fatal("an in-page htmx swap should return just the #gbody fragment")
	}
}
