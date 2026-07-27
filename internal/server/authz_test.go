package server

import (
	"bytes"
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
	"github.com/uppertoe/pstonn/internal/secretbox"
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
	// A real at-rest cipher: the printed-QR routes seal their token before any
	// ownership check, so a nil box would panic instead of exercising the guard.
	box, err := secretbox.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("secretbox: %v", err)
	}
	return &Server{
		cfg:   &config.Config{DisplayLocation: time.UTC},
		store: st,
		box:   box,
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

	// Every id-bearing route, driven through the router by an unrelated account.
	// The store layer is unit-tested for owner scoping, but nothing previously
	// asserted it end-to-end — and these are the routes where a future refactor
	// could quietly drop the handler's ownership check.
	t.Run("cross-owner IDOR is refused on every id-bearing route", func(t *testing.T) {
		permitID, err := s.store.UpsertPermit(ctx, owner, "VPP-IDOR", "1", "Owner permit")
		if err != nil {
			t.Fatal(err)
		}
		pid := strconv.FormatInt(permitID, 10)
		end := time.Now().Add(2 * time.Hour)
		ovID, err := s.store.CreateOverride(ctx, permitID, vehID, time.Now(), &end, owner)
		if err != nil {
			t.Fatal(err)
		}
		grantID, err := s.store.CreateGuestGrant(ctx, owner, permitID, "Nanny", false,
			[]int64{vehID}, []store.GuestRecipient{{Email: "guest@example.com", TokenHash: hashGuestToken("idor-token-aaaabbbbccccdddd")}})
		if err != nil {
			t.Fatal(err)
		}
		gid := strconv.FormatInt(grantID, 10)

		// The permit-card fragment must not disclose another account's permit.
		// (Pages that go through appShell need a live council client, so they are
		// covered by the store-level owner scoping instead of here.)
		if w := s.doReq("GET", "/permits/"+pid+"/card", other, goodOrigin, nil); w.Code == http.StatusOK &&
			strings.Contains(w.Body.String(), "Owner permit") {
			t.Fatal("GET /permits/{id}/card leaked the owner's permit to another account")
		}

		// Mutations must not touch it. A refusal may be 403/404/303 depending on the
		// route's style; what matters is that the object is unchanged afterwards.
		mutations := []struct {
			path string
			form url.Values
		}{
			{"/permits/" + pid + "/name", url.Values{"label": {"HIJACKED"}}},
			{"/permits/" + pid + "/delete", url.Values{}},
			{"/permits/" + pid + "/rules", url.Values{"weekday": {"1"}, "vehicle_id": {strconv.FormatInt(vehID, 10)}}},
			{"/permits/" + pid + "/override", url.Values{"vehicle_id": {strconv.FormatInt(vehID, 10)}, "from_date": {"2030-01-01"}, "until_date": {"2030-01-02"}}},
			{"/permits/" + pid + "/overrides/" + strconv.FormatInt(ovID, 10) + "/delete", url.Values{}},
			{"/permits/" + pid + "/copy-schedule", url.Values{"source": {pid}}},
			{"/guests/" + gid, url.Values{"label": {"HIJACKED"}, "vehicle_id": {strconv.FormatInt(vehID, 10)}}},
			{"/guests/" + gid + "/delete", url.Values{}},
			{"/guests/qr", url.Values{"permit_id": {pid}}},
			{"/guests/printed", url.Values{"permit_id": {pid}}},
			{"/vehicles/" + strconv.FormatInt(vehID, 10) + "/email", url.Values{"email": {"attacker@example.com"}}},
		}
		for _, m := range mutations {
			if w := s.doReq("POST", m.path, other, goodOrigin, m.form); w.Code == http.StatusInternalServerError {
				t.Fatalf("POST %s by a stranger returned 500 (want a clean refusal)", m.path)
			}
		}

		// Nothing was renamed, deleted, or re-pointed.
		p, err := s.store.GetPermit(ctx, permitID)
		if err != nil {
			t.Fatalf("owner's permit was deleted by a stranger: %v", err)
		}
		if p.Label != "Owner permit" || p.Owner != owner {
			t.Fatalf("owner's permit was mutated by a stranger: %+v", p)
		}
		grants, err := s.store.ListGuestGrants(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		if len(grants) != 1 || grants[0].Grant.Label != "Nanny" {
			t.Fatalf("owner's grant was mutated or deleted by a stranger: %+v", grants)
		}
		vs, err := s.store.ListVehiclesFor(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vs {
			if v.ID == vehID && v.Email != "" {
				t.Fatalf("a stranger set a driver email on the owner's vehicle: %q", v.Email)
			}
		}
		// And the owner's own rules/overrides were not added to by the stranger.
		if rules, err := s.store.ListRules(ctx, permitID); err == nil && len(rules) > 0 {
			t.Fatalf("a stranger created a weekly rule on the owner's permit: %+v", rules)
		}
	})

	// The consent gate is an invariant asserted all over the app ("nothing happens
	// before the terms are accepted"), so it needs a test at the boundary — this is
	// the gap that let GET /permits/{id}/card slip through on withUser.
	t.Run("consent gate blocks a user who has not accepted the terms", func(t *testing.T) {
		const fresh = "noconsent@example.com"
		permitID, err := s.store.UpsertPermit(ctx, fresh, "VPP-NC", "1", "Fresh permit")
		if err != nil {
			t.Fatal(err)
		}
		pid := strconv.FormatInt(permitID, 10)
		for _, tc := range []struct{ method, path string }{
			{"GET", "/permits/" + pid + "/card"},
			{"POST", "/vehicles"},
			{"POST", "/guests/qr"},
		} {
			w := s.doReq(tc.method, tc.path, fresh, goodOrigin, url.Values{"registration": {"NEW999"}, "permit_id": {pid}})
			// withConsent redirects a non-consented user home (where the gate renders);
			// what must never happen is the action going through.
			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Fresh permit") {
				t.Fatalf("%s %s served app content before consent", tc.method, tc.path)
			}
		}
		if vs, err := s.store.ListVehiclesFor(ctx, fresh); err == nil && len(vs) > 0 {
			t.Fatalf("a vehicle was created before the terms were accepted: %+v", vs)
		}
	})

	// A primary has nothing to leave; the inverse gate must hold (the secondary
	// case is exercised by the onboarding escape hatch).
	t.Run("primary cannot leave their own account", func(t *testing.T) {
		w := s.doReq("POST", "/account/leave", owner, goodOrigin, url.Values{})
		if w.Code == http.StatusSeeOther {
			t.Fatal("primary POST /account/leave succeeded, want a refusal")
		}
	})
}

// TestGuestTokenAuthz covers the token roles: an unknown or revoked token gets the
// same neutral answer as a valid-but-dead one, a request-only (printed door QR)
// token cannot activate or revert, and a door-QR page discloses none of the
// account's identifying details.
func TestGuestTokenAuthz(t *testing.T) {
	ctx := context.Background()
	s := newAuthzServer(t)
	const owner = "owner@example.com"
	permitID, err := s.store.UpsertPermit(ctx, owner, "VPP-TOK", "1", "12 Smith St front")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetPermitActive(ctx, permitID, "SECRET1"); err != nil {
		t.Fatal(err)
	}
	doorRaw := "door-token-aaaabbbbccccddddeeeeffff"
	if _, err := s.store.CreatePrintedGrant(ctx, owner, permitID, hashGuestToken(doorRaw), ""); err != nil {
		t.Fatal(err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "app.example.com"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}

	t.Run("unknown token is refused", func(t *testing.T) {
		for _, path := range []string{"/g/definitely-not-a-real-token", "/g/live/definitely-not-a-real-token"} {
			if w := get(path); w.Code == http.StatusOK {
				t.Fatalf("GET %s = 200, want a refusal", path)
			}
		}
	})

	t.Run("door QR discloses no owner email, plate, or label", func(t *testing.T) {
		body := get("/g/" + doorRaw).Body.String()
		for _, secret := range []string{owner, "SECRET1", "12 Smith St front"} {
			if strings.Contains(body, secret) {
				t.Fatalf("public door-QR page disclosed %q", secret)
			}
		}
	})

	t.Run("request-only token cannot revert or poll live", func(t *testing.T) {
		if w := get("/g/live/" + doorRaw); w.Code == http.StatusOK {
			t.Fatalf("GET /g/live for a door token = 200, want a refusal")
		}
		r := httptest.NewRequest("POST", "/g/"+doorRaw+"/revert", strings.NewReader(""))
		r.Host = "app.example.com"
		r.Header.Set("Origin", "http://app.example.com")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "back on the permit") {
			t.Fatal("a door-QR token performed a revert")
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
