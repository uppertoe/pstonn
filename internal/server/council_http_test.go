package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/council"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// The council-touching handlers — link, the permit picker, adding a permit,
// clearing a plate — driven over HTTP against the REAL generic council client
// running on the fake provider. Until the provider split these handlers had never
// been exercised end to end (the server held a concrete client nobody could
// stand in for). Sealing, session persistence, capability gating and the typed
// error vocabulary are all on the path here, not stubbed.

type councilRig struct {
	s    *Server
	st   *store.Store
	fake *fake.Provider
	ctx  context.Context
}

func newCouncilRig(t *testing.T) *councilRig {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secretbox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := fake.New()
	f.ApplyDelay = 0
	f.RejectPassword = "wrong"
	reg, err := council.Load(config.CouncilConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultCouncil = reg.Default.ID
	client := parking.NewClientFor(reg.Default.ID, f, st, box, nil)
	mux := council.NewMux(st, map[string]*parking.Client{reg.Default.ID: client})
	sched := scheduler.New(st, mux, time.UTC, scheduler.Options{})
	s := &Server{
		cfg:      &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store:    st,
		box:      box,
		terms:    loadTerms(""),
		council:  mux,
		councils: reg,
		sched:    sched,
	}
	return &councilRig{s: s, st: st, fake: f, ctx: context.Background()}
}

const rigUser = "lily@example.com"

// consent accepts the terms for the user, the gate every council route sits behind.
func (r *councilRig) consent(t *testing.T, email string) {
	t.Helper()
	if err := r.st.RecordConsent(r.ctx, email, r.s.terms.Version, r.s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
}

func (r *councilRig) link(t *testing.T, email string) {
	t.Helper()
	if err := r.s.council.Link(r.ctx, email, email, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
}

func (r *councilRig) post(path string, email string, form url.Values) *httptest.ResponseRecorder {
	return r.s.doReq(http.MethodPost, path, email, "https://app.example.com", form)
}

func (r *councilRig) get(path string, email string) *httptest.ResponseRecorder {
	return r.s.doReq(http.MethodGet, path, email, "", nil)
}

func TestCouncilLinkOverHTTP(t *testing.T) {
	r := newCouncilRig(t)
	r.consent(t, rigUser)

	t.Run("wrong password lands on the guidance, stores nothing", func(t *testing.T) {
		rr := r.post("/council/link", rigUser, url.Values{"council_password": {"wrong"}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?link=rejected" {
			t.Fatalf("code=%d location=%q", rr.Code, rr.Header().Get("Location"))
		}
		if r.s.council.Linked(r.ctx, rigUser) {
			t.Fatal("a rejected password left a session behind")
		}
	})
	t.Run("portal push-back is not blamed on the password", func(t *testing.T) {
		r.fake.LoginErr = &provider.Unavailable{Status: 503, Surface: provider.SurfaceLogin}
		defer func() { r.fake.LoginErr = nil }()
		r.consent(t, "busy@example.com")
		rr := r.post("/council/link", "busy@example.com", url.Values{"council_password": {"ok"}})
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "Your password was not the problem") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
	})
	t.Run("empty password is refused before any login", func(t *testing.T) {
		rr := r.post("/council/link", rigUser, url.Values{})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code=%d", rr.Code)
		}
	})
	t.Run("good password links, saves the opted-in password, lands on the picker", func(t *testing.T) {
		rr := r.post("/council/link", rigUser, url.Values{"council_password": {"ok"}, "save_password": {"1"}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?linked=1" {
			t.Fatalf("code=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), excerpt(rr.Body.String()))
		}
		cs, err := r.st.GetCouncilSession(r.ctx, rigUser)
		if err != nil || cs.Cookie == "" || cs.Password == "" {
			t.Fatalf("session/password not stored: %+v %v", cs, err)
		}
		if cs.CouncilEmail != rigUser {
			t.Fatalf("council username %q, want the verified email (the pin)", cs.CouncilEmail)
		}
		// The landing page after ?linked=1 is the picker with the account's permits.
		page := r.get("/schedule?linked=1", rigUser)
		if page.Code != 200 || !strings.Contains(page.Body.String(), "VPP-SANDBOX") || !strings.Contains(page.Body.String(), "Council account linked.") {
			t.Fatalf("picker after link: code=%d body=%s", page.Code, excerpt(page.Body.String()))
		}
	})
}

func TestPickerOverHTTP(t *testing.T) {
	r := newCouncilRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)

	t.Run("visitor permits are offered, a resident permit is not", func(t *testing.T) {
		r.fake.Extra = []provider.Permit{{CouncilPermitID: "77", PermitTypeID: "1", PermitNumber: "RPP77", PermitType: "(A) 1st Resident Permit", Status: "Granted", CanChangeVehicle: true}}
		defer func() { r.fake.Extra = nil }()
		body := r.get("/schedule", rigUser).Body.String()
		for _, want := range []string{`name="council_permit_id" value="90001"`, `name="council_permit_id" value="90002"`, "RPP77", "Only visitor permits can be scheduled."} {
			if !strings.Contains(body, want) {
				t.Errorf("picker missing %q:\n%s", want, excerpt(body))
			}
		}
		if strings.Contains(body, `name="council_permit_id" value="77"`) {
			t.Error("the resident permit was offered for adding")
		}
	})
	t.Run("a partial list is said out loud", func(t *testing.T) {
		r.fake.Partial = true
		defer func() { r.fake.Partial = false }()
		body := r.get("/schedule", rigUser).Body.String()
		if !strings.Contains(body, "We could only load part of your permit list") {
			t.Fatalf("partial list not disclosed:\n%s", excerpt(body))
		}
	})
	t.Run("an expired session routes to re-link, not a dead end", func(t *testing.T) {
		r.fake.ListErr = provider.ErrSessionExpired
		defer func() { r.fake.ListErr = nil }()
		body := r.get("/schedule", rigUser).Body.String()
		if !strings.Contains(body, "Reconnect your council account") {
			t.Fatalf("expired session did not prompt a re-link:\n%s", excerpt(body))
		}
	})
}

func TestAddPermitOverHTTP(t *testing.T) {
	r := newCouncilRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	add := func(id string) *httptest.ResponseRecorder {
		return r.post("/permits", rigUser, url.Values{"council_permit_id": {id}, "label": {"Visitor"}})
	}

	t.Run("a visitor permit is adopted from the council record", func(t *testing.T) {
		rr := add("90001")
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?added=1" {
			t.Fatalf("code=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), excerpt(rr.Body.String()))
		}
		ps, _ := r.st.ListPermitsFor(r.ctx, rigUser)
		if len(ps) != 1 || ps[0].CouncilPermitID != "90001" || ps[0].PermitTypeID != "14" || ps[0].ActiveRegistration != "SBX1AB" || ps[0].PermitNumber != "VPP-SANDBOX" {
			t.Fatalf("stored permit = %+v", ps)
		}
	})
	t.Run("a resident permit is refused by the authoritative gate", func(t *testing.T) {
		r.fake.Extra = []provider.Permit{{CouncilPermitID: "77", PermitTypeID: "1", PermitNumber: "RPP77", PermitType: "(A) 1st Resident Permit", Status: "Granted", CanChangeVehicle: true}}
		defer func() { r.fake.Extra = nil }()
		rr := add("77")
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "only manages visitor permits") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
	})
	t.Run("a forged id the account does not hold is refused", func(t *testing.T) {
		if rr := add("424242"); rr.Code != http.StatusForbidden {
			t.Fatalf("code=%d", rr.Code)
		}
	})
	t.Run("absence from a partial list proves nothing", func(t *testing.T) {
		r.fake.Partial = true
		defer func() { r.fake.Partial = false }()
		rr := add("424242")
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "only load part of your permit list") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
	})
	t.Run("a permit another account manages cannot be taken over", func(t *testing.T) {
		if _, err := r.st.UpsertPermit(r.ctx, "other@example.com", "90002", "15", "Theirs"); err != nil {
			t.Fatal(err)
		}
		rr := add("90002")
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "another p.stonn account") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
	})
	t.Run("an expired session says so instead of denying ownership", func(t *testing.T) {
		r.fake.ListErr = provider.ErrSessionExpired
		defer func() { r.fake.ListErr = nil }()
		rr := add("90001")
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "re-link") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
	})
}

func TestClearPermitOverHTTP(t *testing.T) {
	r := newCouncilRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	if rr := r.post("/permits", rigUser, url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, _ := r.st.ListPermitsFor(r.ctx, rigUser)
	pid := ps[0].ID
	path := "/permits/" + strconv.FormatInt(pid, 10) + "/clear"

	t.Run("a scheduled permit cannot be emptied", func(t *testing.T) {
		vid, err := r.st.CreateVehicle(r.ctx, rigUser, "ABC123", "Van")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.st.SetRule(r.ctx, pid, time.Now().UTC().Weekday(), vid); err != nil {
			t.Fatal(err)
		}
		rr := r.post(path, rigUser, nil)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "has a car scheduled right now") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
		if reg, _ := r.fake.Current("90001"); reg != "SBX1AB" {
			t.Fatalf("the council record was changed anyway: %q", reg)
		}
		// Drop the rule for the next case.
		rules, _ := r.st.ListRules(r.ctx, pid)
		for _, ru := range rules {
			_ = r.st.ClearRule(r.ctx, pid, ru.Weekday)
		}
	})
	t.Run("an unscheduled permit is emptied at the council and locally", func(t *testing.T) {
		rr := r.post(path, rigUser, nil)
		// A plain (non-htmx) form post lands back on the schedule.
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
		if reg, _ := r.fake.Current("90001"); reg != "" {
			t.Fatalf("council record still shows %q", reg)
		}
		p, _ := r.st.GetPermit(r.ctx, pid)
		if p.ActiveRegistration != "" {
			t.Fatalf("local plate still %q", p.ActiveRegistration)
		}
	})
}

func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

// Two enabled councils: the sign-up form asks which, the choice is recorded before
// the login, and the session and permits are filed under it — a write from that
// account reaches that council's portal and no other.
func TestTwoCouncilsOverHTTP(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "two.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secretbox.New(bytes.Repeat([]byte{3}, 32))
	regPath := filepath.Join(t.TempDir(), "councils.json")
	if err := os.WriteFile(regPath, []byte(`{"councils":[
	  {"id":"stonnington","name":"City of Stonnington","short":"Stonnington","connector":"fake","timezone":"Australia/Melbourne","policy":{"visitor_word":"visitor","resident_word":"resident"},"enabled":true},
	  {"id":"othertown","name":"Othertown Council","short":"Othertown","connector":"fake","timezone":"Australia/Perth","policy":{"visitor_word":"visitor"},"enabled":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := council.Load(config.CouncilConfig{}, regPath)
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultCouncil = reg.Default.ID
	fakes := map[string]*fake.Provider{}
	clients := map[string]*parking.Client{}
	for _, c := range reg.Enabled() {
		f := fake.New()
		f.ApplyDelay = 0
		fakes[c.ID] = f
		clients[c.ID] = parking.NewClientFor(c.ID, f, st, box, nil)
	}
	mux := council.NewMux(st, clients)
	s := &Server{
		cfg:   &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store: st, box: box, terms: loadTerms(""), council: mux, councils: reg,
		sched: scheduler.New(st, mux, time.UTC, scheduler.Options{}),
	}
	ctx := context.Background()
	const user = "perth@example.com"
	if err := st.RecordConsent(ctx, user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	// The onboarding page asks which council.
	page := s.doReq(http.MethodGet, "/schedule", user, "", nil).Body.String()
	if !strings.Contains(page, `name="council_id"`) || !strings.Contains(page, "Othertown Council") {
		t.Fatalf("no council choice offered:\n%s", excerpt(page))
	}
	// Linking without a choice is refused; with one, recorded.
	if rr := s.doReq(http.MethodPost, "/council/link", user, "https://app.example.com", url.Values{"council_password": {"ok"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("link without a council: code=%d", rr.Code)
	}
	rr := s.doReq(http.MethodPost, "/council/link", user, "https://app.example.com", url.Values{"council_password": {"ok"}, "council_id": {"othertown"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("link: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if cs, _ := st.GetCouncilSession(ctx, user); cs.CouncilID != "othertown" {
		t.Fatalf("session filed under %q", cs.CouncilID)
	}
	if rr := s.doReq(http.MethodPost, "/permits", user, "https://app.example.com", url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, _ := st.ListPermitsFor(ctx, user)
	if len(ps) != 1 || ps[0].CouncilID != "othertown" {
		t.Fatalf("permit filed under %+v", ps)
	}
	// A clear from this account reaches Othertown's portal, not Stonnington's.
	if rr := s.doReq(http.MethodPost, "/permits/"+strconv.FormatInt(ps[0].ID, 10)+"/clear", user, "https://app.example.com", nil); rr.Code != http.StatusSeeOther {
		t.Fatalf("clear: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if reg, _ := fakes["othertown"].Current("90001"); reg != "" {
		t.Fatalf("othertown still shows %q", reg)
	}
	if reg, _ := fakes["stonnington"].Current("90001"); reg == "" {
		t.Fatal("the clear reached the wrong council's portal")
	}
	// And the account cannot be re-pointed at the other council while linked.
	if rr := s.doReq(http.MethodPost, "/council/link", user, "https://app.example.com", url.Values{"council_password": {"ok"}, "council_id": {"stonnington"}}); rr.Code != http.StatusConflict {
		t.Fatalf("re-point while linked: code=%d", rr.Code)
	}
}
