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
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// The tenant-touching handlers — link, the permit picker, adding a permit,
// clearing a plate — driven over HTTP against the REAL generic tenant client
// running on the fake provider. Until the provider split these handlers had never
// been exercised end to end (the server held a concrete client nobody could
// stand in for). Sealing, session persistence, capability gating and the typed
// error vocabulary are all on the path here, not stubbed.

type tenantRig struct {
	s    *Server
	st   *store.Store
	fake *fake.Provider
	ctx  context.Context
}

func newTenantRig(t *testing.T) *tenantRig {
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
	reg, err := tenant.Load(config.CouncilConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultTenant = reg.Default.ID
	client := parking.NewClientFor(reg.Default.ID, f, st, box, nil)
	mux := tenant.NewMux(st, map[string]*parking.Client{reg.Default.ID: client})
	sched := scheduler.New(st, mux, time.UTC, scheduler.Options{})
	s := &Server{
		cfg:      &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store:    st,
		box:      box,
		terms:    loadTerms(""),
		tenant:   mux,
		registry: reg,
		sched:    sched,
	}
	return &tenantRig{s: s, st: st, fake: f, ctx: context.Background()}
}

const rigUser = "primary@example.com"

// consent accepts the terms for the user, the gate every tenant route sits behind.
func (r *tenantRig) consent(t *testing.T, email string) {
	t.Helper()
	if err := r.st.RecordConsent(r.ctx, email, r.s.terms.Version, r.s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
}

func (r *tenantRig) link(t *testing.T, email string) {
	t.Helper()
	if err := r.s.tenant.Link(r.ctx, email, "", email, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
}

func (r *tenantRig) post(path string, email string, form url.Values) *httptest.ResponseRecorder {
	return r.s.doReq(http.MethodPost, path, email, "https://app.example.com", form)
}

func (r *tenantRig) get(path string, email string) *httptest.ResponseRecorder {
	return r.s.doReq(http.MethodGet, path, email, "", nil)
}

func TestTenantLinkOverHTTP(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)

	t.Run("wrong password lands on the guidance, stores nothing", func(t *testing.T) {
		rr := r.post("/tenant/link", rigUser, url.Values{"portal_password": {"wrong"}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?link=rejected" {
			t.Fatalf("code=%d location=%q", rr.Code, rr.Header().Get("Location"))
		}
		if r.s.tenant.Linked(r.ctx, rigUser, "") {
			t.Fatal("a rejected password left a session behind")
		}
	})
	t.Run("portal push-back is not blamed on the password", func(t *testing.T) {
		r.fake.LoginErr = &provider.Unavailable{Status: 503, Surface: provider.SurfaceLogin}
		defer func() { r.fake.LoginErr = nil }()
		r.consent(t, "busy@example.com")
		rr := r.post("/tenant/link", "busy@example.com", url.Values{"portal_password": {"ok"}})
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "Your password was not the problem") {
			t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
		}
	})
	t.Run("empty password is refused before any login", func(t *testing.T) {
		rr := r.post("/tenant/link", rigUser, url.Values{})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("code=%d", rr.Code)
		}
	})
	t.Run("good password links, saves the opted-in password, lands on the picker", func(t *testing.T) {
		rr := r.post("/tenant/link", rigUser, url.Values{"portal_password": {"ok"}, "save_password": {"1"}})
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?linked=1" {
			t.Fatalf("code=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), excerpt(rr.Body.String()))
		}
		cs, err := r.st.GetTenantSession(r.ctx, rigUser)
		if err != nil || cs.Cookie == "" || cs.Password == "" {
			t.Fatalf("session/password not stored: %+v %v", cs, err)
		}
		if cs.TenantEmail != rigUser {
			t.Fatalf("council username %q, want the verified email (the pin)", cs.TenantEmail)
		}
		// The landing page after ?linked=1 is the picker with the account's permits.
		page := r.get("/schedule?linked=1", rigUser)
		if page.Code != 200 || !strings.Contains(page.Body.String(), "VPP-SANDBOX") || !strings.Contains(page.Body.String(), "Council account linked.") {
			t.Fatalf("picker after link: code=%d body=%s", page.Code, excerpt(page.Body.String()))
		}
	})
}

func TestPickerOverHTTP(t *testing.T) {
	r := newTenantRig(t)
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
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	add := func(id string) *httptest.ResponseRecorder {
		return r.post("/permits", rigUser, url.Values{"council_permit_id": {id}, "label": {"Visitor"}})
	}

	t.Run("a visitor permit is adopted from the council record", func(t *testing.T) {
		rr := add("90001")
		// The fake portal offers a second visitor permit (90002) still unmanaged, so
		// the landing carries the set-up-another nudge (see TestAddPermitNudges...).
		if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?added=1&more=1" {
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
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	if rr := r.post("/permits", rigUser, url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, _ := r.st.ListPermitsFor(r.ctx, rigUser)
	pid := ps[0].ID
	path := "/permits/" + strconv.FormatInt(pid, 10) + "/clear"

	t.Run("a scheduled permit cannot be emptied", func(t *testing.T) {
		vid, err := r.st.CreateVehicle(r.ctx, rigUser, "ABC123", "Van", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.st.SetRule(r.ctx, pid, 0, time.Now().In(tenant.Stonnington().Location()).Weekday(), vid); err != nil {
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
			_ = r.st.ClearRule(r.ctx, pid, 0, ru.Weekday)
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

// Two enabled registry: the sign-up form asks which, the choice is recorded before
// the login, and the session and permits are filed under it — a write from that
// account reaches that tenant's portal and no other.
func TestTwoTenantsOverHTTP(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "two.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secretbox.New(bytes.Repeat([]byte{3}, 32))
	regPath := filepath.Join(t.TempDir(), "councils.json")
	if err := os.WriteFile(regPath, []byte(`{"tenants":[
	  {"id":"stonnington","name":"City of Stonnington","short":"Stonnington","connector":"fake","model":"swap","timezone":"Australia/Melbourne","policy":{"visitor_word":"visitor","resident_word":"resident"},"enabled":true},
	  {"id":"othertown","name":"Othertown Council","short":"Othertown","connector":"fake","model":"swap","timezone":"Australia/Perth","policy":{"visitor_word":"visitor"},"enabled":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := tenant.Load(config.CouncilConfig{}, regPath)
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultTenant = reg.Default.ID
	fakes := map[string]*fake.Provider{}
	clients := map[string]*parking.Client{}
	for _, c := range reg.Enabled() {
		f := fake.New()
		f.ApplyDelay = 0
		fakes[c.ID] = f
		clients[c.ID] = parking.NewClientFor(c.ID, f, st, box, nil)
	}
	mux := tenant.NewMux(st, clients)
	s := &Server{
		cfg:   &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store: st, box: box, terms: loadTerms(""), tenant: mux, registry: reg,
		sched: scheduler.New(st, mux, time.UTC, scheduler.Options{}),
	}
	ctx := context.Background()
	const user = "perth@example.com"
	if err := st.RecordConsent(ctx, user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	// The onboarding page asks which tenant.
	page := s.doReq(http.MethodGet, "/schedule", user, "", nil).Body.String()
	if !strings.Contains(page, `name="tenant_id"`) || !strings.Contains(page, "Othertown Council") {
		t.Fatalf("no council choice offered:\n%s", excerpt(page))
	}
	// Linking without a choice is refused; with one, recorded.
	if rr := s.doReq(http.MethodPost, "/tenant/link", user, "https://app.example.com", url.Values{"portal_password": {"ok"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("link without a council: code=%d", rr.Code)
	}
	rr := s.doReq(http.MethodPost, "/tenant/link", user, "https://app.example.com", url.Values{"portal_password": {"ok"}, "tenant_id": {"othertown"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("link: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if cs, _ := st.GetTenantSession(ctx, user); cs.TenantID != "othertown" {
		t.Fatalf("session filed under %q", cs.TenantID)
	}
	if rr := s.doReq(http.MethodPost, "/permits", user, "https://app.example.com", url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, _ := st.ListPermitsFor(ctx, user)
	if len(ps) != 1 || ps[0].TenantID != "othertown" {
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
	// A second home: linking the other tenant too is allowed, both sessions
	// coexist, and each permit stays filed under its own tenant.
	if rr := s.doReq(http.MethodPost, "/tenant/link", user, "https://app.example.com", url.Values{"portal_password": {"ok"}, "tenant_id": {"stonnington"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("link second tenant: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	sessions, _ := st.ListTenantSessionsFor(ctx, user)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v, want one per tenant", sessions)
	}
	if id, _ := st.TenantIDFor(ctx, user); id != "stonnington" {
		t.Fatalf("current tenant after linking it = %q", id)
	}
	if rr := s.doReq(http.MethodPost, "/permits", user, "https://app.example.com", url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add in second tenant: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, _ = st.ListPermitsFor(ctx, user)
	tenants := map[string]int{}
	for _, p := range ps {
		tenants[p.TenantID]++
	}
	if tenants["othertown"] != 1 || tenants["stonnington"] != 1 {
		t.Fatalf("permits by tenant = %v", tenants)
	}
}

// The second-home flow over HTTP: with two tenants the user menu offers the
// switcher; selecting an unlinked tenant lands on the picker, which offers that
// tenant's link form; after linking, Settings shows a card per connection, permit
// cards are labelled by tenant, and unlinking one tenant leaves the other.
func TestTenantSwitcherOverHTTP(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "sw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secretbox.New(bytes.Repeat([]byte{5}, 32))
	regPath := filepath.Join(t.TempDir(), "councils.json")
	if err := os.WriteFile(regPath, []byte(`{"tenants":[
	  {"id":"stonnington","name":"City of Stonnington","short":"Stonnington","connector":"fake","model":"swap","timezone":"Australia/Melbourne","policy":{"visitor_word":"visitor","resident_word":"resident"},"enabled":true},
	  {"id":"othertown","name":"Othertown Council","short":"Othertown","connector":"fake","model":"swap","timezone":"Australia/Perth","policy":{"visitor_word":"visitor"},"enabled":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := tenant.Load(config.CouncilConfig{}, regPath)
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultTenant = reg.Default.ID
	clients := map[string]*parking.Client{}
	for _, c := range reg.Enabled() {
		f := fake.New()
		f.ApplyDelay = 0
		clients[c.ID] = parking.NewClientFor(c.ID, f, st, box, nil)
	}
	mux := tenant.NewMux(st, clients)
	s := &Server{
		cfg:   &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store: st, box: box, terms: loadTerms(""), tenant: mux, registry: reg,
		sched:  scheduler.New(st, mux, time.UTC, scheduler.Options{}),
		notify: notify.New(st, nil, "", "", "https://p.example", "", "", time.UTC, nil, nil),
	}
	ctx := context.Background()
	const user = "two@example.com"
	if err := st.RecordConsent(ctx, user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		return s.doReq(http.MethodPost, path, user, "https://app.example.com", form)
	}
	// Link the first tenant and add a permit.
	if rr := post("/tenant/link", url.Values{"portal_password": {"ok"}, "tenant_id": {"stonnington"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("link: %d %s", rr.Code, excerpt(rr.Body.String()))
	}
	if rr := post("/permits", url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", rr.Code)
	}
	// The menu names the current area and offers "Connect another area…" (the
	// picker), rather than listing every unlinked council inline — the menu length
	// tracks the areas you use, not the areas the registry serves.
	page := s.doReq(http.MethodGet, "/schedule", user, "", nil).Body.String()
	if !strings.Contains(page, `href="/tenant/connect"`) || !strings.Contains(page, "Connect another area…") || !strings.Contains(page, "City of Stonnington") {
		t.Fatalf("switcher missing:\n%s", excerpt(page))
	}
	if strings.Contains(page, "Connect Othertown Council…") {
		t.Fatal("the menu must not list unlinked areas inline; they live on /tenant/connect")
	}
	if strings.Contains(page, `class="pdetail ptenant"`) {
		t.Fatal("a single-tenant account must not show tenant labels")
	}
	// The connect-area picker lists the unlinked area with a one-click connect.
	connect := s.doReq(http.MethodGet, "/tenant/connect", user, "", nil).Body.String()
	if !strings.Contains(connect, `name="tenant_id" value="othertown"`) || !strings.Contains(connect, "Othertown Council") {
		t.Fatalf("connect-area picker missing othertown:\n%s", excerpt(connect))
	}
	// Selecting an unlinked tenant lands on the picker, which offers its link form.
	rr := post("/tenant/select", url.Values{"tenant_id": {"othertown"}})
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/permits/new" {
		t.Fatalf("select unlinked: %d → %q", rr.Code, rr.Header().Get("Location"))
	}
	pick := s.doReq(http.MethodGet, "/permits/new", user, "", nil).Body.String()
	if !strings.Contains(pick, `action="/tenant/link"`) || !strings.Contains(pick, "Connect your Othertown Council account") || !strings.Contains(pick, `<option value="othertown" selected>`) {
		t.Fatalf("picker for an unlinked tenant should offer its link form:\n%s", excerpt(pick))
	}
	if rr := post("/tenant/link", url.Values{"portal_password": {"ok"}, "tenant_id": {"othertown"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("link second: %d", rr.Code)
	}
	if rr := post("/permits", url.Values{"council_permit_id": {"90002"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add second: %d %s", rr.Code, excerpt(rr.Body.String()))
	}
	// Both permits, labelled by tenant; the menu now says "switch".
	page = s.doReq(http.MethodGet, "/schedule", user, "", nil).Body.String()
	if strings.Count(page, `class="pdetail ptenant"`) != 2 || !strings.Contains(page, "Switch to City of Stonnington") {
		t.Fatalf("labels/switcher after second link:\n%s", excerpt(page))
	}
	// Settings: the current tenant's card plus one for the other connection.
	settings := s.doReq(http.MethodGet, "/settings", user, "", nil).Body.String()
	if !strings.Contains(settings, "City of Stonnington connection") || !strings.Contains(settings, `name="tenant_id" value="stonnington"`) {
		t.Fatalf("other connection card missing:\n%s", excerpt(settings))
	}
	// Unlink the OTHER tenant by id: its session goes, the current one stays.
	if rr := post("/tenant/unlink", url.Values{"tenant_id": {"stonnington"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("unlink: %d", rr.Code)
	}
	if mux.Linked(ctx, user, "stonnington") || !mux.Linked(ctx, user, "othertown") {
		t.Fatal("unlink touched the wrong tenant")
	}
	// Selecting a linked tenant goes straight to the schedule.
	if rr := post("/tenant/select", url.Values{"tenant_id": {"othertown"}}); rr.Header().Get("Location") != "/schedule" {
		t.Fatalf("select linked → %q", rr.Header().Get("Location"))
	}
	if rr := post("/tenant/select", url.Values{"tenant_id": {"nowhere"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown tenant: %d", rr.Code)
	}
}

// After adding a permit, addPermit nudges toward a second one — but only while the
// council list still holds another unmanaged visitor permit (?more=1). The fake
// portal offers two visitor permits (90001, 90002).
func TestAddPermitNudgesWhileAnotherRemains(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)

	// First add: the other visitor permit is still unmanaged → nudge.
	rr := r.post("/permits", rigUser, url.Values{
		"council_permit_id": {"90001"}, "permit_type_id": {"14"}, "label": {"VPP-SANDBOX"}})
	if rr.Code != http.StatusSeeOther || !strings.Contains(rr.Header().Get("Location"), "more=1") {
		t.Fatalf("first add should nudge for the second: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
	// Second add: nothing schedulable remains → no nudge.
	rr = r.post("/permits", rigUser, url.Values{
		"council_permit_id": {"90002"}, "permit_type_id": {"15"}, "label": {"VPP-SANDBOX-2"}})
	if rr.Code != http.StatusSeeOther || strings.Contains(rr.Header().Get("Location"), "more=1") {
		t.Fatalf("second add should not nudge: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// The set-up-another nudge must not point at a permit another account in the same
// tenant already manages — the picker would offer it but the add would 409, a
// dead-end. anotherSchedulableUnmanaged excludes it via a tenant-scoped check.
func TestAddPermitDoesNotNudgeForAnotherAccountsPermit(t *testing.T) {
	r := newTenantRig(t)
	const other = "housemate@example.com"
	r.consent(t, rigUser)
	r.link(t, rigUser)
	r.consent(t, other)
	r.link(t, other)

	// The housemate sets up the tenant's second visitor permit (90002).
	rr := r.post("/permits", other, url.Values{
		"council_permit_id": {"90002"}, "permit_type_id": {"15"}, "label": {"VPP-SANDBOX-2"}})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("housemate setup add failed: code=%d", rr.Code)
	}
	// rigUser adds 90001; 90002 is taken, so no nudge toward it.
	rr = r.post("/permits", rigUser, url.Values{
		"council_permit_id": {"90001"}, "permit_type_id": {"14"}, "label": {"VPP-SANDBOX"}})
	if rr.Code != http.StatusSeeOther || strings.Contains(rr.Header().Get("Location"), "more=1") {
		t.Fatalf("must not nudge toward another account's permit: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

// A visitor permit another household account already manages is shown greyed with a
// reason, not offered as addable — so the picker never dangles a "Set up" that would
// 409, and the "more than one visitor permit" plural copy stays honest (only one is
// actually set-up-able here).
func TestPickerGreysAnotherAccountsPermit(t *testing.T) {
	r := newTenantRig(t)
	const other = "housemate@example.com"
	r.consent(t, rigUser)
	r.link(t, rigUser)
	r.consent(t, other)
	r.link(t, other)

	// The housemate sets up 90002; the tenant now holds it under another account.
	if rr := r.post("/permits", other, url.Values{
		"council_permit_id": {"90002"}, "permit_type_id": {"15"}, "label": {"VPP-SANDBOX-2"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("housemate setup add failed: code=%d", rr.Code)
	}

	body := r.get("/schedule", rigUser).Body.String()
	if !strings.Contains(body, `name="council_permit_id" value="90001"`) {
		t.Error("90001 should be offered to this account")
	}
	if strings.Contains(body, `name="council_permit_id" value="90002"`) {
		t.Error("90002 is managed by another account — it must be greyed, not offered as addable")
	}
	if !strings.Contains(body, "Someone else at your address manages this one") {
		t.Errorf("missing the cross-account reason:\n%s", excerpt(body))
	}
	if strings.Contains(body, "more than one visitor permit") {
		t.Error("only one permit is truly set-up-able, so the plural guidance must not show")
	}
}

// Adding an EXPIRED permit (kept addable for copy-onto-renewal) must still nudge
// toward a live, unmanaged visitor permit — that permit is exactly what to surface.
func TestAddExpiredPermitStillNudges(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	r.fake.Extra = []provider.Permit{{
		CouncilPermitID: "88", PermitTypeID: "14", PermitNumber: "VPP-OLD",
		PermitType: "(A) 1st Visitor Permit", Status: "Cancelled", CanChangeVehicle: true,
		EndDate: time.Now().AddDate(0, 0, -30)}}
	defer func() { r.fake.Extra = nil }()

	rr := r.post("/permits", rigUser, url.Values{
		"council_permit_id": {"88"}, "permit_type_id": {"14"}, "label": {"VPP-OLD"}})
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/schedule?added=expired&more=1" {
		t.Fatalf("expired add should nudge toward the live permits: code=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}
