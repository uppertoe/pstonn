package server

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/store"
)

func melbourne(t *testing.T) *time.Location {
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// samplePermitView is the schedule-page fixture at the current time (substring
// assertions only). samplePermitViewAt pins the clock for the golden renders.
func samplePermitView(loc *time.Location) permitView { return samplePermitViewAt(loc, time.Now()) }

func samplePermitViewAt(loc *time.Location, at time.Time) permitView {
	now := at.In(loc)
	end := now.Add(4 * time.Hour)
	vv := []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}}
	var days []dayView
	for _, wd := range weekdaysDisplay {
		days = append(days, dayView{PermitID: 7, WeekdayNum: int(wd), Name: shortDay(wd), VehicleID: 1, Reg: "ABC123", Label: "Van", Color: "#2f6feb"})
	}
	var cal []calView
	for d := 0; d < 14; d++ {
		cal = append(cal, calView{DayLabel: "Mon 2", Reg: "ABC123", Color: "#2f6feb", Source: "roster", HasOneoff: d == 1, IsToday: d == 0})
	}
	return permitView{
		Permit:        model.Permit{ID: 7, CouncilPermitID: "14576", Label: "Visitor", ActiveRegistration: "ABC123"},
		DesiredReg:    "ABC123",
		DesiredSource: "roster",
		Weeks:         []weekView{{Index: 0, Num: 1, IsCurrent: true, Days: days}},
		CycleWeeks:    1,
		CanAddWeek:    true,
		Cal:           cal,
		Overrides:     []overrideView{{ID: 3, PermitID: 7, Reg: "XYZ789", Label: "Mum", Color: "#127a49", StartsAt: now, EndsAt: &end, CreatedBy: "a@b.com"}},
		Vehicles:      vv,
		// Registration-state selector on the one-off plate form (home first).
		Regions: []provider.Region{{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}, {Code: "SA", Label: "SA"}},
		Loc:     loc,
	}
}

// TestFillExpiry locks the calendar-day arithmetic behind the expiry labels.
func TestFillExpiry(t *testing.T) {
	loc := melbourne(t)
	now := time.Date(2026, 7, 20, 15, 0, 0, 0, loc)
	cases := []struct {
		name         string
		end          time.Time
		in           string
		soon, expird bool
	}{
		{"today", time.Date(2026, 7, 20, 23, 0, 0, 0, loc), "today", true, false},
		{"tomorrow", time.Date(2026, 7, 21, 1, 0, 0, 0, loc), "tomorrow", true, false},
		{"in-week", time.Date(2026, 7, 27, 9, 0, 0, 0, loc), "in 7 days", true, false},
		{"far-off", time.Date(2026, 12, 1, 9, 0, 0, 0, loc), "in 134 days", false, false},
		{"yesterday", time.Date(2026, 7, 19, 9, 0, 0, 0, loc), "yesterday", false, true},
		{"expired", time.Date(2026, 7, 10, 9, 0, 0, 0, loc), "10 days ago", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pv := permitView{Loc: loc, Permit: model.Permit{EndDate: c.end}}
			fillExpiry(&pv, now)
			if pv.ExpiryIn != c.in || pv.ExpiresSoon != c.soon || pv.Expired != c.expird {
				t.Fatalf("got in=%q soon=%v expired=%v; want in=%q soon=%v expired=%v",
					pv.ExpiryIn, pv.ExpiresSoon, pv.Expired, c.in, c.soon, c.expird)
			}
		})
	}
	// Unknown expiry stays blank.
	var pv permitView
	pv.Loc = loc
	fillExpiry(&pv, now)
	if pv.ExpiryLabel != "" || pv.ExpiryIn != "" {
		t.Fatalf("zero end date should stay blank, got %q/%q", pv.ExpiryLabel, pv.ExpiryIn)
	}
}

// TestTemplatesRender exercises the "dashboard" template in every state plus the
// swappable "permit-body" fragment, verifying they parse and execute cleanly.
func TestTemplatesRender(t *testing.T) {
	loc := melbourne(t)
	user := identity.User{Email: "a@b.com"}
	tm := loadTerms("")

	cases := templateRenderCases(loc, user, tm, time.Now())
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := templates.ExecuteTemplate(&buf, "dashboard", c.data); err != nil {
				t.Fatalf("render dashboard/%s: %v", c.name, err)
			}
			if !strings.Contains(buf.String(), c.want) {
				t.Fatalf("dashboard/%s output missing %q", c.name, c.want)
			}
		})
	}

	// The permit-body fragment surfaces expiry when the permit view carries it.
	for _, ec := range permitBodyCases(loc, time.Now()) {
		var b bytes.Buffer
		if err := templates.ExecuteTemplate(&b, "permit-body", ec.pv()); err != nil {
			t.Fatalf("render permit-body/%s: %v", ec.name, err)
		}
		if !strings.Contains(b.String(), ec.want) {
			t.Fatalf("permit-body/%s missing %q", ec.name, ec.want)
		}
	}

	// At the attempt cap the card must NOT arm another poll, so a tenant outage or
	// a change the tenant keeps refusing cannot loop the card forever.
	capped := samplePermitView(loc)
	capped.Applying = true
	capped.armPlatePoll(len(platePollDelays))
	var cb bytes.Buffer
	if err := templates.ExecuteTemplate(&cb, "permit-body", capped); err != nil {
		t.Fatalf("render permit-body/poll-cap: %v", err)
	}
	if strings.Contains(cb.String(), "/permits/7/card") {
		t.Fatalf("permit-body armed a follow-up poll at the attempt cap:\n%s", cb.String())
	}
	// And it must show the honest failure mark, not a spinner frozen mid-check.
	if !strings.Contains(cb.String(), "pwarn") {
		t.Fatalf("capped card with an outstanding change did not show the unconfirmed mark:\n%s", cb.String())
	}
	if strings.Contains(cb.String(), `class="pchk"`) {
		t.Fatalf("capped card is still showing a spinner instead of the unconfirmed mark:\n%s", cb.String())
	}

	// The htmx fragment must render standalone (it's swapped in on schedule edits).
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "permit-body", samplePermitView(loc)); err != nil {
		t.Fatalf("render permit-body: %v", err)
	}
	for _, want := range []string{"Weekly roster", "This week and next", "One-off booking", "ABC123", "→"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("permit-body output missing %q", want)
		}
	}
	// With ShowSetupNudge unset (the sample has a roster), the empty-schedule nudge
	// must be absent — a QR-only or already-scheduled household never sees it.
	if strings.Contains(buf.String(), "isn't on a schedule yet") {
		t.Fatal("setup nudge shown when ShowSetupNudge is false")
	}
	// The teleported modals must NOT live in the swap fragment. Every card
	// re-render (the plate poll's timer swap, roster edits, one-off add/delete)
	// replaces #pbody with a fresh permit-body — if a modal were inside it, that
	// swap would destroy a modal the user has open, blanking the visitor QR
	// mid-display. They belong in permit-modals, rendered once as a sibling.
	for _, leaked := range []string{`id="qrbody-`, `x-show="qrOpen"`, `x-show="addOpen"`} {
		if strings.Contains(buf.String(), leaked) {
			t.Fatalf("permit-body (the swap target) contains %q — a modal moved back inside the swap fragment, so a card re-render will null it while it's open:\n%s", leaked, buf.String())
		}
	}
	// The full schedule page must still render the wrapper and the modals as its sibling.
	var page bytes.Buffer
	if err := templates.ExecuteTemplate(&page, "dashboard", dashboardData{
		User: identity.User{Email: "a@b.com"}, State: "app", Page: "schedule", Loc: loc,
		Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
		App:      &appData{Permits: []permitView{samplePermitView(loc)}},
	}); err != nil {
		t.Fatalf("render schedule page: %v", err)
	}
	for _, want := range []string{`id="pbody-7"`, `id="qrbody-7"`, `x-show="qrOpen"`, `x-show="addOpen"`} {
		if !strings.Contains(page.String(), want) {
			t.Fatalf("schedule page missing %q — the pbody wrapper or the modals aren't rendered", want)
		}
	}
}

// TestColorOfPlate: the "on permit now" badge colours the plate only when it is
// one of the household's own cars. Empty is meaningful — it renders neutral, so
// a visitor's one-off plate reads as "not one of yours" rather than borrowing a
// colour that belongs to a different car.
func TestColorOfPlate(t *testing.T) {
	vs := []vehicleView{
		{Label: "Ours", Registration: "WGP472", Color: "#2f6feb"},
		{Label: "Nanny", Registration: "1AB2CD", Color: "#127a49"},
	}
	cases := []struct{ plate, want, why string }{
		{"WGP472", "#2f6feb", "exact match"},
		{"1AB2CD", "#127a49", "second car"},
		{"wgp472", "#2f6feb", "council echoes plates back in mixed case"},
		{" 1AB 2CD ", "#127a49", "spacing varies in how plates are entered"},
		{"ZZZ999", "", "a visitor's plate is not one of the household's cars"},
		{"", "", "nothing on the permit"},
	}
	for _, c := range cases {
		if got := colorOfPlate(vs, c.plate); got != c.want {
			t.Errorf("colorOfPlate(%q) = %q, want %q (%s)", c.plate, got, c.want, c.why)
		}
	}
}

// TestVehiclePaletteIsDistinct guards the ordering contract: colours are handed
// out first-unused, so the sequence itself is the design. A duplicate would give
// two of a household's cars the same colour and break the at-a-glance cue.
func TestVehiclePaletteIsDistinct(t *testing.T) {
	seen := map[string]int{}
	for i, c := range store.VehiclePaletteForTest() {
		if len(c) != 7 || c[0] != '#' {
			t.Errorf("palette[%d] = %q, want a 6-digit hex", i, c)
		}
		if prev, dup := seen[c]; dup {
			t.Errorf("palette[%d] duplicates palette[%d] (%s)", i, prev, c)
		}
		seen[c] = i
	}
	if len(seen) < 16 {
		t.Errorf("palette has %d colours; a household here can have many cars (carers, grandparents, friends)", len(seen))
	}
}

// TestLegendVehicles: the colour key shows exactly the cars whose colour is on
// the page, and counts the rest. Listing every car turned into a four-row wall
// that pushed the permit card below the fold once a household had a nanny, a
// carer and grandparents.
func TestLegendVehicles(t *testing.T) {
	all := []vehicleView{
		{ID: 1, Label: "Ours", Registration: "AAA111", Color: "#2f6feb"},
		{ID: 2, Label: "Nanny", Registration: "BBB222", Color: "#127a49"},
		{ID: 3, Label: "Carer", Registration: "CCC333", Color: "#b54708"},
		{ID: 4, Label: "Gran", Registration: "DDD444", Color: "#7a5af8"},
	}

	t.Run("only colours in use, in input order", func(t *testing.T) {
		shown, more := legendVehicles(all, map[string]bool{"#b54708": true, "#2f6feb": true})
		if len(shown) != 2 || more != 2 {
			t.Fatalf("shown=%d more=%d, want 2 and 2", len(shown), more)
		}
		if shown[0].Label != "Ours" || shown[1].Label != "Carer" {
			t.Errorf("got %q,%q — input order must be preserved so the key is stable",
				shown[0].Label, shown[1].Label)
		}
	})

	t.Run("nothing on the page means no key", func(t *testing.T) {
		shown, more := legendVehicles(all, map[string]bool{})
		if len(shown) != 0 || more != 4 {
			t.Fatalf("shown=%d more=%d, want 0 and 4: with no colours rendered there is nothing to explain",
				len(shown), more)
		}
	})

	t.Run("a colourless car is never shown", func(t *testing.T) {
		// "" is what an ad-hoc visitor plate resolves to; it must not match a car
		// that somehow has no stored colour.
		vs := append(append([]vehicleView{}, all...), vehicleView{ID: 9, Label: "Legacy", Color: ""})
		shown, _ := legendVehicles(vs, map[string]bool{"": true})
		if len(shown) != 0 {
			t.Fatalf("shown=%d, want 0", len(shown))
		}
	})
}

// TestOverrideEndsDefault locks the rule that a one-off booking ends by default.
//
// It used to be that leaving "Until" empty meant the booking ran forever, so the
// open-ended option was what you got by NOT deciding — and an indefinite one-off
// silently overrides the household's weekly roster until somebody notices. Now
// only an explicit choice does that.
func TestOverrideEndsDefault(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	start := time.Date(2026, 8, 4, 9, 30, 0, 0, loc) // a Tuesday morning

	// F6: the end is the day BOUNDARY (midnight starting the next day), because
	// model.Resolve treats it as exclusive — a 23:59 end left the last minute of the
	// day to the weekly roster, costing two tenant writes and two notifications
	// where one was intended. So "ends the day it starts" reads as the next date at
	// 00:00.
	cases := []struct {
		ends string
		want string // "" = indefinite
		why  string
	}{
		{"day", "2026-08-05T00:00", "ends the day it starts"},
		{"nextday", "2026-08-06T00:00", "overnight runs to the end of the next day"},
		{"open", "", "the only way to get an indefinite booking"},
		{"", "2026-08-05T00:00", "a missing field must fall back to the SAFE default, not to forever"},
		{"nonsense", "2026-08-05T00:00", "an unexpected value must not resurrect forever-by-accident"},
	}
	for _, c := range cases {
		var got *time.Time
		switch c.ends {
		case "open":
			got = nil
		case "nextday":
			e := endOfDay(start.AddDate(0, 0, 1), loc)
			got = &e
		default:
			e := endOfDay(start, loc)
			got = &e
		}
		switch {
		case c.want == "" && got != nil:
			t.Errorf("ends=%q gave an end time, want indefinite (%s)", c.ends, c.why)
		case c.want != "" && got == nil:
			t.Errorf("ends=%q gave an indefinite booking, want %s (%s)", c.ends, c.want, c.why)
		case c.want != "" && got.Format("2006-01-02T15:04") != c.want:
			t.Errorf("ends=%q = %s, want %s (%s)", c.ends, got.Format("2006-01-02T15:04"), c.want, c.why)
		}
	}
}

// TestEndOfDayUsesStartDay: "end of the day" is measured from the day the booking
// STARTS, so a booking made now for next Tuesday ends next Tuesday night — not in
// the past, which is what "end of today" would have meant.
func TestEndOfDayUsesStartDay(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	future := time.Date(2026, 9, 15, 8, 0, 0, 0, loc)
	got := endOfDay(future, loc)
	if want := "2026-09-16T00:00"; got.Format("2006-01-02T15:04") != want { // the boundary that closes 15 Sep; see F6
		t.Fatalf("endOfDay = %s, want %s", got.Format("2006-01-02T15:04"), want)
	}
	if !got.After(future) {
		t.Fatal("a future booking must not end before it starts")
	}
}

// TestEmptyGarageNudges: with no saved vehicles, the roster popover and the
// one-off modal must explain their prerequisite at the moment of use instead of
// dead-ending — the popover's only option was "clear" (a no-op that reads as
// broken) and the modal opened on an empty vehicle picker beside a plate field.
// And the page-level "add your plates" banner stays quiet for a household
// already living on guest QRs, which need no saved cars at all.
func TestEmptyGarageNudges(t *testing.T) {
	loc := melbourne(t)
	empty := samplePermitView(loc)
	empty.Vehicles = nil

	var body bytes.Buffer
	if err := templates.ExecuteTemplate(&body, "permit-body", empty); err != nil {
		t.Fatalf("render permit-body: %v", err)
	}
	if !strings.Contains(body.String(), "The roster runs on your saved cars") {
		t.Fatal("empty-garage roster popover does not explain what the roster needs")
	}
	if strings.Contains(body.String(), "clear day") {
		t.Fatal("empty-garage roster popover still offers the no-op clear button")
	}

	var modal bytes.Buffer
	if err := templates.ExecuteTemplate(&modal, "permit-modals", empty); err != nil {
		t.Fatalf("render permit-modals: %v", err)
	}
	if !strings.Contains(modal.String(), "mode:'plate'") {
		t.Fatal("empty-garage one-off modal does not default to the plate field")
	}
	if strings.Contains(modal.String(), "A saved car") {
		t.Fatal("empty-garage one-off modal still shows the saved-car toggle")
	}
	if !strings.Contains(modal.String(), "Save your cars") {
		t.Fatal("empty-garage one-off modal lost the quiet save-your-cars pointer")
	}

	// A stocked garage keeps the original behaviour.
	full := samplePermitView(loc)
	var modalFull bytes.Buffer
	if err := templates.ExecuteTemplate(&modalFull, "permit-modals", full); err != nil {
		t.Fatalf("render permit-modals (full): %v", err)
	}
	if !strings.Contains(modalFull.String(), "mode:'car'") || !strings.Contains(modalFull.String(), "A saved car") {
		t.Fatal("stocked-garage one-off modal lost its saved-car default")
	}

	// Page banner: shown to a no-vehicle household with no guest activity,
	// hidden for one already using guest QRs.
	for _, tc := range []struct {
		guestActive bool
		wantBanner  bool
	}{{false, true}, {true, false}} {
		var page bytes.Buffer
		d := dashboardData{Loc: loc, App: &appData{GuestActive: tc.guestActive}}
		if err := templates.ExecuteTemplate(&page, "page-schedule", d); err != nil {
			t.Fatalf("render page-schedule (guestActive=%v): %v", tc.guestActive, err)
		}
		got := strings.Contains(page.String(), "Add your plates")
		if got != tc.wantBanner {
			t.Fatalf("guestActive=%v: banner shown=%v, want %v", tc.guestActive, got, tc.wantBanner)
		}
	}
}

// TestClearButtonGating: the "take the car off" action shows only in the
// lingering-plate state — a plate on the permit with nothing scheduled for now.
// With a schedule covering now (the sample has a roster), or with no plate, the
// button must be absent, because a clear would either be re-applied or is moot.
func TestClearButtonGating(t *testing.T) {
	loc := melbourne(t)

	// Lingering plate: something on the permit, nothing scheduled now.
	lingering := samplePermitView(loc)
	lingering.DesiredSource = ""
	lingering.CanClear = true
	lingering.Permit.ActiveRegistration = "OLD999"
	var b bytes.Buffer
	if err := templates.ExecuteTemplate(&b, "permit-body", lingering); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(b.String(), "/clear") || !strings.Contains(b.String(), "Remove OLD999") {
		t.Fatalf("lingering-plate card missing the take-off action:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "permit-actions") {
		t.Fatal("clear button not in the shared action row beside the QR button")
	}
	if !strings.Contains(b.String(), "loses cover the moment you do this") {
		t.Fatal("clear confirm does not name the fine risk")
	}

	// Scheduled now: no button (a clear would be re-applied).
	scheduled := samplePermitView(loc) // has a roster/desired
	scheduled.CanClear = false
	var b2 bytes.Buffer
	if err := templates.ExecuteTemplate(&b2, "permit-body", scheduled); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(b2.String(), "/clear") {
		t.Fatal("clear action shown when a schedule covers now")
	}
}

// renderCase is one full-page render: a view model and a substring the page must
// contain. The list is shared with the golden harness (golden_test.go), which
// renders every case at a pinned clock and compares the whole page.
type renderCase struct {
	name string
	data dashboardData
	want string
}

func templateRenderCases(loc *time.Location, user identity.User, tm Terms, now time.Time) []renderCase {
	return []renderCase{
		{"landing", dashboardData{State: "landing", Loc: loc}, "Schedule your City of Stonnington"},
		{"landing-signedin", dashboardData{State: "landing", SignedIn: true, Loc: loc}, "Open the app"},
		{"security", dashboardData{State: "security", Loc: loc}, "The short version"},
		{"security-encryption", dashboardData{State: "security", Loc: loc}, "AES-256-GCM"},
		{"how", dashboardData{State: "how", Loc: loc}, "get a Stonnington ePermit"},
		{"how-demos", dashboardData{State: "how", Loc: loc}, "data-demo=\"roster\""},
		{"how-demos-doorqr", dashboardData{State: "how", Loc: loc}, "data-demo=\"doorqr\""},
		// Signed-in /how is the in-app feature tour: app chrome, demos only — no
		// pre-signup intro, connect demo or before-you-start section.
		{"how-signedin", dashboardData{State: "how", SignedIn: true, User: user, LogoutURL: "https://auth.example.com/logout", Loc: loc}, "Back to Schedule"},
		{"contact", dashboardData{State: "contact", Contact: true, Loc: loc}, "Send message"},
		{"contact-sent", dashboardData{State: "contact", Contact: true, Flash: "Thanks. Your message has been sent.", Loc: loc}, "has been sent"},
		{"terms", dashboardData{User: user, State: "terms", Loc: loc, Terms: termsView{Version: tm.Version, Clauses: tm.Clauses, Intro: tm.Intro}}, "I agree"},
		{"terms-updated", dashboardData{User: user, State: "terms", Loc: loc, Terms: termsView{Version: tm.Version, Clauses: tm.Clauses, Updated: true}}, "terms have changed"},
		{"onboarding", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{}}, "Link your council account"},
		// An invitee with no tenant link of their own can reach no page but this one,
		// so the invitation must be answerable here — with the owner it was rendered
		// for carried in the form (acceptInvite checks it).
		{"onboarding answers a pending invite", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{},
			Invite: &inviteView{Owner: "rd@example.com"}}, `action="/account/invite/accept"`},
		{"onboarding invite names the owner", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{},
			Invite: &inviteView{Owner: "rd@example.com"}}, `name="owner" value="rd@example.com"`},
		// A partial permit read holding ZERO rows must not be reported as an empty
		// account. Saying "your council account doesn't have any permits on it yet" to
		// someone who holds several is a flat falsehood they cannot act on.
		{"picker-partial-empty", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{PermitsUnknown: true}}, "couldn't load your permit list"},
		{"onboarding-savepw", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{}}, "Save my password"},
		// On a FIRST link the box is TICKED. Without a saved password the schedule
		// stops the first time the tenant ends the session — which happens whenever
		// the resident signs in to ePermits themselves — and it stops silently, which
		// is how a car ends up on the wrong permit. The stored value is a
		// parking-permit login, sealed at rest and recoverable by the tenant's own
		// forgot-password email.
		{"onboarding-savepw-default-checked", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{}}, `name="save_password" value="1" checked>`},
		{"relink-savepw-respects-optout", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, AutoReconnect: false, Loc: loc, Onboard: &onboardData{}}, `name="save_password" value="1">`},
		{"relink-savepw-respects-opton", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, AutoReconnect: true, Loc: loc, Onboard: &onboardData{}}, `name="save_password" value="1" checked>`},
		{"relink", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, Loc: loc, Onboard: &onboardData{}}, "Reconnect your council account"},
		{"capacity-full", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{CapacityFull: true}}, "p.stonn is full at the moment"},
		{"link-rejected offers sign-out", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkHelp: true},
			LogoutURL: "https://auth.example.com/logout", Loc: loc},
			"then sign back in here with that address"},
		{"link-rejected without a logout URL still names the fix", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkHelp: true}, Loc: loc},
			"Sign out, then sign back in here with that address."},
		// The reset deep link LEADS the rejected banner: the tenant can't tell a
		// wrong password from an account that never had a working one, and the
		// 2026-08 access logs showed rejected signups giving up without ever
		// being offered the reset.
		{"link-rejected leads with the council reset link", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkHelp: true}, Loc: loc},
			"idm/account/ForgotPassword"},
		{"link-rejected names the never-set-one case", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkHelp: true}, Loc: loc},
			"or never set one?"},
		// The reset offer also sits NEXT TO the password ask itself, before the
		// first failed attempt burns tenant lockout budget.
		{"link-form offers reset beside the password field", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc, Onboard: &onboardData{}},
			"idm/account/ForgotPassword"},
		{"link-throttled deep-links the reset too", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkThrottled: true}, Loc: loc},
			"idm/account/ForgotPassword"},
		// Inside a social in-app webview the password manager can't auto-fill;
		// the advice must appear BEFORE the field defeats them, and only there —
		// in a real browser it would be wrong and worrying.
		{"onboarding warns inside the Facebook webview", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{InAppBrowser: true}, Loc: loc},
			"In the Facebook, Instagram or Google app right now?"},
		// The terms page names the NEXT step's prerequisite (the ePermits
		// password) while there is still time to fix it — first acceptance only:
		// a re-accept returns to a working app, and a secondary links nothing.
		{"terms heads-up names the ePermits password", dashboardData{User: user, State: "terms", IsPrimary: true, Loc: loc,
			Terms: termsView{Version: tm.Version, Clauses: tm.Clauses, Intro: tm.Intro}},
			"ePermits password"},
		{"link-throttled pairs the wait with the remedies", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkThrottled: true},
			LogoutURL: "https://auth.example.com/logout", Loc: loc},
			"please wait about 15 minutes"},
		{"link-throttled names the ePermits email check", dashboardData{User: user, State: "onboarding", IsPrimary: true, Onboard: &onboardData{LinkThrottled: true}, Loc: loc},
			"your ePermits account must be under"},
		{"onboarding-secondary", dashboardData{User: user, State: "onboarding", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc, Onboard: &onboardData{}}, "Waiting for the account owner"},
		{"picker", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{OfferedCount: 1, Pick: []pickView{
			{CouncilPermitID: "14576", PermitTypeID: "14", PermitNumber: "VPP24714", PermitType: "(A) 1st Visitor Permit", CurrentRego: "ABC123", Addable: true},
			{CouncilPermitID: "9001", PermitTypeID: "3", PermitNumber: "RPP5", PermitType: "(B) Resident Permit", Addable: false, Reason: "Only visitor permits can be scheduled."},
		}}}, "Only visitor permits can be scheduled."},
		// Two offered visitor permits: the guidance acknowledges both rather than
		// saying "your visitor permit" (singular) over a two-choice screen.
		{"picker two visitor permits", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{OfferedCount: 2, Pick: []pickView{
			{CouncilPermitID: "14576", PermitTypeID: "14", PermitNumber: "VPP24714", PermitType: "(A) 1st Visitor Permit", CurrentRego: "ABC123", Addable: true},
			{CouncilPermitID: "14577", PermitTypeID: "15", PermitNumber: "VPP24715", PermitType: "(A) 2nd Visitor Permit", CurrentRego: "DEF456", Addable: true},
		}}}, "You have more than one visitor permit"},
		// A dead permit is grouped under its own heading with a status pill and a
		// button that says what adding it is for — never the live card's "Manage".
		{"picker groups dead permits", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{Pick: []pickView{
			{CouncilPermitID: "1", PermitNumber: "VPP1", PermitType: "(A) 1st Visitor Permit", CurrentRego: "LIVE01", Addable: true},
			{CouncilPermitID: "2", PermitNumber: "VPP2", PermitType: "(A) 1st Visitor Permit", CurrentRego: "OLD999", Addable: true, Dead: true, Status: "Cancelled"},
		}}}, "Older permits"},
		{"picker dead permit shows its status", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{Pick: []pickView{
			{CouncilPermitID: "2", PermitNumber: "VPP2", PermitType: "(A) 1st Visitor Permit", CurrentRego: "OLD999", Addable: true, Dead: true, Status: "Cancelled"},
		}}}, `<span class="pick-status">Cancelled</span>`},
		{"picker dead permit has the copy button", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{Pick: []pickView{
			{CouncilPermitID: "2", PermitNumber: "VPP2", PermitType: "(A) 1st Visitor Permit", Addable: true, Dead: true, Status: "Rejected"},
		}}}, "Add to copy its old schedule"},
		{"picker with only dead permits says so", dashboardData{User: user, State: "picker", Loc: loc, Picker: &pickerData{Pick: []pickView{
			{CouncilPermitID: "2", PermitNumber: "VPP2", PermitType: "(A) 1st Visitor Permit", Addable: true, Dead: true, Status: "Cancelled"},
		}}}, "All your permits are managed or no longer active."},
		// The copy outcome is shown to the person who ran it, on the card itself.
		{"permit card shows a copy outcome", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App: &appData{Permits: []permitView{func() permitView {
				pv := samplePermitViewAt(loc, now)
				pv.Notice = "Schedule copied. Guest passes and QR codes moved across with it — links that people have saved keep working."
				return pv
			}()}},
		}, "links that people have saved keep working"},
		{"guide page", dashboardData{State: "guide", Guide: &guidesFor(defaultTenantView)[0], Loc: loc}, "How do I change the car on my Stonnington visitor permit?"},
		{"share page", dashboardData{User: user, State: "share", Loc: loc, Share: &shareData{ShareEmailAvailable: true}}, `action="/share/invite"`},
		{"share page without mail hides the form", dashboardData{User: user, State: "share", Loc: loc, Share: &shareData{}}, "Open the printable card"},
		{"share card", dashboardData{User: user, State: "share-card", Loc: loc, Share: &shareData{ShareQR: "data:image/png;base64,AAAA", ShareURL: "p.stonn.org"}}, `alt="QR code to p.stonn.org"`},
		{"app-contact-link", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc, Contact: true,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{Permits: []permitView{samplePermitViewAt(loc, now)}},
		}, "/contact"},
		{"schedule", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{Permits: []permitView{samplePermitViewAt(loc, now)}},
		}, "Weekly roster"},
		// Right after adding a permit while another visitor permit is still unmanaged:
		// the "manage another" control becomes the highlighted "set up your other permit".
		{"schedule-more-to-set-up", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{MoreToSetUp: true, Permits: []permitView{samplePermitViewAt(loc, now)}},
		}, "Set up your other permit"},
		// Sustained council-side trouble: a plain, reassuring status banner.
		{"schedule-council-trouble", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			CouncilTrouble: true, CouncilName: "City of Stonnington",
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{Permits: []permitView{samplePermitViewAt(loc, now)}},
		}, "parking system is having problems"},
		{"schedule-expired-section", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App: &appData{Permits: []permitView{samplePermitViewAt(loc, now)},
				ExpiredPermits: []expiredPermitView{{ID: 4, Label: "Old Visitor", Detail: "VPP24714 · 1st Visitor Permit", StatusText: "Expired 1 Jul 2026"}}},
		}, "VPP24714 · 1st Visitor Permit"},
		{"schedule-only-expired", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{ExpiredPermits: []expiredPermitView{{ID: 4, Label: "Old Visitor", StatusText: "Cancelled"}}},
		}, "Got a new permit instead?"},
		{"schedule-share-hint", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{ShowShareHint: true, Permits: []permitView{samplePermitViewAt(loc, now)}},
		}, "Shared access"},
		{"schedule-guest-hint", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{ShowGuestHint: true, Permits: []permitView{samplePermitViewAt(loc, now)}},
		}, "guest pass"},
		{"vehicles", dashboardData{User: user, State: "app", Page: "vehicles", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb", State: "NSW"}},
			Regions:  []provider.Region{{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}, {Code: "SA", Label: "SA"}},
		}, "ABC123"},
		{"activity", dashboardData{User: user, State: "app", Page: "activity", Loc: loc,
			App: &appData{Log: []store.ApplyRecord{{PermitID: 7, Registration: "ABC123", Source: "roster", Status: "success", At: now}}},
		}, "Activity"},
		// Source codes render as words, not raw internal tags.
		{"activity-source-label", dashboardData{User: user, State: "app", Page: "activity", Loc: loc,
			App: &appData{Log: []store.ApplyRecord{{PermitID: 7, Registration: "ABC123", Source: "roster", Status: "success", At: now}}},
		}, "weekly roster"},
		// A removal has no plate: it reads "plate removed", not "manual" with an empty pill.
		{"activity-removal", dashboardData{User: user, State: "app", Page: "activity", Loc: loc,
			App: &appData{Log: []store.ApplyRecord{{PermitID: 7, Registration: "", Source: "manual", Status: "success", Detail: "vehicle removed by a@b.com", At: now}}},
		}, "plate removed"},
		{"settings", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, Settings: &settingsData{RelinkBy: "15 Oct 2026"}}, "Council connection"},
		{"settings-quiet-hours", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc,
			Settings: &settingsData{Notify: notifyView{EmailAvailable: true, EmailEnabled: true, QuietEnabled: true, QuietFrom: 22, QuietUntil: 6}}}, "hold overnight notices"},
		{"settings-autoreconnect-on", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, AutoReconnect: true, Settings: &settingsData{TenantLinked: true}}, "Turn off"},
		{"settings-autoreconnect-off", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, AutoReconnect: false, Settings: &settingsData{TenantLinked: true}}, "Your password isn't saved"},
		{"settings-last-reconnect", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, AutoReconnect: true, Settings: &settingsData{TenantLinked: true, LastReconnect: "14 Jul 2026, 3:04pm"}}, "14 Jul 2026, 3:04pm"},
		{"settings-no-reconnect-yet", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, AutoReconnect: true, Settings: &settingsData{TenantLinked: true}}, "hasn't been needed yet"},
		{"security-data-promise", dashboardData{State: "security", Loc: loc}, "never sold"},
		{"security-council-note", dashboardData{State: "security", Contact: true, Loc: loc}, "For the City of Stonnington"},
		{"settings-share", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, Settings: &settingsData{}}, "Add person"},
		{"settings-members", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, Settings: &settingsData{},
			Members: []memberView{{Email: "nanny@example.com", Added: "1 Jul 2026"}}}, "nanny@example.com"},
		{"settings-secondary", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc, Settings: &settingsData{}}, "Leave this account"},
		// An invitee who already runs their own permits gets the blocked variant: the
		// rule stated, Decline offered, and NO Accept form that could only fail.
		{"settings-invite-blocked-own", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, Settings: &settingsData{},
			Invite: &inviteView{Owner: "rd@example.com", Blocked: "own"}}, "can&rsquo;t also join another account"},
		{"settings-invite-blocked-shared", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, Settings: &settingsData{},
			Invite: &inviteView{Owner: "rd@example.com", Blocked: "shared"}}, "Remove them first, or decline the invitation"},
		{"schedule install hint", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			App:      &appData{ShowInstallHint: true, Permits: []permitView{samplePermitViewAt(loc, now)}}}, "Add to Home Screen"},
		{"guests-page", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			GuestMgmt: &guestMgmt{GuestsEnabled: true,
				PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
				Guests: []guestGrantView{{ID: 1, Label: "Friday", PermitLabel: "Visitor Permit",
					Cars:       []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
					Recipients: []guestRecipientView{{TokenID: 9, Email: "dad@example.com"}}}}}}, "Guest passes"},
		// A pass on a dead permit says so on its card and names the way out.
		{"guests-page flags a pass on a dead permit", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			GuestMgmt: &guestMgmt{GuestsEnabled: true,
				PermitOpts: []permitOpt{{ID: 2, Label: "New permit"}},
				Guests: []guestGrantView{{ID: 1, Label: "Friday", PermitLabel: "VPP25619 — no longer active", PermitDead: true,
					Recipients: []guestRecipientView{{TokenID: 9, Email: "dad@example.com"}}}}}}, "Copy the schedule to your new permit and this pass moves with it."},
		{"guests-trust-warning", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			Vehicles:  []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			GuestMgmt: &guestMgmt{GuestsEnabled: true, PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}}}}, "send it to people you trust"},
		{"guests-qr-contrast", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			Vehicles:  []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			GuestMgmt: &guestMgmt{GuestsEnabled: true, PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}}}}, "don't give lasting access"},
		{"guests-resend", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			GuestMgmt: &guestMgmt{GuestsEnabled: true,
				PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
				Guests: []guestGrantView{{ID: 1, Label: "Friday", PermitLabel: "Visitor Permit",
					Cars:       []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
					Recipients: []guestRecipientView{{TokenID: 9, Email: "dad@example.com"}}}}}}, "Re-send"},
		{"guests-secondary-can-manage", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc,
			Vehicles:  []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			GuestMgmt: &guestMgmt{GuestsEnabled: true, PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}}}}, "Create a new guest pass"},
		{"guests-edit", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			Vehicles:  []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}, {ID: 2, Label: "Dad", Registration: "AAA222", Color: "#222"}},
			GuestMgmt: &guestMgmt{GuestsEnabled: true, PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}}},
			Edit: &editGrantView{ID: 1, Label: "Friday", PermitLabel: "Visitor Permit", AllowOvernight: true,
				Selected: map[int64]bool{1: true}, Recipients: []guestRecipientView{{TokenID: 9, Email: "dad@example.com"}}}}, "Editing pass"},
		{"guest-menu", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", OwnerEmail: "held@example.com", PermitLabel: "Visitor Permit", CurrentReg: "ABC123",
			Cars: []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}, AllowOvernight: true}}, "Managed by"},
		{"guest-bookmark-tip", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", PermitLabel: "Visitor Permit",
			Cars: []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}}}, "add it to your home screen"},
		{"guest-manifest-link", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "toktok", PermitLabel: "Visitor Permit",
			Cars: []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}}}, "/g/manifest/toktok"},
		{"guest-rescan-applied", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", PermitLabel: "Visitor Permit", AllowPlate: true, RequestOnly: true,
			Req: &guestWaitView{Plate: "GUEST1", ReqID: 4, Nonce: "n", Status: "applied", Until: "the end of today"}}},
			"is on the permit until the end of today"},
		{"guest-rescan-superseded", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", PermitLabel: "Visitor Permit", AllowPlate: true, RequestOnly: true,
			Req: &guestWaitView{Plate: "GUEST1", ReqID: 4, Nonce: "n", Status: "superseded"}}},
			"it has since been changed"},
		{"guest-rescan-ended", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", PermitLabel: "Visitor Permit", AllowPlate: true, RequestOnly: true,
			Req: &guestWaitView{Plate: "GUEST1", ReqID: 4, Nonce: "n", Status: "ended"}}},
			"has ended"},
		{"guest-rescan-pending-polls", dashboardData{State: "guest", Loc: loc, Guest: guestActView{
			Token: "tok", PermitLabel: "Visitor Permit", AllowPlate: true, RequestOnly: true,
			Req: &guestWaitView{Plate: "GUEST1", ReqID: 4, Nonce: "nn", Status: "pending"}}},
			"/g/req/4?n=nn"},
		{"guests-recent-activity", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc,
			GuestMgmt: &guestMgmt{GuestsEnabled: true,
				PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
				RecentRequests: []guestDecidedView{
					{Plate: "GUEST1", PermitLabel: "Visitor Permit", Outcome: "Approved", DecidedBy: "mum@example.com", Ago: "2 hr ago",
						Live: "No longer on the permit — since replaced by OWNER9.", Warn: true},
					{Plate: "GUEST2", PermitLabel: "Visitor Permit", Outcome: "Not answered", Ago: "3 hr ago"}}}},
			"since replaced by OWNER9"},
		{"guest-result-ok", dashboardData{State: "guest-result", Loc: loc,
			Flash: "AAA111 is now on the permit until the end of today.", Guest: guestActView{OwnerEmail: "held@example.com"}}, "on the permit"},
		{"guest-gone", dashboardData{State: "guest-result", Loc: loc,
			Warn: "This link is no longer active. Ask the account holder for a new one."}, "no longer active"},
	}
}

// fragmentCase is one permit-body fragment render; shared with the golden harness.
type fragmentCase struct {
	name string
	pv   func() permitView
	want string
}

func permitBodyCases(loc *time.Location, now time.Time) []fragmentCase {
	return []fragmentCase{
		{"soon", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.ExpiryLabel = "3 Aug 2026"
			p.ExpiryIn = "in 12 days"
			p.ExpiresSoon = true
			return p
		}, "renew it with the council"},
		{"expired", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.ExpiryLabel = "1 Jul 2026"
			p.ExpiryIn = "5 days ago"
			p.Expired = true
			return p
		}, "copy your schedule onto the new permit"},
		{"valid", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.ExpiryLabel = "1 Jan 2027"
			p.ExpiryIn = "in 168 days"
			return p
		}, "Valid until 1 Jan 2027"},
		{"copy-from-empty", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.RosterEmpty = true
			p.CopyPitch = true
			p.CopyFrom = []permitOpt{{ID: 9, Label: "Old Visitor"}}
			return p
		}, "Is this a new permit replacing an old one?"},
		{"copy-pitch-dismissed", func() permitView {
			// Pitch answered (dismissed/copied/roster set): the quiet button
			// remains even while the roster is still empty.
			p := samplePermitViewAt(loc, now)
			p.RosterEmpty = true
			p.CopyPitch = false
			p.CopyFrom = []permitOpt{{ID: 9, Label: "Old Visitor"}}
			return p
		}, "Copy schedule from another permit"},
		{"copy-from-option", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.CopyFrom = []permitOpt{{ID: 9, Label: "Old Visitor"}}
			return p
		}, "Copy schedule from another permit"},
		{"permit-detail", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.Detail = "VPP24714 · (A) 1st Visitor Permit"
			return p
		}, "VPP24714 · (A) 1st Visitor Permit"},
		{"plate-refreshing-follow-up", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.PlateRefreshing = true
			p.armPlatePoll(0)
			return p
		}, `hx-get="/permits/7/card?n=1"`},
		// The timer poll swaps ONLY the .nowbadge, not the whole #pbody — otherwise
		// the empty-schedule nudge (a .banner with an entry animation) re-animates on
		// every tick. A regression to a full-body swap drops hx-select and fails here.
		{"poll-narrows-to-nowbadge", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.PlateRefreshing = true
			p.armPlatePoll(0)
			return p
		}, `hx-select=".nowbadge"`},
		// A cold render leaning on a recent council confirmation: tick and age hint
		// up front, the poll still riding along to catch drift.
		{"plate-recent-tick", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.PlateRefreshing, p.PlateRecent, p.PlateCheckedAgo = true, true, "checked 2 hr ago"
			p.armPlatePoll(0)
			return p
		}, `checked 2 hr ago`},
		{"applying-follow-up", func() permitView {
			// A change in flight arms the same bounded poll, even with a fresh cache.
			p := samplePermitViewAt(loc, now)
			p.Applying = true
			p.armPlatePoll(0)
			return p
		}, `hx-get="/permits/7/card?n=1"`},
		{"applying-spinner", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.Applying = true
			return p
		}, `Applying your change`},
		// A typed-plate override day gets the striped bar. Without it the day fell
		// back to the neutral bar and a covered day read as "nothing scheduled".
		{"adhoc-override-bar", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.Cal[2] = calView{DayLabel: "Tue 3", Reg: "XYZ789", Source: "override", Adhoc: true, Usual: "ABC123", HasOneoff: true}
			return p
		}, `class="bar adhoc"`},
		// An override day names the roster plate it displaced, so "usually A,
		// currently B" is readable from the calendar popover.
		{"override-usual-plate", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.Cal[2] = calView{DayLabel: "Tue 3", Reg: "XYZ789", Source: "override", Adhoc: true, Usual: "ABC123", HasOneoff: true}
			return p
		}, `usually ABC123`},
		// The empty-schedule setup nudge shows only when ShowSetupNudge is set.
		{"setup-nudge-shown", func() permitView {
			p := samplePermitViewAt(loc, now)
			p.ShowSetupNudge = true
			return p
		}, `isn't on a schedule yet`},
		// A cycling roster renders the week tabs (with the "now" mark on the
		// current week), per-week panes, and the labelled calendar rows.
		{"cycle-tabs", func() permitView {
			return sampleCyclingPermitView(loc, now)
		}, `role="tablist"`},
		{"cycle-now-marker", func() permitView {
			return sampleCyclingPermitView(loc, now)
		}, `class="wknow"`},
		{"cycle-calendar-row-labels", func() permitView {
			return sampleCyclingPermitView(loc, now)
		}, `Next week — Week 2`},
		// Removing a week answers with the stateless Undo riding the banner.
		{"cycle-remove-undo", func() permitView {
			p := sampleCyclingPermitView(loc, now)
			p.Notice = "Removed week 2. The roster is back to a single repeating week."
			p.UndoWeek = "1:1|2026-09-06"
			return p
		}, `name="undo"`},
	}
}

// sampleCyclingPermitView is samplePermitViewAt grown to a two-week cycle, week
// 1 (index 0) current.
func sampleCyclingPermitView(loc *time.Location, now time.Time) permitView {
	p := samplePermitViewAt(loc, now)
	week2 := make([]dayView, len(p.Weeks[0].Days))
	copy(week2, p.Weeks[0].Days)
	for i := range week2 {
		week2[i].Week = 1
	}
	p.Weeks = append(p.Weeks, weekView{Index: 1, Num: 2, Days: week2})
	p.CycleWeeks = 2
	p.CanAddWeek = true
	p.CalRowLabels = []string{"This week — Week 1", "Next week — Week 2"}
	return p
}
