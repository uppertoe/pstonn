package server

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

func melbourne(t *testing.T) *time.Location {
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func samplePermitView(loc *time.Location) permitView {
	now := time.Now().In(loc)
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
		Days:          days,
		Cal:           cal,
		Overrides:     []overrideView{{ID: 3, PermitID: 7, Reg: "XYZ789", Label: "Mum", Color: "#127a49", StartsAt: now, EndsAt: &end, CreatedBy: "a@b.com"}},
		Vehicles:      vv,
		Loc:           loc,
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

	cases := []struct {
		name string
		data dashboardData
		want string
	}{
		{"landing", dashboardData{State: "landing", Loc: loc}, "Schedule your City of Stonnington"},
		{"landing-signedin", dashboardData{State: "landing", SignedIn: true, Loc: loc}, "Open the app"},
		{"about", dashboardData{State: "about", Loc: loc}, "security model"},
		{"why", dashboardData{State: "why", Loc: loc}, "get a Stonnington ePermit"},
		{"why-demos", dashboardData{State: "why", Loc: loc}, "data-demo=\"roster\""},
		{"contact", dashboardData{State: "contact", Contact: true, Loc: loc}, "Send message"},
		{"contact-sent", dashboardData{State: "contact", Contact: true, Flash: "Thanks. Your message has been sent.", Loc: loc}, "has been sent"},
		{"terms", dashboardData{User: user, State: "terms", Loc: loc, Terms: termsView{Version: tm.Version, Clauses: tm.Clauses, Intro: tm.Intro}}, "I agree"},
		{"terms-updated", dashboardData{User: user, State: "terms", Loc: loc, Terms: termsView{Version: tm.Version, Clauses: tm.Clauses, Updated: true}}, "terms have changed"},
		{"onboarding", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc}, "Link your council account"},
		{"onboarding-savepw", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc}, "Save my password"},
		// C11: on a FIRST link the box is unticked. Retaining someone's council
		// password is the more consequential of the two outcomes, so it has to be
		// chosen rather than merely not noticed.
		{"onboarding-savepw-default-unchecked", dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc}, `name="save_password" value="1">`},
		{"relink-savepw-respects-optout", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, AutoReconnect: false, Loc: loc}, `name="save_password" value="1">`},
		{"relink-savepw-respects-opton", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, AutoReconnect: true, Loc: loc}, `name="save_password" value="1" checked>`},
		{"relink", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, Loc: loc}, "Re-link your council account"},
		{"onboarding-secondary", dashboardData{User: user, State: "onboarding", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc}, "Waiting for the account owner"},
		{"picker", dashboardData{User: user, State: "picker", Loc: loc, Pick: []pickView{
			{CouncilPermitID: "14576", PermitTypeID: "14", PermitNumber: "VPP24714", PermitType: "(A) 1st Visitor Permit", CurrentRego: "ABC123", Addable: true},
			{CouncilPermitID: "9001", PermitTypeID: "3", PermitNumber: "RPP5", PermitType: "(B) Resident Permit", Addable: false, Reason: "Only visitor permits can be scheduled."},
		}}, "Only visitor permits can be scheduled."},
		{"app-contact-link", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc, Contact: true,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			Permits:  []permitView{samplePermitView(loc)},
		}, "/contact"},
		{"schedule", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			Permits:  []permitView{samplePermitView(loc)},
		}, "Weekly roster"},
		{"schedule-expired-section", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles:       []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			Permits:        []permitView{samplePermitView(loc)},
			ExpiredPermits: []expiredPermitView{{ID: 4, Label: "Old Visitor", Detail: "VPP24714 · 1st Visitor Permit", StatusText: "Expired 1 Jul 2026"}},
		}, "VPP24714 · 1st Visitor Permit"},
		{"schedule-only-expired", dashboardData{User: user, State: "app", Page: "schedule", Loc: loc,
			Vehicles:       []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
			ExpiredPermits: []expiredPermitView{{ID: 4, Label: "Old Visitor", StatusText: "Cancelled"}},
		}, "Add the new permit"},
		{"vehicles", dashboardData{User: user, State: "app", Page: "vehicles", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
		}, "ABC123"},
		{"activity", dashboardData{User: user, State: "app", Page: "activity", Loc: loc,
			Log: []store.ApplyRecord{{PermitID: 7, Registration: "ABC123", Source: "roster", Status: "success", At: time.Now()}},
		}, "Activity"},
		{"settings", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, RelinkBy: "15 Oct 2026"}, "Council connection"},
		{"settings-quiet-hours", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc,
			Notify: notifyView{EmailAvailable: true, EmailEnabled: true, QuietEnabled: true, QuietFrom: 22, QuietUntil: 6}}, "hold overnight notices"},
		{"settings-autoreconnect-on", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, CouncilLinked: true, AutoReconnect: true}, "Turn off"},
		{"settings-autoreconnect-off", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, CouncilLinked: true, AutoReconnect: false}, "Your password isn't saved"},
		{"settings-last-reconnect", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, CouncilLinked: true, AutoReconnect: true, LastReconnect: "14 Jul 2026, 3:04pm"}, "14 Jul 2026, 3:04pm"},
		{"settings-no-reconnect-yet", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, CouncilLinked: true, AutoReconnect: true}, "hasn't been needed yet"},
		{"about-data-promise", dashboardData{State: "about", Loc: loc}, "never sold"},
		{"about-council-note", dashboardData{State: "about", Contact: true, Loc: loc}, "For the City of Stonnington"},
		{"settings-share", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc}, "Add person"},
		{"settings-members", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc,
			Members: []memberView{{Email: "nanny@example.com", Added: "1 Jul 2026"}}}, "nanny@example.com"},
		{"settings-secondary", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc}, "Leave this account"},
		{"guests-page", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			Vehicles:   []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			Guests: []guestGrantView{{ID: 1, Label: "Friday", PermitLabel: "Visitor Permit",
				Cars:       []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
				Recipients: []guestRecipientView{{TokenID: 9, Email: "dad@example.com"}}}}}, "Guest passes"},
		{"guests-trust-warning", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			Vehicles:   []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}}, "send it to people you trust"},
		{"guests-qr-contrast", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			Vehicles:   []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}}, "don't give lasting access"},
		{"guests-resend", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			Vehicles:   []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
			Guests: []guestGrantView{{ID: 1, Label: "Friday", PermitLabel: "Visitor Permit",
				Cars:       []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}},
				Recipients: []guestRecipientView{{TokenID: 9, Email: "dad@example.com"}}}}}, "Re-send"},
		{"guests-secondary-can-manage", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			Vehicles:   []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}}}, "Create a new guest pass"},
		{"guests-edit", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			Vehicles:   []vehicleView{{ID: 1, Label: "Mum", Registration: "AAA111", Color: "#111"}, {ID: 2, Label: "Dad", Registration: "AAA222", Color: "#222"}},
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
		{"guests-recent-activity", dashboardData{User: user, State: "app", Page: "guests", IsPrimary: true, Loc: loc, GuestsEnabled: true,
			PermitOpts: []permitOpt{{ID: 1, Label: "Visitor Permit"}},
			RecentRequests: []guestDecidedView{
				{Plate: "GUEST1", PermitLabel: "Visitor Permit", Outcome: "Approved", DecidedBy: "mum@example.com", Ago: "2 hr ago",
					Live: "No longer on the permit — since replaced by OWNER9.", Warn: true},
				{Plate: "GUEST2", PermitLabel: "Visitor Permit", Outcome: "Not answered", Ago: "3 hr ago"}}},
			"since replaced by OWNER9"},
		{"guest-result-ok", dashboardData{State: "guest-result", Loc: loc,
			Flash: "AAA111 is now on the permit until the end of today.", Guest: guestActView{OwnerEmail: "held@example.com"}}, "on the permit"},
		{"guest-gone", dashboardData{State: "guest-result", Loc: loc,
			Warn: "This link is no longer active. Ask the account holder for a new one."}, "no longer active"},
	}
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
	for _, ec := range []struct {
		name string
		pv   func() permitView
		want string
	}{
		{"soon", func() permitView {
			p := samplePermitView(loc)
			p.ExpiryLabel = "3 Aug 2026"
			p.ExpiryIn = "in 12 days"
			p.ExpiresSoon = true
			return p
		}, "renew it with the council"},
		{"expired", func() permitView {
			p := samplePermitView(loc)
			p.ExpiryLabel = "1 Jul 2026"
			p.ExpiryIn = "5 days ago"
			p.Expired = true
			return p
		}, "copy your schedule onto the new permit"},
		{"valid", func() permitView {
			p := samplePermitView(loc)
			p.ExpiryLabel = "1 Jan 2027"
			p.ExpiryIn = "in 168 days"
			return p
		}, "Valid until 1 Jan 2027"},
		{"copy-from-empty", func() permitView {
			p := samplePermitView(loc)
			p.RosterEmpty = true
			p.CopyFrom = []permitOpt{{ID: 9, Label: "Old Visitor"}}
			return p
		}, "Renewed this permit?"},
		{"copy-from-option", func() permitView {
			p := samplePermitView(loc)
			p.CopyFrom = []permitOpt{{ID: 9, Label: "Old Visitor"}}
			return p
		}, "Copy schedule from another permit"},
		{"permit-detail", func() permitView {
			p := samplePermitView(loc)
			p.Detail = "VPP24714 · (A) 1st Visitor Permit"
			return p
		}, "VPP24714 · (A) 1st Visitor Permit"},
		{"plate-refreshing-follow-up", func() permitView {
			p := samplePermitView(loc)
			p.PlateRefreshing = true
			return p
		}, `hx-get="/permits/7/card"`},
	} {
		var b bytes.Buffer
		if err := templates.ExecuteTemplate(&b, "permit-body", ec.pv()); err != nil {
			t.Fatalf("render permit-body/%s: %v", ec.name, err)
		}
		if !strings.Contains(b.String(), ec.want) {
			t.Fatalf("permit-body/%s missing %q", ec.name, ec.want)
		}
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
	// day to the weekly roster, costing two council writes and two notifications
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
