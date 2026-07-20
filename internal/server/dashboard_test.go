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
		{"vehicles", dashboardData{User: user, State: "app", Page: "vehicles", Loc: loc,
			Vehicles: []vehicleView{{ID: 1, Label: "Van", Registration: "ABC123", Color: "#2f6feb"}},
		}, "ABC123"},
		{"activity", dashboardData{User: user, State: "app", Page: "activity", Loc: loc,
			Log: []store.ApplyRecord{{PermitID: 7, Registration: "ABC123", Source: "roster", Status: "success", At: time.Now()}},
		}, "Activity"},
		{"settings", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, RelinkBy: "15 Oct 2026"}, "Council connection"},
		{"settings-autoreconnect-on", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, CouncilLinked: true, AutoReconnect: true}, "Turn off"},
		{"settings-autoreconnect-off", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc, CouncilLinked: true, AutoReconnect: false}, "Your password isn't saved"},
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
