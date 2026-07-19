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
		{"relink", dashboardData{User: user, State: "onboarding", IsPrimary: true, Relink: true, Loc: loc}, "Re-link your council account"},
		{"onboarding-secondary", dashboardData{User: user, State: "onboarding", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc}, "Waiting for the account owner"},
		{"picker", dashboardData{User: user, State: "picker", Loc: loc, Pick: []pickView{
			{CouncilPermitID: "14576", PermitTypeID: "14", PermitNumber: "VPP24714", PermitType: "(A) 1st Visitor Permit", CurrentRego: "ABC123", Suggested: true},
		}}, "VPP24714"},
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
		{"settings-share", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc}, "Add person"},
		{"settings-members", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: true, Loc: loc,
			Members: []memberView{{Email: "nanny@example.com", Added: "1 Jul 2026"}}}, "nanny@example.com"},
		{"settings-secondary", dashboardData{User: user, State: "app", Page: "settings", IsPrimary: false, SharedWith: "primary@example.com", Loc: loc}, "Leave this account"},
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
