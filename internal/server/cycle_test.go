package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// TestSetRuleWeekIsParsedStrictly: the cycle week gets the same strictness as
// weekday and vehicle_id — a defaulted-to-0 week would silently edit week 1.
// Blank is grandfathered ONLY for a plain weekly roster (the pre-cycle form
// shape); a cycling permit must name its week, and an out-of-range or garbage
// week is refused with nothing written.
func TestSetRuleWeekIsParsedStrictly(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "cycleweek@example.com"
	const origin = "https://app.example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "CYC-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	vid, err := r.st.CreateVehicle(ctx, user, "XYZ789", "Mum", "")
	if err != nil {
		t.Fatal(err)
	}
	rules := "/permits/" + itoa64(id) + "/rules"

	// Plain weekly roster: blank week still works (week 0), a named week 0 too,
	// but week 1 does not exist yet.
	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {itoa64(vid)}}); w.Code != http.StatusOK {
		t.Fatalf("blank week on a weekly roster = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"week": {"1"}, "weekday": {"2"}, "vehicle_id": {itoa64(vid)}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("week 1 on a 1-week roster = %d, want 422", w.Code)
	}

	// Grow the cycle: week 1 becomes writable, week 2 and garbage stay refused.
	if w := r.s.doHX(http.MethodPost, "/permits/"+itoa64(id)+"/weeks/add", user, origin, nil); w.Code != http.StatusOK {
		t.Fatalf("add week = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"week": {"1"}, "weekday": {"2"}, "vehicle_id": {itoa64(vid)}}); w.Code != http.StatusOK {
		t.Fatalf("week 1 after adding it = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	for _, bad := range []string{"2", "-1", "abc", ""} {
		w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"week": {bad}, "weekday": {"3"}, "vehicle_id": {itoa64(vid)}})
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("week %q on a 2-week roster = %d, want 422", bad, w.Code)
		}
	}
	rs, err := r.st.ListRules(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, ru := range rs {
		if ru.Weekday == time.Wednesday {
			t.Fatalf("a refused week wrote a Wednesday rule anyway: %+v", ru)
		}
	}
}

// TestCycleWeekEndpoints: the add/remove/restore trio end to end through the
// HTTP surface — the cap at four, the tabs and "now" marker in the fragment,
// the remove reply carrying a working Undo, and the round trip restoring the
// removed week's days.
func TestCycleWeekEndpoints(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "cyclehttp@example.com"
	const origin = "https://app.example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "CYC-2", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	vid, err := r.st.CreateVehicle(ctx, user, "ABC123", "Van", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.st.SetRule(ctx, id, 0, time.Monday, vid); err != nil {
		t.Fatal(err)
	}
	add := "/permits/" + itoa64(id) + "/weeks/add"

	w := r.s.doHX(http.MethodPost, add, user, origin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("add = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	body := w.Body.String()
	if !strings.Contains(body, `role="tablist"`) || !strings.Contains(body, "Week 2") {
		t.Fatalf("fragment after add carries no week tabs: %s", excerpt(body))
	}
	if !strings.Contains(body, `class="wknow"`) {
		t.Fatal("no \"now\" marker on the current week's tab")
	}
	// The seeded copy: week 1 holds week 0's Monday.
	rs, _ := r.st.ListRules(ctx, id)
	if len(rs) != 2 {
		t.Fatalf("rules after add = %d, want the copied Monday in both weeks", len(rs))
	}

	// Cap: grow to four, then the fifth is refused.
	for i := 0; i < 2; i++ {
		if w := r.s.doHX(http.MethodPost, add, user, origin, nil); w.Code != http.StatusOK {
			t.Fatalf("grow = %d", w.Code)
		}
	}
	if w := r.s.doHX(http.MethodPost, add, user, origin, nil); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("fifth week = %d, want 422", w.Code)
	}

	// Remove the last week: the reply's banner carries the Undo payload.
	w = r.s.doHX(http.MethodPost, "/permits/"+itoa64(id)+"/weeks/remove", user, origin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("remove = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	body = w.Body.String()
	if !strings.Contains(body, "Removed week 4") {
		t.Fatalf("remove reply does not name the week: %s", excerpt(body))
	}
	m := regexp.MustCompile(`name="undo" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("remove reply carries no undo payload: %s", excerpt(body))
	}
	if p, _ := r.st.GetPermit(ctx, id); p.CycleWeeks != 3 {
		t.Fatalf("cycle after remove = %d weeks, want 3", p.CycleWeeks)
	}

	// Undo restores the week and its Monday.
	w = r.s.doHX(http.MethodPost, "/permits/"+itoa64(id)+"/weeks/restore", user, origin, url.Values{"undo": {m[1]}})
	if w.Code != http.StatusOK {
		t.Fatalf("restore = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	p, _ := r.st.GetPermit(ctx, id)
	if p.CycleWeeks != 4 {
		t.Fatalf("cycle after undo = %d weeks, want 4", p.CycleWeeks)
	}
	rs, _ = r.st.ListRules(ctx, id)
	found := false
	for _, ru := range rs {
		if ru.Week == 3 && ru.Weekday == time.Monday && ru.VehicleID == vid {
			found = true
		}
	}
	if !found {
		t.Fatalf("undo did not restore week 4's Monday: %+v", rs)
	}

	// A tampered payload is refused.
	w = r.s.doHX(http.MethodPost, "/permits/"+itoa64(id)+"/weeks/restore", user, origin, url.Values{"undo": {"9:999999|nonsense"}})
	if w.Code == http.StatusOK {
		t.Fatal("a tampered undo payload was accepted")
	}
}

// TestCalendarCrossesTheCycleBoundary: the 14-day grid straddles two cycle
// weeks, so the second row must render the OTHER week's car, the row labels
// must name both weeks, and an override's "usually" must come from the day's
// own week — not the current one.
func TestCalendarCrossesTheCycleBoundary(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const owner = "calcycle@example.com"
	id, err := r.st.UpsertPermit(ctx, owner, "CYC-3", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	vidA, err := r.st.CreateVehicle(ctx, owner, "AAA111", "Week-one car", "")
	if err != nil {
		t.Fatal(err)
	}
	vidB, err := r.st.CreateVehicle(ctx, owner, "BBB222", "Week-two car", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.AddCycleWeek(ctx, owner, id, "2026-09-06"); err != nil {
		t.Fatal(err)
	}
	// Wednesdays differ by week; week 1's Wednesday also gets an override so
	// its popover must say "usually BBB222" (its own week), never AAA111.
	if err := r.st.SetRule(ctx, id, 0, time.Wednesday, vidA); err != nil {
		t.Fatal(err)
	}
	if err := r.st.SetRule(ctx, id, 1, time.Wednesday, vidB); err != nil {
		t.Fatal(err)
	}
	p := model.Permit{ID: id, Owner: owner, TenantID: r.s.registry.Default.ID, CouncilPermitID: "CYC-3", PermitTypeID: "1", CycleWeeks: 2, CycleAnchor: "2026-09-06"}
	loc := r.s.locForPermit(ctx, p)
	// Wednesday 2026-09-09 local: week 0. The grid's second row is week 1.
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, loc)
	nextWed := time.Date(2026, 9, 16, 0, 0, 0, 0, loc)
	wedEnd := nextWed.AddDate(0, 0, 1)
	if _, err := r.st.CreateOverride(ctx, id, vidA, nextWed, &wedEnd, owner); err != nil {
		t.Fatal(err)
	}
	regs := map[int64]string{vidA: "AAA111", vidB: "BBB222"}
	pv, err := r.s.buildPermitView(ctx, p, nil, map[int64]string{}, regs, map[int64]string{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pv.CalRowLabels) != 2 || !strings.Contains(pv.CalRowLabels[0], "Week 1") || !strings.Contains(pv.CalRowLabels[1], "Week 2") {
		t.Fatalf("CalRowLabels = %v, want this week as Week 1 and next as Week 2", pv.CalRowLabels)
	}
	if pv.CurrentWeek != 0 || pv.CycleWeeks != 2 || len(pv.Weeks) != 2 {
		t.Fatalf("cycle view: current=%d weeks=%d panes=%d", pv.CurrentWeek, pv.CycleWeeks, len(pv.Weeks))
	}
	// Row 1 Wednesday (index 3): week 0's car. Row 2 Wednesday (index 10): the
	// override, whose Usual is week 1's OWN roster car.
	if got := pv.Cal[3].Reg; got != "AAA111" {
		t.Fatalf("this week's Wednesday = %q, want AAA111", got)
	}
	d := pv.Cal[10]
	if d.Source != "override" || d.Reg != "AAA111" {
		t.Fatalf("next week's Wednesday = %+v, want the AAA111 override", d)
	}
	if d.Usual != "BBB222" {
		t.Fatalf("override's usually = %q, want week 2's own car BBB222 (not the current week's)", d.Usual)
	}
}
