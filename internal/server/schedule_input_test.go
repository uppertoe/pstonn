package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// TestOneOffTimeWithoutDateRefused: a start time typed with the date left blank
// used to be dropped on the floor — combineDateTime treats a blank date as
// "unset" — so "from 9:00" quietly became "from now". The until path already
// refused the same shape; this pins the from path doing the same, with nothing
// booked.
func TestOneOffTimeWithoutDateRefused(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "oneoff@example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "ONE-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	w := r.s.doHX(http.MethodPost, "/permits/"+itoa64(id)+"/override", user, "https://app.example.com",
		url.Values{"from_time": {"09:00"}, "plate": {"ABC123"}})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "Pick a start date") {
		t.Fatalf("time without a date = %d %q, want 422 asking for the date", w.Code, w.Body.String())
	}
	if ovs, err := r.st.ListOverrides(ctx, id, time.Now()); err != nil || len(ovs) != 0 {
		t.Fatalf("a refused booking was still created: %v %v", ovs, err)
	}
}

// TestSetRuleVehicleIDIsParsedStrictly: the roster car used to go through atoi64,
// which maps anything unparseable to 0 — and 0 is the "clear this day" sentinel,
// so a mangled id emptied the day instead of being refused. Garbage is a form
// error; blank and "0" still clear.
func TestSetRuleVehicleIDIsParsedStrictly(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "roster@example.com"
	const origin = "https://app.example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "RULE-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	vid, err := r.st.CreateVehicle(ctx, user, "XYZ789", "Mum", "")
	if err != nil {
		t.Fatal(err)
	}
	rules := "/permits/" + itoa64(id) + "/rules"
	monday := func(t *testing.T) int64 {
		t.Helper()
		rs, err := r.st.ListRules(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rs {
			if rule.Weekday == time.Monday {
				return rule.VehicleID
			}
		}
		return 0
	}

	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {itoa64(vid)}}); w.Code != http.StatusOK {
		t.Fatalf("set Monday = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	if got := monday(t); got != vid {
		t.Fatalf("Monday = vehicle %d, want %d", got, vid)
	}
	w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {"abc"}})
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "That car isn't valid") {
		t.Fatalf("garbage vehicle id = %d %q, want 422", w.Code, w.Body.String())
	}
	if got := monday(t); got != vid {
		t.Fatalf("a refused edit changed Monday to vehicle %d (0 = cleared): the garbage was read as \"clear\"", got)
	}
	for _, clear := range []string{"0", ""} {
		if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {itoa64(vid)}}); w.Code != http.StatusOK {
			t.Fatalf("re-set Monday = %d", w.Code)
		}
		if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {clear}}); w.Code != http.StatusOK {
			t.Fatalf("vehicle_id=%q = %d, want 200 (clear)", clear, w.Code)
		}
		if got := monday(t); got != 0 {
			t.Fatalf("vehicle_id=%q left Monday on vehicle %d, want cleared", clear, got)
		}
	}
}

// TestBuildPermitViewTodayFollowsPermitZone: the calendar's "today" is the
// permit's calendar day. The full page used to hand buildPermitView a clock in
// the owner's tenant zone while the htmx card refresh handed it the permit's, and
// the day was built from the clock's Year/Month/Day — so for part of every day
// the two renders disagreed about which cell was today. Whatever zone the clock
// arrives in, the cell marked today must be the permit-zone date.
func TestBuildPermitViewTodayFollowsPermitZone(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const owner = "zones@example.com"
	id, err := r.st.UpsertPermit(ctx, owner, "ZONE-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	p := model.Permit{ID: id, Owner: owner, TenantID: r.s.registry.Default.ID, CouncilPermitID: "ZONE-1", PermitTypeID: "1"}
	loc := r.s.locForPermit(ctx, p)
	// Late evening UTC is already the next morning in Melbourne, so the two zones
	// name different days — the fixture is only a test of anything while they do.
	now := time.Date(2026, time.August, 10, 15, 30, 0, 0, time.UTC)
	want := now.In(loc).Format("Mon 2")
	if want == now.Format("Mon 2") {
		t.Fatalf("permit zone %s renders %q for the fixture instant, same as UTC — the fixture no longer exercises the zone difference", loc, want)
	}
	pv, err := r.s.buildPermitView(ctx, p, nil, map[int64]string{}, map[int64]string{}, map[int64]string{}, now)
	if err != nil {
		t.Fatal(err)
	}
	var today []string
	for _, c := range pv.Cal {
		if c.IsToday {
			today = append(today, c.DayLabel)
		}
	}
	if len(today) != 1 || today[0] != want {
		t.Fatalf("today cells = %v, want exactly [%q] (the permit-zone date)", today, want)
	}
}

// TestExpiredViewUsesExpiryDeadline: the compact expired row decided "Expired
// <date>" by comparing now with the bare EndDate instant, which is UTC midnight
// at the START of the last valid day — so a permit still good until tonight, in
// the section for another reason, was captioned expired from mid-morning. Every
// has-this-finished question goes through model.ExpiryDeadline.
func TestExpiredViewUsesExpiryDeadline(t *testing.T) {
	loc := melbourne(t)
	p := model.Permit{CouncilPermitID: "X1", Status: "Cancelled",
		EndDate: time.Date(2026, time.August, 10, 0, 0, 0, 0, time.UTC)} // the tenant's zoneless "10 Aug"
	// Monday afternoon on the final valid day: not expired, so the row says why it
	// is really here.
	if got := buildExpiredView(p, time.Date(2026, time.August, 10, 14, 30, 0, 0, loc), loc).StatusText; got != "Cancelled" {
		t.Fatalf("on the last valid day: %q, want the cancellation (not yet expired)", got)
	}
	// Just past the deadline: expired, named by its last valid day.
	if got := buildExpiredView(p, time.Date(2026, time.August, 11, 0, 30, 0, 0, loc), loc).StatusText; got != "Expired 10 Aug 2026" {
		t.Fatalf("after the deadline: %q, want \"Expired 10 Aug 2026\"", got)
	}
}
