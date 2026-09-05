package model

import (
	"testing"
	"time"
)

// Both 2026 Melbourne DST transitions fall on Sundays — exactly on cycle-week
// boundaries — so walking those days hour by hour is the sharpest pin there is:
// the week index must flip at local midnight Sunday and nowhere else, however
// many hours the Sunday holds.
func TestWeekAtFlipsAtLocalSundayMidnightAcrossDST(t *testing.T) {
	loc := melbourne(t)
	// Anchor on a Sunday two weeks before each transition, so the transition
	// Sunday begins week 0 again (14 days = 2 whole cycles of 1 week... use a
	// 2-week cycle: the transition Sunday starts week 0, the Saturday before it
	// ends week 1).
	cases := []struct {
		name   string
		anchor string // a Sunday, 14 days before the transition Sunday
		sunday time.Time
	}{
		{"spring forward", "2026-09-20", time.Date(2026, 10, 4, 0, 0, 0, 0, loc)},
		{"fall back", "2026-03-22", time.Date(2026, 4, 5, 0, 0, 0, 0, loc)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cyc := Cycle{Weeks: 2, Anchor: c.anchor}
			// The Saturday before the transition Sunday is the last day of week 1.
			for h := 0; h < 24; h++ {
				at := c.sunday.AddDate(0, 0, -1).Add(time.Duration(h) * time.Hour).In(loc)
				if at.Day() != c.sunday.AddDate(0, 0, -1).Day() {
					continue // DST arithmetic pushed past the day; irrelevant here
				}
				if got := cyc.WeekAt(at); got != 1 {
					t.Fatalf("Saturday %s: WeekAt = %d, want 1", at, got)
				}
			}
			// Every real hour of the transition Sunday itself is week 0.
			end := c.sunday.AddDate(0, 0, 1)
			for at := c.sunday; at.Before(end); at = at.Add(time.Hour) {
				if got := cyc.WeekAt(at.In(loc)); got != 0 {
					t.Fatalf("Sunday %s: WeekAt = %d, want 0", at.In(loc), got)
				}
			}
		})
	}
}

// A corrupt or missing anchor must degrade to the weekly behaviour (week 0),
// never to a wrong random week; an anchor in the future must wrap non-negative
// rather than resolve a week index no rule can match.
func TestWeekAtDegenerateAnchors(t *testing.T) {
	loc := melbourne(t)
	now := time.Date(2026, 9, 9, 10, 0, 0, 0, loc) // a Wednesday
	if got := (Cycle{Weeks: 1, Anchor: "2026-09-06"}).WeekAt(now); got != 0 {
		t.Fatalf("Weeks=1: WeekAt = %d, want 0", got)
	}
	if got := (Cycle{Weeks: 3, Anchor: ""}).WeekAt(now); got != 0 {
		t.Fatalf("empty anchor: WeekAt = %d, want 0", got)
	}
	if got := (Cycle{Weeks: 3, Anchor: "garbage"}).WeekAt(now); got != 0 {
		t.Fatalf("garbage anchor: WeekAt = %d, want 0", got)
	}
	// Anchor two weeks in the FUTURE: -2 weeks from it, so with 3 weeks the
	// index wraps to 1 (never negative).
	if got := (Cycle{Weeks: 3, Anchor: "2026-09-20"}).WeekAt(now); got != 1 {
		t.Fatalf("future anchor: WeekAt = %d, want 1", got)
	}
	// A non-Sunday anchor names its own week: any day of that week anchors the
	// same cycle.
	sun := (Cycle{Weeks: 2, Anchor: "2026-09-06"}).WeekAt(now)
	wed := (Cycle{Weeks: 2, Anchor: "2026-09-09"}).WeekAt(now)
	if sun != wed {
		t.Fatalf("mid-week anchor disagrees with its Sunday: %d vs %d", wed, sun)
	}
}

// ReanchoredCycle is the single formula behind every week-count change: growing
// preserves the current index, shrinking wraps it, and repeated edits inside
// one week compose.
func TestReanchoredCycle(t *testing.T) {
	loc := melbourne(t)
	now := time.Date(2026, 9, 16, 15, 0, 0, 0, loc) // a Wednesday

	// Grow 1→2: the current week becomes index 0.
	c2 := ReanchoredCycle(now, Cycle{Weeks: 1}, 2)
	if c2.Weeks != 2 || c2.WeekAt(now) != 0 {
		t.Fatalf("1→2: %+v, WeekAt=%d", c2, c2.WeekAt(now))
	}
	if c2.Anchor != "2026-09-13" { // the Sunday of now's week
		t.Fatalf("1→2 anchor = %q, want the current Sunday", c2.Anchor)
	}
	// Next Sunday must begin week 1.
	if got := c2.WeekAt(time.Date(2026, 9, 20, 1, 0, 0, 0, loc)); got != 1 {
		t.Fatalf("week after 1→2: WeekAt = %d, want 1", got)
	}

	// Append 2→3 preserves the current index whatever it is: jump the clock into
	// week 1 first.
	inWeek1 := time.Date(2026, 9, 23, 9, 0, 0, 0, loc)
	if got := c2.WeekAt(inWeek1); got != 1 {
		t.Fatalf("setup: WeekAt = %d, want 1", got)
	}
	c3 := ReanchoredCycle(inWeek1, c2, 3)
	if c3.Weeks != 3 || c3.WeekAt(inWeek1) != 1 {
		t.Fatalf("2→3 changed the current week: %+v, WeekAt=%d", c3, c3.WeekAt(inWeek1))
	}

	// Shrink 3→2 while inside the last (removed) week wraps: index 2 → 0.
	inWeek2 := time.Date(2026, 9, 30, 9, 0, 0, 0, loc)
	if got := c3.WeekAt(inWeek2); got != 2 {
		t.Fatalf("setup: WeekAt = %d, want 2", got)
	}
	back2 := ReanchoredCycle(inWeek2, c3, 2)
	if back2.WeekAt(inWeek2) != 0 {
		t.Fatalf("3→2 inside the removed week: WeekAt = %d, want 0 (wrap)", back2.WeekAt(inWeek2))
	}

	// Shrink to 1 clears the anchor entirely.
	if c1 := ReanchoredCycle(now, c3, 1); c1.Weeks != 1 || c1.Anchor != "" {
		t.Fatalf("→1 should clear the cycle: %+v", c1)
	}

	// Two edits in one week compose: 1→2 then 2→3 on the same day keeps index 0
	// and the same anchor.
	c3b := ReanchoredCycle(now, c2, 3)
	if c3b.Anchor != c2.Anchor || c3b.WeekAt(now) != 0 {
		t.Fatalf("same-week compose drifted: %+v", c3b)
	}
}

// Resolve must pick the rule from the cycle week now falls in, never another
// week's rule for the same weekday — and its duplicate-row tie-break stays
// confined within one week.
func TestResolveSelectsTheCycleWeeksRule(t *testing.T) {
	loc := melbourne(t)
	cyc := Cycle{Weeks: 2, Anchor: "2026-09-06"}
	rules := []WeeklyRule{
		{ID: 1, Week: 0, Weekday: time.Monday, VehicleID: 10},
		{ID: 2, Week: 1, Weekday: time.Monday, VehicleID: 20},
	}
	week0Mon := time.Date(2026, 9, 7, 9, 0, 0, 0, loc)
	week1Mon := time.Date(2026, 9, 14, 9, 0, 0, 0, loc)
	if got := Resolve(week0Mon, cyc, rules, nil); got.VehicleID != 10 {
		t.Fatalf("week 0 Monday resolved %d, want 10", got.VehicleID)
	}
	if got := Resolve(week1Mon, cyc, rules, nil); got.VehicleID != 20 {
		t.Fatalf("week 1 Monday resolved %d, want 20", got.VehicleID)
	}
	// A weekday only rostered in the OTHER week is a gap, not a borrow.
	tue := []WeeklyRule{{ID: 3, Week: 1, Weekday: time.Tuesday, VehicleID: 30}}
	week0Tue := time.Date(2026, 9, 8, 9, 0, 0, 0, loc)
	if got := Resolve(week0Tue, cyc, tue, nil); got.Source != SourceNone {
		t.Fatalf("week 0 Tuesday borrowed week 1's rule: %+v", got)
	}
	// Duplicate rows within one week still break ties by highest ID; a higher ID
	// in the other week must not win.
	dup := []WeeklyRule{
		{ID: 5, Week: 0, Weekday: time.Monday, VehicleID: 50},
		{ID: 6, Week: 0, Weekday: time.Monday, VehicleID: 60},
		{ID: 9, Week: 1, Weekday: time.Monday, VehicleID: 90},
	}
	if got := Resolve(week0Mon, cyc, dup, nil); got.VehicleID != 60 {
		t.Fatalf("tie-break leaked across weeks: %+v", got)
	}
}

// NextChange must report a Sunday cycle flip as a change when the weeks roster
// different cars for that weekday — and stay quiet when they roster the same
// car (no write happens).
func TestNextChangeSeesCycleFlips(t *testing.T) {
	loc := melbourne(t)
	cyc := Cycle{Weeks: 2, Anchor: "2026-09-06"}
	now := time.Date(2026, 9, 12, 20, 0, 0, 0, loc) // Saturday evening, week 0
	diff := []WeeklyRule{
		{ID: 1, Week: 0, Weekday: time.Saturday, VehicleID: 10},
		{ID: 2, Week: 0, Weekday: time.Sunday, VehicleID: 10},
		{ID: 3, Week: 1, Weekday: time.Sunday, VehicleID: 20},
	}
	got := NextChange(now, 48*time.Hour, cyc, diff, nil)
	want := time.Date(2026, 9, 13, 0, 0, 0, 0, loc)
	if got == nil || !got.Equal(want) {
		t.Fatalf("cycle flip to a different car not reported: got %v, want %v", got, want)
	}
	// Same car both weeks: the flip is not a write. (Week 1 Sunday rosters the
	// same vehicle, and nothing else changes inside the horizon.)
	same := []WeeklyRule{
		{ID: 1, Week: 0, Weekday: time.Saturday, VehicleID: 10},
		{ID: 2, Week: 0, Weekday: time.Sunday, VehicleID: 10},
		{ID: 3, Week: 1, Weekday: time.Sunday, VehicleID: 10},
	}
	if got := NextChange(now, 30*time.Hour, cyc, same, nil); got != nil {
		t.Fatalf("same-car cycle flip wrongly reported as a write: %v", got)
	}
}
