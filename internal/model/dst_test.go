package model

import (
	"testing"
	"time"
)

// Melbourne 2026 transitions, which every case below is built around:
//
//	DST ENDS   Sun 2026-04-05: 03:00 AEDT → 02:00 AEST, so 02:00-02:59 happens TWICE.
//	           That Sunday is 25 hours long.
//	DST STARTS Sun 2026-10-04: 02:00 AEST → 03:00 AEDT, so 02:00-02:59 never exists.
//	           That Sunday is 23 hours long.
//
// This app's whole job is wall-clock scheduling in this zone, and until now no test
// had ever loaded it across a transition. A day that is not 24 hours long is exactly
// where "the permit expired a day early" and "the guest pass ended at the wrong
// moment" come from, and both of those are a real parking fine.
func melbourne(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatalf("load Australia/Melbourne (the tzdata embed in main.go should make this work anywhere): %v", err)
	}
	return loc
}

// Sanity-check the fixture itself. If these two facts ever stop holding, every test
// below is quietly testing nothing, so assert them explicitly rather than trusting
// the zone database to match the comment above.
func TestMelbourneTransitionsAreWhereWeThink(t *testing.T) {
	loc := melbourne(t)

	// 2026-10-04 is 23 hours long: midnight to midnight spans 23h.
	startDay := time.Date(2026, 10, 4, 0, 0, 0, 0, loc)
	nextDay := time.Date(2026, 10, 5, 0, 0, 0, 0, loc)
	if got := nextDay.Sub(startDay); got != 23*time.Hour {
		t.Errorf("2026-10-04 is %v long, want 23h (spring forward)", got)
	}

	// 2026-04-05 is 25 hours long.
	endDay := time.Date(2026, 4, 5, 0, 0, 0, 0, loc)
	endNext := time.Date(2026, 4, 6, 0, 0, 0, 0, loc)
	if got := endNext.Sub(endDay); got != 25*time.Hour {
		t.Errorf("2026-04-05 is %v long, want 25h (fall back)", got)
	}
}

// ExpiryDeadline is "the instant the permit's final day is over". On a 23- or
// 25-hour day that is still the next local midnight, NOT 24 hours after the start —
// getting this wrong retires a live permit early (so its plate stops being kept
// right, which is the fine) or keeps a dead one a day too long.
func TestExpiryDeadlineAcrossTransitions(t *testing.T) {
	loc := melbourne(t)

	cases := []struct {
		name    string
		endDate time.Time
		want    time.Time
		wantLen time.Duration // length of the permit's final local day
	}{
		{
			// The council sends a bare date, which the store parses as UTC midnight.
			name:    "final day is the 23-hour spring-forward day",
			endDate: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC),
			want:    time.Date(2026, 10, 5, 0, 0, 0, 0, loc),
			wantLen: 23 * time.Hour,
		},
		{
			name:    "final day is the 25-hour fall-back day",
			endDate: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC),
			want:    time.Date(2026, 4, 6, 0, 0, 0, 0, loc),
			wantLen: 25 * time.Hour,
		},
		{
			name:    "an ordinary 24-hour day still behaves",
			endDate: time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC),
			want:    time.Date(2026, 6, 16, 0, 0, 0, 0, loc),
			wantLen: 24 * time.Hour,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExpiryDeadline(c.endDate, loc)
			if !got.Equal(c.want) {
				t.Fatalf("ExpiryDeadline = %s, want %s", got, c.want)
			}
			// The deadline must be the next local midnight, so the final day's length is
			// whatever the zone says it is — never a hardcoded 24h.
			dayStart := time.Date(c.endDate.Year(), c.endDate.Month(), c.endDate.Day(), 0, 0, 0, 0, loc)
			if l := got.Sub(dayStart); l != c.wantLen {
				t.Errorf("the final day measured %v, want %v — the deadline is not tracking the local day", l, c.wantLen)
			}
		})
	}
}

// The permit must stay active for every moment of its last local day, including the
// repeated 02:30 on the fall-back day and right up to one second before midnight.
func TestInactiveHoldsThroughTheWholeFinalDay(t *testing.T) {
	loc := melbourne(t)

	// Final day = the 25-hour day, so there are two distinct 02:30 instants.
	p := Permit{EndDate: time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), Status: "Approved"}

	firstTwoThirty := time.Date(2026, 4, 4, 15, 30, 0, 0, time.UTC)  // 02:30 AEDT on the 5th
	secondTwoThirty := time.Date(2026, 4, 4, 16, 30, 0, 0, time.UTC) // 02:30 AEST on the 5th
	if firstTwoThirty.In(loc).Hour() != 2 || secondTwoThirty.In(loc).Hour() != 2 {
		t.Fatalf("fixture wrong: %s and %s should both be 02:xx local",
			firstTwoThirty.In(loc), secondTwoThirty.In(loc))
	}

	for _, now := range []time.Time{
		time.Date(2026, 4, 5, 0, 0, 0, 0, loc),    // first instant of the final day
		firstTwoThirty,                            // 02:30 the first time round
		secondTwoThirty,                           // 02:30 the second time round
		time.Date(2026, 4, 5, 23, 59, 59, 0, loc), // last second of the final day
	} {
		if p.Inactive(now, loc) {
			t.Errorf("permit reported inactive at %s (local %s) — it is still valid that day",
				now, now.In(loc))
		}
	}

	// And it IS finished once the next local day has begun.
	if !p.Inactive(time.Date(2026, 4, 6, 0, 0, 0, 0, loc), loc) {
		t.Error("permit should be inactive once the day after EndDate has started locally")
	}
}

// Same on the short day: a 23-hour final day must not end an hour early.
func TestInactiveOnTheSpringForwardDay(t *testing.T) {
	loc := melbourne(t)
	p := Permit{EndDate: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC), Status: "Approved"}

	if p.Inactive(time.Date(2026, 10, 4, 23, 59, 59, 0, loc), loc) {
		t.Error("permit reported inactive in the last second of its 23-hour final day")
	}
	if !p.Inactive(time.Date(2026, 10, 5, 0, 0, 0, 0, loc), loc) {
		t.Error("permit should be inactive once 5 Oct has begun locally")
	}
}

// A weekly rule is day-granular and keyed on now.Weekday(). Across a transition the
// local calendar day must be what decides, so a Sunday rule fires for every instant
// of that Sunday however many hours it has.
func TestWeeklyRuleResolvesByLocalDayAcrossTransitions(t *testing.T) {
	loc := melbourne(t)
	rules := []WeeklyRule{{Weekday: time.Sunday, VehicleID: 7}}

	for _, name := range []string{"spring forward 2026-10-04", "fall back 2026-04-05"} {
		var day time.Time
		if name[0] == 's' {
			day = time.Date(2026, 10, 4, 0, 0, 0, 0, loc)
		} else {
			day = time.Date(2026, 4, 5, 0, 0, 0, 0, loc)
		}
		t.Run(name, func(t *testing.T) {
			// Walk the whole local day in real hours; every instant is still that Sunday.
			end := day.AddDate(0, 0, 1)
			for now := day; now.Before(end); now = now.Add(time.Hour) {
				// Resolve reads now.Weekday(), so the caller must hand it a local time — every
				// call site in the app converts first, and this asserts why that matters.
				local := now.In(loc)
				res := Resolve(local, rules, nil)
				if res.Source != SourceRoster || res.VehicleID != 7 {
					t.Fatalf("at %s (local %s, weekday %s) the Sunday rule did not fire: %+v",
						now, local, local.Weekday(), res)
				}
			}
		})
	}
}

// A nonexistent local time cannot be represented, so time.Date normalises it. The
// app must not end up with a booking that silently never fires; assert what actually
// happens so the behaviour is pinned rather than assumed.
func TestNonexistentLocalTimeNormalisesForward(t *testing.T) {
	loc := melbourne(t)
	// 02:30 on 2026-10-04 does not exist.
	got := time.Date(2026, 10, 4, 2, 30, 0, 0, loc)
	if got.In(loc).Hour() == 2 {
		t.Fatalf("02:30 should not exist on 2026-10-04; got %s", got.In(loc))
	}
	// Go resolves it to the same absolute instant 02:30 AEST would have been, which
	// presents as 03:30 AEDT — an hour later on the clock, not a dropped booking.
	if h, m := got.In(loc).Hour(), got.In(loc).Minute(); h != 3 || m != 30 {
		t.Errorf("2026-10-04 02:30 normalised to %s, expected 03:30 local", got.In(loc))
	}
	// The important property for this app: it is a real instant on the right day, so a
	// booking made for it still resolves rather than vanishing.
	if got.In(loc).Day() != 4 {
		t.Errorf("normalised instant landed on day %d, want 4", got.In(loc).Day())
	}
}

// An ambiguous local time resolves to one of the two; either is fine, but it must be
// a real instant on the right day so the booking still fires.
func TestAmbiguousLocalTimeResolvesToARealInstant(t *testing.T) {
	loc := melbourne(t)
	got := time.Date(2026, 4, 5, 2, 30, 0, 0, loc) // happens twice
	local := got.In(loc)
	if local.Hour() != 2 || local.Minute() != 30 {
		t.Fatalf("2026-04-05 02:30 resolved to %s, expected an 02:30", local)
	}
	if local.Day() != 5 {
		t.Errorf("landed on day %d, want 5", local.Day())
	}
}

// Resolve's window boundaries are documented as start-inclusive and end-exclusive.
// Only "clearly inside / clearly outside" was covered before, and the boundary is
// where a plate is either applied a moment too early or dropped a moment too late.
func TestResolveWindowBoundariesToTheSecond(t *testing.T) {
	loc := melbourne(t)
	start := time.Date(2026, 6, 15, 9, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)

	rules := []WeeklyRule{{Weekday: start.Weekday(), VehicleID: 1}}
	overrides := []Override{{
		ID: 10, VehicleID: 2, StartsAt: start, EndsAt: &end,
		CreatedAt: start.Add(-time.Hour), CreatedBy: "someone@example.com",
	}}

	cases := []struct {
		name       string
		now        time.Time
		wantSource Source
		wantVeh    int64
	}{
		{"one second before the start, the roster still holds", start.Add(-time.Second), SourceRoster, 1},
		{"exactly at the start, the booking takes over (inclusive)", start, SourceOverride, 2},
		{"one second after the start", start.Add(time.Second), SourceOverride, 2},
		{"one second before the end, still the booking", end.Add(-time.Second), SourceOverride, 2},
		{"exactly at the end, the booking is over (exclusive)", end, SourceRoster, 1},
		{"one second after the end", end.Add(time.Second), SourceRoster, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Resolve(c.now, rules, overrides)
			if res.Source != c.wantSource || res.VehicleID != c.wantVeh {
				t.Errorf("at %s got %+v, want source %v vehicle %d", c.now.In(loc), res, c.wantSource, c.wantVeh)
			}
		})
	}
}

// CreatedAt is only second-precision, so two bookings made in the same second tie —
// and "freshest wins" has to stay deterministic rather than depending on scan order.
func TestResolveTieBreaksOnIDWhenCreatedAtMatches(t *testing.T) {
	loc := melbourne(t)
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, loc)
	created := now.Add(-time.Minute)
	start := now.Add(-time.Hour)

	lower := Override{ID: 5, VehicleID: 50, StartsAt: start, CreatedAt: created}
	higher := Override{ID: 6, VehicleID: 60, StartsAt: start, CreatedAt: created}

	// Both orderings must give the same answer, or the result depends on scan order.
	for _, ovs := range [][]Override{{lower, higher}, {higher, lower}} {
		res := Resolve(now, nil, ovs)
		if res.VehicleID != 60 {
			t.Errorf("tie broke to vehicle %d, want 60 (the higher ID = later insert)", res.VehicleID)
		}
	}
}

// An open-ended booking has no end, so it must beat the roster indefinitely —
// including across a transition, where a naive "start + 24h" would expire it.
func TestOpenEndedOverrideSurvivesATransition(t *testing.T) {
	loc := melbourne(t)
	start := time.Date(2026, 10, 3, 20, 0, 0, 0, loc) // the evening before spring forward
	ovs := []Override{{ID: 1, VehicleID: 9, StartsAt: start, CreatedAt: start}}
	rules := []WeeklyRule{{Weekday: time.Sunday, VehicleID: 1}}

	for _, now := range []time.Time{
		start.Add(time.Hour),
		time.Date(2026, 10, 4, 1, 0, 0, 0, loc),  // before the jump
		time.Date(2026, 10, 4, 4, 0, 0, 0, loc),  // after the jump
		time.Date(2026, 10, 6, 12, 0, 0, 0, loc), // days later
	} {
		res := Resolve(now, rules, ovs)
		if res.Source != SourceOverride || res.VehicleID != 9 {
			t.Errorf("at %s the open-ended booking stopped winning: %+v", now.In(loc), res)
		}
	}
}
