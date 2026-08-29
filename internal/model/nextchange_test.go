package model

import (
	"testing"
	"time"
)

// The scenarios here pin NextChange to the scheduler's actual write behaviour:
// the watchdog warns a household during an outage IFF a tenant write was due,
// so a false "no change" hides a missed write (a car exposed to a fine) while a
// false "change" wakes a household whose permit was fine all along.

func melb(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestNextChangeRosterBoundary(t *testing.T) {
	loc := melb(t)
	// Monday noon; Monday=veh1, Tuesday=veh2 → the write is due at Tuesday 00:00.
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, loc) // a Monday
	rules := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 1},
		{ID: 2, Weekday: time.Tuesday, VehicleID: 2},
	}
	got := NextChange(now, 48*time.Hour, rules, nil)
	want := time.Date(2026, 8, 25, 0, 0, 0, 0, loc)
	if got == nil || !got.Equal(want) {
		t.Fatalf("next change = %v, want %v", got, want)
	}
}

func TestNextChangeSameCarConsecutiveDaysIsNoWrite(t *testing.T) {
	loc := melb(t)
	// The same car Monday AND Tuesday: midnight passes, no write is due — mailing
	// this household about an outage would be exactly the false alarm the design
	// is trying to kill.
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, loc)
	rules := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 1},
		{ID: 2, Weekday: time.Tuesday, VehicleID: 1},
	}
	if got := NextChange(now, 36*time.Hour, rules, nil); got != nil {
		t.Fatalf("same-car rollover reported a change at %v", got)
	}
}

func TestNextChangeGapLeavesPlateAlone(t *testing.T) {
	loc := melb(t)
	// Monday=veh1, Tuesday empty, Wednesday=veh1 again: the plate lingers through
	// the gap and Wednesday needs no write. Wednesday=veh2 would.
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, loc)
	same := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 1},
		{ID: 3, Weekday: time.Wednesday, VehicleID: 1},
	}
	if got := NextChange(now, 72*time.Hour, same, nil); got != nil {
		t.Fatalf("gap then the same car reported a change at %v", got)
	}
	diff := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 1},
		{ID: 3, Weekday: time.Wednesday, VehicleID: 2},
	}
	got := NextChange(now, 72*time.Hour, diff, nil)
	want := time.Date(2026, 8, 26, 0, 0, 0, 0, loc)
	if got == nil || !got.Equal(want) {
		t.Fatalf("gap then a different car = %v, want %v", got, want)
	}
}

func TestNextChangeBookingBoundaries(t *testing.T) {
	loc := melb(t)
	now := time.Date(2026, 8, 24, 8, 0, 0, 0, loc)
	rules := []WeeklyRule{{ID: 1, Weekday: time.Monday, VehicleID: 1}}
	start := time.Date(2026, 8, 24, 9, 0, 0, 0, loc)
	end := time.Date(2026, 8, 24, 17, 0, 0, 0, loc)
	booked := start.Add(-24 * time.Hour)
	ov := []Override{{ID: 1, VehicleID: 2, StartsAt: start, EndsAt: &end, CreatedAt: booked}}

	// The booking's start is the next write…
	got := NextChange(now, 24*time.Hour, rules, ov)
	if got == nil || !got.Equal(start) {
		t.Fatalf("next change = %v, want the booking start %v", got, start)
	}
	// …and once inside it, handing back to the roster car at 17:00 is the next.
	inside := time.Date(2026, 8, 24, 12, 0, 0, 0, loc)
	got = NextChange(inside, 24*time.Hour, rules, ov)
	if got == nil || !got.Equal(end) {
		t.Fatalf("next change from inside booking = %v, want its end %v", got, end)
	}
}

func TestNextChangeBookingOfRosterCarIsNoWrite(t *testing.T) {
	loc := melb(t)
	// Booking the car that the roster already has on: resolution flips source at
	// 09:00 but the plate never moves, so no write is due all day.
	now := time.Date(2026, 8, 24, 8, 0, 0, 0, loc)
	rules := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 1},
		{ID: 2, Weekday: time.Tuesday, VehicleID: 1},
	}
	start := time.Date(2026, 8, 24, 9, 0, 0, 0, loc)
	end := time.Date(2026, 8, 24, 17, 0, 0, 0, loc)
	ov := []Override{{ID: 1, VehicleID: 1, StartsAt: start, EndsAt: &end, CreatedAt: start.Add(-time.Hour)}}
	if got := NextChange(now, 36*time.Hour, rules, ov); got != nil {
		t.Fatalf("booking the rostered car reported a change at %v", got)
	}
}

func TestNextChangeAdHocPlateComparesNormalised(t *testing.T) {
	loc := melb(t)
	// Two back-to-back ad-hoc bookings of "the same" plate written differently
	// ("abc 123" vs "ABC123") are one plate on the wire — no second write.
	now := time.Date(2026, 8, 24, 8, 0, 0, 0, loc)
	mid := time.Date(2026, 8, 24, 12, 0, 0, 0, loc)
	end := time.Date(2026, 8, 24, 17, 0, 0, 0, loc)
	ov := []Override{
		{ID: 1, Registration: "abc 123", StartsAt: now.Add(-time.Hour), EndsAt: &mid, CreatedAt: now.Add(-2 * time.Hour)},
		{ID: 2, Registration: "ABC123", StartsAt: mid, EndsAt: &end, CreatedAt: now.Add(-time.Hour)},
	}
	if got := NextChange(now, 12*time.Hour, nil, ov); got != nil {
		t.Fatalf("re-spelt plate reported a change at %v", got)
	}
}

func TestNextChangeRespectsHorizon(t *testing.T) {
	loc := melb(t)
	// The change exists — Tuesday's car differs — but it is beyond the horizon,
	// and the watchdog must not be told about writes it isn't yet covering.
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, loc)
	rules := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 1},
		{ID: 2, Weekday: time.Tuesday, VehicleID: 2},
	}
	if got := NextChange(now, 6*time.Hour, rules, nil); got != nil {
		t.Fatalf("change beyond the horizon reported: %v", got)
	}
}

func TestNextChangeFromEmptyScheduleCountsFirstAllocation(t *testing.T) {
	loc := melb(t)
	// Nothing allocated now (the lingering plate is unknowable at this layer), so
	// the first future allocation is treated as a write — over-reporting by at
	// most one, in the harmless direction for an outage warning.
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, loc) // Monday, no Monday rule
	rules := []WeeklyRule{{ID: 2, Weekday: time.Tuesday, VehicleID: 2}}
	got := NextChange(now, 24*time.Hour, rules, nil)
	want := time.Date(2026, 8, 25, 0, 0, 0, 0, loc)
	if got == nil || !got.Equal(want) {
		t.Fatalf("first allocation from empty = %v, want %v", got, want)
	}
}
