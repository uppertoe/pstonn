package model

import (
	"testing"
	"time"
)

// A "clear" roster day is a scheduled state that ranks exactly like a rego's:
// a booking still running wins over it (a guest's overnight tap made the day
// before keeps its plate until the end of the next day, and only then does
// the day clear), a booking made on the day wins over it, and with nothing
// running the day resolves to clear. Nothing scheduled stays nothing scheduled.
func TestResolveClearDayRanksLikeARego(t *testing.T) {
	loc, _ := time.LoadLocation("Australia/Melbourne")
	// Saturday 19 Sep 2026 is the clear day; Friday has a rego.
	rules := []WeeklyRule{
		{ID: 1, Weekday: time.Friday, VehicleID: 7},
		{ID: 2, Weekday: time.Saturday, Empty: true},
	}
	fri := time.Date(2026, 9, 18, 20, 0, 0, 0, loc)
	satMorning := time.Date(2026, 9, 19, 9, 0, 0, 0, loc)
	satNight := time.Date(2026, 9, 19, 23, 30, 0, 0, loc)
	sun := time.Date(2026, 9, 20, 9, 0, 0, 0, loc)

	// No bookings: Friday's rego, Saturday clear, Sunday nothing scheduled.
	if r := Resolve(fri, Cycle{Weeks: 1}, rules, nil); r.VehicleID != 7 || r.Empty {
		t.Fatalf("friday = %+v", r)
	}
	if r := Resolve(satMorning, Cycle{Weeks: 1}, rules, nil); !r.Empty || r.Source != SourceRoster || r.VehicleID != 0 {
		t.Fatalf("saturday = %+v, want a clear roster day", r)
	}
	if r := Resolve(sun, Cycle{Weeks: 1}, rules, nil); r.Source != SourceNone || r.Empty {
		t.Fatalf("sunday = %+v, want nothing scheduled", r)
	}

	// An overnight guest booking made Friday evening runs to the end of
	// Saturday: it keeps its plate all Saturday, and the clear applies after.
	end := EndOfDay(fri.AddDate(0, 0, 1), loc) // end of Saturday
	overnight := []Override{{ID: 1, Registration: "GUEST1", StartsAt: fri, EndsAt: &end, CreatedBy: "guest", CreatedAt: fri}}
	if r := Resolve(satMorning, Cycle{Weeks: 1}, rules, overnight); r.Registration != "GUEST1" || r.Empty {
		t.Fatalf("saturday under an overnight booking = %+v, want the booking's plate", r)
	}
	if r := Resolve(satNight, Cycle{Weeks: 1}, rules, overnight); r.Registration != "GUEST1" || r.Empty {
		t.Fatalf("late saturday under an overnight booking = %+v", r)
	}
	if r := Resolve(end, Cycle{Weeks: 1}, rules, overnight); r.Source != SourceNone {
		t.Fatalf("sunday after the booking = %+v, want nothing scheduled", r)
	}
	// The switch from the booking's plate to "clear" on a clear day IS a write
	// the watchdog counts; here the booking ends into Sunday, which schedules
	// nothing, so no write is due in the horizon after Saturday morning.
	if next := NextChange(satMorning, 48*time.Hour, Cycle{Weeks: 1}, rules, overnight); next != nil {
		t.Fatalf("next change = %v, want none (the booking ends into an unscheduled day)", next)
	}
	// Whereas a booking ending mid-Saturday hands back to the clear day: a write.
	mid := time.Date(2026, 9, 19, 14, 0, 0, 0, loc)
	short := []Override{{ID: 2, Registration: "GUEST1", StartsAt: fri, EndsAt: &mid, CreatedBy: "guest", CreatedAt: fri}}
	if next := NextChange(satMorning, 48*time.Hour, Cycle{Weeks: 1}, rules, short); next == nil || !next.Equal(mid) {
		t.Fatalf("next change = %v, want %v (the clear day resumes)", next, mid)
	}
	// An empty booking made on a rego day clears it while it runs.
	clearEnd := time.Date(2026, 9, 18, 22, 0, 0, 0, loc)
	clearing := []Override{{ID: 3, Empty: true, StartsAt: fri, EndsAt: &clearEnd, CreatedBy: "owner", CreatedAt: fri}}
	if r := Resolve(fri, Cycle{Weeks: 1}, rules, clearing); !r.Empty || r.Source != SourceOverride {
		t.Fatalf("friday under a clearing booking = %+v", r)
	}
}
