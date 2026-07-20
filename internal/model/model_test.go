package model

import (
	"testing"
	"time"
)

func TestPermitInactive(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	now := mustTime(t, "2026-07-20 12:00 +1000")
	day := func(s string) time.Time { return mustTime(t, s+" 00:00 +1000") }
	cases := []struct {
		name string
		p    Permit
		want bool
	}{
		{"active granted", Permit{Status: "Granted", EndDate: day("2026-07-25")}, false},
		{"unknown (no data)", Permit{}, false},
		// Inclusive last day: still active THROUGH the EndDate day...
		{"expires today, still valid", Permit{Status: "Granted", EndDate: day("2026-07-20")}, false},
		// ...and retired only once the following day has begun.
		{"expired yesterday", Permit{Status: "Granted", EndDate: day("2026-07-19")}, true},
		// Word-boundary status match, not substring:
		{"cancelled status", Permit{Status: "Cancelled", EndDate: day("2026-07-25")}, true},
		{"suspended status", Permit{Status: "Suspended"}, true},
		{"expired status word", Permit{Status: "Expired"}, true},
		{"expiring is NOT dead", Permit{Status: "Expiring", EndDate: day("2026-07-25")}, false},
		{"due to expire is NOT dead", Permit{Status: "Due to expire", EndDate: day("2026-07-25")}, false},
		{"future end, live status", Permit{Status: "Current", EndDate: day("2026-07-25")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.p.Inactive(now, loc); got != c.want {
				t.Fatalf("Inactive = %v, want %v", got, c.want)
			}
		})
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	// A fixed offset keeps the test independent of tzdata availability.
	tm, err := time.Parse("2006-01-02 15:04 -0700", s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm
}

func TestResolve(t *testing.T) {
	// 2026-07-20 is a Monday, 2026-07-21 a Tuesday (AEST +1000).
	monday := mustTime(t, "2026-07-20 09:00 +1000")
	tuesday := mustTime(t, "2026-07-21 09:00 +1000")

	rules := []WeeklyRule{
		{ID: 1, Weekday: time.Monday, VehicleID: 10},
		{ID: 2, Weekday: time.Tuesday, VehicleID: 20},
	}

	t.Run("roster picks the weekday vehicle", func(t *testing.T) {
		if got := Resolve(monday, rules, nil); got.VehicleID != 10 || got.Source != SourceRoster {
			t.Fatalf("monday: got %+v, want vehicle 10 via roster", got)
		}
		if got := Resolve(tuesday, rules, nil); got.VehicleID != 20 || got.Source != SourceRoster {
			t.Fatalf("tuesday: got %+v, want vehicle 20 via roster", got)
		}
	})

	t.Run("no rule for the weekday resolves to none", func(t *testing.T) {
		sunday := mustTime(t, "2026-07-19 09:00 +1000")
		if got := Resolve(sunday, rules, nil); got.Source != SourceNone {
			t.Fatalf("sunday: got %+v, want none", got)
		}
	})

	t.Run("active override beats the roster", func(t *testing.T) {
		end := mustTime(t, "2026-07-20 18:00 +1000")
		ovr := []Override{{ID: 1, VehicleID: 99, StartsAt: mustTime(t, "2026-07-20 08:00 +1000"), EndsAt: &end}}
		if got := Resolve(monday, rules, ovr); got.VehicleID != 99 || got.Source != SourceOverride {
			t.Fatalf("override: got %+v, want vehicle 99 via override", got)
		}
	})

	t.Run("expired override is ignored", func(t *testing.T) {
		end := mustTime(t, "2026-07-20 08:30 +1000")
		ovr := []Override{{ID: 1, VehicleID: 99, StartsAt: mustTime(t, "2026-07-20 07:00 +1000"), EndsAt: &end}}
		if got := Resolve(monday, rules, ovr); got.VehicleID != 10 || got.Source != SourceRoster {
			t.Fatalf("expired override: got %+v, want fall back to roster vehicle 10", got)
		}
	})

	t.Run("most recently created override wins", func(t *testing.T) {
		// Both windows cover `monday`; the one booked later takes the wheel,
		// regardless of start time.
		ovr := []Override{
			{ID: 1, VehicleID: 55, StartsAt: mustTime(t, "2026-07-20 06:00 +1000"), CreatedAt: mustTime(t, "2026-07-19 09:00 +1000")},
			{ID: 2, VehicleID: 66, StartsAt: mustTime(t, "2026-07-20 08:00 +1000"), CreatedAt: mustTime(t, "2026-07-19 10:00 +1000")},
		}
		if got := Resolve(monday, rules, ovr); got.VehicleID != 66 {
			t.Fatalf("overlap: got %+v, want vehicle 66 (created latest)", got)
		}
	})

	t.Run("ad-hoc plate override wins with its literal registration", func(t *testing.T) {
		ovr := []Override{
			{ID: 1, Registration: "GUEST99", StartsAt: mustTime(t, "2026-07-20 08:00 +1000"), CreatedAt: mustTime(t, "2026-07-20 08:00 +1000")},
		}
		got := Resolve(monday, rules, ovr)
		if got.Source != SourceOverride || got.Registration != "GUEST99" || got.VehicleID != 0 {
			t.Fatalf("ad-hoc: got %+v, want registration GUEST99, no vehicle", got)
		}
	})

	t.Run("a later-created override beats an earlier one that starts later", func(t *testing.T) {
		// The guest scenario: a fresh activation (created now, starting now) must
		// win over a pre-existing booking whose window also covers `monday`, even
		// though that booking starts later in the day.
		ovr := []Override{
			{ID: 1, VehicleID: 55, StartsAt: mustTime(t, "2026-07-20 09:00 +1000"), CreatedAt: mustTime(t, "2026-07-19 09:00 +1000")},
			{ID: 2, VehicleID: 66, StartsAt: mustTime(t, "2026-07-20 08:00 +1000"), CreatedAt: mustTime(t, "2026-07-20 08:00 +1000")},
		}
		if got := Resolve(monday, rules, ovr); got.VehicleID != 66 {
			t.Fatalf("guest overlap: got %+v, want vehicle 66 (created latest)", got)
		}
	})
}
