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

func TestFindDisplaced(t *testing.T) {
	now := mustTime(t, "2026-07-20 12:00 +1000")
	end := mustTime(t, "2026-07-20 23:59 +1000")
	live := func(id int64, vehicleID int64, reg, by string, created time.Time) Override {
		return Override{ID: id, VehicleID: vehicleID, Registration: reg,
			StartsAt: mustTime(t, "2026-07-20 08:00 +1000"), EndsAt: &end, CreatedBy: by, CreatedAt: created}
	}
	vehicles := map[int64]VehicleInfo{
		5: {Registration: "MUM123", Label: "Mum's car", Email: "nanny@example.com"},
		6: {Registration: "NOMAIL1", Label: "Spare"},
	}
	members := []string{"owner@example.com", "partner@example.com"}
	early := mustTime(t, "2026-07-20 09:00 +1000")
	later := mustTime(t, "2026-07-20 10:00 +1000")

	t.Run("guest booker is warned", func(t *testing.T) {
		ovr := []Override{live(1, 0, "GUEST99", "pa@example.com", early)}
		got := FindDisplaced(ovr, vehicles, "GUEST99", "beast-driver@example.com", members, now)
		if got.Reg != "GUEST99" || got.Contact != "pa@example.com" {
			t.Fatalf("got %+v, want pa@example.com warned", got)
		}
	})
	t.Run("whitespace variant of the departing plate still matches", func(t *testing.T) {
		// The plate we changed away from is reported by the council as "GUEST 99",
		// the booking stored it as "GUEST99". Same car, so the booker must still be
		// warned — under strings.EqualFold the space made them differ and the warning
		// was silently dropped.
		ovr := []Override{live(1, 0, "GUEST99", "pa@example.com", early)}
		got := FindDisplaced(ovr, vehicles, "GUEST 99", "beast-driver@example.com", members, now)
		if got.Contact != "pa@example.com" {
			t.Fatalf("got %+v, want pa@example.com warned despite the whitespace difference", got)
		}
	})
	t.Run("self-displacement across channels is quiet", func(t *testing.T) {
		// Pa swaps his own citroen for his own beast: same email, so no warning —
		// even when the two bookings came through different links or channels.
		ovr := []Override{live(1, 0, "GUEST99", "pa@example.com", early)}
		if got := FindDisplaced(ovr, vehicles, "GUEST99", "PA@example.com", members, now); got != (DisplacedBooking{}) {
			t.Fatalf("got %+v, want quiet", got)
		}
	})
	t.Run("member booking of a saved car warns the attached driver", func(t *testing.T) {
		// Borrowed-car case: a member booked mum's car on the driver's behalf.
		ovr := []Override{live(1, 5, "", "owner@example.com", early)}
		got := FindDisplaced(ovr, vehicles, "MUM123", "", members, now)
		if got.Contact != "nanny@example.com" {
			t.Fatalf("got %+v, want nanny@example.com warned", got)
		}
	})
	t.Run("guest booker beats the vehicle's attached email", func(t *testing.T) {
		// The person who tapped the link is more likely the one parked than the
		// car's usual driver.
		ovr := []Override{live(1, 5, "", "pa@example.com", early)}
		got := FindDisplaced(ovr, vehicles, "MUM123", "", members, now)
		if got.Contact != "pa@example.com" {
			t.Fatalf("got %+v, want pa@example.com warned", got)
		}
	})
	t.Run("member's own booking with no driver email is quiet", func(t *testing.T) {
		ovr := []Override{live(1, 6, "", "owner@example.com", early)}
		if got := FindDisplaced(ovr, vehicles, "NOMAIL1", "", members, now); got != (DisplacedBooking{}) {
			t.Fatalf("got %+v, want quiet (fanout covers the member)", got)
		}
	})
	t.Run("vehicle email that is a member is quiet", func(t *testing.T) {
		veh := map[int64]VehicleInfo{5: {Registration: "MUM123", Email: "partner@example.com"}}
		ovr := []Override{live(1, 5, "", "visitor (QR)", early)}
		if got := FindDisplaced(ovr, veh, "MUM123", "", members, now); got != (DisplacedBooking{}) {
			t.Fatalf("got %+v, want quiet (fanout covers the member)", got)
		}
	})
	t.Run("unreachable booking reports the plate with no contact", func(t *testing.T) {
		ovr := []Override{live(1, 0, "VIS777", "visitor (printed QR)", early)}
		got := FindDisplaced(ovr, vehicles, "VIS777", "", members, now)
		if got.Reg != "VIS777" || got.Contact != "" {
			t.Fatalf("got %+v, want VIS777 with no contact", got)
		}
	})
	t.Run("annotated CreatedBy still yields a clean address", func(t *testing.T) {
		ovr := []Override{live(1, 0, "GUEST99", "pa@example.com (undo)", early)}
		got := FindDisplaced(ovr, vehicles, "GUEST99", "", members, now)
		if got.Contact != "pa@example.com" {
			t.Fatalf("got %+v, want pa@example.com (annotation stripped)", got)
		}
	})
	t.Run("newest matching booking decides the contact", func(t *testing.T) {
		ovr := []Override{
			live(1, 0, "GUEST99", "old@example.com", early),
			live(2, 0, "GUEST99", "recent@example.com", later),
		}
		got := FindDisplaced(ovr, vehicles, "GUEST99", "", members, now)
		if got.Contact != "recent@example.com" {
			t.Fatalf("got %+v, want the newest booking's contact", got)
		}
	})
	t.Run("no live booking for the plate is quiet", func(t *testing.T) {
		ovr := []Override{live(1, 0, "GUEST99", "pa@example.com", early)}
		if got := FindDisplaced(ovr, vehicles, "ROSTER1", "", members, now); got != (DisplacedBooking{}) {
			t.Fatalf("got %+v, want quiet (roster/external plate)", got)
		}
	})
}

// TestSamePlate (F5): one rule for "is this the same car?", because the sites that
// decide "does the council need writing to?" and "has the plate changed?" must not
// disagree. When they did, a case-only echo from the portal drove a real council
// write, a "your permit was updated" notification and a displaced-driver email for
// a change that changed nothing.
func TestSamePlate(t *testing.T) {
	same := []struct{ a, b string }{
		{"ABC123", "abc123"},
		{"ABC123", "AbC123"},
		{"ABC123", "ABC 123"},      // the portal echoes back whatever spacing was typed
		{"ABC123", " ABC123 "},     // ...and whatever padding
		{"ABC123", "ABC-123"},      // display separators are not part of the rego
		{"ABC123", "ABC·123"},      // ...in any script
		{"ABC123", "ABC 123"},      // a pasted plate carries the source's whitespace (NBSP)
		{"ABC123", "ABC\t123\r\n"}, // ...or a copied table cell's
		{"", ""},                   // both unknown
	}
	for _, c := range same {
		if !SamePlate(c.a, c.b) {
			t.Errorf("SamePlate(%q, %q) = false, want true", c.a, c.b)
		}
	}
	// Anything beyond case and spacing is a genuinely different car, and treating it
	// as the same one would leave a car uncovered — the failure that costs a fine.
	notSame := []struct{ a, b string }{
		{"ABC123", "ABC124"},
		{"ABC123", "ABC12"},
		{"ABC123", ""},
		{"AB1C23", "ABC123"},
	}
	for _, c := range notSame {
		if SamePlate(c.a, c.b) {
			t.Errorf("SamePlate(%q, %q) = true, want false", c.a, c.b)
		}
	}
}

// TestExpiryDeadline (F7): EndDate is the INCLUSIVE last valid day, reported by the
// council as a zoneless date we parse as UTC midnight. Anything comparing `now`
// against that bare instant treats the permit as finished from ~10-11am Melbourne
// time on its final valid day, while it is still live and still needs its plate
// kept right.
func TestExpiryDeadline(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	end := mustTime(t, "2026-07-20 00:00 +0000") // how the council date arrives
	got := ExpiryDeadline(end, loc)
	if want := mustTime(t, "2026-07-21 00:00 +1000"); !got.Equal(want) {
		t.Fatalf("ExpiryDeadline = %s, want %s", got, want)
	}
	// The instant the old bare-instant compare went quiet is still well inside the
	// permit's life.
	lateOnTheLastDay := mustTime(t, "2026-07-20 22:00 +1000")
	if !lateOnTheLastDay.Before(got) {
		t.Fatal("10pm on the last valid day must still be before the deadline")
	}
	// Same boundary Inactive uses, so nothing can be "expired" for one check and
	// "live" for the other.
	p := Permit{Status: "Granted", EndDate: end}
	if p.Inactive(lateOnTheLastDay, loc) {
		t.Fatal("Inactive and ExpiryDeadline disagree about the last valid day")
	}
	if !p.Inactive(got, loc) {
		t.Fatal("a permit must be inactive from its deadline onward")
	}
}

// The rollover spread delays only CLOCK-driven changes; a change someone is
// waiting on must never be delayed. Resolve draws that line via Scheduled/Since,
// and the equality boundary — a booking whose start time is exactly when it was
// created ("start now") — must land on the immediate side.
func TestResolveScheduledClassification(t *testing.T) {
	monday := mustTime(t, "2026-07-20 09:00 +1000")
	rules := []WeeklyRule{{ID: 1, Weekday: time.Monday, VehicleID: 10}}

	t.Run("roster is scheduled from local midnight", func(t *testing.T) {
		got := Resolve(monday, rules, nil)
		if !got.Scheduled {
			t.Fatal("a roster day is clock-driven and must be Scheduled")
		}
		if midnight := mustTime(t, "2026-07-20 00:00 +1000"); !got.Since.Equal(midnight) {
			t.Fatalf("roster Since = %s, want local midnight %s", got.Since, midnight)
		}
	})

	t.Run("advance booking is scheduled from its start", func(t *testing.T) {
		start := mustTime(t, "2026-07-20 08:00 +1000")
		ovr := []Override{{ID: 1, VehicleID: 99, StartsAt: start, CreatedAt: mustTime(t, "2026-07-19 10:00 +1000")}}
		got := Resolve(monday, rules, ovr)
		if !got.Scheduled || !got.Since.Equal(start) {
			t.Fatalf("advance booking: Scheduled=%v Since=%s, want true from %s", got.Scheduled, got.Since, start)
		}
	})

	t.Run("start == created is immediate, not scheduled (the boundary)", func(t *testing.T) {
		now := mustTime(t, "2026-07-20 08:00 +1000")
		ovr := []Override{{ID: 1, VehicleID: 99, StartsAt: now, CreatedAt: now}}
		got := Resolve(monday, rules, ovr)
		if got.Scheduled {
			t.Fatal("a booking that starts exactly when it was made is immediate — someone is waiting — and must NOT be spread")
		}
		if !got.Since.Equal(now) {
			t.Fatalf("immediate booking Since = %s, want the creation time %s", got.Since, now)
		}
	})

	t.Run("backdated booking (start before created) is immediate", func(t *testing.T) {
		created := mustTime(t, "2026-07-20 08:00 +1000")
		ovr := []Override{{ID: 1, VehicleID: 99, StartsAt: mustTime(t, "2026-07-20 06:00 +1000"), CreatedAt: created}}
		got := Resolve(monday, rules, ovr)
		if got.Scheduled || !got.Since.Equal(created) {
			t.Fatalf("backdated booking: Scheduled=%v Since=%s, want immediate from %s", got.Scheduled, got.Since, created)
		}
	})
}

// If the data ever holds two roster rules for one weekday, the winner must be
// deterministic (highest ID), not dependent on query row order.
func TestRosterTieBreakIsDeterministic(t *testing.T) {
	now := mustTime(t, "2026-07-20 12:00 +1000")
	wd := now.Weekday()
	rules := []WeeklyRule{{ID: 1, Weekday: wd, VehicleID: 10}, {ID: 2, Weekday: wd, VehicleID: 20}}
	if res := Resolve(now, rules, nil); res.Source != SourceRoster || res.VehicleID != 20 {
		t.Fatalf("tie-break picked vehicle %d (source %v), want the highest-ID rule's 20", res.VehicleID, res.Source)
	}
	// Order-independent: the reversed slice yields the same winner.
	if res := Resolve(now, []WeeklyRule{{ID: 2, Weekday: wd, VehicleID: 20}, {ID: 1, Weekday: wd, VehicleID: 10}}, nil); res.VehicleID != 20 {
		t.Fatalf("winner depended on slice order: got %d", res.VehicleID)
	}
}
