package server

import (
	"testing"
	"time"
)

// TestAttemptForStaleness: the poll budget must resume from the reading's real
// age, so a page reload during a tenant outage cannot reset the spinner — the
// gap that made the honest "couldn't confirm" mark effectively unreachable
// (only a tab left open for the whole ~5-minute budget ever saw it).
func TestAttemptForStaleness(t *testing.T) {
	if got := attemptForStaleness(0); got != 0 {
		t.Fatalf("fresh reading: attempt = %d, want 0", got)
	}
	if got := attemptForStaleness(-time.Minute); got != 0 {
		t.Fatalf("negative staleness: attempt = %d, want 0", got)
	}
	// A minute of staleness lands mid-budget: some attempts consumed, some left.
	if got := attemptForStaleness(time.Minute); got <= 0 || got >= len(platePollDelays) {
		t.Fatalf("1 min stale: attempt = %d, want inside (0, %d)", got, len(platePollDelays))
	}
	// Stale for hours: the budget is spent, so the render shows "couldn't
	// confirm" immediately rather than a fresh spinner.
	if got := attemptForStaleness(3 * time.Hour); got != len(platePollDelays) {
		t.Fatalf("hours stale: attempt = %d, want the cap %d", got, len(platePollDelays))
	}
}

// TestArmPlatePollStampsToday: today's calendar cell must mirror the pill —
// a solid confident bar on a day whose change has not been confirmed is how a
// resident reads "covered" off a permit that has been failing for days.
func TestArmPlatePollStampsToday(t *testing.T) {
	mk := func() *permitView {
		return &permitView{
			Cal:      []calView{{DayLabel: "Sun 9"}, {DayLabel: "Mon 10", IsToday: true}, {DayLabel: "Tue 11"}},
			Applying: true, PlateRefreshing: true,
		}
	}

	// Mid-budget: today is marked applying, not unconfirmed.
	pv := mk()
	pv.armPlatePoll(0)
	if !pv.Cal[1].Applying || pv.Cal[1].Unconfirmed {
		t.Fatalf("mid-budget today = %+v, want Applying and not Unconfirmed", pv.Cal[1])
	}
	if pv.Cal[0].Applying || pv.Cal[2].Applying {
		t.Fatal("only today may carry the confirmation state")
	}

	// Budget exhausted (e.g. seeded by a long-stale reading): unconfirmed wins.
	pv = mk()
	pv.pollSeed = len(platePollDelays)
	pv.armPlatePoll(0)
	if !pv.PlateUnconfirmed || !pv.Cal[1].Unconfirmed || pv.Cal[1].Applying {
		t.Fatalf("exhausted budget: pill unconfirmed=%v today=%+v, want both unconfirmed", pv.PlateUnconfirmed, pv.Cal[1])
	}
	if pv.PollNext != 0 {
		t.Fatalf("exhausted budget must not arm another poll, PollNext=%d", pv.PollNext)
	}

	// Settled (nothing outstanding): no stamps, no marks.
	pv = mk()
	pv.Applying, pv.PlateRefreshing = false, false
	pv.armPlatePoll(0)
	if pv.Cal[1].Applying || pv.Cal[1].Unconfirmed || pv.PlateUnconfirmed {
		t.Fatalf("settled card must carry no warning state, today=%+v", pv.Cal[1])
	}
}
