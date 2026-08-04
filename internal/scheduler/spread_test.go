package scheduler

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// The rollover spread exists to stop every household's midnight roster change
// leaving this one IP at once. Its whole risk is that it delays the WRONG thing:
// a change somebody is standing there waiting for. These tests pin both halves —
// scheduled changes are staggered, live ones never are.

// spreadScheduler builds a scheduler with a configured window cap and a fleet of
// n permits. The fleet matters: the effective window scales with it, so a test
// that forgot to set it would be exercising a disabled spread.
func spreadScheduler(window time.Duration, n int64) *Scheduler {
	s := &Scheduler{spreadWindow: window, opDrain: 3 * time.Second, interval: time.Minute}
	s.fleetSize.Store(n)
	return s
}

// A booking or guest activation that takes effect the moment it is made must go on
// the next tick. Delaying it by up to a window is the one outcome that would make
// the app feel broken: the user watches the dashboard and nothing happens.
func TestSpreadNeverDelaysALiveChange(t *testing.T) {
	s := spreadScheduler(60*time.Minute, 500)
	now := time.Now()
	live := model.Resolution{Source: model.SourceOverride, Since: now, Scheduled: false}
	// Every permit id, not a sampled few: a hash that happened to give one id a
	// zero offset would hide the bug for exactly the ids the test tried.
	for id := int64(1); id <= 500; id++ {
		if !s.spreadElapsed(id, live, now) {
			t.Fatalf("permit %d had a live user change delayed by the rollover spread", id)
		}
	}
}

// The point of the exercise: at the boundary itself, almost nothing should be
// eligible. If most permits fire immediately the burst is unchanged.
func TestSpreadStaggersAScheduledRollover(t *testing.T) {
	// 500 permits * 3s * 2 = 50m of wanted window, under the 60m cap, so the fleet
	// sets the window and the cap does not bind.
	const window = 50 * time.Minute
	s := spreadScheduler(60*time.Minute, 500)
	midnight := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	roster := model.Resolution{Source: model.SourceRoster, Since: midnight, Scheduled: true}

	const n = 500
	eligibleAt := func(d time.Duration) int {
		c := 0
		for id := int64(1); id <= n; id++ {
			if s.spreadElapsed(id, roster, midnight.Add(d)) {
				c++
			}
		}
		return c
	}

	// At the boundary the burst must be a trickle, not a stampede.
	if got := eligibleAt(0); got > n/20 {
		t.Errorf("%d/%d permits fired at the boundary itself; the spread is not spreading", got, n)
	}
	// Roughly uniform: halfway through the window, roughly half are eligible.
	if got := eligibleAt(window / 2); got < n*2/5 || got > n*3/5 {
		t.Errorf("at half the window %d/%d were eligible, want roughly half — the offsets are not uniform", got, n)
	}
	// And nothing is stranded: by the end of the window every permit has had its turn.
	if got := eligibleAt(window); got != n {
		t.Errorf("only %d/%d permits were eligible after the full window; some would be stranded", got, n)
	}
}

// S14: a short advance booking must never be starved by a spread slot that lands
// after it ends. With a wide window (large fleet) the offset can exceed a brief
// booking's whole life; without the clamp such a booking would be held past its end,
// never applied and never reported, then silently dropped. Every permit's short
// booking must be eligible for at least one minute of its window.
func TestSpreadNeverStarvesAShortBooking(t *testing.T) {
	// A 60m window: offsets spread across the whole hour, so ~half the fleet draws a
	// slot beyond a 30-minute booking.
	s := spreadScheduler(60*time.Minute, 450)
	start := time.Date(2026, 8, 1, 23, 50, 0, 0, time.UTC)
	end := start.Add(30 * time.Minute)
	booking := model.Resolution{Source: model.SourceOverride, Since: start, Scheduled: true, Until: &end}
	for id := int64(1); id <= 450; id++ {
		eligible := false
		for m := 0; m <= 30; m++ {
			if s.spreadElapsed(id, booking, start.Add(time.Duration(m)*time.Minute)) {
				eligible = true
				break
			}
		}
		if !eligible {
			t.Fatalf("permit %d: a 30-minute booking was never eligible in its whole window (starved by its spread slot)", id)
		}
	}
}

// A permit must keep the SAME slot every day. A fresh draw each rollover would
// re-pile permits at random and, worse, let one permit sit near the end of the
// window repeatedly by luck.
func TestSpreadOffsetIsStablePerPermit(t *testing.T) {
	s := spreadScheduler(60*time.Minute, 500)
	const window = 50 * time.Minute
	for id := int64(1); id <= 100; id++ {
		first := s.spreadOffset(id, window)
		for i := 0; i < 5; i++ {
			if got := s.spreadOffset(id, window); got != first {
				t.Fatalf("permit %d drew offset %s then %s; slots must be stable across restarts and days", id, first, got)
			}
		}
		if first < 0 || first >= window {
			t.Fatalf("permit %d offset %s is outside the window", id, first)
		}
	}
}

// Disabling the window must restore the old behaviour exactly, so an operator can
// turn the whole thing off if it ever misbehaves.
func TestSpreadDisabledAppliesImmediately(t *testing.T) {
	s := spreadScheduler(0, 500)
	midnight := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	roster := model.Resolution{Source: model.SourceRoster, Since: midnight, Scheduled: true}
	for id := int64(1); id <= 200; id++ {
		if !s.spreadElapsed(id, roster, midnight) {
			t.Fatalf("permit %d was delayed with the spread disabled", id)
		}
	}
}

// A clock that jumps backwards must not strand a permit behind a negative
// interval, and a resolution with no known start must not be held at all.
func TestSpreadIsSafeOnOddInputs(t *testing.T) {
	s := spreadScheduler(60*time.Minute, 500)
	now := time.Now()
	if !s.spreadElapsed(1, model.Resolution{Source: model.SourceRoster, Since: now.Add(time.Hour), Scheduled: true}, now) {
		t.Error("a Since in the future (clock skew) held a change back")
	}
	if !s.spreadElapsed(1, model.Resolution{Source: model.SourceRoster, Scheduled: true}, now) {
		t.Error("a zero Since held a change back")
	}
}

// The bound is what the operator is told at startup, so it has to be right about
// which limit is binding: below permits*opDrain the serial drain dominates and
// the window is smoothing nothing.
func TestRolloverBoundReportsTheBindingLimit(t *testing.T) {
	s := spreadScheduler(60*time.Minute, 500)

	// 500 permits: 25m drain, wanted window 50m, under the 60m cap -> spreading.
	if bound, spreading := s.RolloverBound(500); !spreading || bound != 50*time.Minute+time.Minute {
		t.Errorf("500 permits: bound %s spreading=%v, want 51m and spreading", bound, spreading)
	}
	// 1500 permits: 75m drain, wanted window 150m but capped at 60m — the cap is now
	// BELOW the drain, so the window is no longer smoothing and must say so.
	if bound, spreading := s.RolloverBound(1500); spreading || bound != 75*time.Minute+time.Minute {
		t.Errorf("1500 permits: bound %s spreading=%v, want 76m and NOT spreading", bound, spreading)
	}
	if bound, _ := s.RolloverBound(0); bound != 0 {
		t.Errorf("no permits should bound at 0, got %s", bound)
	}
}

// A small deployment has no herd to smooth: a handful of changes drain in seconds.
// Scaling the window to the fleet is what stops the spread delaying every midnight
// rollover by the full configured cap to solve a problem that does not exist.
func TestSpreadIsNegligibleForASmallFleet(t *testing.T) {
	s := spreadScheduler(60*time.Minute, 5) // 5 * 3s * 2 = 30s
	if got := s.effectiveSpread(); got != 30*time.Second {
		t.Errorf("5 permits produced a %s window, want 30s — a small fleet must not be delayed", got)
	}
	// Everything is through within that half minute.
	midnight := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	roster := model.Resolution{Source: model.SourceRoster, Since: midnight, Scheduled: true}
	for id := int64(1); id <= 5; id++ {
		if !s.spreadElapsed(id, roster, midnight.Add(30*time.Second)) {
			t.Errorf("permit %d still delayed 30s past the boundary on a 5-permit fleet", id)
		}
	}
}

// The cap is the operator's bound on how stale a permit may get, so it must
// actually bind once the fleet is large enough to want more.
func TestSpreadRespectsTheConfiguredCap(t *testing.T) {
	s := spreadScheduler(20*time.Minute, 5000) // wants 500m, capped at 20m
	if got := s.effectiveSpread(); got != 20*time.Minute {
		t.Errorf("effective window %s ignored the 20m cap", got)
	}
}

// Before any pass has counted the fleet there is no herd size to scale against,
// and guessing one would delay changes on the strength of nothing.
func TestSpreadInactiveUntilTheFleetIsCounted(t *testing.T) {
	s := &Scheduler{spreadWindow: time.Hour, opDrain: 3 * time.Second, interval: time.Minute}
	if got := s.effectiveSpread(); got != 0 {
		t.Errorf("window %s before any reconcile pass; want 0", got)
	}
}
