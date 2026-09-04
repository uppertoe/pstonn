package scheduler

import (
	"testing"
	"time"
)

// TestInjectedClockDrivesNotifyHold proves the s.now() seam is real: a time-gated
// scheduler decision (the notify retry hold) is driven entirely by the injected
// clock, so time-dependent logic can be tested deterministically instead of with
// real sleeps. holdNotify stamps the expiry from s.now(); notifyHeld compares
// against a caller-supplied instant, so advancing the clock moves the gate.
func TestInjectedClockDrivesNotifyHold(t *testing.T) {
	s := &Scheduler{notifyRetry: 5 * time.Minute}
	base := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	s.clock = func() time.Time { return base }

	s.holdNotify("k") // expiry = base + 5m, read through the injected clock
	if !s.notifyHeld("k", base.Add(time.Minute)) {
		t.Fatal("inside the hold window: want held")
	}
	if s.notifyHeld("k", base.Add(6*time.Minute)) {
		t.Fatal("past the hold window: want not held")
	}

	// Advance the clock an hour and re-hold: the expiry tracks the clock, not wall
	// time, so the new window is anchored at base+1h with nothing slept.
	s.clock = func() time.Time { return base.Add(time.Hour) }
	s.holdNotify("k")
	if !s.notifyHeld("k", base.Add(time.Hour+time.Minute)) {
		t.Fatal("re-held at the advanced clock: want held")
	}
	if s.notifyHeld("k", base.Add(time.Hour+6*time.Minute)) {
		t.Fatal("past the advanced window: want not held")
	}
}

// TestNowFallsBackToWallClock: a Scheduler with no injected clock (production, and
// any direct construction) uses real time, so the seam is invisible when unused.
func TestNowFallsBackToWallClock(t *testing.T) {
	s := &Scheduler{}
	before := time.Now()
	got := s.now()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Fatalf("now() with a nil clock = %v, want within [%v, %v]", got, before, after)
	}
}
