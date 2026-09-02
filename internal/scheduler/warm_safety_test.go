package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
)

// The warm jitter must be ONE-SIDED: a session's renew threshold may fall below the
// configured interval (renew a little early) but must never rise above it. Symmetric
// jitter used to push the upper half of the band past the interval — harmless at a
// short interval, but at an interval near the idle window it could cross the cliff
// and let the cookie lapse before the first renew attempt.
func TestWarmThresholdJitterIsOneSidedDown(t *testing.T) {
	st := newStore(t)
	// No idle window → clamp disabled, so we isolate the jitter shape around a plain
	// 105m interval.
	s := New(st, &fakeTenant{}, time.UTC, Options{WarmInterval: 105 * time.Minute, JitterFrac: 0.2})
	base := 105 * time.Minute
	low := time.Duration(float64(base) * 0.8)
	updated := time.Unix(1_700_000_000, 0)
	for i := 0; i < 200; i++ {
		owner := "owner-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		got := s.warmThresholdFor(owner, updated, 0)
		if got > base {
			t.Fatalf("%s threshold %s exceeds the configured interval %s — jitter is not one-sided", owner, got, base)
		}
		if got < low {
			t.Fatalf("%s threshold %s is below interval×(1-jitter)=%s", owner, got, low)
		}
	}
}

// The safety clamp is what makes a long warm interval safe: however high the
// configured interval, the effective threshold must stay at least WarmSafetyMargin
// below the idle window, so the fast recovery tick always has runway to retry a
// failed renew before the cookie would lapse.
func TestWarmThresholdClampedBelowIdleWindow(t *testing.T) {
	st := newStore(t)
	const idle, margin = 10 * time.Hour, time.Hour
	// Interval set ABOVE the idle window — the pathological operator mistake the
	// clamp exists to survive.
	s := New(st, &fakeTenant{}, time.UTC, Options{
		WarmInterval: 12 * time.Hour, IdleWindow: idle, WarmSafetyMargin: margin, JitterFrac: 0.2,
	})
	ceil := idle - margin // 9h
	updated := time.Unix(1_700_000_000, 0)
	for i := 0; i < 200; i++ {
		owner := "own-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		got := s.warmThresholdFor(owner, updated, s.idleWindow)
		if got > ceil {
			t.Fatalf("%s threshold %s exceeds idleWindow-margin %s — a session could lapse before its first renew", owner, got, ceil)
		}
		// And still comfortably clear of the window itself.
		if got >= idle {
			t.Fatalf("%s threshold %s is not below the idle window %s", owner, got, idle)
		}
	}
}

// While the fleet breaker is open (a CONFIRMED shared block), drift must be
// suspended entirely — the recovering capacity belongs to warming and due writes,
// not the low-value grid read. Because the drift timestamp is not advanced, the read
// resumes as soon as the block clears.
func TestDriftSuspendedWhileBreakerOpen(t *testing.T) {
	ctx := context.Background()
	const owner = "blocked@example.com"
	st := newStore(t)
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	fc := &fakeTenant{permits: []parking.PermitInfo{{CouncilPermitID: "p1", Status: "Granted"}}}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour,
		WarmInterval: time.Nanosecond, DriftInterval: time.Nanosecond, Notifier: nf})
	time.Sleep(2 * time.Millisecond)

	// Breaker open: a pass warms (a cheap local no-op under the breaker) but must do
	// NO grid read, even though drift is due.
	fc.blocked = true
	s.keepWarm(ctx)
	if n := fc.listCallCount(); n != 0 {
		t.Fatalf("drift ran while the breaker was open: %d grid reads", n)
	}

	// Block clears: drift is still due (timestamp untouched), so it now runs.
	fc.blocked = false
	s.keepWarm(ctx)
	if n := fc.listCallCount(); n != 1 {
		t.Fatalf("drift did not resume after the block cleared: %d grid reads", n)
	}
}

// A session whose cookie is dead is probed ONCE and handed to the reconnect
// queue. While the item sits there (in backoff, or deferred by a login-shape
// break) nothing marks the session known-dead in the store, so every recovery
// tick used to issue a real Refresh and earn the same 401. The queue answers
// instead; probing resumes once the item leaves it.
func TestWarmSkipsSessionAlreadyQueuedForReconnect(t *testing.T) {
	ctx := context.Background()
	const owner = "dead@example.com"
	st := newStore(t)
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	fc := &fakeTenant{refreshErr: parking.ErrSessionExpired}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: &fakeNotifier{on: true}})
	time.Sleep(2 * time.Millisecond)

	for i := 0; i < 3; i++ {
		s.keepWarm(ctx)
	}
	if n := len(fc.refreshed); n != 1 {
		t.Fatalf("a session queued for reconnect was probed %d times across 3 passes, want 1", n)
	}
	if !s.reconnectQueued(owner, "") {
		t.Fatal("the dead session should be sitting in the reconnect queue")
	}

	// The queue empties (here: the worker recovers it), so the next pass may probe
	// again — and, the fake still reporting it dead, re-queues it.
	fc.reconnectSet = true
	if !s.drainOneReconnect(ctx) {
		t.Fatal("the queued reconnect was not drained")
	}
	if s.reconnectQueued(owner, "") {
		t.Fatal("a recovered session must leave the queue")
	}
	s.keepWarm(ctx)
	if n := len(fc.refreshed); n != 2 {
		t.Fatalf("probing did not resume once the queue emptied: %d refreshes, want 2", n)
	}
}
