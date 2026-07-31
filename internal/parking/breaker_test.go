package parking

import (
	"testing"
	"time"
)

func testBreaker() *breaker {
	// threshold 3, window 2m, cooldown 5m, probe every 30s.
	return newBreaker(3, 2*time.Minute, 5*time.Minute, 30*time.Second)
}

// One or two owners pushed back is not enough: a single account whose permit was
// revoked must not pause the whole fleet. It takes THRESHOLD distinct owners
// within the window — the signature of a shared-edge/IP block.
func TestBreakerOpensOnlyOnDistinctOwners(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	// The same owner striking repeatedly is still one owner: never trips.
	for i := 0; i < 10; i++ {
		b.onPushback(t0.Add(time.Duration(i)*time.Second), "solo@x", 0)
	}
	if open, _ := b.allow(t0.Add(11 * time.Second)); !open {
		t.Fatal("one owner's repeated pushback tripped the fleet breaker")
	}

	// Three distinct owners within the window trips it.
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0.Add(time.Second), "b@x", 0)
	b.onPushback(t0.Add(2*time.Second), "c@x", 0)
	if open, wait := b.allow(t0.Add(3 * time.Second)); open || wait <= 0 {
		t.Fatalf("three distinct owners did not open the circuit (open=%v wait=%s)", open, wait)
	}
}

// Owners that struck longer ago than the window must not count toward the
// threshold, or the breaker would trip on unrelated blips spread across an hour.
func TestBreakerForgetsOwnersOutsideTheWindow(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0.Add(30*time.Second), "b@x", 0)
	// c strikes well after a and b have aged out of the 2m window.
	b.onPushback(t0.Add(5*time.Minute), "c@x", 0)
	if open, _ := b.allow(t0.Add(5 * time.Minute)); open == false {
		t.Fatal("stale pushbacks from a and b counted toward the threshold")
	}
}

// The open → half-open → closed cycle: paused during the cooldown, one probe let
// through after it, and a probe success closes the circuit for everyone.
func TestBreakerHalfOpensAndClosesOnProbeSuccess(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0, "b@x", 0)
	b.onPushback(t0, "c@x", 0) // open until t0+5m

	if open, _ := b.allow(t0.Add(4 * time.Minute)); open {
		t.Fatal("circuit allowed traffic while still inside the cooldown")
	}
	// After the cooldown one probe is allowed...
	if open, _ := b.allow(t0.Add(5 * time.Minute)); !open {
		t.Fatal("circuit did not half-open after the cooldown")
	}
	// ...but a second concurrent caller is held off for the probe interval.
	if open, _ := b.allow(t0.Add(5*time.Minute + time.Second)); open {
		t.Fatal("a second caller probed during the same probe interval — stampede")
	}
	// The probe succeeds: the circuit closes for everyone.
	b.onSuccess(t0.Add(5*time.Minute+2*time.Second), "a@x")
	if open, _ := b.allow(t0.Add(5*time.Minute + 3*time.Second)); !open {
		t.Fatal("a successful probe did not close the circuit")
	}
}

// A failed probe must re-open the circuit rather than let the herd back in.
func TestBreakerReopensOnProbeFailure(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0, "b@x", 0)
	b.onPushback(t0, "c@x", 0)

	// Half-open probe at t0+5m, then it gets pushed back.
	b.allow(t0.Add(5 * time.Minute))
	b.onPushback(t0.Add(5*time.Minute+time.Second), "a@x", 0)

	// Still paused: back off for the full cooldown again.
	if open, wait := b.allow(t0.Add(5*time.Minute + 2*time.Second)); open || wait < 4*time.Minute {
		t.Fatalf("a failed probe did not re-open the circuit (open=%v wait=%s)", open, wait)
	}
}

// A Retry-After larger than the default cooldown must be honoured, so the breaker
// never probes sooner than the edge told us to.
func TestBreakerHonoursRetryAfter(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0, "b@x", 0)
	b.onPushback(t0, "c@x", 20*time.Minute) // edge asked for 20m

	if open, wait := b.allow(t0.Add(10 * time.Minute)); open || wait < 9*time.Minute {
		t.Fatalf("a 20m Retry-After was not honoured (open=%v wait=%s)", open, wait)
	}
}

// A nil breaker is always-allow, so the feature disables cleanly.
func TestNilBreakerAllows(t *testing.T) {
	var b *breaker
	if open, _ := b.allow(time.Now()); !open {
		t.Fatal("a nil breaker must allow all traffic")
	}
	b.onPushback(time.Now(), "a@x", 0) // must not panic
	b.onSuccess(time.Now(), "a@x")     // must not panic
}
