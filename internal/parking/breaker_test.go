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
	if _, open, _ := b.allow(t0.Add(11 * time.Second)); !open {
		t.Fatal("one owner's repeated pushback tripped the fleet breaker")
	}

	// Three distinct owners within the window trips it.
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0.Add(time.Second), "b@x", 0)
	b.onPushback(t0.Add(2*time.Second), "c@x", 0)
	if _, open, wait := b.allow(t0.Add(3 * time.Second)); open || wait <= 0 {
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
	if _, open, _ := b.allow(t0.Add(5 * time.Minute)); !open {
		t.Fatal("stale pushbacks from a and b counted toward the threshold")
	}
}

// The open → half-open → closed cycle: paused during the cooldown, one probe let
// through after it, and the PROBE'S success (with its permit) closes the circuit.
func TestBreakerHalfOpensAndClosesOnProbeSuccess(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0, "b@x", 0)
	b.onPushback(t0, "c@x", 0) // open until t0+5m

	if _, open, _ := b.allow(t0.Add(4 * time.Minute)); open {
		t.Fatal("circuit allowed traffic while still inside the cooldown")
	}
	// After the cooldown one probe is admitted...
	permit, open, _ := b.allow(t0.Add(5 * time.Minute))
	if !open || !permit.probe {
		t.Fatalf("circuit did not admit a half-open probe (open=%v probe=%v)", open, permit.probe)
	}
	// ...but a second concurrent caller is held off for the probe interval.
	if _, open2, _ := b.allow(t0.Add(5*time.Minute + time.Second)); open2 {
		t.Fatal("a second caller probed during the same probe interval — stampede")
	}
	// The probe reports success WITH its permit: the circuit closes for everyone.
	if !b.onSuccess(t0.Add(5*time.Minute+2*time.Second), "a@x", permit) {
		t.Fatal("the probe's success did not close the circuit")
	}
	if _, open, _ := b.allow(t0.Add(5*time.Minute + 3*time.Second)); !open {
		t.Fatal("circuit did not report closed after the probe succeeded")
	}
}

// THE REGRESSION for the reviewed race: a request admitted while the circuit was
// CLOSED, but returning AFTER it opened, must NOT close it. Its 200 says nothing
// about the block clearing — it may have started (or hit a cache path) before the
// edge began refusing. Only the designated probe closes the circuit.
func TestBreakerStaleInFlightSuccessDoesNotClose(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	// 1. Request A is admitted while the circuit is closed.
	permitA, open, _ := b.allow(t0)
	if !open || permitA.probe {
		t.Fatalf("A should be admitted as an ordinary (non-probe) request: open=%v probe=%v", open, permitA.probe)
	}
	// 2. The circuit then opens (three distinct owners pushed back).
	b.onPushback(t0.Add(time.Second), "a@x", 0)
	b.onPushback(t0.Add(time.Second), "b@x", 0)
	b.onPushback(t0.Add(time.Second), "c@x", 0)
	// 3. A now returns 200 and reports success with its stale permit.
	if b.onSuccess(t0.Add(2*time.Second), "a@x", permitA) {
		t.Fatal("a stale in-flight success closed a freshly-opened circuit")
	}
	// 4. The circuit must still be paused.
	if _, open, _ := b.allow(t0.Add(3 * time.Second)); open {
		t.Fatal("circuit was not still open after the stale success")
	}
	// 5. The later designated probe succeeds and closes it.
	permitP, open, _ := b.allow(t0.Add(6 * time.Minute))
	if !open || !permitP.probe {
		t.Fatalf("no half-open probe after cooldown (open=%v probe=%v)", open, permitP.probe)
	}
	if !b.onSuccess(t0.Add(6*time.Minute+time.Second), "a@x", permitP) {
		t.Fatal("the designated probe's success did not close the circuit")
	}
}

// A probe from a SUPERSEDED open episode must not close a circuit that has since
// re-opened: its permit carries a stale generation. This covers a slow probe that
// is overtaken by a fresh block.
func TestBreakerStaleProbeGenerationCannotClose(t *testing.T) {
	b := testBreaker()
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	b.onPushback(t0, "a@x", 0)
	b.onPushback(t0, "b@x", 0)
	b.onPushback(t0, "c@x", 0) // open (generation 1)

	// Half-open probe admitted (generation 1).
	permit, open, _ := b.allow(t0.Add(5 * time.Minute))
	if !open || !permit.probe {
		t.Fatalf("expected a probe (open=%v probe=%v)", open, permit.probe)
	}
	// Before the probe returns, a fresh block re-opens the circuit (generation 2).
	b.onPushback(t0.Add(5*time.Minute+time.Second), "d@x", 0)
	b.onPushback(t0.Add(5*time.Minute+time.Second), "e@x", 0)
	b.onPushback(t0.Add(5*time.Minute+time.Second), "f@x", 0)
	// The stale probe now reports success: it must NOT close the re-opened circuit.
	if b.onSuccess(t0.Add(5*time.Minute+2*time.Second), "a@x", permit) {
		t.Fatal("a probe from a superseded generation closed a re-opened circuit")
	}
	if _, open, _ := b.allow(t0.Add(5*time.Minute + 3*time.Second)); open {
		t.Fatal("circuit was wrongly reported closed")
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
	if _, open, wait := b.allow(t0.Add(5*time.Minute + 2*time.Second)); open || wait < 4*time.Minute {
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

	if _, open, wait := b.allow(t0.Add(10 * time.Minute)); open || wait < 9*time.Minute {
		t.Fatalf("a 20m Retry-After was not honoured (open=%v wait=%s)", open, wait)
	}
}

// A nil breaker is always-allow, so the feature disables cleanly.
func TestNilBreakerAllows(t *testing.T) {
	var b *breaker
	if _, open, _ := b.allow(time.Now()); !open {
		t.Fatal("a nil breaker must allow all traffic")
	}
	b.onPushback(time.Now(), "a@x", 0)              // must not panic
	b.onSuccess(time.Now(), "a@x", breakerPermit{}) // must not panic
}

// restore must re-pause the breaker when a persisted block is still in force (a
// restart must not clear it), and stay closed when the persisted pause has expired.
func TestBreakerRestore(t *testing.T) {
	// In-force pause → restored open (refuses traffic).
	b := testBreaker()
	b.restore(time.Now().Add(5*time.Minute), time.Now(), 9)
	if _, ok, _ := b.allow(time.Now()); ok {
		t.Fatal("a restored in-force pause should refuse traffic")
	}
	// Generation carried forward, so a stale probe from before the restart can't close.
	if _, _, gen := b.snapshot(); gen != 9 {
		t.Fatalf("restore did not carry the generation forward: got %d", gen)
	}

	// Expired pause → restored closed (allows traffic).
	b2 := testBreaker()
	b2.restore(time.Now().Add(-time.Minute), time.Time{}, 3)
	if _, ok, _ := b2.allow(time.Now()); !ok {
		t.Fatal("a restored EXPIRED pause should not keep the circuit open")
	}
}
