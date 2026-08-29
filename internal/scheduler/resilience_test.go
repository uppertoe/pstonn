package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A deterministic panic reconciling ONE permit must not abort the pass and starve
// every permit after it: it is recovered per-unit, alerted, and the remaining
// permits still get processed.
func TestPermitPanicDoesNotAbortThePass(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	// Two permits due for a change (roster differs from active); the first panics.
	seedActivePermit(t, st, "a@example.com", "boom", "ROSTERA", "OLDA")
	seedActivePermit(t, st, "b@example.com", "ok", "ROSTERB", "OLDB")
	fc := &fakeTenant{panicOn: "boom"}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn})

	s.reconcileAll(ctx) // must not itself panic
	time.Sleep(40 * time.Millisecond)

	// The other permit still got its tenant write despite the first one panicking.
	sawOK := false
	for _, id := range fc.callSnap() {
		if id == "ok" {
			sawOK = true
		}
	}
	if !sawOK {
		t.Fatalf("the non-panicking permit was starved by the panic; calls=%v", fc.callSnap())
	}
	if !hasAdmin(fn, "panicked during reconcile") {
		t.Fatalf("no per-permit panic alert: %v", fn.adminSnap())
	}
}

// LastReconcile is the "last CLEAN pass" a watchdog trusts, so a pass that bails on
// its first database read must NOT stamp it — only the attempt clock advances.
func TestReconcileStampsSuccessOnlyOnCleanPass(t *testing.T) {
	st := newStore(t)
	s := New(st, &fakeTenant{}, time.UTC, Options{})

	// A clean (empty) pass stamps both attempt and success.
	s.safeReconcile(context.Background())
	att1, rec1 := s.LastReconcileAttempt(), s.LastReconcile()
	if att1.IsZero() || rec1.IsZero() {
		t.Fatalf("a clean pass should stamp both: attempt=%v success=%v", att1, rec1)
	}

	// A pass whose first DB read fails records a NEW attempt but must not advance the
	// clean-reconcile clock.
	st.Close()
	time.Sleep(2 * time.Millisecond)
	s.safeReconcile(context.Background())
	if att2 := s.LastReconcileAttempt(); !att2.After(att1) {
		t.Fatalf("a failed pass should still record an attempt (att2=%v not after %v)", att2, att1)
	}
	if rec2 := s.LastReconcile(); !rec2.Equal(rec1) {
		t.Fatalf("a failed pass must not advance the clean-reconcile clock: %v != %v", rec2, rec1)
	}
}

// A failing drift read must back off per owner, not retry on every warm tick. Without
// this a fleet-wide API-shape change is 500 owners x 3 requests every 3 minutes.
func TestDriftFailureBacksOffAndResets(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "driftbo@example.com"
	seedSession(t, st, owner)
	s := New(st, &fakeTenant{}, time.UTC, Options{DriftInterval: 6 * time.Hour, Notifier: &fakeNotifier{on: true, admin: true}})
	cs, _ := st.GetTenantSession(ctx, owner)

	if s.driftBackedOff(owner, time.Now()) {
		t.Fatal("a healthy owner must not start backed off")
	}
	s.noteDriftFailure(ctx, owner, errors.New("boom"))
	if !s.driftBackedOff(owner, time.Now()) {
		t.Fatal("a failed drift read must back the owner off")
	}
	// The backoff gates driftDue, which is what actually stops the retry.
	cs.DriftCheckedAt = time.Time{}
	cs.UpdatedAt = time.Now().Add(-24 * time.Hour) // long overdue
	if s.driftDue(cs, time.Now()) {
		t.Fatal("a backed-off owner must not be drift-due")
	}
	// It must be well clear of the 3-minute warm tick, or it damps nothing.
	if !s.driftBackedOff(owner, time.Now().Add(10*time.Minute)) {
		t.Fatal("the first backoff step must outlast several warm ticks")
	}
	// Success clears it.
	s.noteDriftSuccess(owner)
	if s.driftBackedOff(owner, time.Now()) {
		t.Fatal("a successful drift read must clear the backoff")
	}
	if !s.driftDue(cs, time.Now()) {
		t.Fatal("an overdue owner should be drift-due again once the backoff clears")
	}
}

// Cancelling a reconnect must not leave drift bookkeeping behind for an owner who is
// gone — the two maps are only otherwise cleared on success.
func TestCancelReconnectClearsDriftBookkeeping(t *testing.T) {
	st := newStore(t)
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: &fakeNotifier{on: true}})
	s.noteDriftFailure(context.Background(), "gone@example.com", errors.New("boom"))
	s.CancelReconnect("gone@example.com")
	s.driftMu.Lock()
	n := len(s.driftRetryAt) + len(s.driftFails)
	s.driftMu.Unlock()
	if n != 0 {
		t.Fatalf("drift bookkeeping leaked %d entries for a cancelled owner", n)
	}
}
