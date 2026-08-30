package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A tenant write is confirmed (SetVehicle re-reads to verify), so on a local-commit
// failure the car IS on the permit — but the app must NOT book a clean success: the
// stale ActiveRegistration would drive a duplicate apply + "updated" notice next pass
// and be wrong across a restart. It must alert the operator, leave the state for a
// reconcile to heal, and then notify exactly once.
func TestCommitAfterApplyAlertsAndHeals(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "commit@example.com"
	pid, _ := seedActivePermit(t, st, owner, "c-1", "ROSTER1", "OLD999") // roster wants ROSTER1
	fc := &fakeTenant{}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn})

	// The tenant write succeeds but the local commit fails.
	s.commitActive = func(context.Context, int64, string) error { return errors.New("disk full") }
	s.reconcileAll(ctx)
	time.Sleep(40 * time.Millisecond) // systemAlert delivers async

	if len(fc.callSnap()) == 0 {
		t.Fatal("the council was never asked to change the plate")
	}
	// The durable record is still stale (commit failed)...
	if p, _ := st.GetPermit(ctx, pid); p.ActiveRegistration != "OLD999" {
		t.Fatalf("active = %q, want the stale OLD999 (commit failed)", p.ActiveRegistration)
	}
	// ...the operator is alerted...
	if !hasAdmin(fn, "not recorded locally") {
		t.Fatalf("no commit-after-apply alert: %v", fn.adminSnap())
	}
	// ...and NO clean success was reported to the user on this pass.
	if applied := fn.appliedSnap(); len(applied) != 0 {
		t.Fatalf("a notification was sent despite the uncommitted state: %+v", applied)
	}

	// Heal: commit works now; once the deferral has elapsed (the branch defers the
	// permit rather than kicking it — see TestCommitFailureDeferralHoldsUnderRun),
	// the next pass re-records and notifies exactly once.
	s.commitActive = st.SetPermitActive
	s.clearRetry(pid) // the 8-tick window has passed
	s.reconcileAll(ctx)
	time.Sleep(40 * time.Millisecond) // notifyUser delivers async
	if p, _ := st.GetPermit(ctx, pid); p.ActiveRegistration != "ROSTER1" {
		t.Fatalf("after healing, active = %q, want ROSTER1", p.ActiveRegistration)
	}
	oks := 0
	for _, a := range fn.appliedSnap() {
		if a.ok {
			oks++
		}
	}
	if oks != 1 {
		t.Fatalf("success notifications = %d, want exactly 1 (only the healed pass)", oks)
	}
}

// TestCommitFailureDeferralHoldsUnderRun drives the commit-after-apply branch
// through the real loop. The branch defers the permit for 8 ticks, but it used to
// KickPermit straight after — and KickPermit clears that very deferral, so every
// tick re-ran the doomed apply. Calling reconcileAll directly (as the test above
// does) never sees this, because nothing consumes the kick. Here the loop runs at
// a 10ms tick for well under the deferral (8 ticks x 0.8 jitter floor = 64ms), so
// a second council write within the window can only mean the deferral was erased.
func TestCommitFailureDeferralHoldsUnderRun(t *testing.T) {
	st := newStore(t)
	const owner = "commit-run@example.com"
	seedActivePermit(t, st, owner, "c-run", "ROSTER1", "OLD999")
	fc := &fakeTenant{}
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true, admin: true}})
	s.interval = 10 * time.Millisecond
	s.commitActive = func(context.Context, int64, string) error { return errors.New("disk full") }

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()
	s.Run(ctx) // returns when ctx expires; joins the helper loops

	if n := len(fc.callSnap()); n != 1 {
		t.Fatalf("council writes = %d within the deferral, want exactly 1 (the deferral was erased by a kick)", n)
	}
}
