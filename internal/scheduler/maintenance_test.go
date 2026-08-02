package scheduler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The daily snapshot must have REAL exclusion against a reconcile pass, not the old
// check-then-act on an atomic. While a pass holds the shared maintenance lock, a
// snapshot attempt must defer (not run, not block) — under the old reconciling-atomic
// check it would have started, because holding the lock is not the same as having
// stamped the atomic (that gap was the race).
func TestSnapshotDefersWhileReconcileHoldsLock(t *testing.T) {
	st := newStore(t)
	s := New(st, &fakeCouncil{}, time.UTC, Options{})
	s.snapshotPath = filepath.Join(t.TempDir(), "snap.db") // due: lastSnapshot is zero

	s.maintenanceMu.RLock() // stand in for an in-flight reconcile pass
	done := make(chan struct{})
	go func() { s.maybeSnapshot(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		s.maintenanceMu.RUnlock()
		t.Fatal("maybeSnapshot blocked instead of deferring while a reconcile held the lock")
	}
	s.maintenanceMu.RUnlock()

	if _, err := os.Stat(s.snapshotPath); !os.IsNotExist(err) {
		t.Fatalf("a snapshot ran while a reconcile held the lock (stat err=%v)", err)
	}
}

// A FAILED alert delivery must not mute the alert for the full throttle: a second
// call after the short retry window (but well within the throttle) must be allowed to
// re-send, and a SUCCESSFUL delivery must then hold the full throttle.
func TestSystemAlertRetriesAfterFailedDelivery(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	fn := &fakeNotifier{on: true, admin: true}
	fn.setAdminErr(errors.New("smtp down"))
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})
	s.alertRetry = time.Millisecond // shrink the retry window for the test

	// First attempt fails.
	s.systemAlert(ctx, "k", "subj", "body")
	time.Sleep(20 * time.Millisecond)
	if n := len(fn.adminSnap()); n != 1 {
		t.Fatalf("first attempt count = %d, want 1", n)
	}

	// After the retry window, a second attempt is allowed and now succeeds.
	fn.setAdminErr(nil)
	s.systemAlert(ctx, "k", "subj", "body")
	time.Sleep(20 * time.Millisecond)
	if n := len(fn.adminSnap()); n != 2 {
		t.Fatalf("attempts = %d, want 2 — a failed delivery muted the retry", n)
	}

	// The successful delivery now holds the FULL throttle: an immediate third call is
	// suppressed.
	s.systemAlert(ctx, "k", "subj", "body")
	time.Sleep(20 * time.Millisecond)
	if n := len(fn.adminSnap()); n != 2 {
		t.Fatalf("attempts = %d, want 2 — a successful delivery should hold the full throttle", n)
	}
}
