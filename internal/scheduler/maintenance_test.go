package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

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

// The in-flight notification claim dedups: a second delivery for the same permit+key
// can't launch while the first is still queued/running, so a fleet-wide event doesn't
// re-amplify each pass before the durable key is written.
func TestNotifyInFlightClaimDedups(t *testing.T) {
	s := New(newStore(t), &fakeCouncil{}, time.UTC, Options{})
	const claim = "1|success|A>B"
	if !s.claimNotify(claim) {
		t.Fatal("first claim should succeed")
	}
	if s.claimNotify(claim) {
		t.Fatal("a second claim while in-flight must fail (dedup)")
	}
	s.releaseNotify(claim)
	if !s.claimNotify(claim) {
		t.Fatal("claim should succeed again after release")
	}
}
