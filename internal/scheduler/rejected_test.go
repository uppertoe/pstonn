package scheduler

import (
	"context"
	"testing"
	"time"
)

// A REJECTED change (the portal said no to this exact write) is parked: no further
// council attempt, however many passes run, and the household is told once — not
// retried forever at the 30-minute cap (~144 requests a day per permit) with a
// fresh notice every morning. A user action that plausibly changed things (an
// edit or a re-link, both of which go through KickPermit/KickOwner) un-parks it.
func TestRejectedChangeIsParkedUntilKicked(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "rejected@example.com"
	pid, _ := seedActivePermit(t, st, owner, "rej-1", "ROSTER1", "OLD999")
	fc := &fakeTenant{setErr: rejectedErr()}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn})

	for i := 0; i < 5; i++ {
		s.reconcileAll(ctx)
	}
	time.Sleep(40 * time.Millisecond) // notifyUser delivers async
	if n := len(fc.callSnap()); n != 1 {
		t.Fatalf("council writes = %d after a rejection, want 1 (the permit should be parked)", n)
	}
	if n := len(fn.appliedSnap()); n != 1 {
		t.Fatalf("notifications = %d, want exactly 1", n)
	}
	// Parked reads as deferred far beyond any backoff cap.
	if !s.retryDeferred(pid, time.Now().Add(24*time.Hour)) {
		t.Fatal("a rejected permit should stay deferred well past the 30-minute cap")
	}
	if out := fn.outcomeSnap()[0]; out.Transient || out.OK {
		t.Fatalf("a rejection must be reported as final: %+v", out)
	}

	// A schedule edit clears the parking and the change is tried again.
	s.KickPermit(pid)
	s.reconcileAll(ctx)
	if n := len(fc.callSnap()); n != 2 {
		t.Fatalf("council writes = %d after a kick, want 2 (the kick should un-park)", n)
	}
	// Refused again for the same reason: the row and the notice are the ones
	// already delivered, so nothing new is sent (told once per distinct refusal).
	time.Sleep(40 * time.Millisecond)
	if n := len(fn.appliedSnap()); n != 1 {
		t.Fatalf("notifications = %d after an identical second refusal, want still 1", n)
	}

	// A re-link (KickOwner) un-parks too.
	s.KickOwner(ctx, owner)
	s.reconcileAll(ctx)
	if n := len(fc.callSnap()); n != 3 {
		t.Fatalf("council writes = %d after KickOwner, want 3", n)
	}
	// The permit heals once the portal accepts: streak and parking clear together.
	fc.setErr = nil
	s.KickPermit(pid)
	s.reconcileAll(ctx)
	if p, _ := st.GetPermit(ctx, pid); p.ActiveRegistration != "ROSTER1" || p.FailStreak != 0 {
		t.Fatalf("after acceptance: active=%q streak=%d, want ROSTER1/0", p.ActiveRegistration, p.FailStreak)
	}
	if s.retryDeferred(pid, time.Now()) {
		t.Fatal("a successful apply must clear the parking")
	}
}
