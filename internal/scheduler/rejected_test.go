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

// A parked refusal is about ONE plate. Monday's roster car A is refused and
// parked; Tuesday's roster car B is a write the portal has never seen, and used
// to sit behind Monday's parking until an edit, a re-link or a restart — a whole
// day of the wrong car on the permit with the household told nothing new. The
// park must lift on its own when the target changes, and B's apply must then be
// logged and notified like any other.
func TestParkedRefusalDoesNotHoldADifferentTarget(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "moved-on@example.com"
	pid, _ := seedActivePermit(t, st, owner, "rej-2", "PLATEA", "OLD999")
	fc := &fakeTenant{setErr: rejectedErr()}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn})

	// Monday: A is refused and parked.
	for i := 0; i < 3; i++ {
		s.reconcileAll(ctx)
	}
	if n := len(fc.callSnap()); n != 1 {
		t.Fatalf("council writes = %d after a rejection, want 1 (parked)", n)
	}

	// Tuesday: the roster now names B, and the portal is fine with it.
	vehB, err := st.CreateVehicle(ctx, owner, "PLATEB", "Tuesday car", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, pid, time.Now().In(time.UTC).Weekday(), vehB); err != nil {
		t.Fatal(err)
	}
	fc.setErr = nil
	s.reconcileAll(ctx) // no kick: the next ordinary tick must see it
	if n, last := len(fc.callSnap()), fc.lastReg(); n != 2 || last != "PLATEB" {
		t.Fatalf("council writes = %d (last %q) after the target changed, want 2 with PLATEB (the parking must lift)", n, last)
	}
	if p, _ := st.GetPermit(ctx, pid); p.ActiveRegistration != "PLATEB" || p.FailStreak != 0 {
		t.Fatalf("after B applied: active=%q streak=%d, want PLATEB/0", p.ActiveRegistration, p.FailStreak)
	}
	if last, err := st.LastApply(ctx, pid); err != nil || last.Status != "success" || last.Registration != "PLATEB" {
		t.Fatalf("last activity row = %+v (%v), want a success for PLATEB", last, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		outs := fn.outcomeSnap()
		if n := len(outs); n >= 2 && outs[n-1].OK && outs[n-1].Reg == "PLATEB" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B's apply was never notified; outcomes: %+v", fn.outcomeSnap())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The parking was specific to A. An ordinary (non-parked) backoff is not a
	// statement about the target and still holds whatever the target becomes.
	if s.retryDeferred(pid, time.Now()) {
		t.Fatal("a successful apply must leave no deferral behind")
	}
	s.deferRetry(pid, 3)
	s.unparkIfTargetChanged(pid, "SOMETHING-ELSE")
	if !s.retryDeferred(pid, time.Now()) {
		t.Fatal("an ordinary transient backoff must not be lifted by a target change")
	}
}
