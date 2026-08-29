package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
)

// The nightmare this guards against: a fleet block silently leaves households on
// the wrong plate until they are fined. When the breaker is OPEN (a confirmed
// block), a due change that keeps failing must warn the household SOONER and
// URGENTLY — the change genuinely will not apply until the block clears, so the
// reassuring "still updating" would be dangerous. When the breaker is closed (an
// isolated hiccup that usually self-heals), the softer, later warning still stands.
func TestBusyWarningEscalatesOnConfirmedBlock(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "blocked@example.com", "blk-1"

	// run drives `ticks` reconcile passes against a tenant that keeps returning
	// ErrCouncilBusy, with the fleet breaker reported open or closed, and returns
	// the user-facing outcomes that fired.
	run := func(blocked bool, ticks int) []notify.ApplyOutcome {
		st := newStore(t)
		seedActivePermit(t, st, owner, cid, "WANT1", "OLD1") // a change to WANT1 is due
		fc := &fakeTenant{setErr: parking.ErrCouncilBusy, blocked: blocked}
		nf := &fakeNotifier{on: true, admin: true}
		s := New(st, fc, time.UTC, Options{Notifier: nf})
		for i := 0; i < ticks; i++ {
			s.reconcileAll(ctx)
		}
		time.Sleep(15 * time.Millisecond) // let the async notifyUser goroutine land
		return nf.outcomeSnap()
	}

	// Confirmed block: silent just before the block threshold...
	if got := run(true, blockNotifyThreshold-1); len(got) != 0 {
		t.Fatalf("warned before the block threshold (%d ticks): %d outcomes", blockNotifyThreshold-1, len(got))
	}
	// ...and an URGENT, act-now warning naming the still-covered plate AT it.
	got := run(true, blockNotifyThreshold)
	if len(got) == 0 {
		t.Fatalf("no warning at the block threshold (%d ticks)", blockNotifyThreshold)
	}
	o := got[len(got)-1]
	if o.OK || !o.Urgent {
		t.Fatalf("confirmed-block warning was not an urgent failure: %+v", o)
	}
	if o.CurrentReg != "OLD1" {
		t.Fatalf("warning must name the plate still on the permit, got CurrentReg=%q", o.CurrentReg)
	}

	// An ISOLATED hiccup (breaker closed) must NOT escalate early — at the block
	// threshold it is still within its softer, longer busy window and stays quiet.
	if got := run(false, blockNotifyThreshold); len(got) != 0 {
		t.Fatalf("an isolated hiccup warned at the block threshold: %d outcomes", len(got))
	}

	// Sanity: the escalated wait really is shorter than the ordinary one.
	if blockNotifyThreshold >= busyNotifyThreshold {
		t.Fatalf("block threshold %d must be shorter than the busy threshold %d", blockNotifyThreshold, busyNotifyThreshold)
	}
}

// TestBusyEscalationSurvivesEarlierSoftNotice pins the common REAL ordering: the
// tenant starts refusing, the household gets the soft "still updating, we'll
// keep trying" notice, and only THEN does the fleet breaker confirm the block.
// With the old "busy|"+plate key both notices deduped to one, so the urgent
// "change the vehicle yourself now to avoid a fine" message — the exact
// escalation blockNotifyThreshold exists for — could never be delivered in that
// order.
func TestBusyEscalationSurvivesEarlierSoftNotice(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "escalate@example.com", "esc-1"
	st := newStore(t)
	seedActivePermit(t, st, owner, cid, "WANT1", "OLD1")

	fc := &fakeTenant{setErr: parking.ErrCouncilBusy} // breaker closed: isolated hiccup
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})

	// Phase 1: sustained-but-unconfirmed busy delivers the soft notice.
	for i := 0; i < busyNotifyThreshold; i++ {
		s.reconcileAll(ctx)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(nf.outcomeSnap()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the soft busy notice never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if o := nf.outcomeSnap()[0]; o.Urgent {
		t.Fatalf("the unconfirmed notice should be soft, got %+v", o)
	}

	// Phase 2: the breaker opens. The next failing tick must escalate URGENTLY
	// even though a notice for this plate was already delivered today.
	fc.mu.Lock()
	fc.blocked = true
	fc.mu.Unlock()
	s.reconcileAll(ctx)
	deadline = time.Now().Add(2 * time.Second)
	for {
		outs := nf.outcomeSnap()
		if len(outs) >= 2 && outs[len(outs)-1].Urgent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the urgent confirmed-block escalation was deduped by the earlier soft notice; outcomes: %+v", outs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
