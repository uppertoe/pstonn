package scheduler

import (
	"context"
	"errors"
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

// TestAuthOutageStaysSoftWithCouncilDownCopy: an open auth circuit (the council's
// sign-in is down for the household too) must NOT escalate to the act-now warning —
// there is nothing they can do at the council. It stays on the soft tier and timing
// (busyNotifyThreshold, not urgent), but the outcome is flagged CouncilDown so the
// copy says plainly the council is down rather than the vague "still updating".
func TestAuthOutageStaysSoftWithCouncilDownCopy(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "authgated@example.com", "ag-1"

	run := func(gated bool, ticks int) []notify.ApplyOutcome {
		st := newStore(t)
		seedActivePermit(t, st, owner, cid, "WANT1", "OLD1")
		fc := &fakeTenant{setErr: parking.ErrCouncilBusy, authGated: gated} // breaker CLOSED
		nf := &fakeNotifier{on: true, admin: true}
		s := New(st, fc, time.UTC, Options{Notifier: nf})
		for i := 0; i < ticks; i++ {
			s.reconcileAll(ctx)
		}
		time.Sleep(15 * time.Millisecond)
		return nf.outcomeSnap()
	}

	// An auth outage does NOT escalate: silent at the block threshold, like an
	// ordinary hiccup — it must wait for the soft threshold.
	if got := run(true, blockNotifyThreshold); len(got) != 0 {
		t.Fatalf("an auth outage escalated early instead of staying soft: %d outcomes", len(got))
	}
	// At the soft threshold it delivers a SOFT notice (not urgent), flagged
	// CouncilDown so the copy names the outage.
	got := run(true, busyNotifyThreshold)
	if len(got) == 0 {
		t.Fatalf("no soft notice at the busy threshold under an auth outage")
	}
	o := got[len(got)-1]
	if o.OK || o.Urgent {
		t.Fatalf("auth-outage notice must be soft, not urgent: %+v", o)
	}
	if !o.CouncilDown {
		t.Fatalf("auth-outage soft notice must be flagged CouncilDown for the clearer copy: %+v", o)
	}
}

// TestAuthOutageWinsOverBreaker: when BOTH the fleet breaker and the auth circuit
// are open, the auth outage takes precedence — the household is told the council is
// down (soft, CouncilDown), never "change it yourself at the council now", which
// they cannot do while the council's sign-in is down.
func TestAuthOutageWinsOverBreaker(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "both@example.com", "both-1"
	st := newStore(t)
	seedActivePermit(t, st, owner, cid, "WANT1", "OLD1")
	fc := &fakeTenant{setErr: parking.ErrCouncilBusy, blocked: true, authGated: true}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})

	// It must NOT escalate early (that would be the act-now path); it waits for the
	// soft threshold and then delivers the council-down copy.
	for i := 0; i < blockNotifyThreshold; i++ {
		s.reconcileAll(ctx)
	}
	time.Sleep(15 * time.Millisecond)
	if got := nf.outcomeSnap(); len(got) != 0 {
		t.Fatalf("both breaker+auth open escalated early instead of staying soft: %+v", got)
	}
	for i := blockNotifyThreshold; i < busyNotifyThreshold; i++ {
		s.reconcileAll(ctx)
	}
	time.Sleep(15 * time.Millisecond)
	got := nf.outcomeSnap()
	if len(got) == 0 {
		t.Fatal("no soft notice fired at the busy threshold")
	}
	if o := got[len(got)-1]; o.Urgent || !o.CouncilDown {
		t.Fatalf("with both breaker and auth open, expected a soft CouncilDown notice, got %+v", o)
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

// TestUndeliveredNoticeRetryIsPaced: the council-busy branch deliberately has no
// deferRetry, so it calls notifyUser on EVERY tick for as long as the block lasts.
// When the household cannot be reached the durable key is never written, and
// each of those ticks used to be a fresh delivery attempt — an SMTP dial per
// permit per minute. The retry must still happen, after a hold, not every tick.
func TestUndeliveredNoticeRetryIsPaced(t *testing.T) {
	ctx := context.Background()
	const owner, cid = "unreachable@example.com", "unr-1"

	run := func(fn *fakeNotifier) *Scheduler {
		st := newStore(t)
		seedActivePermit(t, st, owner, cid, "WANT1", "OLD1")
		fc := &fakeTenant{setErr: parking.ErrCouncilBusy, blocked: true} // confirmed: warns at blockNotifyThreshold
		s := New(st, fc, time.UTC, Options{Notifier: fn})
		// Far longer than the ticks below can take even under -race on a slow
		// runner: the test pins that the hold is honoured, and expires it by hand.
		s.notifyRetry = time.Hour
		for i := 0; i < blockNotifyThreshold+5; i++ {
			s.reconcileAll(ctx)
			time.Sleep(3 * time.Millisecond) // let each tick's async delivery land before the next
		}
		return s
	}
	// attempts waits for the async deliveries to settle at n, or reports how many.
	attempts := func(fn *fakeNotifier, n int) int {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if got := len(fn.appliedSnap()); got == n || time.Now().After(deadline) {
				return got
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	expireHolds := func(s *Scheduler) {
		s.notifyMu.Lock()
		for k := range s.notifyRetryAt {
			s.notifyRetryAt[k] = time.Now().Add(-time.Second)
		}
		s.notifyMu.Unlock()
	}

	// Nobody reached: one attempt, then held — not one per tick.
	fn := &fakeNotifier{on: true, admin: true, deliverSet: true, deliver: 0}
	s := run(fn)
	if n := attempts(fn, 1); n != 1 {
		t.Fatalf("delivery attempts = %d across %d failing ticks, want 1 (held)", n, blockNotifyThreshold+5)
	}
	// ...and once the hold expires, the next tick retries.
	expireHolds(s)
	s.reconcileAll(ctx)
	if n := attempts(fn, 2); n != 2 {
		t.Fatalf("delivery attempts = %d after the hold expired, want 2 (retried)", n)
	}

	// Partial delivery (one member reached, another not): the durable key is not
	// written — the missed member is still owed the notice — but the retry is
	// paced the same way.
	fn = &fakeNotifier{on: true, admin: true, deliverSet: true, deliver: 1, applyErr: errors.New("email member: dial tcp: refused")}
	s = run(fn)
	if n := attempts(fn, 1); n != 1 {
		t.Fatalf("delivery attempts = %d after a partial delivery, want 1 (held)", n)
	}
	permits, _ := s.store.ListPermitsFor(ctx, owner)
	if k, _, _ := s.store.PermitNotify(ctx, permits[0].ID); k != "" {
		t.Fatalf("a partial delivery recorded the durable key %q; the missed member would never be retried", k)
	}
}
