package scheduler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
)

// TestSettleRetractsANeverAppliedBooking: a booking that failed all day and then
// expired used to vanish without a word — settle() cleared the streak, and the
// household's last message was "still updating, p.stonn will keep trying". The
// end of a failure episode whose target NEVER landed must say so.
func TestSettleRetractsANeverAppliedBooking(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "retract@example.com"
	pid, _ := seedActivePermit(t, st, owner, "ret-1", "AAA111", "OLD999")

	fc := &fakeTenant{setErr: parking.ErrCouncilBusy}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})

	// The change to AAA111 fails long enough to matter.
	for i := 0; i < failNotifyThreshold+1; i++ {
		s.reconcileAll(ctx)
	}

	// The target then goes away: the roster day now points at a vehicle whose
	// plate is what the permit already shows — the same shape as a booking window
	// ending. Nothing needs the tenant, so settle() runs.
	veh, err := st.CreateVehicle(ctx, owner, "OLD999", "Already-on car", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRule(ctx, pid, time.Now().In(time.UTC).Weekday(), veh); err != nil {
		t.Fatal(err)
	}
	fc.setErr = nil
	s.reconcileAll(ctx)

	deadline := time.Now().Add(2 * time.Second)
	var retraction *notify.ApplyOutcome
	for retraction == nil {
		for _, o := range nf.outcomeSnap() {
			if strings.Contains(o.Reason, "never applied") {
				o := o
				retraction = &o
				break
			}
		}
		if retraction == nil && time.Now().After(deadline) {
			t.Fatalf("no retraction was sent; outcomes: %+v", nf.outcomeSnap())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if retraction.OK || retraction.Transient {
		t.Fatalf("the retraction must be a hard failure notice (no quiet-hours hold), got %+v", retraction)
	}
	if retraction.Reg != "AAA111" || retraction.CurrentReg != "OLD999" {
		t.Fatalf("the retraction must name the never-applied plate and the one still on: %+v", retraction)
	}

	// And it does not repeat: the streak is cleared, so the next settled tick is quiet.
	before := len(nf.outcomeSnap())
	s.reconcileAll(ctx)
	time.Sleep(20 * time.Millisecond)
	if got := len(nf.outcomeSnap()); got != before {
		t.Fatalf("retraction repeated on a settled tick (%d -> %d outcomes)", before, got)
	}
}

// TestSettleRecordsRecoveryWhenTheChangeLanded: the counterpart — if the failing
// target ends up ON the permit (someone set it at the portal, a guest's inline
// apply committed it, or the transient error was a false-negative), a "was never
// applied" retraction would be flatly wrong. Instead settle closes the episode out
// as a RECOVERY: no notification (a resolved blip needs none), but a "success" row
// is written so the audit log and /admin read fail→resolved rather than sitting on
// the stale "error".
func TestSettleRecordsRecoveryWhenTheChangeLanded(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "landed@example.com"
	pid, _ := seedActivePermit(t, st, owner, "land-1", "AAA111", "OLD999")

	fc := &fakeTenant{setErr: parking.ErrCouncilBusy}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})

	for i := 0; i < failNotifyThreshold+1; i++ {
		s.reconcileAll(ctx)
	}
	// Sanity: the episode left an "error" as the newest apply-log row.
	if last, err := st.LastApply(ctx, pid); err != nil || last.Status != "error" {
		t.Fatalf("precondition: want newest apply row 'error', got %q (err %v)", last.Status, err)
	}
	// The wanted plate lands out of band (portal fix / guest inline commit).
	if err := st.SetPermitActive(ctx, pid, "AAA111"); err != nil {
		t.Fatal(err)
	}
	fc.setErr = nil
	s.reconcileAll(ctx)
	time.Sleep(50 * time.Millisecond)

	// No retraction: the change DID land, so "never applied" would be wrong.
	for _, o := range nf.outcomeSnap() {
		if strings.Contains(o.Reason, "never applied") {
			t.Fatalf("retraction sent for a change that DID land: %+v", o)
		}
	}
	// But the audit trail is closed out: the newest row is now a recovery success on
	// the plate that had been failing, so nothing reads as a permanent error.
	last, err := st.LastApply(ctx, pid)
	if err != nil {
		t.Fatalf("reading last apply: %v", err)
	}
	if last.Status != "success" || last.Registration != "AAA111" || !strings.Contains(last.Detail, "recovered") {
		t.Fatalf("want a recovery success row for AAA111, got status=%q reg=%q detail=%q",
			last.Status, last.Registration, last.Detail)
	}
}
