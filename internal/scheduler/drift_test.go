package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// checkDrift is how the app notices that a permit was changed OUTSIDE p.stonn —
// someone editing it in the council portal directly. Until now no test executed it at
// all, because the fake council always reported an empty current plate, so the drift
// branch could not be reached. That matters more than most untested code: drift
// detection is the only thing that recovers the state where the DB and the council
// disagree, and while they disagree the car actually parked outside is not the car on
// the permit.

// driftSetup builds an owner with one active permit whose roster wants rosterReg and
// whose recorded belief is believedReg, plus a council reporting councilReg.
func driftSetup(t *testing.T, owner, councilID, rosterReg, believedReg, councilReg string) (*store.Store, *fakeCouncil, *fakeNotifier, *Scheduler, int64) {
	t.Helper()
	st := newStore(t)
	pid, _ := seedActivePermit(t, st, owner, councilID, rosterReg, believedReg)
	fc := &fakeCouncil{}
	fc.setCurrent(councilID, councilReg)
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})
	return st, fc, nf, s, pid
}

// The core case: the council shows a plate the app did not put there. The app must
// record what the council actually shows (so the activity log tells the truth, and so
// the re-assertion is not deduped away as a no-op against the pre-drift row) and then
// re-assert the schedule over it.
func TestCheckDriftRecordsAndReasserts(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "drift@example.com", "drift-1"
	st, _, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", "MEDDLED1")

	s.checkDrift(ctx, owner)

	// The DB now believes what the council reports, not what it wished were true.
	p, err := st.GetPermit(ctx, pid)
	if err != nil {
		t.Fatalf("get permit: %v", err)
	}
	if p.ActiveRegistration != "MEDDLED1" {
		t.Fatalf("recorded plate = %q, want the council's MEDDLED1 — otherwise the next reconcile sees no work to do", p.ActiveRegistration)
	}

	// The external change is in the activity log, attributed as external.
	logs, err := st.ListApplyLogFor(ctx, owner, 10)
	if err != nil {
		t.Fatalf("list apply log: %v", err)
	}
	var found *store.ApplyRecord
	for i := range logs {
		if logs[i].Source == "external" {
			found = &logs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no external row in the activity log: %+v", logs)
	}
	if found.Registration != "MEDDLED1" || found.Status != "changed" {
		t.Errorf("external row = reg %q status %q, want MEDDLED1/changed", found.Registration, found.Status)
	}

	// And a reconcile now puts the roster back on the permit.
	s.reconcileAll(ctx)
	p, _ = st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "ROSTER1" {
		t.Errorf("after re-assertion the permit holds %q, want the rostered ROSTER1", p.ActiveRegistration)
	}
}

// A case- or spacing-only difference is the SAME plate — the council echoes plates
// back in whatever form they were typed. Treating that as drift would write an
// "changed directly at the council portal" row and a council write for nothing, which
// is both a false statement about the user's account and pointless traffic.
func TestCheckDriftIgnoresCaseAndSpacingVariants(t *testing.T) {
	ctx := context.Background()
	for _, variant := range []string{"roster1", "ROSTER 1", "  ROSTER1  ", "RoStEr1"} {
		t.Run(variant, func(t *testing.T) {
			const owner, councilID = "same@example.com", "same-1"
			st, fc, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", variant)

			s.checkDrift(ctx, owner)

			if logs, err := st.ListApplyLogFor(ctx, owner, 10); err != nil || len(logs) != 0 {
				t.Errorf("a %q variant was recorded as external drift (%d rows, err=%v)", variant, len(logs), err)
			}
			if calls := fc.callSnap(); len(calls) != 0 {
				t.Errorf("a %q variant drove a council write: %v", variant, calls)
			}
			p, _ := st.GetPermit(ctx, pid)
			if p.ActiveRegistration != "ROSTER1" {
				t.Errorf("the recorded plate was rewritten to %q for a mere spelling difference", p.ActiveRegistration)
			}
		})
	}
}

// A council READ failure must be silent and harmless. It is not evidence of drift, and
// treating it as "the council shows nothing" would blank the permit's recorded plate
// and then claim in the activity log that someone changed it in the portal.
func TestCheckDriftIgnoresReadFailures(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "err@example.com", "err-1"
	st, fc, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", "")
	fc.permitsErr = errors.New("council unreachable")

	s.checkDrift(ctx, owner)

	p, _ := st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "ROSTER1" {
		t.Errorf("a failed council read changed the recorded plate to %q", p.ActiveRegistration)
	}
	if logs, err := st.ListApplyLogFor(ctx, owner, 10); err != nil || len(logs) != 0 {
		t.Errorf("a failed council read wrote %d activity rows (err=%v)", len(logs), err)
	}
}

// Drift reads the owner-level grid, which — unlike managedVehicle — carries nothing
// to corroborate an EMPTY plate with (see parking.emptyIsCredible). So a blank grid
// rego must be confirmed by a per-permit read before the app will believe a permit
// was cleared. Getting this wrong blanks a live permit and tells the household, in
// writing, that someone changed it in the portal when nobody did.
func TestCheckDriftDoesNotTrustAnEmptyGridRego(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "blank@example.com", "blank-1"
	st, fc, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", "ROSTER1")
	// The grid says the permit has no plate; managedVehicle still shows ROSTER1.
	fc.setGridRego(councilID, "")

	s.checkDrift(ctx, owner)

	p, _ := st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "ROSTER1" {
		t.Errorf("an uncorroborated blank grid rego blanked the recorded plate to %q", p.ActiveRegistration)
	}
	if logs, err := st.ListApplyLogFor(ctx, owner, 10); err != nil || len(logs) != 0 {
		t.Errorf("an uncorroborated blank grid rego wrote %d activity rows (err=%v)", len(logs), err)
	}
}

// The grid can disagree with the authoritative managedVehicle read in the other
// direction too: the grid OMITS a rego that managedVehicle still reports. That
// non-empty authoritative value is a real external change and must be adopted. An
// earlier version corroborated the blank but then discarded ANY non-empty
// confirmation, so a grid that persistently omitted a rego could never detect
// drift — the confirming call was paid for and its answer thrown away.
func TestCheckDriftAdoptsAuthoritativePlateWhenGridIsBlank(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "omit@example.com", "omit-1"
	// cached OLD123; managedVehicle reports NEW456; the grid omits the rego (blank).
	st, fc, _, s, pid := driftSetup(t, owner, councilID, "OLD123", "OLD123", "NEW456")
	fc.setGridRego(councilID, "") // grid blank; managedVehicle still shows NEW456

	s.checkDrift(ctx, owner)

	p, _ := st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "NEW456" {
		t.Fatalf("recorded plate = %q, want the authoritative NEW456 the grid omitted", p.ActiveRegistration)
	}
	logs, err := st.ListApplyLogFor(ctx, owner, 10)
	if err != nil {
		t.Fatalf("list apply log: %v", err)
	}
	var ext *store.ApplyRecord
	for i := range logs {
		if logs[i].Source == "external" {
			ext = &logs[i]
		}
	}
	if ext == nil || ext.Registration != "NEW456" {
		t.Fatalf("no external drift row for the grid-omitted NEW456: %+v", logs)
	}
}

// The mirror of the above: when BOTH views agree the permit is empty, it really was
// cleared and the app must record it. This is what keeps the corroboration guard
// from quietly disabling clearing detection altogether.
func TestCheckDriftBelievesACorroboratedClearing(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "cleared2@example.com", "cleared-2"
	st, _, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", "")

	s.checkDrift(ctx, owner)

	p, _ := st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "" {
		t.Errorf("a corroborated clearing was ignored; recorded plate is still %q", p.ActiveRegistration)
	}
}

// The council reporting an EMPTY plate is real drift: somebody cleared the permit, and
// the app must notice rather than keep believing its own cached value.
func TestCheckDriftNoticesAClearedPermit(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "cleared@example.com", "cleared-1"
	st, _, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", "")

	s.checkDrift(ctx, owner)

	p, _ := st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "" {
		t.Errorf("recorded plate = %q, want empty to match the cleared permit", p.ActiveRegistration)
	}
	// And the schedule is re-asserted over the clearing.
	s.reconcileAll(ctx)
	p, _ = st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "ROSTER1" {
		t.Errorf("after re-assertion the permit holds %q, want ROSTER1", p.ActiveRegistration)
	}
}

// An expired permit must not be ACTED on. The owner-level grid read happens either
// way — it is one call for the whole account, which is the point of reading the grid
// — but an expired permit must produce no drift row and no council write, because
// the app no longer manages it.
//
// The expiry is set on the COUNCIL, not just locally: the council is the authority
// on end dates and checkDrift writes what it reports into the permit row, so a
// locally-expired permit the council still reports as current is not expired.
func TestCheckDriftSkipsInactivePermits(t *testing.T) {
	ctx := context.Background()
	const owner, councilID = "expired@example.com", "expired-1"
	st, fc, _, s, pid := driftSetup(t, owner, councilID, "ROSTER1", "ROSTER1", "MEDDLED1")

	// Retire the permit: an end date whose local day is well past.
	past := time.Now().AddDate(0, 0, -10)
	fc.setCouncilEndDate(councilID, past)
	if err := st.UpdatePermitMeta(ctx, owner, councilID, "Approved", "", "", past); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	if p, err := st.GetPermit(ctx, pid); err != nil || !p.Inactive(time.Now(), time.UTC) {
		t.Fatalf("fixture is not actually inactive (err=%v)", err)
	}

	s.checkDrift(ctx, owner)

	if logs, err := st.ListApplyLogFor(ctx, owner, 10); err != nil || len(logs) != 0 {
		t.Errorf("an inactive permit was drift-checked (%d rows, err=%v)", len(logs), err)
	}
	if calls := fc.callSnap(); len(calls) != 0 {
		t.Errorf("an inactive permit drove council traffic: %v", calls)
	}
}

// Drift must run on its OWN cadence, not on every keep-warm. A session that is
// warm-due but not yet drift-due gets warmed with NO grid read; once drift comes
// due, a pass does the grid read. This is the decoupling that stops keep-warm from
// doubling its own council traffic.
func TestDriftDecoupledFromWarm(t *testing.T) {
	ctx := context.Background()
	const owner = "decouple@example.com"
	st := newStore(t)
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	fc := &fakeCouncil{permits: []parking.PermitInfo{{CouncilPermitID: "p1", Status: "Granted"}}}
	nf := &fakeNotifier{on: true}

	// Warm every tick; drift every 6h (baseline is the just-seeded UpdatedAt, so not
	// due). A pass should warm the session but make NO grid read.
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour,
		WarmInterval: time.Nanosecond, DriftInterval: 6 * time.Hour, Notifier: nf})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(ctx)
	if len(fc.refreshed) == 0 {
		t.Fatal("session was not warmed")
	}
	if n := fc.listCallCount(); n != 0 {
		t.Fatalf("drift ran on a warm even though it was not due: %d grid reads", n)
	}

	// Bring drift due: now a pass should do exactly one grid read.
	s.driftInterval = time.Nanosecond
	s.keepWarm(ctx)
	if n := fc.listCallCount(); n != 1 {
		t.Fatalf("drift did not run exactly once when due: %d grid reads", n)
	}
}
