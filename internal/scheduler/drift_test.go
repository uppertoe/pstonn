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
// someone editing it in the tenant portal directly. Until now no test executed it at
// all, because the fake tenant always reported an empty current plate, so the drift
// branch could not be reached. That matters more than most untested code: drift
// detection is the only thing that recovers the state where the DB and the tenant
// disagree, and while they disagree the car actually parked outside is not the car on
// the permit.

// driftSetup builds an owner with one active permit whose roster wants rosterReg and
// whose recorded belief is believedReg, plus a tenant reporting tenantReg.
func driftSetup(t *testing.T, owner, tenantID, rosterReg, believedReg, tenantReg string) (*store.Store, *fakeTenant, *fakeNotifier, *Scheduler, int64) {
	t.Helper()
	st := newStore(t)
	pid, _ := seedActivePermit(t, st, owner, tenantID, rosterReg, believedReg)
	fc := &fakeTenant{}
	fc.setCurrent(tenantID, tenantReg)
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})
	return st, fc, nf, s, pid
}

// The core case: the tenant shows a plate the app did not put there. The app must
// record what the tenant actually shows (so the activity log tells the truth, and so
// the re-assertion is not deduped away as a no-op against the pre-drift row) and then
// re-assert the schedule over it.
func TestCheckDriftRecordsAndReasserts(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "drift@example.com", "drift-1"
	st, _, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", "MEDDLED1")

	s.checkDrift(ctx, owner, "")

	// The DB now believes what the tenant reports, not what it wished were true.
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

// A case- or spacing-only difference is the SAME plate — the tenant echoes plates
// back in whatever form they were typed. Treating that as drift would write an
// "changed directly at the council portal" row and a tenant write for nothing, which
// is both a false statement about the user's account and pointless traffic.
func TestCheckDriftIgnoresCaseAndSpacingVariants(t *testing.T) {
	ctx := context.Background()
	for _, variant := range []string{"roster1", "ROSTER 1", "  ROSTER1  ", "RoStEr1"} {
		t.Run(variant, func(t *testing.T) {
			const owner, tenantID = "same@example.com", "same-1"
			st, fc, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", variant)

			s.checkDrift(ctx, owner, "")

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

// A tenant READ failure must be silent and harmless. It is not evidence of drift, and
// treating it as "the council shows nothing" would blank the permit's recorded plate
// and then claim in the activity log that someone changed it in the portal.
func TestCheckDriftIgnoresReadFailures(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "err@example.com", "err-1"
	st, fc, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", "")
	fc.permitsErr = errors.New("council unreachable")

	s.checkDrift(ctx, owner, "")

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
	const owner, tenantID = "blank@example.com", "blank-1"
	st, fc, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", "ROSTER1")
	// The grid says the permit has no plate; managedVehicle still shows ROSTER1.
	fc.setGridRego(tenantID, "")

	s.checkDrift(ctx, owner, "")

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
	const owner, tenantID = "omit@example.com", "omit-1"
	// cached OLD123; managedVehicle reports NEW456; the grid omits the rego (blank).
	st, fc, _, s, pid := driftSetup(t, owner, tenantID, "OLD123", "OLD123", "NEW456")
	fc.setGridRego(tenantID, "") // grid blank; managedVehicle still shows NEW456

	s.checkDrift(ctx, owner, "")

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
	const owner, tenantID = "cleared2@example.com", "cleared-2"
	st, _, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", "")

	s.checkDrift(ctx, owner, "")

	p, _ := st.GetPermit(ctx, pid)
	if p.ActiveRegistration != "" {
		t.Errorf("a corroborated clearing was ignored; recorded plate is still %q", p.ActiveRegistration)
	}
}

// The tenant reporting an EMPTY plate is real drift: somebody cleared the permit, and
// the app must notice rather than keep believing its own cached value.
func TestCheckDriftNoticesAClearedPermit(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "cleared@example.com", "cleared-1"
	st, _, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", "")

	s.checkDrift(ctx, owner, "")

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
// — but an expired permit must produce no drift row and no tenant write, because
// the app no longer manages it.
//
// The expiry is set on the COUNCIL, not just locally: the tenant is the authority
// on end dates and checkDrift writes what it reports into the permit row, so a
// locally-expired permit the tenant still reports as current is not expired.
func TestCheckDriftSkipsInactivePermits(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "expired@example.com", "expired-1"
	st, fc, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "ROSTER1", "MEDDLED1")

	// Retire the permit: an end date whose local day is well past.
	past := time.Now().AddDate(0, 0, -10)
	fc.setTenantEndDate(tenantID, past)
	if err := st.UpdatePermitMeta(ctx, owner, st.DefaultTenant, tenantID, "Approved", "", "", past); err != nil {
		t.Fatalf("set expiry: %v", err)
	}
	if p, err := st.GetPermit(ctx, pid); err != nil || !p.Inactive(time.Now(), time.UTC) {
		t.Fatalf("fixture is not actually inactive (err=%v)", err)
	}

	s.checkDrift(ctx, owner, "")

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
// doubling its own tenant traffic.
func TestDriftDecoupledFromWarm(t *testing.T) {
	ctx := context.Background()
	const owner = "decouple@example.com"
	st := newStore(t)
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	fc := &fakeTenant{permits: []parking.PermitInfo{{CouncilPermitID: "p1", Status: "Granted"}}}
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

// A FAILED grid read must NOT advance drift_checked_at. Otherwise a single failed
// read — most likely during a tenant outage, exactly when we most want to keep
// re-reading — stands the drift check down for a whole interval instead of retrying
// on the next pass. The warm itself still succeeds (it uses a different call), so
// the session is alive and drift is due: the exact path that used to mark the check
// done regardless of the read's outcome.
func TestFailedDriftDoesNotMarkChecked(t *testing.T) {
	ctx := context.Background()
	const owner = "driftfail@example.com"
	st := newStore(t)
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	fc := &fakeTenant{permits: []parking.PermitInfo{{CouncilPermitID: "p1", Status: "Granted"}}}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour,
		WarmInterval: time.Nanosecond, DriftInterval: time.Nanosecond, Notifier: nf})
	time.Sleep(2 * time.Millisecond)

	// The grid read fails while the warm succeeds.
	fc.permitsErr = errors.New("council unreachable")
	s.keepWarm(ctx)

	cs, err := st.GetTenantSession(ctx, owner)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if !cs.DriftCheckedAt.IsZero() {
		t.Fatalf("a failed drift read advanced drift_checked_at to %v — the retry is now suppressed for a full interval", cs.DriftCheckedAt)
	}

	// Recovery: the next pass reads the grid successfully and only now marks it done.
	fc.permitsErr = nil
	s.keepWarm(ctx)
	cs, _ = st.GetTenantSession(ctx, owner)
	if cs.DriftCheckedAt.IsZero() {
		t.Fatal("a successful drift read did not advance drift_checked_at")
	}
}

// Drift's compare-and-swap must be judged against what we believed when the tenant
// read STARTED. Reading the baseline afterwards folded a concurrent apply into the
// expected value, so the swap succeeded and regressed the record to a plate the tenant
// no longer holds — costing a false "changed at the portal" row, a duplicate notice,
// and (if the target flips before the next tick) a permit shown as covered when it is
// not, until the next drift read hours later.
func TestDriftDoesNotRegressAnApplyThatLandedDuringTheRead(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "raced@example.com", "raced-1"
	st, fc, _, s, pid := driftSetup(t, owner, tenantID, "ROSTER1", "OLD999", "OLD999")

	// While the tenant read is in flight, an apply commits a NEWER plate.
	fc.onListPermits = func() {
		if err := st.SetPermitActive(ctx, pid, "NEW222"); err != nil {
			t.Errorf("simulated concurrent apply: %v", err)
		}
	}

	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatalf("drift: %v", err)
	}

	p, err := st.GetPermit(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.ActiveRegistration != "NEW222" {
		t.Fatalf("drift regressed the record to %q; the apply that landed during the read must win", p.ActiveRegistration)
	}
}

// TestPartialPermitListIsNotACompletedDriftCheck pins that acting on a page is not the
// same as having checked the account. If the tenant starts paging and we advance
// last_drift_check anyway, the permits behind the first page are never read again:
// their plate drift goes undetected and their expiry warnings never fire, silently and
// for good. The work we CAN do still happens; only the checkpoint is withheld.
func TestPartialPermitListIsNotACompletedDriftCheck(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "paged@example.com"
	// Session only: this test seeds its OWN permit ("14576") below and counts exactly
	// one, so it must not also get seedSession's generic warm-permit.
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: owner, Cookie: "seed"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	pid, err := st.UpsertPermit(ctx, owner, "14576", "14", "Permit")
	if err != nil {
		t.Fatalf("permit: %v", err)
	}
	vid, err := st.CreateVehicle(ctx, owner, "PAGE01", "car", "")
	if err != nil {
		t.Fatalf("vehicle: %v", err)
	}
	if err := st.SetRule(ctx, pid, time.Monday, vid); err != nil {
		t.Fatalf("rule: %v", err)
	}

	// A permit the tenant DOES return, so the pass has real work to do: the meta write
	// below is what proves the partial path still does everything it can before it
	// declines to check the owner off.
	fc := &fakeTenant{partialPermits: true, permits: []parking.PermitInfo{{
		CouncilPermitID: "14576", PermitNumber: "VPP9", PermitType: "Resident",
		Status: "Active", CurrentRego: "PAGE01",
	}}}
	s := New(st, fc, time.UTC, Options{WarmInterval: time.Hour, DriftInterval: time.Nanosecond})

	if err := s.checkDrift(ctx, owner, ""); !errors.Is(err, parking.ErrPermitListPartial) {
		t.Fatalf("checkDrift = %v, want ErrPermitListPartial: a page must not be reported "+
			"as a completed check of the whole account", err)
	}
	// The work we COULD do still happened.
	got, err := st.ListPermitsFor(ctx, owner)
	if err != nil || len(got) != 1 {
		t.Fatalf("permits: %v / %d", err, len(got))
	}
	if got[0].PermitNumber != "VPP9" {
		t.Fatalf("the partial pass skipped the metadata refresh for a permit it DID read: %+v; "+
			"declining the checkpoint must not mean declining the work", got[0])
	}

	// And the checkpoint really is withheld end-to-end, through warmOne rather than by
	// reading checkDrift's return value.
	cs, err := st.GetTenantSession(ctx, owner)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	s.warmOne(ctx, cs)
	after, err := st.GetTenantSession(ctx, owner)
	if err != nil {
		t.Fatalf("session after: %v", err)
	}
	if !after.DriftCheckedAt.IsZero() {
		t.Fatalf("last_drift_check was advanced (%s) on a partial list; the permits behind "+
			"the page would never be read again", after.DriftCheckedAt)
	}

	// A complete list still checks the owner off, so the guard rejects truncation and
	// not drift in general.
	fc.mu.Lock()
	fc.partialPermits = false
	fc.mu.Unlock()
	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatalf("a complete permit list must check the owner off: %v", err)
	}
	s.warmOne(ctx, cs)
	done, err := st.GetTenantSession(ctx, owner)
	if err != nil {
		t.Fatalf("session done: %v", err)
	}
	if done.DriftCheckedAt.IsZero() {
		t.Fatal("a complete permit list did not advance last_drift_check")
	}
}

// TestDriftTellsTheHousehold: a plate changed at the council directly is news
// the household must hear, not just an activity row.
func TestDriftTellsTheHousehold(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "drift-notice@example.com", "drift-notice"
	_, _, nf, s, _ := driftSetup(t, owner, tenantID, "BBB222", "BBB222", "AAA111")
	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	nf.mu.Lock()
	got := append([]string(nil), nf.drifts...)
	nf.mu.Unlock()
	if len(got) != 1 || got[0] != owner+"|AAA111" {
		t.Fatalf("drift notices = %v, want one to the household naming AAA111", got)
	}
}
