package scheduler

import (
	"context"
	"errors"
	"fmt"
	"github.com/uppertoe/pstonn/internal/redact"
	"hash/fnv"
	"slices"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// driftThresholdFor is this owner's stable, jittered drift-read interval. Stable
// per owner (a deterministic hash) so a household's drift reads keep their own
// phase rather than aligning across the fleet, and phased separately from keep-warm
// (a "drift:" prefix) so the two cadences don't beat together into a burst.
func (s *Scheduler) driftThresholdFor(owner string) time.Duration {
	if s.jitterFrac <= 0 {
		return s.driftInterval
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte("drift:" + owner))
	u := float64(h.Sum64()>>11) / float64(uint64(1)<<53)
	return time.Duration(float64(s.driftInterval) * (1 + (u*2-1)*s.jitterFrac))
}

// noteDriftFailure backs the owner off exponentially (5m, 10m, ... capped at the drift
// interval) so a persistent failure costs one read per backoff rather than one per warm
// tick. A shape failure additionally feeds a distinct-owner tally: several owners
// failing the same way is an API change, not a blip, and the operator should hear once.
func (s *Scheduler) noteDriftFailure(ctx context.Context, owner string, err error) {
	s.driftMu.Lock()
	s.driftFails[owner]++
	n := s.driftFails[owner]
	// Start at the warm tick and climb fast: the pass ticks every 3 minutes, so a 5m
	// first step barely damped the fleet-wide case this exists for. 15m x 4^(n-1)
	// reaches the cap in three failures instead of seven.
	backoff := 15 * time.Minute
	for i := 1; i < n && i < 5; i++ {
		backoff *= 4
	}
	if s.driftInterval > 0 && backoff > s.driftInterval {
		backoff = s.driftInterval
	}
	s.driftRetryAt[owner] = s.now().Add(backoff)
	var distinct int
	if kind, _ := parking.FailureOf(err); kind == parking.FailUnexpected {
		s.driftShape = append(pruneChurn(s.driftShape, s.now()), churnEvent{owner, s.now()})
		distinct = distinctOwners(s.driftShape)
	}
	s.driftMu.Unlock()
	if distinct >= sessionChurnAlertOwners {
		s.systemAlert(ctx, "drift-shape",
			"Council permit reads are failing the same way for several accounts",
			fmt.Sprintf("%d different accounts have had a drift/permit read rejected as an unexpected response within the last hour. That pattern is an API-shape change rather than a blip: permit status, expiry and external-change detection are stale for those accounts until it is fixed. Reads are backing off, so traffic is bounded meanwhile.", distinct))
	}
}

func (s *Scheduler) noteDriftSuccess(owner string) {
	s.driftMu.Lock()
	delete(s.driftFails, owner)
	delete(s.driftRetryAt, owner)
	s.driftMu.Unlock()
}

// noteDriftDeferred backs an owner off by a whole drift interval without touching the
// failure ladder: the read worked, it was just not a complete account.
func (s *Scheduler) noteDriftDeferred(owner string) {
	s.driftMu.Lock()
	delete(s.driftFails, owner)
	s.driftRetryAt[owner] = s.now().Add(s.driftThresholdFor(owner))
	s.driftMu.Unlock()
}

// alertTruncatedList raises the paging alert at most once a day. Truncation persists
// until pagination can collect the account, and systemAlert's default 30-minute repeat
// would be 48 alerts a day — muted inside one, taking the rest of the channel with it.
// The interval is passed DOWN rather than gated here, so a failed delivery still
// retries on the short window instead of being silenced for a day.
func (s *Scheduler) alertTruncatedList(ctx context.Context) {
	s.systemAlertEvery(ctx, "council-permit-list-truncated",
		"The council is only returning part of the permit list",
		"Permit reads are coming back as pages and we could not collect the whole account, so the permits "+
			"we could not reach are not being drift-checked: their plate changes go undetected and their "+
			"expiry warnings will not fire. See truncated_grid_* on /status for the last observed counts.",
		24*time.Hour)
}

func (s *Scheduler) driftBackedOff(owner string, now time.Time) bool {
	s.driftMu.Lock()
	defer s.driftMu.Unlock()
	at, ok := s.driftRetryAt[owner]
	return ok && now.Before(at)
}

// driftDue reports whether the owner-grid drift/expiry read is due for this
// session. A session that has never had one — a fresh link, or a row migrated
// before the column existed — falls back to the warm clock as its baseline, so it
// is NOT treated as instantly overdue, which would drift-read the whole fleet at
// once right after the migrating deploy.
func (s *Scheduler) driftDue(cs store.TenantSession, now time.Time) bool {
	if s.driftInterval <= 0 {
		return false
	}
	if s.driftBackedOff(cs.Owner, now) {
		return false // a failing read is retried on its own backoff, not every warm tick
	}
	if s.driftRequested(cs.Owner) {
		return true // someone observed evidence of drift; verify on the next pass, not in 6h
	}
	baseline := cs.DriftCheckedAt
	if baseline.IsZero() {
		baseline = cs.UpdatedAt
	}
	return now.Sub(baseline) >= s.driftThresholdFor(cs.Owner)
}

// RequestDriftSoon asks for this owner's next drift read to run on the next
// warm pass (≤3 min) instead of waiting out the ~6h cadence. Callers use it
// when they have SEEN evidence the local plate belief diverged from the
// tenant — e.g. the guest page's cached tenant read disagreeing with the
// stored active_registration — so the belief heals while the moment still
// matters (a guest is at the kerb), through the normal drift path with all its
// care (CAS adopt, external-change audit row, backoff, credibility checks).
//
// In-memory on purpose: a request lost to a restart just means that owner
// falls back to the regular cadence, and the observation that prompted it will
// recur if it still holds. Idempotent; cleared only once a drift round
// completes durably for the owner, so a failed read keeps the intent (the
// backoff still paces retries meanwhile).
func (s *Scheduler) RequestDriftSoon(owner string) {
	s.driftMu.Lock()
	if s.driftAsap == nil {
		s.driftAsap = make(map[string]struct{})
	}
	s.driftAsap[owner] = struct{}{}
	s.driftMu.Unlock()
}

func (s *Scheduler) driftRequested(owner string) bool {
	s.driftMu.Lock()
	defer s.driftMu.Unlock()
	_, ok := s.driftAsap[owner]
	return ok
}

func (s *Scheduler) clearDriftRequest(owner string) {
	s.driftMu.Lock()
	delete(s.driftAsap, owner)
	s.driftMu.Unlock()
}

// bumpFailStreak increments and returns the consecutive-failure count for a
// permit; clearFailStreak resets it after a success. Persisted (on the permit
// row) so a restart doesn't reset the grace before a transient failure is alerted.
// checkDrift re-reads the tenant's actual current plate for the owner's permits
// and writes it into active_registration. Reconcile skips a permit when the
// scheduled plate already equals the CACHED active_registration, so if someone
// changed the vehicle directly in the tenant portal, reconcile would never
// notice — until a dashboard visit refreshed the cache. Doing this read on the
// slow keep-warm cadence (already rate-spaced, once a session refreshes) catches
// that drift and re-arms reconcile, at gentle tenant load rather than a per-tick
// firehose. Any correction is kicked so reconcile re-applies the schedule promptly.
//
// It reads ONE owner-level Index/grid call rather than one managedVehicle call per
// managed permit. A 2026-07-31 capture confirmed the grid's VehicleRego agrees with
// managedVehicle's RegistrationNumber, and that the same row already carries the
// status and end date the expiry warning needs — which used to be a SECOND tenant
// call right after this one. So the per-warm tenant cost is now one API request
// regardless of how many permits an owner manages, instead of managed+1.
//
// Only visitor permits are manageable (see server.isVisitorPermit), so that is
// typically one or two per household rather than the full permit list — the capture
// account held three permits but only one addable one. The win is therefore modest
// per household; what matters is that permit count leaves the scaling term entirely.
func (s *Scheduler) checkDrift(ctx context.Context, owner, tenantID string) error {
	// The caller (keepWarm) already spaced this call from the previous one, and the
	// transport governor spaces at the request level, so no extra sleep here.
	// Capture our belief BEFORE the tenant round trip. The CAS below exists to discard
	// a reading that an apply overtook mid-flight — reading the baseline afterwards
	// folded that apply INTO the expected value, so the swap succeeded and regressed the
	// record to a plate the tenant no longer holds.
	before, berr := s.store.ListPermitsFor(ctx, owner)
	if berr != nil {
		return berr
	}
	// Only this tenant's permits: the account may hold permits with another
	// tenant, which this session cannot see and must not judge missing.
	before = slices.DeleteFunc(before, func(p model.Permit) bool { return p.TenantID != tenantID })
	wasActive := make(map[int64]string, len(before))
	for _, p := range before {
		wasActive[p.ID] = p.ActiveRegistration
	}
	live, complete, err := s.tenant.ListPermitsComplete(ctx, owner, tenantID)
	if err != nil {
		// A read failure is not evidence of drift, and — critically — it is not a
		// drift check either: report it so the caller does NOT advance
		// drift_checked_at and suppress the retry for a whole interval. Worst
		// exactly when the tenant is degraded and we most want to keep trying.
		return err
	}
	byTenantID := make(map[string]parking.PermitInfo, len(live))
	// A drift round is only "done" if every required write landed. Recording a partial
	// round as complete stands the check down for the whole drift interval (hours),
	// which is exactly when it should retry soonest.
	var incomplete error
	for _, pi := range live {
		byTenantID[pi.CouncilPermitID] = pi
		// Refresh expiry/status/type from the same response. Owner-scoped, so it
		// only touches rows this account manages.
		if err := s.store.UpdatePermitMeta(ctx, owner, tenantID, pi.CouncilPermitID, pi.Status, pi.PermitNumber, pi.PermitType, pi.EndDate); err != nil {
			alog.Infof("drift meta write for permit %s: %v", pi.CouncilPermitID, err)
			incomplete = err
		}
	}

	// Re-read AFTER the meta write so Inactive below is judged on the expiry the
	// tenant just reported, not the one we believed a moment ago.
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return err // couldn't compare against our own record; retry rather than mark done
	}
	// The same tenant filter as `before`. Council permit ids are the PORTAL's ids
	// and overlap between portals (see parking's permitMine), so without this the
	// loop below keyed another tenant's permit into THIS tenant's grid row: a plate
	// that matched by id alone was adopted as "changed directly at the council" on
	// a permit this session cannot even see, and the kicked reconcile then wrote
	// the schedule over it at the other portal.
	permits = slices.DeleteFunc(permits, func(p model.Permit) bool { return p.TenantID != tenantID })
	drifted := false
	now := s.now()
	for i := range permits {
		p := permits[i]
		if p.Inactive(now, s.locOf(p.Owner, p.TenantID)) {
			continue // don't act on permits we no longer manage
		}
		pi, ok := byTenantID[p.CouncilPermitID]
		if !ok {
			continue // the tenant no longer lists it; syncing that is not drift's job
		}
		actual := pi.CurrentRego
		if actual == "" && !model.SamePlate("", p.ActiveRegistration) {
			// The grid claims the permit was cleared, but an empty grid rego is the one
			// reading the grid cannot be trusted on: it carries nothing to corroborate
			// "no vehicle" the way managedVehicle does (permitVehicleCount, see
			// parking.emptyIsCredible), and blanking a plate on a misread writes a FALSE
			// "changed at the portal" row and tells the household their permit was
			// cleared when it wasn't. So confirm against the authoritative per-permit
			// read and ADOPT whatever it reports — which may be a genuine clearing ("")
			// OR a plate the grid simply omitted. The latter is itself a real external
			// change; discarding it (an earlier version continued on any non-empty
			// confirmation) left a grid that persistently omits a rego unable to detect
			// drift at all, even though the confirming call had already been paid for.
			confirmed, cerr := s.tenant.CurrentVehicle(ctx, owner, p)
			if cerr != nil {
				// Couldn't confirm; believe nothing — but this round did NOT answer the
				// question it was for, so it must not be recorded as a completed check.
				incomplete = cerr
				continue
			}
			actual = confirmed
		}
		if model.SamePlate(actual, p.ActiveRegistration) {
			// Agrees with our record (incl. the common grid==cached case): no drift —
			// but a read that agrees is still a council confirmation. Keep the stamp
			// fresh so a household whose plate never changes still gets the tick on
			// a cold dashboard visit instead of a spinner (the dashboard's own touch
			// only fires after its background read lands).
			if e := s.store.TouchPermitConfirmed(ctx, p.ID, p.ActiveRegistration, s.now()); e != nil {
				alog.Infof("stamp confirmation for permit %s: %v", p.CouncilPermitID, e)
			}
			continue
		}
		alog.Infof("council drift on permit %s: cached %q, council shows %q — refreshing", p.CouncilPermitID, p.ActiveRegistration, actual)
		// Record the external change durably so it appears in the activity log
		// (nothing p.stonn does to the permit should be invisible) and so the
		// re-assertion the kicked reconcile is about to perform isn't deduped
		// away as a no-op against the pre-drift apply row.
		// Compare-and-swap against the belief this drift round READ, not a blind write:
		// the grid read above took seconds, and a guest or reconcile apply may have
		// committed a newer plate meanwhile. Writing over that would regress the record
		// to a plate the tenant no longer holds — a false "changed at the portal" row
		// and a duplicate "updated" notice on the way back. If it lost the race, the
		// other writer's value is the fresh one; drop ours and skip the drift row.
		// Swap against what we believed when the tenant read STARTED, not what the row
		// says now: an apply that landed during the read must win, not be overwritten.
		swapped, e := s.store.SetPermitActiveIfUnchanged(ctx, p.ID, wasActive[p.ID], actual)
		if e != nil || !swapped {
			if e != nil {
				alog.Infof("drift adopt for permit %s: %v", p.CouncilPermitID, e)
				incomplete = e // detected drift we failed to record: retry soon, not in 6h
			}
			continue
		}
		s.logApply(ctx, p.ID, actual, "external", "changed", "changed directly at the council portal")
		// Whoever's car was on before the portal edit may be parked and now uncovered:
		// same warning as any other displacement, worded for what actually happened.
		s.warnExternallyDisplaced(ctx, p, wasActive[p.ID])
		// And tell the household itself: nothing that changes their permit should be
		// invisible, least of all a change p.stonn did not make. Durable and soft
		// (quiet hours apply); a failure to queue it is logged, not fatal.
		if s.notifier != nil && s.notifier.Enabled() {
			if e := s.notifier.NotifyDriftChanged(ctx, p.Owner, p.TenantID, permitLabel(p), actual); e != nil {
				alog.Infof("enqueue drift notice for %s: %v", redact.Email(p.Owner), e)
			}
		}
		// Clear the delivered-notification fingerprint. The tenant now holds a plate we
		// did not set, and the reconcile this kicks will re-assert the schedule over it.
		// If the external edit RESTORED the previous plate, that re-assertion is the same
		// prev→want transition as the original apply, so the transition key alone would
		// dedup the "your permit was updated" notice away and the resident would never
		// learn their deliberate manual change was reverted — the exact fine-risk case the
		// notice exists for. Clearing forces the next apply to be treated as new.
		if e := s.store.SetPermitNotifiedKey(ctx, p.ID, ""); e != nil {
			alog.Infof("clear notified key for permit %s after drift: %v", p.CouncilPermitID, e)
		}
		drifted = true
	}
	if drifted {
		s.Kick() // reconcile now: re-apply the schedule over the drift
	}
	s.warnExpiring(ctx, owner)
	if !complete {
		// Everything above ran for the permits we WERE sent — that work is real and worth
		// keeping. But the owner has not been drift-checked, and saying so is the whole
		// point: advancing last_drift_check here would retire the permits behind the page
		// from view entirely, and if the tenant settles into a stable first page their
		// plate drift and expiry warnings would go missing for good. Returning an error
		// leaves the checkpoint alone and puts the owner on the ordinary drift backoff,
		// so this cannot become a retry storm either.
		s.alertTruncatedList(ctx)
		// JOINED, not replaced. Whatever went wrong for the permits we DID read is still
		// the more urgent error and its identity is load-bearing: a SessionExpiredError
		// here is how we learn a cookie was killed tenant-side, and warmOne only queues
		// the reconnect if it can still find that error. Returning a bare marker instead
		// left dead sessions unqueued, and hid FailUnexpected from the API-shape tally so
		// the "several accounts failing the same way" alert could never fire.
		return errors.Join(incomplete, parking.ErrPermitListPartial)
	}
	// Only a fully-applied round counts as a drift check (see MarkDriftChecked).
	return incomplete
}

// warnExpiring sends the one-time approaching-expiry warning for any permit now
// within expiryLead of its end date. It makes NO tenant call: checkDrift has
// already written the tenant's own status and end date for every permit from the
// grid read it shares with drift detection, so this reads purely local state.
func (s *Scheduler) warnExpiring(ctx context.Context, owner string) {
	if s.expiryLead <= 0 {
		return
	}
	// The expiry + reminded flag reflect the meta write checkDrift just made.
	managed, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return
	}
	now := s.now()
	for i := range managed {
		p := managed[i]
		if p.EndDate.IsZero() || p.ExpiryReminded {
			continue
		}
		// Warn once we're inside the lead window, up until the permit has expired.
		// "Expired" has to mean the end of EndDate's local DAY (model.ExpiryDeadline),
		// the same boundary Permit.Inactive uses: EndDate is a zoneless tenant date
		// parsed as UTC midnight, so comparing `now` against the bare instant closed
		// the warning window at ~10-11am local on the permit's final valid day. A
		// notifier that was down through the lead window would then never warn at all,
		// which is the outage this reminder exists to survive.
		if now.Before(p.EndDate.Add(-s.expiryLead)) || !now.Before(model.ExpiryDeadline(p.EndDate, s.locOf(p.Owner, p.TenantID))) {
			continue
		}
		if s.notifier == nil || !s.notifier.Enabled() {
			return
		}
		label := p.Label
		if label == "" {
			label = "visitor permit"
		}
		if s.notifier.NotifyPermitExpiry(ctx, owner, p.TenantID, label, p.EndDate.In(s.locOf(p.Owner, p.TenantID))) > 0 {
			if e := s.store.MarkPermitExpiryReminded(ctx, p.ID); e != nil {
				alog.Infof("mark permit %d expiry-reminded: %v", p.ID, e)
			}
		}
	}
}

// warnExternallyDisplaced warns the driver whose car a tenant-portal edit just
// removed. It loads what it needs itself: the drift pass has no override or
// vehicle context, and this is rare enough that two small reads are fine.
func (s *Scheduler) warnExternallyDisplaced(ctx context.Context, p model.Permit, prev string) {
	if prev == "" {
		return
	}
	now := s.now().In(s.locOf(p.Owner, p.TenantID))
	overrides, err := s.store.ListOverrides(ctx, p.ID, now)
	if err != nil {
		return
	}
	vehicles, err := s.store.ListVehiclesFor(ctx, p.Owner)
	if err != nil {
		return
	}
	byID := make(map[int64]model.VehicleInfo, len(vehicles))
	for _, v := range vehicles {
		byID[v.ID] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email, State: v.State}
	}
	members, err := s.store.AccountEmails(ctx, p.Owner)
	if err != nil {
		return
	}
	d := model.FindDisplaced(overrides, byID, prev, "", members, now)
	if d.Reg == "" {
		// Same gate as displaced(): the saved-vehicle fallback warns prev's regular
		// driver only when prev was TODAY's rostered car. A plate lingering from a
		// prior day (or a default) that a portal edit happened to replace has no
		// parked driver to warn.
		rules, err := s.store.ListRules(ctx, p.ID)
		if err != nil {
			return
		}
		if roster := model.Resolve(now, rules, nil); roster.Source == model.SourceRoster &&
			model.SamePlate(prev, byID[roster.VehicleID].Registration) {
			d = model.FindDisplacedVehicle(byID, prev, "", members)
		}
	}
	if d.Contact != "" {
		s.warnDisplacedHow(ctx, p, d, prev, "it was changed at the council")
	}
}
