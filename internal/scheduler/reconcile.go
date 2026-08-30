package scheduler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/redact"
)

// spreadElapsed reports whether a permit may act on a SCHEDULED change yet.
//
// Rosters are written in human hours, so households pile onto the same few
// boundaries — overwhelmingly midnight — and every one of their changes leaves
// this single IP in the minutes after it.
//
// What that actually looks like on the wire is worth being precise about, because
// it decides what spreading can and cannot fix. The transport governor already caps
// the request RATE, so a shared boundary is NOT a back-to-back burst: it is a
// sustained stream at the governor's ceiling, lasting roughly permits*opDrain (one
// operation's worth of requests per opDrain). Spreading does not remove a spike that
// was never there. What it does is lower that sustained rate further, by making
// permits become eligible over a window instead of all at the boundary.
//
// That only works while the window is WIDER than the serial drain. Below it the
// loop is saturated either way and the window changes nothing — which is what
// RolloverBound reports, so an operator is never left believing a too-narrow
// window is helping.
//
// Each permit gets a fixed slot: permit P acts at Since + offset(P), offset spread
// evenly across the effective window. It is derived from the permit id alone, so a
// permit keeps the same slot across restarts and across days rather than being
// re-drawn into a fresh pile-up, and it needs no stored state.
//
// A change somebody is waiting for is never delayed: only res.Scheduled changes
// are spread, so a booking or guest activation made just now still goes on the
// next tick.
//
// The cost is precision — between the boundary and its slot a permit still shows
// the previous day's plate — which is why the window is bounded by configuration
// and why startup prints the convergence bound rather than leaving it implicit.
func (s *Scheduler) spreadElapsed(permitID int64, res model.Resolution, now time.Time) bool {
	window := s.effectiveSpread()
	if window <= 0 || !res.Scheduled || res.Since.IsZero() {
		return true
	}
	elapsed := now.Sub(res.Since)
	if elapsed < 0 {
		return true // clock skew: never hold a change back on a nonsense interval
	}
	// Past the whole window everything is eligible, so a permit can never be
	// stranded by a boundary it somehow missed.
	if elapsed >= window {
		return true
	}
	offset := s.spreadOffset(permitID, window)
	// A BOOKING is a person naming exact times — "the nanny from 9" — and the
	// visitor is standing at the kerb at its start, so every held minute is
	// uncovered exposure while the calendar shows the day as handled. The full
	// window exists for ROSTER rollovers, where whole streets share midnight and
	// nobody is waiting at 00:00; overrides don't herd onto one boundary like
	// that (and the governor still paces the wire), so they get a tight cap: a
	// tenth of the booking, never more than spreadOverrideCap. The all-or-nothing
	// guard below stopped a booking SHORTER than its slot from being starved
	// outright, but an 8-hour booking with a 50-minute slot was still held the
	// full 50 minutes.
	if res.Source == model.SourceOverride {
		if res.Until != nil {
			if d := res.Until.Sub(res.Since); d > 0 && offset > d/10 {
				offset = d / 10
			}
		}
		if offset > spreadOverrideCap {
			offset = spreadOverrideCap
		}
	}
	// A short advance booking must never be starved by a slot that lands after it ends.
	// The offset is drawn from the permit id across the whole window (up to ~an hour),
	// so a booking whose window is shorter than its slot would reach its end while still
	// being held here — never applied, never reported, and then silently dropped when
	// Resolve stops returning it. If the booking would be over by the time its slot
	// fires, act now: the whole point of the booking is this plate during its window.
	if res.Until != nil && !res.Until.After(res.Since.Add(offset)) {
		return true
	}
	return elapsed >= offset
}

// spreadOverrideCap bounds how long the rollover spread may hold an advance
// BOOKING past its named start time, whatever the fleet-wide window works out
// to. Ten minutes still staggers any small cluster of same-hour bookings while
// keeping the promise the booking form made about when the plate changes.
const spreadOverrideCap = 10 * time.Minute

// spreadSpacingFactor sets the target pace as a multiple of the per-operation drain:
// at 2, a shared boundary is retired at half the rate the governor would allow, so
// the tenant sees a stream at half saturation instead of a saturated one.
const spreadSpacingFactor = 2

// effectiveSpread is how wide the rollover window actually is right now: enough to
// pace THIS fleet at spreadSpacingFactor*opDrain, capped by the configured maximum.
// opDrain is the time one operation occupies the governor at its sustained rate, so
// the window tracks the SAME throughput knob as everything else — raise the governor
// rate and this shrinks with no separate tuning.
//
// It scales with the fleet because a fixed window is wrong at both ends. A small
// deployment has no herd to smooth — a handful of changes drain in seconds — so a
// flat 30 minutes would delay every midnight rollover half an hour to solve a
// problem that does not exist. A large one needs a window well past its own serial
// drain before the rate drops at all. Deriving it from the fleet size gives a
// deployment of five permits a window of seconds and a deployment of five hundred
// the full configured cap, with no operator retuning in between.
func (s *Scheduler) effectiveSpread() time.Duration {
	if s.spreadWindow <= 0 || s.opDrain <= 0 {
		return 0
	}
	n := s.fleetSize.Load()
	if n <= 0 {
		return 0 // no pass has counted the fleet yet; spread nothing on a guess
	}
	want := time.Duration(n) * s.opDrain * spreadSpacingFactor
	if want > s.spreadWindow {
		return s.spreadWindow
	}
	return want
}

// spreadOffset is a permit's fixed position in the rollover window, uniform in
// [0, window). Hashed rather than taken from the id directly so that sequential
// ids — which arrive in signup order, and so cluster by household and by street —
// do not map to adjacent slots.
func (s *Scheduler) spreadOffset(permitID int64, window time.Duration) time.Duration {
	h := fnv.New64a()
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(permitID))
	_, _ = h.Write(b[:])
	u := float64(h.Sum64()>>11) / float64(uint64(1)<<53) // uniform in [0,1)
	return time.Duration(u * float64(window))
}

// RolloverBound reports when a boundary shared by n permits is expected to have
// fully converged, and whether spreading is doing anything for that fleet.
//
// Two limits apply and the larger wins: the window staggers when each permit
// becomes ELIGIBLE, and the governor then drains eligible permits at one operation
// per opDrain. A window at or below n*opDrain is not smoothing — the governor-paced
// drain is already the constraint — and saying so is the point of the second return
// value.
func (s *Scheduler) RolloverBound(n int) (bound time.Duration, spreading bool) {
	if n <= 0 {
		return 0, false
	}
	drain := time.Duration(n) * s.opDrain
	window := time.Duration(n) * s.opDrain * spreadSpacingFactor
	if window > s.spreadWindow {
		window = s.spreadWindow
	}
	bound = drain
	if window > bound {
		bound = window
	}
	// Plus the tick that notices the last permit became eligible.
	return bound + s.interval, window > drain
}

// reconcileAll runs one reconcile pass, returning true only if it COMPLETED — false
// if it bailed early on a database read failure (so the caller does not stamp a clean
// "last reconcile" that a watchdog would mistake for a healthy pass).
func (s *Scheduler) reconcileAll(ctx context.Context) bool {
	s.reconciling.Store(true)
	defer s.reconciling.Store(false)
	permits, err := s.store.ListPermits(ctx)
	if err != nil {
		log.Printf("scheduler: list permits: %v", err)
		s.systemAlert(ctx, "db-permits", "Scheduler database error",
			fmt.Sprintf("Reconcile could not read permits: %v. No plate changes are being applied until this clears.", err))
		return false
	}
	vehicles, err := s.store.ListVehicleRefs(ctx)
	if err != nil {
		log.Printf("scheduler: list vehicles: %v", err)
		s.systemAlert(ctx, "db-vehicles", "Scheduler database error",
			fmt.Sprintf("Reconcile could not read vehicles: %v. No plate changes are being applied until this clears.", err))
		return false
	}
	// Key by (owner, id): a permit's scheduled vehicle_id is resolved ONLY among
	// its owner's vehicles, so a rule/override that somehow references a foreign
	// id can never read another user's registration.
	vehByOwnerID := make(map[ownerVehicle]model.VehicleInfo, len(vehicles))
	for _, v := range vehicles {
		vehByOwnerID[ownerVehicle{v.Owner, v.ID}] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email, State: v.State}
	}
	// The herd the rollover window is sized against. Total permits over-estimates
	// how many share any one boundary, which errs toward a wider window (gentler on
	// the tenant, slightly later convergence) rather than a narrower one.
	s.fleetSize.Store(int64(len(permits)))

	now := time.Now().In(s.loc)
	stats := &passStats{failOwners: map[string]bool{}, unexpectedOwners: map[string]bool{}, busyOwners: map[string]bool{}}
	// When many permits change at the same wall-clock boundary (a midnight/9am roster
	// rollover), applying them back-to-back would be a burst from one IP that rate
	// heuristics notice. Two things prevent that now: the rollover spread staggers
	// when each permit becomes ELIGIBLE (spreadElapsed), and the transport governor
	// caps the request RATE — so this loop makes governed calls with no per-permit
	// sleep of its own.
	active := 0
	activeOwners := map[string]bool{}
	for _, p := range permits {
		// An expired or cancelled permit can't be changed; skip it so we don't
		// hammer the tenant with doomed writes or alarm the user with failures.
		// It stays in the store as a copy-schedule source until removed.
		if p.Inactive(now, s.locOf(p.Owner, p.TenantID)) {
			continue
		}
		active++
		activeOwners[p.Owner] = true
		s.progress() // per-permit liveness, so a long legitimate pass is not a stall
		s.safeReconcilePermit(ctx, p, vehByOwnerID, stats)
		// The governor paced the writes; we only need to abandon the pass promptly on
		// shutdown instead of driving doomed writes into a cancelled context.
		if ctx.Err() != nil {
			return false
		}
	}
	s.detectSystemic(ctx, stats, len(activeOwners))
	return true
}

// safeReconcilePermit reconciles ONE permit under panic recovery, so a deterministic
// panic on a single bad record cannot abort the pass and starve every permit ordered
// after it (which, with stable DB ordering, would repeat forever). The outer
// safeReconcile recover remains a backstop.
func (s *Scheduler) safeReconcilePermit(ctx context.Context, p model.Permit, vehByOwnerID map[ownerVehicle]model.VehicleInfo, stats *passStats) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: permit %s panicked (recovered); skipping it: %v", p.CouncilPermitID, r)
			s.systemAlert(ctx, "panic-permit", "A permit panicked during reconcile",
				fmt.Sprintf("Reconciling permit %s panicked and was skipped so the rest of the pass could continue: %v\n\nIt will be retried next pass; if it keeps panicking that record needs attention.", p.CouncilPermitID, r))
		}
	}()
	s.reconcilePermit(ctx, p, vehByOwnerID, stats)
}

type ownerVehicle struct {
	owner string
	id    int64
}

// passStats accumulates failures across one reconcile pass so a fleet-wide
// problem (a tenant outage or API change) can be reported to the operator
// directly, instead of only surfacing as per-user notifications.
type passStats struct {
	failOwners       map[string]bool
	unexpectedOwners map[string]bool
	busyOwners       map[string]bool // tenant pushed back (ErrCouncilBusy) this pass
}

// displaced resolves who should be warned that prev (the plate just removed)
// belonged to a still-live booking: the shared model.FindDisplaced policy, fed
// this permit's owner-scoped vehicles and account members. Matching on the
// outgoing plate is a heuristic; a false miss or spurious note is low-harm.
func (s *Scheduler) displaced(ctx context.Context, p model.Permit, overrides []model.Override, vehByOwnerID map[ownerVehicle]model.VehicleInfo, rules []model.WeeklyRule, prev, actor string, source model.Source, now time.Time) model.DisplacedBooking {
	if prev == "" {
		return model.DisplacedBooking{}
	}
	vehicles := make(map[int64]model.VehicleInfo)
	for i := range overrides {
		if id := overrides[i].VehicleID; id != 0 {
			if v, ok := vehByOwnerID[ownerVehicle{p.Owner, id}]; ok {
				vehicles[id] = v
			}
		}
	}
	members, err := s.store.AccountEmails(ctx, p.Owner)
	if err != nil {
		return model.DisplacedBooking{} // can't tell member from guest; stay quiet
	}
	if d := model.FindDisplaced(overrides, vehicles, prev, actor, members, now); d.Reg != "" {
		return d
	}
	// No live booking had put prev on: it was there through the roster, or it is
	// lingering — a prior day's roster car, or a default, that no longer matches
	// today's schedule. The roster's own day change is expected and told to nobody.
	if source == model.SourceRoster || source == model.SourceNone {
		return model.DisplacedBooking{}
	}
	// A booking, a guest, or a manual change mid-day replaced prev. The fallback
	// below warns prev's regular driver on the theory they are parked today — but
	// that only holds when prev is TODAY's rostered plate. A lingering plate means
	// nobody was actually scheduled today, so its driver is not parked and must not
	// be warned. (Without this gate, a one-off replacing yesterday's leftover plate
	// emailed that driver and told the account it had — the reported bug.)
	roster := model.Resolve(now, rules, nil) // the roster/none pick, one-offs excluded
	if roster.Source != model.SourceRoster {
		return model.DisplacedBooking{} // today has no rostered car; nobody was scheduled
	}
	if rr := vehByOwnerID[ownerVehicle{p.Owner, roster.VehicleID}].Registration; rr == "" || !model.SamePlate(prev, rr) {
		return model.DisplacedBooking{} // prev was not today's rostered car — lingering
	}
	own := make(map[int64]model.VehicleInfo)
	for k, v := range vehByOwnerID {
		if k.owner == p.Owner {
			own[k.id] = v
		}
	}
	return model.FindDisplacedVehicle(own, prev, actor, members)
}

// settle ends any failure or tenant-block episode for a permit that needs no
// tenant write this tick, whether that is because the permit already shows the
// target or because there is no target to apply.
//
// The streak previously only ever reset on a SCHEDULER apply success, and then
// only when a target resolved: an episode that ended any other way — a guest's
// inline apply (which writes active_registration itself), the roster changing to
// match what is already on the permit, or the target becoming unresolvable when
// its vehicle was deleted — left the counter inflated PERMANENTLY. A single
// one-minute blip weeks later would then land straight on the alert threshold,
// alarming the user instantly instead of after the intended grace, and take the
// maximum 30-minute backoff on the first failure of a fresh episode. Gated on the
// loaded value so the common already-correct pass stays read-only on the shared
// SQLite connection.
func (s *Scheduler) settle(ctx context.Context, p model.Permit) {
	if p.FailStreak == 0 {
		return
	}
	// p is the snapshot ListPermits took at the START of the pass. The gate above
	// keeps the common case read-only on that snapshot, but the close-out below
	// acts on the streak and the plate, and both can have moved since: a guest's
	// inline apply, a settle on an earlier pass whose snapshot this one predates,
	// or the streak itself bumped by an apply that failed between the two reads.
	// Judging a stale streak logged "recovered" twice — once from the pass that
	// ended the episode, once more from the next pass still holding the old
	// snapshot — and judging a stale plate could close an episode that had just
	// reopened. Re-read, and act only on a belief that still holds.
	fresh, err := s.store.GetPermit(ctx, p.ID)
	if err != nil {
		log.Printf("scheduler: settle permit %d: could not re-read it: %v", p.ID, err)
		return // the next pass sees the durable state and settles then
	}
	if fresh.FailStreak == 0 || !model.SamePlate(fresh.ActiveRegistration, p.ActiveRegistration) {
		return // already settled, or the plate moved under us: not this pass's call
	}
	p.FailStreak, p.ActiveRegistration = fresh.FailStreak, fresh.ActiveRegistration
	// A failure episode is ending: the scheduled plate is back in place, so nothing
	// needs the tenant. Close out the last logged failure so the audit trail doesn't
	// sit on a stale "error" — which of the two ways it ends depends on whether the
	// plate we failed to set is now the one on the permit. Streak-gated like the
	// original retraction notice: an episode too brief to have alarmed anyone is too
	// brief to annotate, and the /admin panel already reads a settled short blip as
	// "cleared" off the (now zero) fail streak.
	if p.FailStreak >= failNotifyThreshold {
		if last, err := s.store.LastApply(ctx, p.ID); err == nil && last.Status == "error" && last.Registration != "" {
			if model.SamePlate(last.Registration, p.ActiveRegistration) {
				// The plate we failed to set is now confirmed ON the permit: the change
				// landed after all — a transient false-negative, a later retry, or someone
				// set it at the portal / a guest's inline apply. Record the recovery so the
				// activity log and /admin read fail→resolved instead of a permanent error.
				// Audit only: a resolved blip needs no notification.
				s.logApply(ctx, p.ID, last.Registration, last.Source, "success",
					"recovered after a transient failure — the permit is confirmed on this vehicle")
			} else {
				// The failing target went AWAY without ever landing. A 9am–5pm booking the
				// tenant blocked all day used to end exactly here at 5pm: want reverted to
				// a plate already on the permit and the streak was cleared with nothing ever
				// sent — so the household's last word was the reassuring "still updating,
				// p.stonn will keep trying", about a visitor uncovered the whole day. Tell
				// them it never applied.
				reason := fmt.Sprintf("That change is no longer scheduled — the booking ended or the schedule moved on — and it was never applied: the permit showed %s the whole time.", p.ActiveRegistration)
				s.logApply(ctx, p.ID, last.Registration, last.Source, "error", reason)
				s.notifyUser(ctx, p, notify.ApplyOutcome{
					Owner:       p.Owner,
					PermitLabel: permitLabel(p),
					Reg:         last.Registration,
					OK:          false,
					CurrentReg:  p.ActiveRegistration,
					Reason:      reason,
					Action: "Nothing to apply now — this corrects the earlier notice that p.stonn was still trying. " +
						"If " + last.Registration + " parked there during the booking, it was not covered.",
					// Not transient: this must not sit behind a quiet-hours hold and
					// arrive as a stale correction long after the next booking started.
				}, "unapplied|"+last.Registration+"|"+s.failureKeyDay(p))
			}
		}
	}
	s.clearFailStreak(ctx, p.ID)
	s.clearRetry(p.ID)
}

// noteUnscheduled reports whether this is the first tick on which a permit has
// been in the given "nothing to apply" state, remembering it so later ticks stay
// quiet. These states persist for as long as the gap in the schedule does — a
// whole weekend on a weekday-only roster — so anything that speaks every tick is a
// firehose, and the thing worth reporting is the TRANSITION into the state.
func (s *Scheduler) noteUnscheduled(permitID int64, state string) bool {
	if s.unscheduled[permitID] == state {
		return false
	}
	s.unscheduled[permitID] = state
	return true
}

// clearUnscheduled re-arms the notice once the permit has a target again, so a
// second gap later is reported afresh.
func (s *Scheduler) clearUnscheduled(permitID int64) {
	delete(s.unscheduled, permitID)
}

// reportUnresolvable makes a schedule that points at a car we cannot find
// visible: a log line, a row in the user-facing activity log, and one
// notification. Only on entry into the state (noteUnscheduled), so a condition
// that does not clear itself cannot turn into a per-tick alert — and so the
// activity-log read logApply does to dedup is not paid every tick either.
//
// The registration on the row is the plate the permit is STILL showing, because
// that is the fact the household needs: the car they think is covered is not, and
// the car that is covered may not be there.
func (s *Scheduler) reportUnresolvable(ctx context.Context, p model.Permit, res model.Resolution) {
	if !s.noteUnscheduled(p.ID, fmt.Sprintf("unresolved|%d|%s", res.VehicleID, model.NormPlate(p.ActiveRegistration))) {
		return
	}
	log.Printf("scheduler: permit %s: the %s points at vehicle %d, which is not one of %s's saved cars; permit still shows %q",
		p.CouncilPermitID, res.Source, res.VehicleID, redact.Email(p.Owner), p.ActiveRegistration)
	const reason = "The car this permit is scheduled to use is no longer saved, so p.stonn has not changed the permit."
	const action = "Open p.stonn and choose a car for today, or add the car back."
	s.logApply(ctx, p.ID, p.ActiveRegistration, string(res.Source), "error", reason)
	s.notifyUser(ctx, p, notify.ApplyOutcome{
		Owner:       p.Owner,
		PermitLabel: permitLabel(p),
		Reg:         p.ActiveRegistration,
		OK:          false,
		CurrentReg:  p.ActiveRegistration,
		Reason:      reason,
		Action:      action,
		// Transient, so this respects quiet hours: it is a schedule to fix in the
		// morning, not the kind of hard failure that justifies a 3am push.
		Transient: true,
	}, fmt.Sprintf("unscheduled|%d|%s", res.VehicleID, p.ActiveRegistration))
}

// reportTenantUnavailable makes a permit whose tenant this process does not serve
// visible: a log line, a row in the activity log, and ONE notification (undated
// key: the condition persists until an operator re-enables the tenant, so a daily
// repeat would only teach the household to ignore it). The attempt is a local
// no-op — the mux refuses before any network — so the permit is deferred at the
// backoff cap purely to keep the per-tick dedup reads off the database; the
// standard clears (an edit, a re-link, a restart) let it re-check.
func (s *Scheduler) reportTenantUnavailable(ctx context.Context, p model.Permit, want, wantName string, res model.Resolution) {
	s.deferRetry(p.ID, 5)
	log.Printf("scheduler: permit %s: its council %q is not served by this process; the change to %s cannot be applied", p.CouncilPermitID, p.TenantID, want)
	const reason = "This permit's council is not currently available in p.stonn, so the change could not be applied."
	const action = "Change the vehicle on your permit at the council yourself. p.stonn will resume automatically once the council is available again."
	s.logApply(ctx, p.ID, want, string(res.Source), "error", reason)
	s.notifyUser(ctx, p, notify.ApplyOutcome{
		Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName,
		OK: false, CurrentReg: p.ActiveRegistration,
		Reason: reason, Action: action,
		// Not transient: nothing p.stonn does will change this, so it must not be
		// softened into "still updating" or held for quiet hours.
	}, "tenant-unavailable|"+p.TenantID)
}

// reconcilePermit applies any needed plate change for one permit. It returns
// true when it actually contacted the tenant (so the caller can space bursts).
func (s *Scheduler) reconcilePermit(ctx context.Context, p model.Permit, vehByOwnerID map[ownerVehicle]model.VehicleInfo, stats *passStats) (hitTenant bool) {
	// Resolve against a FRESH clock, not the one captured at the start of the pass: a
	// governed pass over 500-1000 permits legitimately runs for minutes, and an
	// override whose StartsAt falls inside that window must be seen as started for
	// the permit being processed now — otherwise the previous plate is (re)applied
	// and only corrected next pass, leaving the wrong car on a live permit meanwhile.
	now := time.Now().In(s.locOf(p.Owner, p.TenantID))
	rules, err := s.store.ListRules(ctx, p.ID)
	if err != nil {
		log.Printf("scheduler: rules for permit %d: %v", p.ID, err)
		return false
	}
	overrides, err := s.store.ListOverrides(ctx, p.ID, now)
	if err != nil {
		log.Printf("scheduler: overrides for permit %d: %v", p.ID, err)
		return false
	}
	res := model.Resolve(now, rules, overrides)
	if res.Source == model.SourceNone {
		// Nothing scheduled right now; leave the permit as-is. It keeps whatever plate
		// was last put on it, which is worth saying once — but only once, because the
		// gap lasts as long as the gap in the schedule does.
		if s.noteUnscheduled(p.ID, "none|"+model.NormPlate(p.ActiveRegistration)) && p.ActiveRegistration != "" {
			log.Printf("scheduler: permit %s has nothing scheduled now; it still shows %s",
				p.CouncilPermitID, p.ActiveRegistration)
		}
		s.settle(ctx, p)
		return false
	}
	wantInfo := vehByOwnerID[ownerVehicle{p.Owner, res.VehicleID}]
	want := wantInfo.Registration
	wantName := wantInfo.Label
	wantRegion := wantInfo.State // the saved vehicle's registration state
	if res.Registration != "" {  // an ad-hoc one-off plate (not a saved vehicle)
		want = res.Registration
		wantName = ""
		wantRegion = res.State
	}
	if want == "" {
		// The schedule points at a vehicle we cannot turn into a plate: the row was
		// deleted under us, or it belongs to another owner (vehByOwnerID is
		// owner-keyed precisely so that can never resolve). This used to be a fully
		// silent no-op — no log, no activity row, no notification — so the permit sat
		// holding whatever plate it had, indefinitely, while the household believed
		// their schedule was running. Reported once per state, never per tick: the
		// condition does not clear itself, and an alert that repeats every minute is
		// one people learn to ignore.
		s.reportUnresolvable(ctx, p, res)
		s.settle(ctx, p)
		return false
	}
	s.clearUnscheduled(p.ID) // the schedule is resolvable again; re-arm the notice
	if model.SamePlate(want, p.ActiveRegistration) {
		s.settle(ctx, p)
		return false // already correct
	}
	if !s.spreadElapsed(p.ID, res, now) {
		return false // this permit's turn in the rollover window hasn't come up yet
	}
	if s.retryDeferred(p.ID, time.Now()) {
		return false // failing lately; inside its stretched retry window
	}

	// From here the tenant write and the active_registration write that records it
	// are one decision, so take this permit's apply claim first. Skipping (rather
	// than waiting) is deliberate: `want` was computed above, so by the time a wait
	// returned we would be applying a target decided BEFORE the other writer's, which
	// is the clobber the claim exists to prevent. The next tick recomputes and heals.
	release, claimed := s.tryApply(p.ID)
	if !claimed {
		log.Printf("scheduler: permit %s skipped this tick: another plate change is in flight", p.CouncilPermitID)
		return false
	}
	defer release() // idempotent; a panic must never leave a permit claimed forever
	// p came from the snapshot ListPermits took at the start of the pass, and a
	// handler's inline apply may have landed since. Re-read the permit's own belief
	// under the claim so we neither re-apply a plate that is already on (a real
	// tenant write plus a "your permit was updated" notice for a no-op) nor act on a
	// stale failure streak.
	fresh, ferr := s.store.GetPermit(ctx, p.ID)
	if ferr != nil {
		// The permit may have been removed mid-pass. Falling through wrote a real plate
		// change to the tenant for a permit we no longer manage, then booked it as a
		// clean success (SetPermitActive matches 0 rows and returns nil), re-creating
		// activity and notify rows for the id DeletePermit just cleaned up and emailing
		// "your permit was updated" for the permit they just removed.
		log.Printf("scheduler: skipping permit %d: could not re-read it under the claim: %v", p.ID, ferr)
		return false
	}
	if fresh.Inactive(now, s.locOf(p.Owner, p.TenantID)) {
		// checkDrift may have written a tenant-reported expiry earlier in THIS pass.
		// Writing anyway earns a tenant refusal that alarms the household with "the
		// tenant would not let p.stonn update your permit" for a permit that expired.
		return false
	}
	{
		p.ActiveRegistration, p.FailStreak = fresh.ActiveRegistration, fresh.FailStreak
		if model.SamePlate(want, p.ActiveRegistration) {
			s.settle(ctx, p)
			return false
		}
	}

	prev := p.ActiveRegistration // the plate we're changing away from
	err = s.tenant.SetVehicle(ctx, p.Owner, p, want, wantRegion)
	var commitErr error
	if err == nil {
		commitErr = s.commitActive(ctx, p.ID, want)
	}
	// The decision is recorded, so drop the claim before the bookkeeping below: the
	// activity row, the notifications and (on an expired session) a full headless
	// re-login are none of them this permit's plate write, and a household tapping a
	// guest link must not wait out a 20-second reconnect to get their car on.
	release()
	switch {
	case err == nil && commitErr != nil:
		// The tenant confirmed the change (SetVehicle re-reads to verify), so the car
		// IS on the permit — this is not a failure to tell the user about. But we must
		// not book it as a clean success either: the stale ActiveRegistration would
		// drive a duplicate apply + "updated" notice on the next pass, and be wrong
		// across a restart. Alert the operator and Kick a reconcile; the healing pass's
		// pre-read sees the plate already present and records it, notifying exactly once.
		log.Printf("scheduler: permit %s applied at the council but local commit failed: %v", p.CouncilPermitID, commitErr)
		s.systemAlert(ctx, "commit-after-apply",
			"Council change applied but not recorded locally",
			fmt.Sprintf("Permit %s was set to %q at the council (confirmed), but writing that to the local database failed: %v. The car is on the permit; a reconcile will re-record it. If this repeats, the database may be failing.", p.CouncilPermitID, want, commitErr))
		// Pace it like any other failure. Without a streak/backoff this branch Kicked a
		// fleet-wide reconcile immediately, the next pass re-read the same stale plate,
		// applied again, failed to commit again and Kicked again — a continuous loop of
		// tenant reads on the shared egress IP (SetVehicle always pre-reads), starving
		// keep-warm and real due changes, while progress() kept the watchdog quiet.
		// Precondition is a read-OK/write-failing database (full disk, read-only remount).
		//
		// No kick. The deferral IS the fix, and a kick here undid it: KickPermit clears
		// the permit's retry window on the reasoning that a user action made it
		// obsolete, so kicking straight after deferring re-ran the same doomed
		// apply on the very next tick — the loop the deferral was added to stop, just
		// one tick slower. The regular ticker picks the permit up once the window
		// has elapsed; nothing is waiting on this permit that a kick could serve.
		s.bumpFailStreak(ctx, p.ID)
		s.deferRetry(p.ID, 3)
		return true
	case err == nil:
		s.clearFailStreak(ctx, p.ID)
		s.clearRetry(p.ID)
		s.logApply(ctx, p.ID, want, string(res.Source), "success", "")
		// If the plate we just removed had been put on by a still-live booking,
		// warn its driver (email only) so they aren't caught out — and tell the
		// account when that driver was unreachable, so a member can relay it. The
		// notice is enqueued durably (a fast insert), so no goroutine is needed.
		d := s.displaced(ctx, p, overrides, vehByOwnerID, rules, prev, res.By, res.Source, now)
		// Key the notification on the TRANSITION (prev→want), not just the target.
		// Keying on "success|want" alone would treat a re-assertion after an external
		// change (someone edited the plate directly in the tenant portal, which
		// checkDrift logs) as a duplicate of the original apply and stay silent — so
		// the account never hears that their deliberate manual change was reverted.
		// By names whoever created the winning one-off, so a household can tell
		// "my roster ran" from "someone booked over it" — the account is shared, and
		// an unattributed change is indistinguishable from the schedule working.
		// Warn the displaced driver FIRST, and report to the account only what actually
		// happened. This flag picks between "we've emailed the person responsible" and
		// "we had no way to reach them — please tell them", so asserting it from "an
		// address exists" stood BOTH people down when the address was suppressed (a
		// previous bounce/unsubscribe means it is guaranteed never to be delivered).
		told := s.warnDisplaced(ctx, p, d, prev, want)
		s.notifyUser(ctx, p, notify.ApplyOutcome{
			Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName, Source: string(res.Source), By: res.By, OK: true,
			DisplacedReg: d.Reg, DisplacedTold: told,
		}, "success|"+prev+">"+want)
		log.Printf("scheduler: permit %s -> %s (%s)", p.CouncilPermitID, want, res.Source)
		return true
	case errors.Is(err, parking.ErrTenantUnavailable):
		// Checked BEFORE ErrNotLinked, which it wraps. This is not "the household has
		// not linked yet": the permit's tenant is one this process is not serving
		// (disabled or removed from the registry), so the change can never apply
		// here and no dashboard prompt will fix it. It used to fall into the silent
		// branch below and the permit sat unapplied indefinitely with nobody told.
		s.reportTenantUnavailable(ctx, p, want, wantName, res)
		return false
	case errors.Is(err, parking.ErrNotLinked):
		// Not linked yet, stay quiet; the dashboard prompts the user to link.
		return false
	case errors.Is(err, parking.ErrCouncilBusy):
		// Portal is pushing back (Azure Front Door) or we're in a per-owner cooldown. Feed the
		// fleet-wide detector so a systemic block reaches the operator...
		if stats != nil {
			stats.busyOwners[p.Owner] = true
		}
		log.Printf("scheduler: permit %s deferred: %v", p.CouncilPermitID, err)
		// ...and tell the USER if it persists. A brief block is genuinely not worth
		// mentioning, but this was previously silent FOREVER: no activity row, no
		// notification, however long the permit sat showing the wrong plate. The
		// operator alert needs several affected owners, so a single household being
		// blocked reached nobody at all.
		//
		// Deliberately no deferRetry here: a busy attempt is short-circuited locally
		// (no tenant traffic), so retrying each tick costs nothing and means we
		// resume the moment the block lifts, rather than waiting out a backoff.
		// fail_streak is shared with real failures — both mean "consecutive ticks we
		// could not apply" — and a success clears it either way.
		n := s.bumpFailStreak(ctx, p.ID)
		// A CONFIRMED fleet block (breaker open) is not a blip: the change will not
		// apply until it clears, so warn sooner and firmly (act now), not with the
		// reassuring "still updating" a brief single-owner hiccup gets.
		confirmed := s.tenant.Blocked(p.TenantID)
		threshold := busyNotifyThreshold
		reason, action := describeFailure(parking.FailTransient, provider.OpUnknown)
		if confirmed {
			threshold = blockNotifyThreshold
			reason = "The council is refusing p.stonn's connection right now, so your permit cannot be updated."
			action = "If a different car is parked there, change the vehicle on your permit yourself at the council now to avoid a fine — p.stonn will resume automatically once the block clears."
		}
		s.logApply(ctx, p.ID, want, string(res.Source), "error", reason)
		if n >= threshold {
			// The confirmed state is part of the key. With a bare "busy|"+want, the
			// common ordering — soft notice at 15 ticks, breaker confirms the block
			// after — left the urgent "act now to avoid a fine" escalation deduped
			// by the reassuring notice it was supposed to override, so the one
			// message blockNotifyThreshold exists for was unreachable.
			key := "busy|" + want + "|" + s.failureKeyDay(p)
			if confirmed {
				key = "busy-blocked|" + want + "|" + s.failureKeyDay(p)
			}
			s.notifyUser(ctx, p, notify.ApplyOutcome{
				Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName,
				OK: false, CurrentReg: p.ActiveRegistration,
				Reason: reason, Action: action, Transient: true, Urgent: confirmed,
			}, key)
		}
		return false
	case errors.Is(err, parking.ErrNotCaptured):
		// A tenant write endpoint returned "not captured": the API shape may have
		// changed. This is systemic (hits every user), so alert the operator — and
		// ALSO treat it as a normal failed apply for this user: an activity row
		// from the first tick, exponential backoff instead of a retry every
		// minute, and the standard "still updating" notice if it persists.
		s.systemAlert(ctx, "not-captured",
			"Council write endpoint not working (API shape change?)",
			fmt.Sprintf("SetVehicle for permit %s returned ErrNotCaptured. If the council changed its API this affects ALL users; investigate promptly.", p.CouncilPermitID))
		s.handleApplyFailure(ctx, p, want, wantName, string(res.Source), err, stats)
		return true
	case errors.Is(err, parking.ErrSessionExpired):
		// The cookie died. Hand recovery to the reconnect worker (owner-deduplicated,
		// drained out of this pass) rather than reconnecting inline — a mass expiry
		// coinciding with a rollover must not make one reconcile pass block for hours.
		// Defer this permit so it isn't re-attempted every minute meanwhile; the
		// worker kicks the owner's permits the moment the session is back.
		// Only queue when the failure carried the generation it failed at. Untagged, we
		// cannot bind safely (re-reading could pick up a fresh re-link and retire it),
		// so leave it: keep-warm re-probes a dead session every recovery tick (~3 min)
		// and enqueues it there with a properly captured generation.
		if g, ok := parking.SessionGenOf(err); ok {
			s.enqueueReconnect(ctx, p.Owner, p.TenantID, g)
		}
		// Recovery usually lands within a couple of reconnect attempts, but
		// "usually" was previously load-bearing: this branch wrote no activity
		// row, no fail streak and no notification, so a reconnect that kept
		// deferring (a tenant login outage, a changed sign-in page) left the
		// permit showing the wrong plate indefinitely with the household told
		// nothing. Record it like every other failure and alarm once the streak
		// says recovery has stalled. Not fed into passStats: a mass expiry is
		// routine and already has its own systemic alert (session-churn), so it
		// must not trip the multi-user-fail alarm.
		reason := "p.stonn's sign-in to the council expired and signing back in hasn't succeeded yet, so your permit could not be updated."
		s.logApply(ctx, p.ID, want, string(res.Source), "error", reason)
		if n := s.bumpFailStreak(ctx, p.ID); n >= sessionNotifyThreshold {
			s.notifyUser(ctx, p, notify.ApplyOutcome{
				Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName,
				OK: false, CurrentReg: p.ActiveRegistration,
				Reason:    reason,
				Action:    "If a different car is parked there, change the vehicle on your permit yourself at the council now to avoid a fine — p.stonn keeps trying to reconnect, and will email you if you need to re-link.",
				Transient: true, Urgent: true,
			}, "session|"+want+"|"+s.failureKeyDay(p))
		}
		s.deferRetry(p.ID, 3)
		return true
	default:
		s.handleApplyFailure(ctx, p, want, wantName, string(res.Source), err, stats)
		log.Printf("scheduler: permit %s apply error: %v", p.CouncilPermitID, err)
		return true
	}
}
