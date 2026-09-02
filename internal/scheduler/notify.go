package scheduler

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/redact"
)

// claimNotify records a permit+outcome as having a delivery in flight, returning
// false if one already is. releaseNotify clears it once delivery finishes.
func (s *Scheduler) claimNotify(claim string) bool {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if s.notifyInFlight == nil {
		s.notifyInFlight = map[string]struct{}{} // literal-constructed test schedulers
	}
	if _, ok := s.notifyInFlight[claim]; ok {
		return false
	}
	s.notifyInFlight[claim] = struct{}{}
	return true
}

func (s *Scheduler) releaseNotify(claim string) {
	s.notifyMu.Lock()
	delete(s.notifyInFlight, claim)
	s.notifyMu.Unlock()
}

// holdNotify paces the retry of a delivery that reached nobody, or not everyone:
// no further attempt for this permit+outcome until notifyRetry has elapsed. The
// durable notified key is deliberately NOT written for such a delivery, so without
// this the paths that call notifyUser every tick re-dialled SMTP for the same
// household every minute. Entries that have long expired are swept as we go, so a
// key that never succeeds (a dated failure key nobody could be reached about)
// does not accumulate for the life of the process.
func (s *Scheduler) holdNotify(claim string) {
	if s.notifyRetry <= 0 {
		return
	}
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if s.notifyRetryAt == nil {
		s.notifyRetryAt = map[string]time.Time{} // literal-constructed test schedulers
	}
	now := time.Now()
	for k, t := range s.notifyRetryAt {
		if now.Sub(t) > time.Hour {
			delete(s.notifyRetryAt, k)
		}
	}
	s.notifyRetryAt[claim] = now.Add(s.notifyRetry)
}

// notifyHeld reports whether a delivery for claim is inside its retry hold.
func (s *Scheduler) notifyHeld(claim string, now time.Time) bool {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	t, ok := s.notifyRetryAt[claim]
	return ok && now.Before(t)
}

// releaseNotifyHold forgets a hold once the delivery has succeeded.
func (s *Scheduler) releaseNotifyHold(claim string) {
	s.notifyMu.Lock()
	delete(s.notifyRetryAt, claim)
	s.notifyMu.Unlock()
}

// failureNoticeSent reports whether the household was successfully told about a
// failure to put reg on this permit. The durable notified key is the last outcome
// DELIVERED — not attempted — so it is the honest record: every failure key
// starts with its kind and then the plate it was about, and a later success or
// an unrelated notice overwrites it. Used by settle to decide whether a close-out
// may describe itself as correcting an earlier notice.
func (s *Scheduler) failureNoticeSent(ctx context.Context, permitID int64, reg string) bool {
	k, _, err := s.store.PermitNotify(ctx, permitID)
	if err != nil || k == "" {
		return false
	}
	kind, rest, ok := strings.Cut(k, "|")
	if !ok {
		return false
	}
	switch kind {
	case "error", "rejected", "busy", "busy-blocked", "session":
	default:
		return false // a success, or a notice not about a target plate
	}
	plate, _, _ := strings.Cut(rest, "|")
	return model.SamePlate(plate, reg)
}

// alertRelink notifies a user that their tenant connection dropped and they
// must re-link, escalating to the operator if the user cannot be reached, so a
// lapsed session never silently stops managing their permit until fine time.
func (s *Scheduler) alertRelink(owner, tenantID string) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	// Claim + concurrency-limit like notifyUser: the 90-day idle-retirement path can
	// retire a whole onboarding cohort in one warm pass, and an unbounded goroutine +
	// SMTP dial per owner would be a fleet-sized fanout.
	claim := "relink|" + owner
	if !s.claimNotify(claim) {
		return
	}
	go func() {
		defer s.releaseNotify(claim)
		if s.notifyConc != nil {
			s.notifyConc <- struct{}{}
			defer func() { <-s.notifyConc }()
		}
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s.notifier.NotifyRelinkRequired(nctx, owner, tenantID) == 0 {
			_ = s.notifier.NotifyAdmin(nctx, "User could not be told to re-link: "+owner,
				fmt.Sprintf("%s's council session expired, so p.stonn stopped managing their permit, but no re-link notification could be delivered to them. They may get a fine.", owner))
		}
	}()
}

// alertReconnectStalled tells a household that automatic reconnection has been
// failing long enough to count as stalled (see reconnectStalledAlertAttempts)
// while their session is deliberately retained — a tenant login outage or a
// changed sign-in page. Distinct from alertRelink because "re-link now" is the
// wrong instruction here: an interactive re-link goes through the same broken
// login, and recovery resumes on its own once it is repaired. What the
// household needs to know is that the schedule is paused meanwhile.
func (s *Scheduler) alertReconnectStalled(owner, tenantID string) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	claim := "reconnect-stalled|" + owner
	if !s.claimNotify(claim) {
		return
	}
	go func() {
		defer s.releaseNotify(claim)
		if s.notifyConc != nil {
			s.notifyConc <- struct{}{}
			defer func() { <-s.notifyConc }()
		}
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s.notifier.NotifyReconnectStalled(nctx, owner, tenantID) == 0 {
			_ = s.notifier.NotifyAdmin(nctx, "User could not be told their schedule is paused: "+owner,
				fmt.Sprintf("%s's council session expired and auto-reconnect has been failing for over an hour, but no notification could be delivered to them. Their schedule is not being applied; they may get a fine.", owner))
		}
	}()
}

// warnDisplaced emails the driver whose car just came off the permit, reporting
// whether the warning will genuinely reach them. A suppressed address never will, so
// claiming otherwise leaves nobody to tell the driver. (A send-rate throttle is not
// counted as a failure: hitting it means this person has already had six notices in a
// day, so "we told them" remains true.)
func (s *Scheduler) warnDisplaced(ctx context.Context, p model.Permit, d model.DisplacedBooking, prev, want string) bool {
	how := "another car has been put on it"
	if want == "" {
		how = "the permit holder took it off"
	}
	return s.warnDisplacedHow(ctx, p, d, prev, how)
}

// warnDisplacedHow is warnDisplaced with the reason spelled out by the caller
// (the drift path knows the plate was changed at the tenant, not by p.stonn).
func (s *Scheduler) warnDisplacedHow(ctx context.Context, p model.Permit, d model.DisplacedBooking, prev, how string) bool {
	if d.Contact == "" || s.notifier == nil || !s.notifier.Enabled() {
		return false
	}
	if sup, err := s.store.SuppressedAmong(ctx, []string{d.Contact}); err != nil || len(sup) > 0 {
		if err != nil {
			log.Printf("scheduler: suppression check for %s: %v", notify.RedactEmail(d.Contact), err)
		}
		return false // undeliverable (or unknown): tell the account to pass it on
	}
	if err := s.notifier.NotifyDriverDisplaced(ctx, p.Owner, d.Contact, permitLabel(p), prev, how, time.Now()); err != nil {
		log.Printf("scheduler: enqueue driver-displaced for %s: %v", notify.RedactEmail(d.Contact), err)
		return false
	}
	return true
}

// notifyAddedDriver emails the driver of the car just put ON the permit, if that
// car has a contact email and its household left the per-car notify toggle on.
// The symmetric partner of warnDisplaced (which covers a car coming OFF). Best
// effort: a suppressed or throttled address is simply skipped.
func (s *Scheduler) notifyAddedDriver(ctx context.Context, p model.Permit, want string, vehByOwnerID map[ownerVehicle]model.VehicleInfo) {
	if want == "" || s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	// Find the OWNER's saved car matching the new plate; an ad-hoc one-off plate
	// (no saved vehicle) has no driver contact and is skipped.
	var vi model.VehicleInfo
	found := false
	for k, v := range vehByOwnerID {
		if k.owner == p.Owner && model.SamePlate(v.Registration, want) {
			vi, found = v, true
			break
		}
	}
	if !found || vi.Email == "" || !vi.NotifyDriver {
		return
	}
	if sup, err := s.store.SuppressedAmong(ctx, []string{vi.Email}); err != nil || len(sup) > 0 {
		if err != nil {
			log.Printf("scheduler: suppression check for %s: %v", notify.RedactEmail(vi.Email), err)
		}
		return
	}
	if err := s.notifier.NotifyDriverAdded(ctx, p.Owner, p.TenantID, vi.Email, want, vi.Color); err != nil {
		log.Printf("scheduler: enqueue driver-added for %s: %v", notify.RedactEmail(vi.Email), err)
	}
}

// permitLabel is the human name for a permit in notifications.
func permitLabel(p model.Permit) string {
	if p.Label != "" {
		return p.Label
	}
	return "permit " + p.CouncilPermitID
}

// logApply appends an apply outcome to the activity log, deduping on the last row
// so a repeating outcome isn't logged every tick.
func (s *Scheduler) logApply(ctx context.Context, permitID int64, reg, source, status, detail string) {
	if last, err := s.store.LastApply(ctx, permitID); err != nil ||
		!(last.Status == status && last.Registration == reg && last.Detail == detail) {
		_ = s.store.RecordApply(ctx, permitID, reg, source, status, detail)
	}
}

// failureKeyDay stamps failure dedup keys with the local date. The durable
// notified-key dedups "this exact outcome", but a failure that persists across
// a day boundary is a NEW exposure — a different day's visitor sitting on the
// wrong plate — and used to be silently swallowed by the previous day's key:
// Monday's "we couldn't update your permit" suppressed Tuesday's and
// Wednesday's identical failures, so the household heard exactly once however
// many visitors were exposed. Success keys stay undated; re-confirming an
// identical success adds nothing.
func (s *Scheduler) failureKeyDay(p model.Permit) string {
	return time.Now().In(s.locOf(p.Owner, p.TenantID)).Format("2006-01-02")
}

// notifyUser delivers an apply outcome to the user with guaranteed-retry
// semantics: it dedups on the outcome we last SUCCESSFULLY delivered
// (permit_notify), NOT the activity-log row, so an undelivered notification is
// retried on the next tick rather than silently suppressed, and if the user
// cannot be reached the operator is alerted once. key identifies the outcome.
func (s *Scheduler) notifyUser(ctx context.Context, p model.Permit, o notify.ApplyOutcome, key string) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	// The message is about THIS permit: its council's name and portal, whatever
	// tenant the account currently has selected.
	o.TenantID = p.TenantID
	// The outcome's identity travels with it, so the notifier can remember which
	// members a PARTIAL delivery reached and not repeat itself to them on retry.
	o.Key = key
	notifiedKey, adminKey, _ := s.store.PermitNotify(ctx, p.ID)
	if notifiedKey == key {
		return // already successfully told about this exact outcome
	}
	// Claim this permit+outcome SYNCHRONOUSLY before spawning delivery. Under a
	// fleet-wide event the deliveries queue behind notifyConc, so without an in-flight
	// claim the NEXT pass would see the same (not-yet-written) durable key and launch a
	// duplicate for every permit — amplifying goroutines, mail, and DB reads each pass.
	// In-memory: a restart drops the claim, which is fine, the durable notified-key
	// still dedups anything already delivered.
	claim := fmt.Sprintf("%d|%s", p.ID, key)
	if s.notifyHeld(claim, time.Now()) {
		return // a recent attempt reached nobody, or not everyone; its retry is paced
	}
	if !s.claimNotify(claim) {
		return
	}
	go func() {
		defer s.releaseNotify(claim)
		// Detached context first, then re-read the durable key with it. The check
		// before claiming could have raced a delivery that finished and wrote the key in
		// between, then released its claim to us — this catches that. Using the caller's
		// ctx here would fail the read during shutdown and, with the error ignored, look
		// like "not yet delivered"; an inconclusive read defers rather than risking a
		// duplicate, since the next pass retries anyway.
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if k, _, err := s.store.PermitNotify(nctx, p.ID); err != nil || k == key {
			return
		}
		// Bound how many deliveries run at once. A fleet-wide event (a mass rejection
		// or an API-shape change) can call notifyUser for ~every permit on one tick;
		// without this each would open its own SMTP connection and read the DB
		// concurrently — a ~fleet-sized spike of dials + single-connection contention
		// exactly when the system is already stressed. The goroutines are cheap and
		// just queue here; deliveries drain a few at a time. (Escalation and the
		// once-only dedup below are unchanged.)
		if s.notifyConc != nil { // nil only in literal-constructed test schedulers
			s.notifyConc <- struct{}{}
			defer func() { <-s.notifyConc }()
		}
		delivered, err := s.notifier.NotifyApply(nctx, o)
		if delivered != 0 && err != nil {
			// Some members were reached and some were not. Recording the key here would
			// mean the ones that failed are never retried — on a shared account that can
			// be the person who actually parks the car, and for an OK:false outcome that
			// is the fine. Leave the key unset so a later pass re-delivers: the notifier
			// remembers who it reached (o.Key), so the retry goes only to the rest.
			log.Printf("scheduler: partial notify for %s (delivered=%d): %v — not recording, will retry", redact.Email(o.Owner), delivered, err)
			s.holdNotify(claim)
			return
		}
		if delivered != 0 { // >0 delivered, or -1 intentionally suppressed
			s.releaseNotifyHold(claim)
			if e := s.store.SetPermitNotifiedKey(nctx, p.ID, key); e != nil {
				// The notice went out but recording it as sent failed, so the next pass
				// would re-send. Surface it rather than discarding: a persistent failure
				// here means repeated messages to the user.
				log.Printf("scheduler: delivered notice to %s but could not persist its dedup key for permit %d (may re-send): %v", redact.Email(o.Owner), p.ID, e)
				s.systemAlert(nctx, "notify-dedup", "Notification sent but not recorded",
					fmt.Sprintf("A permit notification for %s was delivered, but saving it as sent failed: %v. If this persists the same notice may be delivered repeatedly.", o.Owner, e))
			}
			return
		}
		// Nobody was reached. The next pass retries — after a hold, not every tick:
		// the busy branch re-enters here each minute for as long as the block lasts.
		s.holdNotify(claim)
		if err != nil {
			log.Printf("scheduler: notify %s failed (will retry): %v", redact.Email(o.Owner), err)
		}
		if adminKey != key {
			outcome := "was updated"
			if !o.OK {
				outcome = "did NOT change (fine risk)"
			}
			body := fmt.Sprintf("Could not deliver a permit notification to %s.\n\nPermit: %s\nPlate: %s\nTheir permit %s and they may be unaware.\nError: %v",
				o.Owner, o.PermitLabel, o.Reg, outcome, err)
			if ae := s.notifier.NotifyAdmin(nctx, "User could not be notified: "+o.Owner, body); ae == nil {
				_ = s.store.SetPermitAdminKey(nctx, p.ID, key)
			} else {
				log.Printf("scheduler: admin escalation for %s failed: %v", redact.Email(o.Owner), ae)
			}
		}
	}()
}

// handleApplyFailure records a failed apply and notifies the user, but only after
// a transient problem has PERSISTED (so a one-tick blip that self-heals doesn't
// alarm anyone); a tenant refusal, which won't fix itself, alarms on the first
// tick. The message explains the cause, the consequence (what plate is still on
// the permit), and what to do. It also feeds the systemic-failure detector.
func (s *Scheduler) handleApplyFailure(ctx context.Context, p model.Permit, want, wantName, source string, err error, stats *passStats) {
	kind, op := parking.FailureOf(err)
	reason, action := describeFailure(kind, op)

	// Activity log records the failure from the first tick (visible in-app).
	s.logApply(ctx, p.ID, want, source, "error", reason)

	if stats != nil {
		stats.failOwners[p.Owner] = true
		if kind == parking.FailUnexpected {
			stats.unexpectedOwners[p.Owner] = true
		}
	}

	// Transient/unexpected problems get a grace period, and the next attempt is
	// deferred exponentially in the streak, so a permit that keeps failing doesn't
	// hit the tenant every minute forever. A refusal alarms at once and is PARKED:
	// the portal has said no to this write and will keep saying no, so the permit
	// is not attempted again until a user action (edit, re-link) clears it.
	n := s.bumpFailStreak(ctx, p.ID)
	threshold := failNotifyThreshold
	// The failure key is dated so a persisting TRANSIENT failure re-alarms each
	// day (a new day's visitor is a new exposure). A parked refusal is not
	// re-attempted, so it cannot re-alarm — except across a restart, which forgets
	// the parking, retries once, is refused again and would, on a dated key, tell
	// the household a second time. Undated: told once per distinct refusal.
	key := "error|" + want + "|" + reason + "|" + s.failureKeyDay(p)
	if kind == parking.FailRejected {
		threshold = 1
		s.parkRetry(p.ID, want)
		key = "rejected|" + want + "|" + reason
		action += " p.stonn will not retry this change until you edit the schedule or re-link."
	} else {
		s.deferRetry(p.ID, n)
	}
	if n < threshold {
		return
	}

	s.notifyUser(ctx, p, notify.ApplyOutcome{
		Owner:       p.Owner,
		PermitLabel: permitLabel(p),
		Reg:         want,
		Name:        wantName,
		OK:          false,
		CurrentReg:  p.ActiveRegistration,
		Reason:      reason,
		Action:      action,
		Transient:   kind != parking.FailRejected,
	}, key)
}

// describeFailure turns a failure classification into a plain-English reason and
// a next step for the user.
func describeFailure(kind parking.FailureKind, op parking.Op) (reason, action string) {
	what := opWording[op]
	if what == "" {
		what = "update your permit"
	}
	switch kind {
	case parking.FailRejected:
		return fmt.Sprintf("The council would not let p.stonn %s.", what),
			"Please check the permit on the council website, or change the vehicle there yourself. You may also need to re-link p.stonn from the app."
	case parking.FailUnexpected:
		return fmt.Sprintf("p.stonn got an unexpected response from the council while trying to %s.", what),
			"p.stonn will keep trying. If your permit shows the wrong vehicle, change it on the council website in the meantime."
	default: // FailTransient
		return fmt.Sprintf("p.stonn is having trouble reaching the council to %s.", what),
			"p.stonn will keep trying automatically. If it keeps happening, check your permit on the council website."
	}
}

// opWording is the plain-English phrase for each provider operation. Providers
// report an identifier, never a sentence; the words live here (and move to the
// message catalog with the rest of the copy).
var opWording = map[parking.Op]string{
	provider.OpLogin:        "sign in to your council account",
	provider.OpRefresh:      "keep your council sign-in active",
	provider.OpListPermits:  "list your permits",
	provider.OpReadVehicle:  "read the current vehicle on your permit",
	provider.OpSetVehicle:   "change the vehicle on your permit",
	provider.OpAddVehicle:   "add a vehicle to your permit",
	provider.OpClearVehicle: "remove the vehicle from your permit",
}

func (s *Scheduler) bumpFailStreak(ctx context.Context, permitID int64) int {
	n, err := s.store.BumpFailStreak(ctx, permitID)
	if err != nil {
		log.Printf("scheduler: bump fail streak %d: %v", permitID, err)
		return failNotifyThreshold // on a DB error, don't suppress the alert
	}
	return n
}

func (s *Scheduler) clearFailStreak(ctx context.Context, permitID int64) {
	if err := s.store.ClearFailStreak(ctx, permitID); err != nil {
		log.Printf("scheduler: clear fail streak %d: %v", permitID, err)
	}
}

// detectSystemic alerts the operator when many users' plate changes fail in one
// pass (a tenant outage or API change), so a fleet-wide break is seen directly
// rather than only as scattered per-user notices.
// totalOwners is the number of distinct owners whose active permits were
// reconciled this pass. The failN/busyN counts are owner-keyed sets, so the
// "everything is blocked" equality must compare owners to owners — comparing an
// owner count to a permit count would make it unsatisfiable whenever any owner
// holds more than one permit, hiding a fully-blocked small fleet.
func (s *Scheduler) detectSystemic(ctx context.Context, stats *passStats, totalOwners int) {
	if stats == nil {
		return
	}
	failN, unexpectedN := len(stats.failOwners), len(stats.unexpectedOwners)
	busyN := len(stats.busyOwners)
	// A widespread ErrCouncilBusy is a systemic block (Azure Front Door / egress-IP throttle)
	// that leaves permits stuck; treat it like a broad failure so the operator hears.
	busySystemic := busyN >= 3 || (totalOwners >= 2 && busyN == totalOwners)
	if busySystemic && !(unexpectedN >= 2 || failN >= 3) {
		s.systemAlert(ctx, "council-busy-block",
			"Council is rate-limiting / blocking p.stonn",
			fmt.Sprintf("This reconcile pass, %d of %d users' permits were deferred with a council busy/blocked response. p.stonn's egress IP may be rate-limited or soft-blocked; permit changes are stalled until it clears.", busyN, totalOwners))
		return
	}
	systemic := unexpectedN >= 2 || failN >= 3 || (totalOwners >= 2 && failN == totalOwners)
	if !systemic {
		return
	}
	s.systemAlert(ctx, "multi-user-fail",
		"Plate changes are failing for multiple users",
		fmt.Sprintf("This reconcile pass, %d user(s) had a plate change fail (%d with an unexpected/unparseable council response). This may be a council outage or an API change; check the logs.", failN, unexpectedN))
}
