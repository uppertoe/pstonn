// Package scheduler continuously reconciles each permit's allocated vehicle
// toward the desired state implied by its roster and any active override. It is
// a desired-state loop, not a cron of one-shot events: every tick it computes
// the target and corrects any drift, so a missed tick, a restart, or a failed
// council call simply heals on the next pass.
package scheduler

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// Council is the subset of the council client the scheduler needs: apply a plate
// change, and force a keep-warm session renewal. Keeping it an interface lets the
// reconcile and keep-warm logic be tested without real HTTP.
type Council interface {
	SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error
	Refresh(ctx context.Context, owner string) error
	// CurrentVehicle reads the plate the council actually has on the permit right
	// now (used to detect drift from changes made directly in the council portal).
	CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error)
	// Reconnect re-establishes an expired session from the user's opt-in saved
	// password. Returns parking.ErrNoSavedPassword when none was saved.
	Reconnect(ctx context.Context, owner string) error
	// ListPermits reads the owner's council permits (used to refresh expiry/status).
	ListPermits(ctx context.Context, owner string) ([]parking.PermitInfo, error)
}

// Notifier sends user-facing notifications (the re-authorise reminder, each
// applied plate change / failure, and a re-link prompt) plus operator alerts for
// systemic failures. A nil or disabled Notifier means user notices are not sent.
type Notifier interface {
	Enabled() bool
	AdminConfigured() bool
	SendRenewalReminder(to string, deadline time.Time, confirmURL string) error
	// NotifyApply returns how many channels accepted the message (0 = the user was
	// NOT reached; -1 = intentionally suppressed, e.g. failures-only success).
	NotifyApply(ctx context.Context, o notify.ApplyOutcome) (int, error)
	// NotifyRelinkRequired tells the user to reconnect their council account;
	// returns the number of channels that accepted it (0 = not reached).
	NotifyRelinkRequired(ctx context.Context, owner string) int
	// NotifyPermitExpiry warns the account that a permit is approaching expiry;
	// returns the number of channels that accepted it (0 = not reached).
	NotifyPermitExpiry(ctx context.Context, owner, permitLabel string, expiry time.Time) int
	// NotifyAdmin sends an operator alert to every configured admin channel.
	NotifyAdmin(ctx context.Context, subject, body string) error
	// NotifyDriverDisplaced warns the driver responsible for a displaced booking
	// (a guest or a saved vehicle's attached email — no account) that their car
	// has been taken off the permit.
	NotifyDriverDisplaced(ctx context.Context, owner, to, permitLabel, oldReg, newReg string) error
}

// Options configures the Scheduler's session-lifecycle behaviour.
type Options struct {
	SessionMaxAge time.Duration // re-authorise bound from last link (0 disables)
	WarmInterval  time.Duration // how stale a session may get before renewal (default 45m)
	ReminderLead  time.Duration // how far before the bound to email the confirm link (0 = no reminder)
	ExpiryLead    time.Duration // how far before a permit's expiry to warn the account (0 = no reminder)
	PublicBaseURL string        // absolute base for the email confirm link
	Notifier      Notifier      // nil/disabled = no emails
	RateDelay     time.Duration // minimum pause between council calls within a warm pass (anti-burst)
	JitterFrac    float64       // ± fraction to randomise thresholds/delays (default 0.2)
}

// Scheduler reconciles permits on an interval and keeps linked council sessions
// warm (silent-renewing idle cookies) up to a fixed re-authorise bound, emailing
// a confirm link as that bound approaches.
type Scheduler struct {
	store    *store.Store
	council  Council
	loc      *time.Location
	interval time.Duration

	sessionMaxAge time.Duration
	warmInterval  time.Duration
	reminderLead  time.Duration
	expiryLead    time.Duration
	publicBaseURL string
	notifier      Notifier
	rateDelay     time.Duration
	jitterFrac    float64

	trigger chan struct{}

	// lastReconcile is the unix-nanos of the last completed reconcile pass; the
	// watchdog alerts the operator if it goes stale (a stuck/hung loop).
	lastReconcile atomic.Int64
	// alertMu guards lastAlert, a coarse per-key throttle so a repeating systemic
	// failure does not spam the operator every tick.
	alertMu   sync.Mutex
	lastAlert map[string]time.Time
}

// failNotifyThreshold is how many consecutive failing ticks a TRANSIENT problem
// must persist before the user is alarmed (rejections alarm on the first tick).
const failNotifyThreshold = 3

const systemAlertThrottle = 30 * time.Minute

// New builds a Scheduler. loc is the timezone rosters are expressed in.
func New(st *store.Store, council Council, loc *time.Location, opts Options) *Scheduler {
	warm := opts.WarmInterval
	if warm <= 0 {
		warm = 75 * time.Minute
	}
	jf := opts.JitterFrac
	if jf <= 0 {
		jf = 0.2
	}
	rd := opts.RateDelay
	if rd < 0 {
		rd = 0
	}
	return &Scheduler{
		store:         st,
		council:       council,
		loc:           loc,
		interval:      time.Minute,
		sessionMaxAge: opts.SessionMaxAge,
		warmInterval:  warm,
		reminderLead:  opts.ReminderLead,
		expiryLead:    opts.ExpiryLead,
		publicBaseURL: strings.TrimRight(opts.PublicBaseURL, "/"),
		notifier:      opts.Notifier,
		rateDelay:     rd,
		jitterFrac:    jf,
		trigger:       make(chan struct{}, 1),
		lastAlert:     make(map[string]time.Time),
	}
}

// Kick requests an immediate reconcile (e.g. after a roster/override edit).
// Non-blocking: a pending kick is coalesced.
func (s *Scheduler) Kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// LastReconcile is the time the scheduler last completed a clean reconcile pass
// (zero if none yet). An external watchdog uses this to tell a live-but-wedged
// process from a healthy one: the HTTP server can answer while the work loop is
// stuck, and a stale timestamp reveals that.
func (s *Scheduler) LastReconcile() time.Time {
	ns := s.lastReconcile.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Run drives the reconcile loop and a slower keep-warm loop until ctx is
// cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Seed lastReconcile with the start time so the watchdog can detect a FIRST
	// pass that wedges (hangs before ever stamping a completion). Without this seed
	// lastReconcile stays 0 and the watchdog's "no pass yet" guard would never fire
	// — exactly the boot-time hang the dead-man's switch exists to catch.
	s.lastReconcile.CompareAndSwap(0, time.Now().UnixNano())

	go s.warmLoop(ctx) // keep-warm + reminders on their own cadence, so their
	// rate-limit pauses never stall reconcile
	go s.watchdog(ctx) // alert the operator if reconcile goes stale

	s.safeReconcile(ctx) // reconcile once at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.safeReconcile(ctx)
		case <-s.trigger:
			s.safeReconcile(ctx)
		}
	}
}

// safeReconcile runs one reconcile pass, recovering from a panic (so one bad
// permit can't kill the loop and silently stop all plate changes) and alerting
// the operator when it does. It stamps lastReconcile on a clean pass.
func (s *Scheduler) safeReconcile(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: reconcile panicked (recovered): %v", r)
			s.systemAlert(ctx, "panic-reconcile", "Scheduler reconcile panicked",
				fmt.Sprintf("The reconcile loop panicked and was recovered. Plate changes may be affected until fixed.\n\n%v", r))
			return
		}
		s.lastReconcile.Store(time.Now().UnixNano())
	}()
	s.reconcileAll(ctx)
}

// watchdog is an internal dead-man's switch: if no reconcile pass has completed
// for well over the tick interval, it alerts the operator (a hung loop the panic
// recover can't catch). A fully dead process is caught separately by the Docker
// healthcheck.
func (s *Scheduler) watchdog(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			last := s.lastReconcile.Load()
			if last == 0 {
				continue // no pass has completed yet
			}
			if age := time.Since(time.Unix(0, last)); age > 5*s.interval {
				s.systemAlert(ctx, "reconcile-stall", "Scheduler reconcile stalled",
					fmt.Sprintf("No reconcile pass has completed for %s (interval is %s). Users' permits may not be updating.",
						age.Round(time.Second), s.interval))
			}
		}
	}
}

// systemAlert sends an operator alert for a systemic failure, throttled per key
// so a persistent problem does not spam every tick.
func (s *Scheduler) systemAlert(ctx context.Context, key, subject, body string) {
	if s.notifier == nil || !s.notifier.AdminConfigured() {
		return
	}
	s.alertMu.Lock()
	if t, ok := s.lastAlert[key]; ok && time.Since(t) < systemAlertThrottle {
		s.alertMu.Unlock()
		return
	}
	s.lastAlert[key] = time.Now()
	s.alertMu.Unlock()
	go func() {
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.notifier.NotifyAdmin(nctx, subject, body); err != nil {
			log.Printf("scheduler: admin alert %q failed: %v", key, err)
		}
	}()
}

// warmLoop runs the keep-warm pass on its own cadence, often enough to catch a
// session crossing the (jittered) warm threshold, but far cheaper than the
// per-minute reconcile.
func (s *Scheduler) warmLoop(ctx context.Context) {
	warmEvery := s.warmInterval / 3
	if warmEvery < time.Minute {
		warmEvery = time.Minute
	} else if warmEvery > 15*time.Minute {
		warmEvery = 15 * time.Minute
	}
	t := time.NewTicker(warmEvery)
	defer t.Stop()
	s.safeKeepWarm(ctx) // prime immediately
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.safeKeepWarm(ctx)
		}
	}
}

// safeKeepWarm runs one keep-warm pass, recovering from a panic so the keep-warm
// goroutine can't die and silently let every session lapse.
func (s *Scheduler) safeKeepWarm(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: keep-warm panicked (recovered): %v", r)
			s.systemAlert(ctx, "panic-keepwarm", "Scheduler keep-warm panicked",
				fmt.Sprintf("The keep-warm loop panicked and was recovered. Sessions may lapse until fixed.\n\n%v", r))
		}
	}()
	s.keepWarm(ctx)
}

// warmAction is what keep-warm should do with one session this pass.
type warmAction int

const (
	warmSkip   warmAction = iota // fresh enough; leave it
	warmRenew                    // stale but in-bound; silent-renew to slide the cookie
	warmRetire                   // past the re-authorise bound; drop and require re-link
)

// decideWarm is the pure keep-warm policy: retire a session once it has reached
// the re-authorise bound from its last interactive link (or has no known link
// time), otherwise renew it when it has gone staler than warmInterval. maxAge <= 0
// disables the bound.
func decideWarm(now, linkedAt, updatedAt time.Time, maxAge, warmInterval time.Duration) warmAction {
	if maxAge > 0 && (linkedAt.IsZero() || now.Sub(linkedAt) >= maxAge) {
		return warmRetire
	}
	if now.Sub(updatedAt) < warmInterval {
		return warmSkip
	}
	return warmRenew
}

// keepWarm silent-renews idle-but-valid sessions so their council cookie does not
// lapse, retires sessions that have reached the re-authorise bound, and emails a
// confirm link as that bound approaches. To be light on the council it: jitters
// each session's renew threshold (touches don't align or look mechanical), skips
// sessions whose owner has no schedule to act on (their dashboard use keeps them
// warm), and spaces the council calls it does make within a pass (anti-burst).
func (s *Scheduler) keepWarm(ctx context.Context) {
	sessions, err := s.store.ListCouncilSessions(ctx)
	if err != nil {
		log.Printf("scheduler: list council sessions: %v", err)
		return
	}
	now := time.Now()
	renewed := 0
	for _, cs := range sessions {
		if cs.Cookie == "" {
			continue
		}
		action := decideWarm(now, cs.LinkedAt, cs.UpdatedAt, s.sessionMaxAge, s.jittered(s.warmInterval))
		if action == warmRetire {
			// Past the re-authorise bound (or an unknown link time): stop renewing,
			// drop the session, and let the dashboard prompt a re-link.
			if err := s.store.DeleteCouncilSession(ctx, cs.Owner); err != nil {
				log.Printf("scheduler: retire session %s: %v", cs.Owner, err)
			} else {
				log.Printf("scheduler: session for %s reached the re-link limit; unlinked (re-link required)", cs.Owner)
			}
			continue
		}
		// Approaching-deadline reminder is independent of whether we renew now.
		s.maybeRemind(ctx, cs, now)
		if action == warmSkip {
			continue
		}
		// warmRenew. A linked user who has not built a schedule needs no live
		// session, their own dashboard use silently renews it when they visit.
		if has, err := s.store.OwnerHasSchedule(ctx, cs.Owner); err == nil && !has {
			continue
		}
		// Anti-burst: space out the council calls this pass actually makes.
		if renewed > 0 && s.rateDelay > 0 && !sleepCtx(ctx, s.jittered(s.rateDelay)) {
			return
		}
		renewed++
		switch err := s.council.Refresh(ctx, cs.Owner); {
		case err == nil:
			log.Printf("scheduler: kept session for %s warm", cs.Owner)
			s.checkDrift(ctx, cs.Owner) // piggyback a gentle council-drift check
		case errors.Is(err, parking.ErrSessionExpired):
			if s.recoverOrRetire(ctx, cs.Owner) {
				s.checkDrift(ctx, cs.Owner)
			}
		case errors.Is(err, parking.ErrNotLinked):
			// Raced with an unlink; nothing to do.
		case errors.Is(err, parking.ErrCouncilBusy):
			// Portal pushing back; the client is already backing off. Stay quiet.
		default:
			log.Printf("scheduler: keep-warm %s: %v", cs.Owner, err)
		}
	}
}

// recoverOrRetire handles an expired council session. It first tries a
// saved-password auto-reconnect. On success it returns true (session restored).
// If there is no saved password, or the saved password is genuinely rejected, it
// retires the session (unlink + prompt a manual re-link). But a TRANSIENT failure
// (council busy, network blip, a wrong/rotated encryption key) leaves the session
// AND the saved password in place so a later pass can retry — one unlucky hiccup
// must not permanently disable auto-reconnect. Returns true only when the session
// is usable now.
func (s *Scheduler) recoverOrRetire(ctx context.Context, owner string) bool {
	switch rerr := s.council.Reconnect(ctx, owner); {
	case rerr == nil:
		log.Printf("scheduler: session for %s expired; auto-reconnected from saved password", owner)
		return true
	case errors.Is(rerr, parking.ErrNoSavedPassword):
		// No credentials to retry with → retire and prompt a manual re-link.
	case errors.Is(rerr, parking.ErrLoginRejected):
		log.Printf("scheduler: auto-reconnect for %s rejected (saved password no longer valid)", owner)
	default:
		// Transient — keep the session + saved password and retry on a later pass.
		log.Printf("scheduler: auto-reconnect for %s deferred (transient): %v", owner, rerr)
		return false
	}
	if derr := s.store.DeleteCouncilSession(ctx, owner); derr != nil {
		log.Printf("scheduler: unlink expired session %s: %v", owner, derr)
	} else {
		log.Printf("scheduler: session for %s expired; unlinked (re-link required)", owner)
		s.alertRelink(owner) // proactively tell the user, don't wait for fine time
	}
	return false
}

// alertRelink notifies a user that their council connection dropped and they
// must re-link, escalating to the operator if the user cannot be reached, so a
// lapsed session never silently stops managing their permit until fine time.
func (s *Scheduler) alertRelink(owner string) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	go func() {
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s.notifier.NotifyRelinkRequired(nctx, owner) == 0 {
			_ = s.notifier.NotifyAdmin(nctx, "User could not be told to re-link: "+owner,
				fmt.Sprintf("%s's council session expired, so p.stonn stopped managing their permit, but no re-link notification could be delivered to them. They may get a fine.", owner))
		}
	}()
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

// notifyUser delivers an apply outcome to the user with guaranteed-retry
// semantics: it dedups on the outcome we last SUCCESSFULLY delivered
// (permit_notify), NOT the activity-log row, so an undelivered notification is
// retried on the next tick rather than silently suppressed, and if the user
// cannot be reached the operator is alerted once. key identifies the outcome.
func (s *Scheduler) notifyUser(ctx context.Context, p model.Permit, o notify.ApplyOutcome, key string) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	notifiedKey, adminKey, _ := s.store.PermitNotify(ctx, p.ID)
	if notifiedKey == key {
		return // already successfully told about this exact outcome
	}
	go func() {
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		delivered, err := s.notifier.NotifyApply(nctx, o)
		if delivered != 0 { // >0 delivered, or -1 intentionally suppressed
			_ = s.store.SetPermitNotifiedKey(nctx, p.ID, key)
			return
		}
		if err != nil {
			log.Printf("scheduler: notify %s failed (will retry): %v", o.Owner, err)
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
				log.Printf("scheduler: admin escalation for %s failed: %v", o.Owner, ae)
			}
		}
	}()
}

// handleApplyFailure records a failed apply and notifies the user, but only after
// a transient problem has PERSISTED (so a one-tick blip that self-heals doesn't
// alarm anyone); a council refusal, which won't fix itself, alarms on the first
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

	// Transient/unexpected problems get a grace period; a refusal alarms at once.
	n := s.bumpFailStreak(ctx, p.ID)
	threshold := failNotifyThreshold
	if kind == parking.FailRejected {
		threshold = 1
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
	}, "error|"+want+"|"+reason)
}

// describeFailure turns a failure classification into a plain-English reason and
// a next step for the user.
func describeFailure(kind parking.FailureKind, op string) (reason, action string) {
	if op == "" {
		op = "update your permit"
	}
	switch kind {
	case parking.FailRejected:
		return fmt.Sprintf("The council would not let p.stonn %s.", op),
			"Please check the permit on the council website, or change the vehicle there yourself. You may also need to re-link p.stonn from the app."
	case parking.FailUnexpected:
		return fmt.Sprintf("p.stonn got an unexpected response from the council while trying to %s.", op),
			"p.stonn will keep trying. If your permit shows the wrong vehicle, change it on the council website in the meantime."
	default: // FailTransient
		return fmt.Sprintf("p.stonn is having trouble reaching the council to %s.", op),
			"p.stonn will keep trying automatically. If it keeps happening, check your permit on the council website."
	}
}

// bumpFailStreak increments and returns the consecutive-failure count for a
// permit; clearFailStreak resets it after a success. Persisted (on the permit
// row) so a restart doesn't reset the grace before a transient failure is alerted.
// checkDrift re-reads the council's actual current plate for the owner's permits
// and writes it into active_registration. Reconcile skips a permit when the
// scheduled plate already equals the CACHED active_registration, so if someone
// changed the vehicle directly in the council portal, reconcile would never
// notice — until a dashboard visit refreshed the cache. Doing this read on the
// slow keep-warm cadence (already rate-spaced, once a session refreshes) catches
// that drift and re-arms reconcile, at gentle council load rather than a per-tick
// firehose. Any correction is kicked so reconcile re-applies the schedule promptly.
func (s *Scheduler) checkDrift(ctx context.Context, owner string) {
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return
	}
	drifted := false
	now := time.Now()
	for i := range permits {
		p := permits[i]
		if p.Inactive(now, s.loc) {
			continue // don't read the council for permits we no longer act on
		}
		actual, err := s.council.CurrentVehicle(ctx, owner, p)
		if err != nil {
			continue
		}
		if !strings.EqualFold(actual, p.ActiveRegistration) {
			log.Printf("scheduler: council drift on permit %s: cached %q, council shows %q — refreshing", p.CouncilPermitID, p.ActiveRegistration, actual)
			// Record the external change durably so it appears in the activity log
			// (nothing p.stonn does to the permit should be invisible) and so the
			// re-assertion the kicked reconcile is about to perform isn't deduped
			// away as a no-op against the pre-drift apply row.
			s.logApply(ctx, p.ID, actual, "external", "changed", "changed directly at the council portal")
			if e := s.store.SetPermitActive(ctx, p.ID, actual); e == nil {
				drifted = true
			}
		}
	}
	if drifted {
		s.Kick() // reconcile now: re-apply the schedule over the drift
	}
	s.syncPermitExpiry(ctx, owner) // refresh expiry/status + warn if a permit is expiring
}

// syncPermitExpiry pulls each of the owner's permits from the council, writes back
// their expiry date and status, and — when a permit is within expiryLead of its
// end date — sends the account a one-time approaching-expiry warning. Runs on the
// slow keep-warm cadence off an already-valid session, so it costs one grid call.
func (s *Scheduler) syncPermitExpiry(ctx context.Context, owner string) {
	// Anti-burst: space this council read from the drift reads that just ran.
	if s.rateDelay > 0 && !sleepCtx(ctx, s.jittered(s.rateDelay)) {
		return
	}
	live, err := s.council.ListPermits(ctx, owner)
	if err != nil {
		return
	}
	for _, pi := range live {
		// Update every permit the council reports; owner-scoped, so it only
		// touches rows this account manages.
		_ = s.store.UpdatePermitMeta(ctx, owner, pi.CouncilPermitID, pi.Status, pi.PermitNumber, pi.PermitType, pi.EndDate)
	}
	if s.expiryLead <= 0 {
		return
	}
	// Re-read managed permits so we see the (just-updated) expiry + reminded flag.
	managed, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return
	}
	now := time.Now()
	for i := range managed {
		p := managed[i]
		if p.EndDate.IsZero() || p.ExpiryReminded {
			continue
		}
		// Warn once we're inside the lead window, up until the permit has expired.
		if now.Before(p.EndDate.Add(-s.expiryLead)) || now.After(p.EndDate) {
			continue
		}
		if s.notifier == nil || !s.notifier.Enabled() {
			return
		}
		label := p.Label
		if label == "" {
			label = "visitor permit"
		}
		if s.notifier.NotifyPermitExpiry(ctx, owner, label, p.EndDate.In(s.loc)) > 0 {
			if e := s.store.MarkPermitExpiryReminded(ctx, p.ID); e != nil {
				log.Printf("scheduler: mark permit %d expiry-reminded: %v", p.ID, e)
			}
		}
	}
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
// pass (a council outage or API change), so a fleet-wide break is seen directly
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
	// A widespread ErrCouncilBusy is a systemic block (Akamai / egress-IP throttle)
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

// maybeRemind emails the one-click renewal-confirm link once per cycle when a
// session is within ReminderLead of its re-authorise deadline.
func (s *Scheduler) maybeRemind(ctx context.Context, cs store.CouncilSession, now time.Time) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	if s.sessionMaxAge <= 0 || s.reminderLead <= 0 || cs.LinkedAt.IsZero() || !cs.ReminderSent.IsZero() {
		return
	}
	deadline := cs.LinkedAt.Add(s.sessionMaxAge)
	if now.Before(deadline.Add(-s.reminderLead)) || !now.Before(deadline) {
		return // not yet in the reminder window (or already past the deadline)
	}
	token, err := randToken()
	if err != nil {
		log.Printf("scheduler: reminder token for %s: %v", cs.Owner, err)
		return
	}
	url := s.publicBaseURL + "/council/confirm?token=" + token
	if err := s.notifier.SendRenewalReminder(cs.Owner, deadline.In(s.loc), url); err != nil {
		log.Printf("scheduler: send reminder to %s: %v", cs.Owner, err)
		// The reminder is email-only. If it keeps failing through the window the
		// session lapses silently, so alert the operator (throttled).
		s.systemAlert(ctx, "reminder-send",
			"Renewal reminder could not be sent",
			fmt.Sprintf("Could not email the re-authorise reminder to %s: %v. If this persists their session will lapse without warning.", cs.Owner, err))
		return
	}
	if err := s.store.MarkReminderSent(ctx, cs.Owner, token); err != nil {
		log.Printf("scheduler: mark reminder for %s: %v", cs.Owner, err)
		return
	}
	log.Printf("scheduler: emailed renewal reminder to %s (deadline %s)", cs.Owner, deadline.In(s.loc).Format("2006-01-02"))
}

// jittered returns d scaled by a random factor in [1-jitterFrac, 1+jitterFrac].
func (s *Scheduler) jittered(d time.Duration) time.Duration {
	if s.jitterFrac <= 0 || d <= 0 {
		return d
	}
	j := time.Duration(float64(d) * (1 + (rand.Float64()*2-1)*s.jitterFrac))
	if j < 0 {
		return 0
	}
	return j
}

// randToken returns a 256-bit URL-safe random token for the confirm link.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sleepCtx sleeps for d unless ctx is cancelled first; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Scheduler) reconcileAll(ctx context.Context) {
	permits, err := s.store.ListPermits(ctx)
	if err != nil {
		log.Printf("scheduler: list permits: %v", err)
		s.systemAlert(ctx, "db-permits", "Scheduler database error",
			fmt.Sprintf("Reconcile could not read permits: %v. No plate changes are being applied until this clears.", err))
		return
	}
	vehicles, err := s.store.ListVehicleRefs(ctx)
	if err != nil {
		log.Printf("scheduler: list vehicles: %v", err)
		s.systemAlert(ctx, "db-vehicles", "Scheduler database error",
			fmt.Sprintf("Reconcile could not read vehicles: %v. No plate changes are being applied until this clears.", err))
		return
	}
	// Key by (owner, id): a permit's scheduled vehicle_id is resolved ONLY among
	// its owner's vehicles, so a rule/override that somehow references a foreign
	// id can never read another user's registration.
	vehByOwnerID := make(map[ownerVehicle]model.VehicleInfo, len(vehicles))
	for _, v := range vehicles {
		vehByOwnerID[ownerVehicle{v.Owner, v.ID}] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email}
	}
	now := time.Now().In(s.loc)
	stats := &passStats{failOwners: map[string]bool{}, unexpectedOwners: map[string]bool{}, busyOwners: map[string]bool{}}
	// Space out the council writes: when many permits change at the same wall-clock
	// boundary (a midnight/9am roster rollover), applying them back-to-back is a
	// burst from one IP that rate heuristics notice. We pause a jittered rateDelay
	// after each permit that actually hit the council.
	active := 0
	activeOwners := map[string]bool{}
	for _, p := range permits {
		// An expired or cancelled permit can't be changed; skip it so we don't
		// hammer the council with doomed writes or alarm the user with failures.
		// It stays in the store as a copy-schedule source until removed.
		if p.Inactive(now, s.loc) {
			continue
		}
		active++
		activeOwners[p.Owner] = true
		if s.reconcilePermit(ctx, p, vehByOwnerID, now, stats) && s.rateDelay > 0 {
			if !sleepCtx(ctx, s.jittered(s.rateDelay)) {
				return
			}
		}
	}
	s.detectSystemic(ctx, stats, len(activeOwners))
}

type ownerVehicle struct {
	owner string
	id    int64
}

// passStats accumulates failures across one reconcile pass so a fleet-wide
// problem (a council outage or API change) can be reported to the operator
// directly, instead of only surfacing as per-user notifications.
type passStats struct {
	failOwners       map[string]bool
	unexpectedOwners map[string]bool
	busyOwners       map[string]bool // council pushed back (ErrCouncilBusy) this pass
}

// displaced resolves who should be warned that prev (the plate just removed)
// belonged to a still-live booking: the shared model.FindDisplaced policy, fed
// this permit's owner-scoped vehicles and account members. Matching on the
// outgoing plate is a heuristic; a false miss or spurious note is low-harm.
func (s *Scheduler) displaced(ctx context.Context, p model.Permit, overrides []model.Override, vehByOwnerID map[ownerVehicle]model.VehicleInfo, prev, actor string, now time.Time) model.DisplacedBooking {
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
	return model.FindDisplaced(overrides, vehicles, prev, actor, members, now)
}

// reconcilePermit applies any needed plate change for one permit. It returns
// true when it actually contacted the council (so the caller can space bursts).
func (s *Scheduler) reconcilePermit(ctx context.Context, p model.Permit, vehByOwnerID map[ownerVehicle]model.VehicleInfo, now time.Time, stats *passStats) (hitCouncil bool) {
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
		return false // nothing scheduled right now; leave the permit as-is
	}
	want := vehByOwnerID[ownerVehicle{p.Owner, res.VehicleID}].Registration
	wantName := vehByOwnerID[ownerVehicle{p.Owner, res.VehicleID}].Label
	if res.Registration != "" { // an ad-hoc one-off plate (not a saved vehicle)
		want = res.Registration
		wantName = ""
	}
	if want == "" || want == p.ActiveRegistration {
		return false // already correct (or unknown/foreign vehicle)
	}

	prev := p.ActiveRegistration // the plate we're changing away from
	err = s.council.SetVehicle(ctx, p.Owner, p, want)
	switch {
	case err == nil:
		_ = s.store.SetPermitActive(ctx, p.ID, want)
		s.clearFailStreak(ctx, p.ID)
		s.logApply(ctx, p.ID, want, string(res.Source), "success", "")
		// If the plate we just removed had been put on by a still-live booking,
		// warn its driver (email only) so they aren't caught out — and tell the
		// account when that driver was unreachable, so a member can relay it. The
		// notice is enqueued durably (a fast insert), so no goroutine is needed.
		d := s.displaced(ctx, p, overrides, vehByOwnerID, prev, res.By, now)
		// Key the notification on the TRANSITION (prev→want), not just the target.
		// Keying on "success|want" alone would treat a re-assertion after an external
		// change (someone edited the plate directly in the council portal, which
		// checkDrift logs) as a duplicate of the original apply and stay silent — so
		// the account never hears that their deliberate manual change was reverted.
		s.notifyUser(ctx, p, notify.ApplyOutcome{
			Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName, Source: string(res.Source), OK: true,
			DisplacedReg: d.Reg, DisplacedTold: d.Contact != "",
		}, "success|"+prev+">"+want)
		if d.Contact != "" {
			if err := s.notifier.NotifyDriverDisplaced(ctx, p.Owner, d.Contact, permitLabel(p), prev, want); err != nil {
				log.Printf("scheduler: enqueue driver-displaced for %s: %v", d.Contact, err)
			}
		}
		log.Printf("scheduler: permit %s -> %s (%s)", p.CouncilPermitID, want, res.Source)
		return true
	case errors.Is(err, parking.ErrNotLinked):
		// Not linked yet, stay quiet; the dashboard prompts the user to link.
		return false
	case errors.Is(err, parking.ErrCouncilBusy):
		// Portal is pushing back (Akamai) or we're in a backoff cooldown; the
		// client is already spacing retries. Stay quiet at the USER level (it's
		// expected to be transient), but record it so a FLEET-WIDE block — which
		// would otherwise leave every permit stuck with no alert at all — surfaces
		// to the operator via detectSystemic.
		if stats != nil {
			stats.busyOwners[p.Owner] = true
		}
		log.Printf("scheduler: permit %s deferred: %v", p.CouncilPermitID, err)
		return false
	case errors.Is(err, parking.ErrNotCaptured):
		// A council write endpoint returned "not captured": the API shape may have
		// changed. This is systemic (hits every user), so alert the operator.
		s.systemAlert(ctx, "not-captured",
			"Council write endpoint not working (API shape change?)",
			fmt.Sprintf("SetVehicle for permit %s returned ErrNotCaptured. If the council changed its API this affects ALL users; investigate promptly.", p.CouncilPermitID))
		return true
	case errors.Is(err, parking.ErrSessionExpired):
		// The cookie died between keep-warm passes. Try a saved-password
		// auto-reconnect; failing that, retire the session once (so we stop
		// retrying every minute) and prompt a re-link. A transient reconnect
		// failure preserves the session for a later retry (see recoverOrRetire).
		s.recoverOrRetire(ctx, p.Owner)
		return true
	default:
		s.handleApplyFailure(ctx, p, want, wantName, string(res.Source), err, stats)
		log.Printf("scheduler: permit %s apply error: %v", p.CouncilPermitID, err)
		return true
	}
}
