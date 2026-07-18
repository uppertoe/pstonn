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
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// Council is the subset of the council client the scheduler needs: apply a plate
// change, and force a keep-warm session renewal. Keeping it an interface lets the
// reconcile and keep-warm logic be tested without real HTTP.
type Council interface {
	SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error
	Refresh(ctx context.Context, owner string) error
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
	NotifyApply(ctx context.Context, owner, permitLabel, reg, source string, ok bool, detail string) (int, error)
	// NotifyRelinkRequired tells the user to reconnect their council account;
	// returns the number of channels that accepted it (0 = not reached).
	NotifyRelinkRequired(ctx context.Context, owner string) int
	// NotifyAdmin sends an operator alert to every configured admin channel.
	NotifyAdmin(ctx context.Context, subject, body string) error
}

// Options configures the Scheduler's session-lifecycle behaviour.
type Options struct {
	SessionMaxAge time.Duration // re-authorise bound from last link (0 disables)
	WarmInterval  time.Duration // how stale a session may get before renewal (default 45m)
	ReminderLead  time.Duration // how far before the bound to email the confirm link (0 = no reminder)
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

// Run drives the reconcile loop and a slower keep-warm loop until ctx is
// cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

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
		case errors.Is(err, parking.ErrSessionExpired):
			if derr := s.store.DeleteCouncilSession(ctx, cs.Owner); derr != nil {
				log.Printf("scheduler: unlink expired session %s: %v", cs.Owner, derr)
			} else {
				log.Printf("scheduler: session for %s expired; unlinked (re-link required)", cs.Owner)
				s.alertRelink(cs.Owner) // proactively tell the user, don't wait for fine time
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

// recordApply records an apply outcome to the activity log and notifies the
// owner. Crucially, the notification dedup keys on the outcome we last
// SUCCESSFULLY delivered (stored in permit_notify), NOT on the activity-log row.
// So an undelivered notification is retried on the next tick instead of being
// silently suppressed, and if the user cannot be reached the operator is alerted
// once. This is what keeps a delivery failure from turning into a missed change
// (and a fine) that nobody hears about.
func (s *Scheduler) recordApply(ctx context.Context, p model.Permit, reg, source, status, detail string) {
	key := status + "|" + reg + "|" + detail

	// Activity log: append only when the outcome changed from the last row.
	if last, err := s.store.LastApply(ctx, p.ID); err != nil ||
		!(last.Status == status && last.Registration == reg && last.Detail == detail) {
		_ = s.store.RecordApply(ctx, p.ID, reg, source, status, detail)
	}

	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	notifiedKey, adminKey, _ := s.store.PermitNotify(ctx, p.ID)
	if notifiedKey == key {
		return // the user has already been successfully told about this exact outcome
	}

	label := p.Label
	if label == "" {
		label = "permit " + p.CouncilPermitID
	}
	owner, ok := p.Owner, status == "success"
	go func() {
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		delivered, err := s.notifier.NotifyApply(nctx, owner, label, reg, source, ok, detail)
		if delivered != 0 { // >0 delivered, or -1 intentionally suppressed
			_ = s.store.SetPermitNotifiedKey(nctx, p.ID, key)
			return
		}
		// The user was NOT reached. Do not mark delivered (retry next tick), and
		// escalate to the operator once per distinct outcome.
		if err != nil {
			log.Printf("scheduler: notify %s failed (will retry): %v", owner, err)
		}
		if adminKey != key {
			outcome := "was updated"
			if !ok {
				outcome = "did NOT change (fine risk)"
			}
			body := fmt.Sprintf("Could not deliver a permit notification to %s.\n\nPermit: %s\nPlate: %s\nOutcome: %s / %s\nTheir permit %s and they may be unaware.\nError: %v",
				owner, label, reg, status, detail, outcome, err)
			if ae := s.notifier.NotifyAdmin(nctx, "User could not be notified: "+owner, body); ae == nil {
				_ = s.store.SetPermitAdminKey(nctx, p.ID, key)
			} else {
				log.Printf("scheduler: admin escalation for %s failed: %v", owner, ae)
			}
		}
	}()
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
	regByOwnerID := make(map[ownerVehicle]string, len(vehicles))
	for _, v := range vehicles {
		regByOwnerID[ownerVehicle{v.Owner, v.ID}] = v.Registration
	}
	now := time.Now().In(s.loc)
	// Space out the council writes: when many permits change at the same wall-clock
	// boundary (a midnight/9am roster rollover), applying them back-to-back is a
	// burst from one IP that rate heuristics notice. We pause a jittered rateDelay
	// after each permit that actually hit the council.
	for _, p := range permits {
		if s.reconcilePermit(ctx, p, regByOwnerID, now) && s.rateDelay > 0 {
			if !sleepCtx(ctx, s.jittered(s.rateDelay)) {
				return
			}
		}
	}
}

type ownerVehicle struct {
	owner string
	id    int64
}

// reconcilePermit applies any needed plate change for one permit. It returns
// true when it actually contacted the council (so the caller can space bursts).
func (s *Scheduler) reconcilePermit(ctx context.Context, p model.Permit, regByOwnerID map[ownerVehicle]string, now time.Time) (hitCouncil bool) {
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
	want := regByOwnerID[ownerVehicle{p.Owner, res.VehicleID}]
	if want == "" || want == p.ActiveRegistration {
		return false // already correct (or unknown/foreign vehicle)
	}

	err = s.council.SetVehicle(ctx, p.Owner, p, want)
	switch {
	case err == nil:
		_ = s.store.SetPermitActive(ctx, p.ID, want)
		s.recordApply(ctx, p, want, string(res.Source), "success", "")
		log.Printf("scheduler: permit %s -> %s (%s)", p.CouncilPermitID, want, res.Source)
		return true
	case errors.Is(err, parking.ErrNotLinked):
		// Not linked yet, stay quiet; the dashboard prompts the user to link.
		return false
	case errors.Is(err, parking.ErrCouncilBusy):
		// Portal is pushing back (Akamai) or we're in a backoff cooldown; the
		// client is already spacing retries. Stay quiet at the user level.
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
		// The cookie died between keep-warm passes. Retire the session once so we
		// stop retrying every minute, prompt a re-link on the dashboard, AND
		// proactively notify the user so they aren't caught out by a fine.
		if derr := s.store.DeleteCouncilSession(ctx, p.Owner); derr == nil {
			log.Printf("scheduler: session for %s expired; unlinked (re-link required)", p.Owner)
			s.alertRelink(p.Owner)
		}
		return true
	default:
		s.recordApply(ctx, p, want, string(res.Source), "error", err.Error())
		log.Printf("scheduler: permit %s apply error: %v", p.CouncilPermitID, err)
		return true
	}
}
