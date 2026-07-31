// Package scheduler continuously reconciles each permit's allocated vehicle
// toward the desired state implied by its roster and any active override. It is
// a desired-state loop, not a cron of one-shot events: every tick it computes
// the target and corrects any drift, so a missed tick, a restart, or a failed
// council call simply heals on the next pass.
package scheduler

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
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
	SendRenewalReminder(ctx context.Context, to string, deadline time.Time, confirmURL string) error
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
	SessionMaxAge time.Duration // re-authorise bound measured from the last authenticated visit by any member (0 disables)
	WarmInterval  time.Duration // how stale a session may get before renewal (default 1h45m ≈ 0.7× the safe idle window)
	ReminderLead  time.Duration // how far before the bound to email the confirm link (0 = no reminder)
	ExpiryLead    time.Duration // how far before a permit's expiry to warn the account (0 = no reminder)
	PublicBaseURL string        // absolute base for the email confirm link
	Notifier      Notifier      // nil/disabled = no emails
	RateDelay     time.Duration // minimum pause between council calls within a warm pass (anti-burst)
	JitterFrac    float64       // ± fraction to randomise thresholds/delays (default 0.2)
	SnapshotPath  string        // where to write the daily consistent DB backup snapshot ("" disables)
	// SpreadWindow staggers SCHEDULED plate changes across a window opening at the
	// schedule boundary, so a midnight roster rollover shared by every household
	// does not become one back-to-back burst of council writes. 0 disables it and
	// every due change is applied on the next tick. See spreadElapsed; the price is
	// that a permit can show the previous day's plate until its slot comes up.
	SpreadWindow time.Duration
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
	spreadWindow  time.Duration

	// fleetSize is how many permits the last reconcile pass saw, the herd size the
	// rollover window is scaled against. Written once per pass, read per permit.
	fleetSize atomic.Int64

	trigger chan struct{}

	// lastReconcile is the unix-nanos of the last completed reconcile pass, read by
	// an external watchdog. lastProgress is stamped as the pass WORKS (once per
	// permit), and is what the internal dead-man's switch measures: a pass that
	// legitimately runs long — ~100 changing permits spaced by rateDelay each — takes
	// far longer than any fixed multiple of the tick interval, so a completion-only
	// clock made "reconcile stalled" a fleet-size-dependent false alarm.
	lastReconcile atomic.Int64
	lastProgress  atomic.Int64
	// alertMu guards lastAlert, a coarse per-key throttle so a repeating systemic
	// failure does not spam the operator every tick.
	alertMu   sync.Mutex
	lastAlert map[string]time.Time

	// applyMu guards applying, and applying holds one entry per permit that has a
	// council plate-write in flight right now (the channel is closed on release, so
	// a waiter can block on it without polling). See AcquireApply.
	applyMu  sync.Mutex
	applying map[int64]chan struct{}

	// unscheduled remembers, per permit, the last "nothing to apply" state we
	// reported, so entering that state is announced once instead of every tick.
	// Only touched from the reconcile goroutine, so it needs no lock.
	unscheduled map[int64]string

	// reconciling is true for the duration of a reconcile pass, so the housekeeping
	// loop can keep its stop-the-world snapshot off the top of one (see maybeSnapshot).
	reconciling atomic.Bool

	// snapshotting is true while the daily VACUUM INTO is running. It holds the
	// store's single connection for its whole duration, so the watchdog uses this to
	// name the likely cause rather than reporting an unexplained stall.
	snapshotting atomic.Bool

	// retryMu guards nextTry: per-permit earliest-next-council-attempt deadlines.
	// A persistently failing SetVehicle would otherwise issue a real council
	// write per permit per MINUTE forever (~1,440/day from one IP) — exactly the
	// burst profile the jitter/rate-spacing works to avoid. In-memory only: a
	// restart retries immediately, which is fine (the streak itself is persisted
	// for notification thresholds).
	retryMu sync.Mutex
	nextTry map[int64]time.Time

	// snapshotPath/lastSnapshot drive the daily VACUUM INTO backup snapshot
	// (only touched from the warm loop, so no lock needed).
	snapshotPath string
	lastSnapshot time.Time
}

// failNotifyThreshold is how many consecutive failing ticks a TRANSIENT problem
// must persist before the user is alarmed (rejections alarm on the first tick).
const failNotifyThreshold = 3

// busyNotifyThreshold is how many consecutive ticks the council must keep
// refusing us before the user hears about it. Higher than failNotifyThreshold
// because a short block is expected and self-healing, and these ticks are not
// spaced by a backoff (see the ErrCouncilBusy branch), so this is ~15 minutes of
// a permit we cannot update. Long enough not to cry wolf, short enough to act on.
const busyNotifyThreshold = 15

const systemAlertThrottle = 30 * time.Minute

// New builds a Scheduler. loc is the timezone rosters are expressed in.
func New(st *store.Store, council Council, loc *time.Location, opts Options) *Scheduler {
	warm := opts.WarmInterval
	if warm <= 0 {
		warm = 105 * time.Minute
	}
	jf := opts.JitterFrac
	if jf <= 0 {
		jf = 0.2
	}
	rd := opts.RateDelay
	if rd < 0 {
		rd = 0
	}
	sw := opts.SpreadWindow
	if sw < 0 {
		sw = 0
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
		spreadWindow:  sw,
		trigger:       make(chan struct{}, 1),
		lastAlert:     make(map[string]time.Time),
		nextTry:       make(map[int64]time.Time),
		applying:      make(map[int64]chan struct{}),
		unscheduled:   make(map[int64]string),
		snapshotPath:  opts.SnapshotPath,
	}
}

// Kick requests an immediate reconcile (e.g. after a roster/override edit).
// Non-blocking: a pending kick is coalesced.
//
// It does NOT clear retry backoffs. It used to clear all of them, on the
// reasoning that a user action may have fixed whatever was failing — but the
// scope was wrong in two ways: it cleared every permit in the deployment, not
// the one the user touched, and it is reachable from unauthenticated guest
// activations. One actor kicking in a loop therefore held every failing permit
// in the fleet at the 1-minute reconcile rate instead of its 2–30 minute
// backoff, which is exactly the "a council write per permit per minute forever"
// profile nextTry exists to prevent — during the outage it was designed for.
//
// Callers who genuinely invalidated a backoff (a re-link, an edit to that
// permit) use KickPermit, which clears just that permit's window.
func (s *Scheduler) Kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// KickPermit clears ONE permit's failure backoff and then kicks. Use it after a
// user action that plausibly fixed that permit (a schedule edit, a re-link), so
// they don't wait out a stretched retry window they just made obsolete — without
// disturbing anyone else's backoff.
func (s *Scheduler) KickPermit(permitID int64) {
	if permitID > 0 {
		s.clearRetry(permitID)
	}
	s.Kick()
}

// KickOwner clears the backoffs for one owner's permits and then kicks. Used
// after a re-link, which plausibly fixes every permit on that account.
func (s *Scheduler) KickOwner(ctx context.Context, owner string) {
	if permits, err := s.store.ListPermitsFor(ctx, owner); err == nil {
		for _, p := range permits {
			s.clearRetry(p.ID)
		}
	}
	s.Kick()
}

// deferRetry stretches the permit's next council attempt exponentially in its
// consecutive-failure streak (2, 4, 8, 16, 32 min from a 1-minute interval),
// capped at 30 minutes and jittered.
func (s *Scheduler) deferRetry(permitID int64, streak int) {
	b := s.interval << min(streak, 5)
	if b > 30*time.Minute {
		b = 30 * time.Minute
	}
	s.retryMu.Lock()
	s.nextTry[permitID] = time.Now().Add(s.jittered(b))
	s.retryMu.Unlock()
}

// retryDeferred reports whether the permit is inside a failure-backoff window.
func (s *Scheduler) retryDeferred(permitID int64, now time.Time) bool {
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	t, ok := s.nextTry[permitID]
	return ok && now.Before(t)
}

func (s *Scheduler) clearRetry(permitID int64) {
	s.retryMu.Lock()
	delete(s.nextTry, permitID)
	s.retryMu.Unlock()
}

// AcquireApply claims the exclusive right to change ONE permit's plate at the
// council, and returns the function that releases it. ok is false only when ctx
// is cancelled while waiting, in which case the caller must not apply.
//
// A council write and the active_registration write that records it are one
// decision, and two of them interleaving loses: the guest handler and the
// reconcile loop both call SetVehicle, so the council could end up holding the
// roster plate while the database recorded the guest's. Every later tick then
// compares its target against that (wrong) belief, concludes there is nothing to
// do, and leaves a car uncovered until checkDrift re-reads the portal — up to the
// ~105-minute keep-warm interval later, which for the driver is a fine.
//
// The claim is PER PERMIT, and deliberately no wider. Reconcile calls the council
// once per permit inside its own claim; a global lock would serialise the whole
// pass behind whichever household happens to be mid-activation, and the pass
// already paces itself with rateDelay. Nothing takes this lock while holding a
// database transaction (both callers claim it, then talk to the council, then
// write) so it cannot deadlock against the store's single connection.
//
// Handlers WAIT here rather than skipping: a visitor who taps a car must not
// silently get nothing because a reconcile pass happened to be mid-write on their
// permit. Reconcile does the opposite — see tryApply.
func (s *Scheduler) AcquireApply(ctx context.Context, permitID int64) (release func(), ok bool) {
	for {
		if release, ok := s.tryApply(permitID); ok {
			return release, true
		}
		s.applyMu.Lock()
		busy := s.applying[permitID]
		s.applyMu.Unlock()
		if busy == nil {
			continue // released between the two locks; try to claim it again
		}
		select {
		case <-busy:
		case <-ctx.Done():
			return func() {}, false
		}
	}
}

// tryApply is AcquireApply without the wait: ok is false when another apply for
// this permit is already in flight. Reconcile uses this and skips the permit,
// because by the time a wait finished its `want` would have been computed before
// the other writer's decision — re-applying a stale target is precisely the
// clobber the exclusion exists to prevent. The next tick recomputes and heals.
//
// The returned release is idempotent, so a caller can both defer it (a panic must
// never leak a claim: a permit whose claim is held forever is a permit whose plate
// is never corrected again) and call it early to keep the claim off work that has
// nothing to do with the write.
func (s *Scheduler) tryApply(permitID int64) (release func(), ok bool) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if _, busy := s.applying[permitID]; busy {
		return nil, false
	}
	done := make(chan struct{})
	s.applying[permitID] = done
	var once sync.Once
	return func() {
		once.Do(func() {
			s.applyMu.Lock()
			if s.applying[permitID] == done {
				delete(s.applying, permitID) // keeps the map to in-flight applies only
			}
			s.applyMu.Unlock()
			close(done) // wake every waiter
		})
	}, true
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

	// Seed both clocks with the start time so the watchdog can detect a FIRST pass
	// that wedges (hangs before ever stamping anything). Without this seed they stay
	// 0 and the watchdog's "no pass yet" guard would never fire — exactly the
	// boot-time hang the dead-man's switch exists to catch.
	s.lastReconcile.CompareAndSwap(0, time.Now().UnixNano())
	s.lastProgress.CompareAndSwap(0, time.Now().UnixNano())

	// Join the helper loops before returning, so a caller that waits on Run can
	// safely close the store afterwards (nothing is left mid-DB-call).
	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()
	go func() { // keep-warm + reminders on their own cadence, so their
		// rate-limit pauses never stall reconcile
		defer wg.Done()
		s.warmLoop(ctx)
	}()
	go func() { // alert the operator if reconcile goes stale
		defer wg.Done()
		s.watchdog(ctx)
	}()

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
	s.progress()
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

// progress stamps the reconcile loop's liveness clock. Called at the start of a
// pass and after each permit it considers, so "the loop is alive" is measured by
// WORK DONE rather than by passes completed.
func (s *Scheduler) progress() {
	s.lastProgress.Store(time.Now().UnixNano())
}

// stallThreshold is how long the reconcile loop may go without touching a single
// permit before the operator is told it has wedged.
//
// Measured against progress, not against pass completion, so it does not have to
// bound the duration of a whole pass: a midnight rollover on a large fleet writes
// every permit, each spaced by rateDelay and each waiting on a council round trip,
// which is legitimately many minutes of work and used to false-alarm as a stall.
// What cannot happen legitimately is minutes of NOTHING between two permits, since
// the council client bounds its own calls. Kept a comfortable multiple of the tick
// interval so an idle-but-healthy loop (nothing to do, one pass a minute) is never
// mistaken for a wedged one.
const stallThreshold = 5 * time.Minute

// watchdog is an internal dead-man's switch: if the reconcile loop stops making
// progress for well over the tick interval, it alerts the operator (a hung loop
// the panic recover can't catch). A fully dead process is caught separately by the
// Docker healthcheck.
func (s *Scheduler) watchdog(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			last := s.lastProgress.Load()
			if last == 0 {
				continue // the loop has not started yet
			}
			age := time.Since(time.Unix(0, last))
			threshold := stallThreshold
			if 5*s.interval > threshold {
				threshold = 5 * s.interval // an unusually slow tick sets its own floor
			}
			if age <= threshold {
				continue
			}
			cause := ""
			if s.snapshotting.Load() {
				// The daily VACUUM INTO holds the store's single connection, so the loop
				// is blocked on its first query rather than wedged. Say so: an alert that
				// names the wrong cause costs the operator the whole investigation.
				cause = " A database backup snapshot is running, which holds the single database connection and can block the loop until it finishes."
			}
			s.systemAlert(ctx, "reconcile-stall", "Scheduler reconcile stalled",
				fmt.Sprintf("The reconcile loop has not touched a permit for %s (interval is %s). Users' permits may not be updating.%s",
					age.Round(time.Second), s.interval, cause))
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
	// Recovery cadence. A renewal itself still fires only when a session passes its
	// (per-session, stably-jittered) warmInterval, and a success slides the clock —
	// so healthy sessions cost no extra council calls no matter how fast we tick.
	// Ticking fast only shortens how long a FAILED or pushback-deferred renew waits
	// before its next attempt. That is what lets warmInterval sit at ~0.7× the safe
	// idle window instead of ~0.5× without exposing the narrower margin to a single
	// missed pass. A renew attempted during a council-pushback cooldown is a cheap
	// local no-op (renewLocked short-circuits before any network call), so fast
	// ticks never hammer a portal that is already refusing us.
	const recoveryTick = 3 * time.Minute
	warmEvery := recoveryTick
	if warmEvery > s.warmInterval {
		warmEvery = s.warmInterval // tiny (test) intervals: never tick slower than the interval
	}
	// Housekeeping (guest-request expiry, PII purges, apply-log prune, daily
	// snapshot) is cadence-insensitive; run it far less often than the recovery tick
	// so a fast tick doesn't multiply those queries.
	const houseEvery = 15 * time.Minute

	warmT := time.NewTicker(warmEvery)
	defer warmT.Stop()
	houseT := time.NewTicker(houseEvery)
	defer houseT.Stop()
	s.safeKeepWarm(ctx) // prime renewals
	s.safeSweep(ctx)    // prime housekeeping
	for {
		select {
		case <-ctx.Done():
			return
		case <-warmT.C:
			s.safeKeepWarm(ctx)
		case <-houseT.C:
			s.safeSweep(ctx)
		}
	}
}

// safeSweep runs one housekeeping pass under panic recovery, so a bug in a purge
// query can't kill the warm-loop goroutine and silently let every session lapse.
func (s *Scheduler) safeSweep(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: housekeeping panicked (recovered): %v", r)
		}
	}()
	s.sweepGuestRequests(ctx)
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

// sweepGuestRequests runs periodic housekeeping on the keep-warm cadence:
// pending printed-QR requests expire after an hour (a stale "approve this
// plate?" must not be actionable days later, and abandoned scans drain out of
// the holder's queue), decided rows — visitor plates are PII — are purged after
// 30 days, the apply log is pruned to a 90-day window, and a daily consistent
// DB snapshot is written for file-level backup tools.
func (s *Scheduler) sweepGuestRequests(ctx context.Context) {
	if n, err := s.store.ExpireGuestRequests(ctx, time.Now().Add(-time.Hour)); err != nil {
		log.Printf("scheduler: expire guest requests: %v", err)
	} else if n > 0 {
		log.Printf("scheduler: expired %d stale guest request(s)", n)
	}
	// 7 days, not 30: the only reader (the holder's "recently decided" list) looks
	// back 48 hours, so the rest was a visitor's number plate kept for nothing.
	if _, err := s.store.PurgeDecidedGuestRequests(ctx, time.Now().Add(-7*24*time.Hour)); err != nil {
		log.Printf("scheduler: purge guest requests: %v", err)
	}
	// A decided request past its window no longer needs its poll secret.
	if _, err := s.store.ClearSettledRequestNonces(ctx, time.Now()); err != nil {
		log.Printf("scheduler: clear settled request nonces: %v", err)
	}
	// A revoked guest link's recipient address is no longer needed to run anything.
	if _, err := s.store.ForgetRevokedRecipients(ctx, time.Now().Add(-30*24*time.Hour)); err != nil {
		log.Printf("scheduler: forget revoked recipients: %v", err)
	}
	// Bound the do-not-email list: bounces/unsubscribes age out after 2 years,
	// complaints are kept (see PruneSuppressions), diagnostics cleared at 90 days.
	if _, err := s.store.PruneSuppressions(ctx,
		time.Now().Add(-2*365*24*time.Hour), time.Now().Add(-90*24*time.Hour)); err != nil {
		log.Printf("scheduler: prune suppressions: %v", err)
	}
	// An unclicked confirm token is a live capability; don't leave it lying about
	// once its own TTL has passed. Generous cutoff: the handler enforces the real
	// TTL, this is just housekeeping.
	if _, err := s.store.ClearStaleConfirmTokens(ctx, time.Now().Add(-60*24*time.Hour)); err != nil {
		log.Printf("scheduler: clear stale confirm tokens: %v", err)
	}
	if _, err := s.store.PruneApplyLog(ctx, time.Now().Add(-90*24*time.Hour)); err != nil {
		log.Printf("scheduler: prune apply log: %v", err)
	}
	// Expired one-off/guest bookings: every guest activation writes one and a
	// printed door QR is public, so this table would otherwise grow forever from
	// anonymous traffic and slow every reconcile pass. 90 days keeps plenty of
	// history for the dashboard's past-days rendering.
	if _, err := s.store.PruneOverrides(ctx, time.Now().Add(-90*24*time.Hour)); err != nil {
		log.Printf("scheduler: prune overrides: %v", err)
	}
	// The account change log names people and plates; keep it to the same 90-day
	// window as the apply log rather than accumulating indefinitely.
	if _, err := s.store.PruneChangeLog(ctx, time.Now().Add(-90*24*time.Hour)); err != nil {
		log.Printf("scheduler: prune change log: %v", err)
	}
	s.maybeSnapshot(ctx)
}

// maybeSnapshot writes the daily backup snapshot, at most once a day.
//
// VACUUM INTO holds the store's single connection for its whole duration, so
// while it runs every handler and both loops block on their next query. Two things
// follow. First, it must not start on top of a reconcile pass that is mid-flight:
// a pass blocked between deciding a plate change and performing it is the one
// moment where the delay is measured in fines rather than in latency, so a pass in
// progress defers the snapshot to the next housekeeping tick (15 minutes) instead
// of forcing it. Second, its duration is the number an operator needs when
// something else in the process looks stalled, so it is always logged — a silent
// multi-second stop-the-world is indistinguishable from a bug elsewhere.
func (s *Scheduler) maybeSnapshot(ctx context.Context) {
	if s.snapshotPath == "" || time.Since(s.lastSnapshot) <= 24*time.Hour {
		return
	}
	if s.reconcileInFlight() {
		log.Printf("scheduler: deferring backup snapshot: a reconcile pass is in flight")
		return
	}
	s.snapshotting.Store(true)
	start := time.Now()
	err := s.store.Snapshot(ctx, s.snapshotPath)
	took := time.Since(start)
	s.snapshotting.Store(false)
	if err != nil {
		log.Printf("scheduler: backup snapshot failed after %s: %v", took.Round(time.Millisecond), err)
		// A silently failing backup is exactly the operator condition systemAlert
		// exists for (its per-key throttle keeps the retry loop from spamming).
		s.systemAlert(ctx, "backup-snapshot", "Backup snapshot is failing",
			fmt.Sprintf("The daily database snapshot to %s failed after %s: %v. File-level backups are stale until this succeeds.",
				s.snapshotPath, took.Round(time.Millisecond), err))
		return
	}
	s.lastSnapshot = time.Now()
	log.Printf("scheduler: wrote backup snapshot %s in %s", s.snapshotPath, took.Round(time.Millisecond))
}

// warmAction is what keep-warm should do with one session this pass.
type warmAction int

const (
	warmSkip   warmAction = iota // fresh enough; leave it
	warmRenew                    // stale but in-bound; silent-renew to slide the cookie
	warmRetire                   // past the re-authorise bound; drop and require re-link
)

// decideWarm is the pure keep-warm policy: retire a session once the account has
// been IDLE for maxAge, otherwise renew it when the cookie has gone staler than
// warmInterval. maxAge <= 0 disables the bound.
//
// The bound is measured against lastActive — the last authenticated visit by any
// member of the account, plus a click on the "are you still there?" email —
// because its purpose is to stop holding a council session for a household that
// has left the service or the area. Time since a password was typed is a poor
// proxy for that: a set-and-forget household that uses the app every week would
// be retired on schedule, while someone who moved away a year ago would look
// identical to someone who linked yesterday.
//
// lastActive zero falls back to linkedAt (a session predating the idle clock);
// both zero retires, since an unknown clock cannot be shown to be recent.
func decideWarm(now, lastActive, linkedAt, updatedAt time.Time, maxAge, warmInterval time.Duration) warmAction {
	idleSince := lastActive
	if idleSince.IsZero() {
		idleSince = linkedAt
	}
	if maxAge > 0 && (idleSince.IsZero() || now.Sub(idleSince) >= maxAge) {
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
		action := decideWarm(now, cs.LastActive, cs.LinkedAt, cs.UpdatedAt, s.sessionMaxAge, s.warmThresholdFor(cs.Owner, cs.UpdatedAt))
		if action == warmRetire {
			// Nobody on this account has used the app for the whole bound: stop
			// renewing, drop the session, and let the dashboard prompt a re-link.
			// Re-check the idle clock inside the delete. This pass sleeps between
			// council calls, so the decision above can be minutes old by now — an
			// unconditional delete retired people who came back mid-pass, seconds
			// after they used the app. A no-op also means someone else (the reconcile
			// loop's recoverOrRetire) got there first, so the alert is theirs to send,
			// not ours to duplicate.
			retired, err := s.store.DeleteCouncilSessionIfIdle(ctx, cs.Owner, now.Add(-s.sessionMaxAge))
			switch {
			case err != nil:
				log.Printf("scheduler: retire session %s: %v", cs.Owner, err)
			case retired:
				log.Printf("scheduler: session for %s idle past the re-link limit; unlinked (re-link required)", cs.Owner)
				// The renewal reminder (maybeRemind) is email-only and best-effort, so
				// it must not be the sole signal: tell the user their permit just
				// stopped being managed, exactly as the expired-cookie path does.
				s.alertRelink(cs.Owner)
			default:
				log.Printf("scheduler: skipped retiring %s: the account was used again, or was already unlinked", cs.Owner)
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
	// A reconnect is a full headless login (several sequential round trips), so
	// bound it well under one loop pass: a slow portal must not stall keep-warm or
	// reconcile. A timeout surfaces as a non-terminal error and falls through to
	// the transient branch below — session and saved password are kept, and a
	// later pass retries — exactly as a network blip would.
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch rerr := s.council.Reconnect(rctx, owner); {
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
	// Either way the next attempt is deferred exponentially in the streak, so a
	// permit that keeps failing doesn't hit the council every minute forever.
	n := s.bumpFailStreak(ctx, p.ID)
	s.deferRetry(p.ID, n)
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
//
// It reads ONE owner-level Index/grid call rather than one managedVehicle call per
// managed permit. A 2026-07-31 capture confirmed the grid's VehicleRego agrees with
// managedVehicle's RegistrationNumber, and that the same row already carries the
// status and end date the expiry warning needs — which used to be a SECOND council
// call right after this one. So the per-warm council cost is now one API request
// regardless of how many permits an owner manages, instead of managed+1.
//
// Only visitor permits are manageable (see server.isVisitorPermit), so that is
// typically one or two per household rather than the full permit list — the capture
// account held three permits but only one addable one. The win is therefore modest
// per household; what matters is that permit count leaves the scaling term entirely.
func (s *Scheduler) checkDrift(ctx context.Context, owner string) {
	// Anti-burst: space this read from the silent-renew that just ran.
	if s.rateDelay > 0 && !sleepCtx(ctx, s.jittered(s.rateDelay)) {
		return
	}
	live, err := s.council.ListPermits(ctx, owner)
	if err != nil {
		return // a read failure is not evidence of drift; try again next cycle
	}
	byCouncilID := make(map[string]parking.PermitInfo, len(live))
	for _, pi := range live {
		byCouncilID[pi.CouncilPermitID] = pi
		// Refresh expiry/status/type from the same response. Owner-scoped, so it
		// only touches rows this account manages.
		_ = s.store.UpdatePermitMeta(ctx, owner, pi.CouncilPermitID, pi.Status, pi.PermitNumber, pi.PermitType, pi.EndDate)
	}

	// Re-read AFTER the meta write so Inactive below is judged on the expiry the
	// council just reported, not the one we believed a moment ago.
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return
	}
	drifted := false
	now := time.Now()
	for i := range permits {
		p := permits[i]
		if p.Inactive(now, s.loc) {
			continue // don't act on permits we no longer manage
		}
		pi, ok := byCouncilID[p.CouncilPermitID]
		if !ok {
			continue // the council no longer lists it; syncing that is not drift's job
		}
		actual := pi.CurrentRego
		if model.SamePlate(actual, p.ActiveRegistration) {
			continue
		}
		if actual == "" {
			// An empty grid rego is the one reading the grid cannot be trusted on.
			// managedVehicle corroborates "no vehicle" against permitVehicleCount
			// (see parking.emptyIsCredible) precisely because blanking a plate on a
			// misread writes a FALSE "changed directly at the council portal" row and
			// tells the household their permit was cleared when it wasn't. The grid
			// carries no such corroboration, so pay one extra call to confirm a
			// clearing — rare, and only for the permit that looks cleared.
			confirmed, cerr := s.council.CurrentVehicle(ctx, owner, p)
			if cerr != nil || confirmed != "" {
				continue // unconfirmed, or not actually cleared: believe nothing
			}
		}
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
	if drifted {
		s.Kick() // reconcile now: re-apply the schedule over the drift
	}
	s.warnExpiring(ctx, owner)
}

// warnExpiring sends the one-time approaching-expiry warning for any permit now
// within expiryLead of its end date. It makes NO council call: checkDrift has
// already written the council's own status and end date for every permit from the
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
	now := time.Now()
	for i := range managed {
		p := managed[i]
		if p.EndDate.IsZero() || p.ExpiryReminded {
			continue
		}
		// Warn once we're inside the lead window, up until the permit has expired.
		// "Expired" has to mean the end of EndDate's local DAY (model.ExpiryDeadline),
		// the same boundary Permit.Inactive uses: EndDate is a zoneless council date
		// parsed as UTC midnight, so comparing `now` against the bare instant closed
		// the warning window at ~10-11am local on the permit's final valid day. A
		// notifier that was down through the lead window would then never warn at all,
		// which is the outage this reminder exists to survive.
		if now.Before(p.EndDate.Add(-s.expiryLead)) || !now.Before(model.ExpiryDeadline(p.EndDate, s.loc)) {
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

// maybeRemind emails the one-click renewal-confirm link once per cycle when a
// session is within ReminderLead of its re-authorise deadline.
func (s *Scheduler) maybeRemind(ctx context.Context, cs store.CouncilSession, now time.Time) {
	if s.notifier == nil || !s.notifier.Enabled() {
		return
	}
	// Measured against the same idle clock decideWarm uses, so the reminder is a
	// genuine "we haven't seen you in a while" rather than a fixed anniversary of
	// linking. An active household never sees it, which is the point.
	idleSince := cs.LastActive
	if idleSince.IsZero() {
		idleSince = cs.LinkedAt
	}
	if s.sessionMaxAge <= 0 || s.reminderLead <= 0 || idleSince.IsZero() || !cs.ReminderSent.IsZero() {
		return
	}
	deadline := idleSince.Add(s.sessionMaxAge)
	if now.Before(deadline.Add(-s.reminderLead)) || !now.Before(deadline) {
		return // not yet in the reminder window (or already past the deadline)
	}
	token, err := randToken()
	if err != nil {
		log.Printf("scheduler: reminder token for %s: %v", cs.Owner, err)
		return
	}
	url := s.publicBaseURL + "/council/confirm?token=" + token
	if err := s.notifier.SendRenewalReminder(ctx, cs.Owner, deadline.In(s.loc), url); err != nil {
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

// spreadElapsed reports whether a permit may act on a SCHEDULED change yet.
//
// Rosters are written in human hours, so households pile onto the same few
// boundaries — overwhelmingly midnight — and every one of their changes leaves
// this single IP in the minutes after it.
//
// What that actually looks like on the wire is worth being precise about, because
// it decides what spreading can and cannot fix. reconcileAll already pauses
// rateDelay after each permit it touches, so a shared boundary is NOT a
// back-to-back burst: it is a sustained stream at one permit (three requests) per
// rateDelay, lasting permits*rateDelay. Spreading does not remove a spike that was
// never there. What it does is lower that sustained RATE, by making permits become
// eligible over a window instead of all at the boundary.
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
	return elapsed >= s.spreadOffset(permitID, window)
}

// spreadSpacingFactor sets the target pace as a multiple of rateDelay: at 2, a
// shared boundary is retired at half the rate the loop could manage, so the
// council sees a stream at half saturation instead of a saturated one.
const spreadSpacingFactor = 2

// effectiveSpread is how wide the rollover window actually is right now: enough to
// pace THIS fleet at spreadSpacingFactor*rateDelay, capped by the configured
// maximum delay.
//
// It scales with the fleet because a fixed window is wrong at both ends. A small
// deployment has no herd to smooth — a handful of changes drain in seconds — so a
// flat 30 minutes would delay every midnight rollover half an hour to solve a
// problem that does not exist. A large one needs a window well past its own serial
// drain before the rate drops at all. Deriving it from the fleet size gives a
// deployment of five permits a window of seconds and a deployment of five hundred
// the full configured cap, with no operator retuning in between.
func (s *Scheduler) effectiveSpread() time.Duration {
	if s.spreadWindow <= 0 || s.rateDelay <= 0 {
		return 0
	}
	n := s.fleetSize.Load()
	if n <= 0 {
		return 0 // no pass has counted the fleet yet; spread nothing on a guess
	}
	want := time.Duration(n) * s.rateDelay * spreadSpacingFactor
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
// becomes ELIGIBLE, and the pass then retires eligible permits serially at one per
// rateDelay. A window at or below n*rateDelay is not smoothing — the serial drain
// is already the constraint — and saying so is the point of the second return
// value.
func (s *Scheduler) RolloverBound(n int) (bound time.Duration, spreading bool) {
	if n <= 0 {
		return 0, false
	}
	drain := time.Duration(n) * s.rateDelay
	window := time.Duration(n) * s.rateDelay * spreadSpacingFactor
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

// warmThresholdFor is the renew threshold for one session: warmInterval nudged by
// a small per-session offset that is STABLE within a warm cycle (deterministic in
// owner + updatedAt) but re-derives each cycle (updatedAt slides on every renew).
// Deterministic-not-random matters under the fast recovery tick: a fresh random
// draw every pass would let a session renew on whichever pass happened to roll the
// low end of the band, biasing every renewal toward warmInterval×(1-jitterFrac)
// and quietly raising traffic. A stable per-owner offset also gives better
// desync — each session keeps its own consistent phase — which is the anti-mechanical
// point of the jitter in the first place.
func (s *Scheduler) warmThresholdFor(owner string, updatedAt time.Time) time.Duration {
	if s.jitterFrac <= 0 {
		return s.warmInterval
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(owner))
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(updatedAt.Unix()))
	_, _ = h.Write(b[:])
	u := float64(h.Sum64()>>11) / float64(uint64(1)<<53) // uniform in [0,1)
	return time.Duration(float64(s.warmInterval) * (1 + (u*2-1)*s.jitterFrac))
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

// reconcileInFlight reports whether a reconcile pass is running right now.
func (s *Scheduler) reconcileInFlight() bool { return s.reconciling.Load() }

func (s *Scheduler) reconcileAll(ctx context.Context) {
	s.reconciling.Store(true)
	defer s.reconciling.Store(false)
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
	// The herd the rollover window is sized against. Total permits over-estimates
	// how many share any one boundary, which errs toward a wider window (gentler on
	// the council, slightly later convergence) rather than a narrower one.
	s.fleetSize.Store(int64(len(permits)))

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
		s.progress() // per-permit liveness, so a long legitimate pass is not a stall
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

// settle ends any failure or council-block episode for a permit that needs no
// council write this tick, whether that is because the permit already shows the
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
		p.CouncilPermitID, res.Source, res.VehicleID, p.Owner, p.ActiveRegistration)
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
	want := vehByOwnerID[ownerVehicle{p.Owner, res.VehicleID}].Registration
	wantName := vehByOwnerID[ownerVehicle{p.Owner, res.VehicleID}].Label
	if res.Registration != "" { // an ad-hoc one-off plate (not a saved vehicle)
		want = res.Registration
		wantName = ""
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

	// From here the council write and the active_registration write that records it
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
	// council write plus a "your permit was updated" notice for a no-op) nor act on a
	// stale failure streak.
	if fresh, ferr := s.store.GetPermit(ctx, p.ID); ferr == nil {
		p.ActiveRegistration, p.FailStreak = fresh.ActiveRegistration, fresh.FailStreak
		if model.SamePlate(want, p.ActiveRegistration) {
			s.settle(ctx, p)
			return false
		}
	}

	prev := p.ActiveRegistration // the plate we're changing away from
	err = s.council.SetVehicle(ctx, p.Owner, p, want)
	if err == nil {
		_ = s.store.SetPermitActive(ctx, p.ID, want)
	}
	// The decision is recorded, so drop the claim before the bookkeeping below: the
	// activity row, the notifications and (on an expired session) a full headless
	// re-login are none of them this permit's plate write, and a household tapping a
	// guest link must not wait out a 20-second reconnect to get their car on.
	release()
	switch {
	case err == nil:
		s.clearFailStreak(ctx, p.ID)
		s.clearRetry(p.ID)
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
		// By names whoever created the winning one-off, so a household can tell
		// "my roster ran" from "someone booked over it" — the account is shared, and
		// an unattributed change is indistinguishable from the schedule working.
		s.notifyUser(ctx, p, notify.ApplyOutcome{
			Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName, Source: string(res.Source), By: res.By, OK: true,
			DisplacedReg: d.Reg, DisplacedTold: d.Contact != "",
		}, "success|"+prev+">"+want)
		if d.Contact != "" && s.notifier != nil && s.notifier.Enabled() {
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
		// (no council traffic), so retrying each tick costs nothing and means we
		// resume the moment the block lifts, rather than waiting out a backoff.
		// fail_streak is shared with real failures — both mean "consecutive ticks we
		// could not apply" — and a success clears it either way.
		n := s.bumpFailStreak(ctx, p.ID)
		reason, action := describeFailure(parking.FailTransient, "update your permit")
		s.logApply(ctx, p.ID, want, string(res.Source), "error", reason)
		if n >= busyNotifyThreshold {
			s.notifyUser(ctx, p, notify.ApplyOutcome{
				Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName,
				OK: false, CurrentReg: p.ActiveRegistration,
				Reason: reason, Action: action, Transient: true,
			}, "busy|"+want)
		}
		return false
	case errors.Is(err, parking.ErrNotCaptured):
		// A council write endpoint returned "not captured": the API shape may have
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
		// The cookie died between keep-warm passes. Try a saved-password
		// auto-reconnect; failing that, retire the session once (so we stop
		// retrying every minute) and prompt a re-link. A transient reconnect
		// failure preserves the session for a later retry (see recoverOrRetire) —
		// spaced out, so a lingering outage isn't probed with a login per minute.
		if !s.recoverOrRetire(ctx, p.Owner) {
			s.deferRetry(p.ID, 3) // ~8 min between attempts while the session is unusable
		}
		return true
	default:
		s.handleApplyFailure(ctx, p, want, wantName, string(res.Source), err, stats)
		log.Printf("scheduler: permit %s apply error: %v", p.CouncilPermitID, err)
		return true
	}
}
