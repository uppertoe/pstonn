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
	"github.com/uppertoe/pstonn/internal/redact"
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
	// ListPermitsComplete reads the owner's council permits (to refresh expiry/status)
	// and reports whether the list was the WHOLE account. Drift must not check an owner
	// off for another interval on the strength of one page, so the bool is not optional
	// here — the plain ListPermits the display paths use is not on this interface.
	ListPermitsComplete(ctx context.Context, owner string) ([]parking.PermitInfo, bool, error)
	// Blocked reports whether the fleet circuit breaker is open — a CONFIRMED
	// shared-edge block affecting the whole fleet, not one owner's cooldown. Used
	// to escalate the user-facing block warning (sooner, firmer) once we know a due
	// change genuinely will not apply until the block clears.
	Blocked() bool
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
	// NotifyReconnectStalled tells the household automatic reconnection has been
	// failing for a sustained stretch while their session is retained, so their
	// schedule is paused; returns the number of channels that accepted it.
	NotifyReconnectStalled(ctx context.Context, owner string) int
	// NotifyPermitExpiry warns the account that a permit is approaching expiry;
	// returns the number of channels that accepted it (0 = not reached).
	NotifyPermitExpiry(ctx context.Context, owner, permitLabel string, expiry time.Time) int
	// NotifyAdmin sends an operator alert to every configured admin channel.
	NotifyAdmin(ctx context.Context, subject, body string) error
	// NotifyDriverDisplaced warns the driver responsible for a displaced booking
	// (a guest or a saved vehicle's attached email — no account) that their car
	// has been taken off the permit.
	NotifyDriverDisplaced(ctx context.Context, owner, to, permitLabel, oldReg, newReg string) error
	// SendOnboardNudge emails a stalled signup (terms accepted, council never
	// connected) the once-ever recovery note. Email-only, like the renewal
	// reminder: this person configured no other channel.
	SendOnboardNudge(ctx context.Context, to string) error
	// EmailAvailable reports whether an SMTP sender is configured. The renewal
	// reminder is email-only, so Enabled() (any channel) is the wrong gate for it.
	EmailAvailable() bool
}

// Options configures the Scheduler's session-lifecycle behaviour.
type Options struct {
	SessionMaxAge time.Duration // re-authorise bound measured from the last authenticated visit by any member (0 disables)
	WarmInterval  time.Duration // how stale a session may get before renewal (default 1h45m ≈ 0.7× the safe idle window)
	ReminderLead  time.Duration // how far before the bound to email the confirm link (0 = no reminder)
	ExpiryLead    time.Duration // how far before a permit's expiry to warn the account (0 = no reminder)
	PublicBaseURL string        // absolute base for the email confirm link
	Notifier      Notifier      // nil/disabled = no emails
	OpDrain       time.Duration // modelled time one council operation occupies the governor at its sustained rate; used ONLY to size the rollover spread (no per-call sleep — the governor paces)
	JitterFrac    float64       // ± fraction to randomise thresholds/delays (default 0.2)
	SnapshotPath  string        // where to write the daily consistent DB backup snapshot ("" disables)
	// SpreadWindow staggers SCHEDULED plate changes across a window opening at the
	// schedule boundary, so a midnight roster rollover shared by every household
	// does not become one back-to-back burst of council writes. 0 disables it and
	// every due change is applied on the next tick. See spreadElapsed; the price is
	// that a permit can show the previous day's plate until its slot comes up.
	SpreadWindow time.Duration
	// DriftInterval is how often the owner-grid drift/expiry read runs, on its OWN
	// per-owner cadence decoupled from keep-warm. It used to piggyback on every warm
	// (~105 min), doubling keep-warm's council traffic for a check that catches a
	// rare event (an external portal edit). Default 6h; 0 disables drift reads.
	DriftInterval time.Duration
	// IdleWindow is the estimated council idle-expiry window. When >0 it anchors the
	// warm safety clamp: a session's warm threshold is never allowed within
	// WarmSafetyMargin of it, so WarmInterval can be raised toward the window without
	// risking a lapse before the first renew attempt. 0 disables the clamp.
	IdleWindow time.Duration
	// WarmSafetyMargin is the minimum gap kept between the warm threshold and
	// IdleWindow (the recovery-tick runway to retry a failed renew). Default 1h.
	WarmSafetyMargin time.Duration
}

// Scheduler reconciles permits on an interval and keeps linked council sessions
// warm (silent-renewing idle cookies) up to a fixed re-authorise bound, emailing
// a confirm link as that bound approaches.
type Scheduler struct {
	store *store.Store

	// markDriftChecked indirects the drift checkpoint write. Production always uses the
	// store; a test replaces it to make the write fail, which is the only way to reach
	// the branch that decides whether a failed checkpoint may clear the backoff — and
	// getting that wrong re-reads the council for the same owner every single tick.
	markDriftChecked func(ctx context.Context, owner string) error
	council          Council
	loc              *time.Location
	interval         time.Duration

	sessionMaxAge time.Duration
	warmInterval  time.Duration
	reminderLead  time.Duration
	expiryLead    time.Duration
	publicBaseURL string
	notifier      Notifier
	opDrain       time.Duration // rollover-sizing unit (see Options.OpDrain); NOT a sleep
	jitterFrac    float64
	// Onboarding-nudge audience window, initialised from the onboardNudge*
	// constants. Fields rather than the constants directly so a test can narrow
	// the window without waiting a day for a just-recorded consent to qualify.
	nudgeAfter       time.Duration
	nudgeLookback    time.Duration
	spreadWindow     time.Duration
	driftInterval    time.Duration
	idleWindow       time.Duration // estimated council idle expiry; anchors the warm safety clamp (0 disables it)
	warmSafetyMargin time.Duration // minimum guaranteed gap between the warm threshold and idleWindow

	// fleetSize is how many permits the last reconcile pass saw, the herd size the
	// rollover window is scaled against. Written once per pass, read per permit.
	fleetSize atomic.Int64

	trigger chan struct{}

	// lastReconcile is the unix-nanos of the last COMPLETED reconcile pass, read by
	// an external watchdog. lastReconcileAttempt is stamped at the START of every pass,
	// so the two together distinguish "a clean pass just ran" from "a pass ran but
	// bailed on a database read" — which the completion clock alone cannot show.
	// lastProgress is stamped as the pass WORKS (once per permit), and is what the
	// internal dead-man's switch measures: a pass that legitimately runs long — ~100
	// changing permits drained at the governor's rate — takes far longer than any fixed
	// multiple of the tick interval, so a completion-only clock made "reconcile stalled"
	// a fleet-size-dependent false alarm.
	lastReconcile        atomic.Int64
	lastReconcileAttempt atomic.Int64
	lastProgress         atomic.Int64
	// alertMu guards lastAlert, a coarse per-key throttle so a repeating systemic
	// failure does not spam the operator every tick.
	alertMu   sync.Mutex
	lastAlert map[string]time.Time
	// alertRetry is the short suppression window after a FAILED alert delivery
	// (defaults to systemAlertRetry; a field so tests can shrink it).
	alertRetry time.Duration

	// applyMu guards applying, and applying holds one entry per permit that has a
	// council plate-write in flight right now (the channel is closed on release, so
	// a waiter can block on it without polling). See AcquireApply.
	applyMu  sync.Mutex
	applying map[int64]chan struct{}

	// unscheduled remembers, per permit, the last "nothing to apply" state we
	// reported, so entering that state is announced once instead of every tick.
	// Only touched from the reconcile goroutine, so it needs no lock.
	unscheduled map[int64]string

	// reconciling is true for the duration of a reconcile pass. Retained as a status
	// signal; the snapshot no longer excludes reconcile (it runs on its own connection).
	reconciling atomic.Bool

	// snapshotting is true while the daily VACUUM INTO runs. It now runs on a SEPARATE
	// WAL-reader connection, so it does NOT hold the primary connection and is not a
	// cause of a primary-DB stall; this flag is just a snapshot-in-progress indicator.
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
	// (only touched from the warm loop, so no lock needed). lastSnapshotAttempt is
	// stamped on every try (success or failure) so a FAILING snapshot backs off to
	// hourly instead of repeating a full-size VACUUM every housekeeping tick.
	snapshotPath        string
	lastSnapshot        time.Time
	lastSnapshotAttempt time.Time

	// churnMu guards the session-lifecycle churn windows. A healthy fleet
	// re-authenticates almost never (prod ran days of keep-warm with zero organic
	// re-auths), so a rising expiry/reconnect rate is the fingerprint of a
	// council-side DEFAULT change — a shortened idle window, cookie rotation, or
	// silent-renew disabled — none of which alter response SHAPE, so the
	// shape/pushback detectors cannot see them. In-memory only: a restart zeroes the
	// window, which is fine, since the canary is about a sustained rate, not history.
	churnMu     sync.Mutex
	churnExpiry []churnEvent // scheduler-observed session expiries, last hour
	churnReconn []churnEvent // successful auto-reconnects, last hour

	// commitActive persists a confirmed plate change (defaults to store.SetPermitActive;
	// see New). A field so tests can inject a commit failure.
	commitActive func(ctx context.Context, id int64, registration string) error

	// notifyConc bounds concurrent user-notification deliveries so a fleet-wide event
	// can't spawn a fleet-sized burst of SMTP dials + single-connection DB reads.
	notifyConc chan struct{}

	// reconnectQ is the owner-deduplicated reconnect queue. EVERY ErrSessionExpired
	// discovery (keep-warm, reconcile) enqueues here instead of reconnecting inline;
	// the single reconnectLoop worker drains it, so recovery never blocks a convergence
	// loop and a mass expiry can't stall it for hours. Each item carries the generation
	// (the expired session's linked_at) it belongs to, so a manual relink/unlink since
	// enqueue supersedes stale work rather than clobbering the fresh session. Guarded
	// by reconnectMu.
	reconnectMu sync.Mutex
	reconnectQ  map[string]reconnectItem

	// driftMu guards the per-owner drift backoff and the shape-failure tally. A failed
	// drift read used to leave drift_checked_at alone and so retry on EVERY warm tick
	// (~3 min) indefinitely; with a fleet-wide API-shape change that is 500 owners x 3
	// requests every 3 minutes, driving the governor toward its ceiling until the
	// council pushes back. Failures now back off per owner, and repeated SHAPE failures
	// across distinct owners raise one operator alert.
	driftMu      sync.Mutex
	driftRetryAt map[string]time.Time
	driftFails   map[string]int
	driftShape   []churnEvent

	// reminderWarnMu guards the rate limit on the "no SMTP sender" operator warning.
	reminderWarnMu sync.Mutex
	reminderWarnAt time.Time

	// notifyInFlight claims a permit+outcome key while its delivery goroutine is
	// queued/running, so a fleet-wide event can't re-launch duplicate deliveries every
	// pass before the first has written its durable dedup key. Guarded by notifyMu.
	notifyMu       sync.Mutex
	notifyInFlight map[string]struct{}
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

// blockNotifyThreshold is the SHORTER wait used once the fleet circuit breaker is
// open — a CONFIRMED block. The 15-tick wait exists to avoid crying wolf over a
// blip, but a confirmed fleet block is not a blip: the change will not apply until
// it clears, so the household is told within ~4 minutes and firmly (act now),
// instead of a reassuring "still updating" they might sit on until a fine.
const blockNotifyThreshold = 4

// sessionNotifyThreshold is how many consecutive session-expired reconcile
// attempts a wanted change must survive before the household is alarmed.
// Attempts in this state are spaced ~8 minutes by the fixed deferRetry(3) in
// the ErrSessionExpired branch, so this is roughly half an hour in which the
// schedule wanted a different plate and automatic reconnection kept failing —
// well past the point a routine expire-and-reconnect would have healed itself.
const sessionNotifyThreshold = 4

const systemAlertThrottle = 30 * time.Minute

// maxNotifyConcurrency bounds simultaneous user-notification deliveries (SMTP dials
// + DB reads) so a mass-notification tick paces rather than spikes. See notifyUser.
const maxNotifyConcurrency = 8

// Reconnect-queue pacing. Per-owner backoff after a transient reconnect failure grows
// exponentially from reconnectBackoffMin, capped at reconnectBackoffMax, so a systemic
// login outage doesn't keep re-attempting the whole fleet every few minutes forever.
// reconnectPoll is how often the drain worker rechecks for work.
const (
	reconnectBackoffMin = 5 * time.Minute
	reconnectBackoffMax = 1 * time.Hour
	reconnectPoll       = 3 * time.Second
)

// reconnectStalledAlertAttempts is the backoff count at which the household is
// told reconnection has stalled. recoverOrRetire deliberately never retires a
// session over a transient failure or a changed council sign-in page, which
// used to mean those states were reported to nobody but the operator — the
// schedule silently stopped applying for as long as recovery kept deferring.
// Five attempts is 5+10+20+40 minutes of backoff, so this fires after roughly
// an hour and a quarter of failed reconnects: unambiguously stalled, not a
// blip. Fired once per queue residency (attempts resets when the item leaves).
const reconnectStalledAlertAttempts = 5

// reconnectItem is one queued reconnect: when to next attempt it, when it first
// entered the queue (for the backlog-age metric), the session generation it belongs
// to (the compare-and-swap token), and how many transient failures it has had (for
// exponential backoff).
type reconnectItem struct {
	next     time.Time
	queuedAt time.Time
	gen      int64
	attempts int
}

// reconnectResult is what one reconnect attempt did, so the drain worker knows
// whether to dequeue (recovered or gave up) or retry later (transient).
type reconnectResult int

const (
	reconnectRecovered reconnectResult = iota // session usable now
	reconnectRetired                          // gave up; session dropped, re-link prompted
	reconnectDeferred                         // transient; keep and retry after a backoff
)

// systemAlertRetry is the short window a systemic alert is suppressed for after a
// FAILED delivery, so a transient outbound failure retries soon instead of muting
// the alert for the full throttle. Must be < systemAlertThrottle.
const systemAlertRetry = 5 * time.Minute

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
	od := opts.OpDrain
	if od < 0 {
		od = 0
	}
	sw := opts.SpreadWindow
	if sw < 0 {
		sw = 0
	}
	di := opts.DriftInterval
	if di < 0 {
		di = 0
	}
	iw := opts.IdleWindow
	if iw < 0 {
		iw = 0
	}
	wsm := opts.WarmSafetyMargin
	if wsm <= 0 {
		wsm = time.Hour
	}
	sc := &Scheduler{
		store:            st,
		markDriftChecked: st.MarkDriftChecked,
		council:          council,
		loc:              loc,
		interval:         time.Minute,
		sessionMaxAge:    opts.SessionMaxAge,
		warmInterval:     warm,
		reminderLead:     opts.ReminderLead,
		expiryLead:       opts.ExpiryLead,
		publicBaseURL:    strings.TrimRight(opts.PublicBaseURL, "/"),
		notifier:         opts.Notifier,
		opDrain:          od,
		jitterFrac:       jf,
		spreadWindow:     sw,
		driftInterval:    di,
		idleWindow:       iw,
		warmSafetyMargin: wsm,
		trigger:          make(chan struct{}, 1),
		notifyConc:       make(chan struct{}, maxNotifyConcurrency),
		reconnectQ:       make(map[string]reconnectItem),
		driftRetryAt:     make(map[string]time.Time),
		driftFails:       make(map[string]int),
		notifyInFlight:   make(map[string]struct{}),
		lastAlert:        make(map[string]time.Time),
		alertRetry:       systemAlertRetry,
		nextTry:          make(map[int64]time.Time),
		applying:         make(map[int64]chan struct{}),
		unscheduled:      make(map[int64]string),
		snapshotPath:     opts.SnapshotPath,
		nudgeAfter:       onboardNudgeAfter,
		nudgeLookback:    onboardNudgeLookback,
	}
	// commitActive persists a confirmed plate change. Held as a field, not a direct
	// store call, purely so a test can inject a commit failure and exercise the
	// "council applied but local commit failed" recovery path.
	sc.commitActive = sc.store.SetPermitActive
	return sc
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
// pass behind whichever household happens to be mid-activation, and the governor
// already paces the council calls. Nothing takes this lock while holding a
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

// LastReconcileAttempt is when the most recent pass STARTED (zero if none yet).
// Compared with LastReconcile it shows a pass that ran but bailed on a database read:
// attempt recent, completion stale.
func (s *Scheduler) LastReconcileAttempt() time.Time {
	ns := s.lastReconcileAttempt.Load()
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
	wg.Add(3)
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
	go func() { // the sole owner of automatic reconnects (out of the convergence loops)
		defer wg.Done()
		s.reconnectLoop(ctx)
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
// the operator when it does. It records every ATTEMPT, but stamps lastReconcile
// (the "last clean pass" a watchdog trusts) only when the pass actually completed —
// not when it bailed on a database read or panicked.
func (s *Scheduler) safeReconcile(ctx context.Context) {
	s.progress()
	s.lastReconcileAttempt.Store(time.Now().UnixNano())
	completed := false
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: reconcile panicked (recovered): %v", r)
			s.systemAlert(ctx, "panic-reconcile", "Scheduler reconcile panicked",
				fmt.Sprintf("The reconcile loop panicked and was recovered. Plate changes may be affected until fixed.\n\n%v", r))
			return
		}
		if completed {
			s.lastReconcile.Store(time.Now().UnixNano())
		}
	}()
	completed = s.reconcileAll(ctx)
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
// every permit, drained at the governor's rate and each waiting on a council round
// trip, which is legitimately many minutes of work and used to false-alarm as a stall.
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
			// The snapshot no longer holds the primary connection (separate WAL reader),
			// so it is not a stall cause and is deliberately not named here.
			s.systemAlert(ctx, "reconcile-stall", "Scheduler reconcile stalled",
				fmt.Sprintf("The reconcile loop has not touched a permit for %s (interval is %s). Users' permits may not be updating.",
					age.Round(time.Second), s.interval))
		}
	}
}

// systemAlert sends an operator alert for a systemic failure, throttled per key
// so a persistent problem does not spam every tick.
func (s *Scheduler) systemAlert(ctx context.Context, key, subject, body string) {
	s.systemAlertEvery(ctx, key, subject, body, systemAlertThrottle)
}

// systemAlertEvery is systemAlert with the repeat interval chosen by the caller, for
// conditions that persist. The retry-on-failure behaviour below is the reason this is
// a parameter rather than a wrapper: an outer "once a day" gate stamped before delivery
// would suppress the retry too, so a first attempt that failed would mean the operator
// heard nothing at all for a day.
func (s *Scheduler) systemAlertEvery(ctx context.Context, key, subject, body string, throttle time.Duration) {
	if s.notifier == nil || !s.notifier.AdminConfigured() {
		return
	}
	if throttle <= 0 {
		throttle = systemAlertThrottle
	}
	retry := s.alertRetry
	if retry <= 0 || retry >= throttle {
		retry = systemAlertRetry
	}
	now := time.Now()
	s.alertMu.Lock()
	if t, ok := s.lastAlert[key]; ok && now.Sub(t) < throttle {
		s.alertMu.Unlock()
		return
	}
	// Claim the slot immediately (so a concurrent caller doesn't double-send) but only
	// for a SHORT window: back-date the stamp so the next attempt is allowed after
	// `retry`, not the full throttle. A SUCCESSFUL delivery extends it to the full
	// interval below. This stops a transient SMTP/ntfy blip from muting a critical
	// alert (login-shape, panic, db failure, session-churn) for the whole 30 minutes.
	s.lastAlert[key] = now.Add(-throttle + retry)
	s.alertMu.Unlock()
	go func() {
		nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.notifier.NotifyAdmin(nctx, subject, body); err != nil {
			log.Printf("scheduler: admin alert %q failed (retry in %s): %v", key, retry, err)
			return // leave the short window: the next call after `retry` re-sends
		}
		s.alertMu.Lock()
		s.lastAlert[key] = time.Now() // delivered: hold the full throttle
		s.alertMu.Unlock()
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
			// A deterministic housekeeping panic would otherwise silently disable
			// guest-request expiry, PII pruning, log/override pruning and the daily
			// backup — visible only in local logs. Alert the operator like the other loops.
			s.systemAlert(ctx, "panic-housekeeping", "Scheduler housekeeping panicked",
				fmt.Sprintf("A housekeeping pass panicked and was recovered. Pruning and the daily backup may be stalled until fixed.\n\n%v", r))
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
	s.sweepOnboardNudges(ctx)
	s.maybeSnapshot(ctx)
}

// Bounds of the onboarding-nudge audience window (see store.OnboardNudgeCandidates):
// a signup gets a day to finish on their own before being emailed, and the first
// deploy of the feature reaches back two weeks — far enough to recover the current
// stalled cohort, not far enough to mail people who plainly moved on months ago.
const (
	onboardNudgeAfter    = 24 * time.Hour
	onboardNudgeLookback = 14 * 24 * time.Hour
)

// sweepOnboardNudges emails each stalled signup (terms accepted 1–14 days ago,
// council never connected) the once-ever recovery note, on the housekeeping
// cadence. The mark is written only after the send is settled, so a transient
// SMTP failure retries on a later sweep rather than burning the one shot —
// while a SUPPRESSED address (bounced, complained, unsubscribed) marks as done:
// that outcome never improves by retrying, and each retry is another log line
// about mailing an address that asked to be left alone.
func (s *Scheduler) sweepOnboardNudges(ctx context.Context) {
	// Email-only mail plus a nil-notifier deployment: same gate as the renewal
	// reminder. Without SMTP, candidates simply keep accruing until it exists.
	if s.notifier == nil || !s.notifier.EmailAvailable() {
		return
	}
	now := time.Now()
	owners, err := s.store.OnboardNudgeCandidates(ctx, now.Add(-s.nudgeLookback), now.Add(-s.nudgeAfter))
	if err != nil {
		log.Printf("scheduler: onboarding nudge candidates: %v", err)
		return
	}
	for _, owner := range owners {
		err := s.notifier.SendOnboardNudge(ctx, owner)
		if err != nil && !errors.Is(err, notify.ErrSuppressed) {
			log.Printf("scheduler: onboarding nudge to %s: %v (will retry next sweep)", redact.Email(owner), err)
			continue
		}
		if merr := s.store.MarkOnboardNudgeSent(ctx, owner); merr != nil {
			// The send went out but the mark didn't stick; say so rather than let a
			// later sweep silently contradict "this is the only reminder p.stonn sends".
			log.Printf("scheduler: onboarding nudge to %s sent but not recorded: %v", redact.Email(owner), merr)
			continue
		}
		if err != nil {
			log.Printf("scheduler: onboarding nudge to %s skipped (suppressed address); marked done", redact.Email(owner))
		} else {
			log.Printf("scheduler: onboarding nudge emailed to %s", redact.Email(owner))
		}
	}
}

// maybeSnapshot writes the daily backup snapshot, at most once a day. The snapshot
// runs VACUUM INTO on its OWN connection (see store.Snapshot), so it no longer holds
// the primary connection and no longer needs to exclude a reconcile pass — a WAL
// reader and the writer run concurrently. The single housekeeping loop is the only
// caller, so two snapshots cannot overlap. Its duration is still logged, as the
// number an operator needs when something else in the process looks slow.
func (s *Scheduler) maybeSnapshot(ctx context.Context) {
	if s.snapshotPath == "" || time.Since(s.lastSnapshot) <= 24*time.Hour {
		return
	}
	// Don't retry a failing snapshot every housekeeping tick (15 min). Snapshot writes
	// a full-size copy (VACUUM INTO a temp file next to the live DB), so repeating it
	// against a full or slow volume just pins the disk and can drive it to 100% many
	// times an hour. Once one has been attempted and did not push lastSnapshot forward
	// (i.e. it failed), wait at least an hour before trying again. The daily cadence is
	// unaffected while snapshots succeed, because success advances lastSnapshot and the
	// 24h guard above dominates.
	if !s.lastSnapshotAttempt.IsZero() && time.Since(s.lastSnapshotAttempt) < time.Hour {
		return
	}
	s.lastSnapshotAttempt = time.Now()
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
	s.driftRetryAt[owner] = time.Now().Add(backoff)
	var distinct int
	if kind, _ := parking.FailureOf(err); kind == parking.FailUnexpected {
		s.driftShape = append(pruneChurn(s.driftShape, time.Now()), churnEvent{owner, time.Now()})
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
	s.driftRetryAt[owner] = time.Now().Add(s.driftThresholdFor(owner))
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
func (s *Scheduler) driftDue(cs store.CouncilSession, now time.Time) bool {
	if s.driftInterval <= 0 {
		return false
	}
	if s.driftBackedOff(cs.Owner, now) {
		return false // a failing read is retried on its own backoff, not every warm tick
	}
	baseline := cs.DriftCheckedAt
	if baseline.IsZero() {
		baseline = cs.UpdatedAt
	}
	return now.Sub(baseline) >= s.driftThresholdFor(cs.Owner)
}

// keepWarm silent-renews idle-but-valid sessions so their council cookie does not
// lapse, retires sessions that have reached the re-authorise bound, and emails a
// confirm link as that bound approaches. It also runs the owner-grid drift/expiry
// read on its OWN per-owner cadence (driftDue) — decoupled from warming, which used
// to trigger a grid read on every renew and so doubled keep-warm's council traffic.
// To be light on the council it jitters each session's thresholds (touches don't
// align or look mechanical), skips owners with no permit to act on (their
// session is left to lapse), and spaces the council calls within a pass.
func (s *Scheduler) keepWarm(ctx context.Context) {
	sessions, err := s.store.ListCouncilSessions(ctx)
	if err != nil {
		log.Printf("scheduler: list council sessions: %v", err)
		return
	}
	for _, cs := range sessions {
		// The governor paces the actual council requests this pass makes (warm and
		// drift), so there is no per-call sleep here; we only need to stop promptly
		// on shutdown rather than issue a fresh renew into a cancelled context.
		if ctx.Err() != nil {
			return
		}
		s.warmOne(ctx, cs)
	}
}

// warmOne processes ONE session under panic recovery, so a deterministic panic on a
// single session cannot abort the rest of the warm pass and starve every session
// after it (which, with stable ordering, would repeat forever). It never reconnects
// inline — an expired session is handed to the reconnect worker — so the pass is
// always fast; the clock is read here (not once for the whole pass) so a session
// evaluated late still uses a current time.
func (s *Scheduler) warmOne(ctx context.Context, cs store.CouncilSession) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: keep-warm for %s panicked (recovered); skipping it: %v", redact.Email(cs.Owner), r)
			s.systemAlert(ctx, "panic-keepwarm-session", "A session panicked during keep-warm",
				fmt.Sprintf("Keep-warm for %s panicked and was skipped so the rest of the pass could continue: %v", cs.Owner, r))
		}
	}()
	if cs.Cookie == "" {
		return
	}
	now := time.Now()
	action := decideWarm(now, cs.LastActive, cs.LinkedAt, cs.UpdatedAt, s.sessionMaxAge, s.warmThresholdFor(cs.Owner, cs.UpdatedAt))
	if action == warmRetire {
		// Nobody on this account has used the app for the whole bound: stop
		// renewing, drop the session, and let the dashboard prompt a re-link.
		// Re-check the idle clock inside the delete: an unconditional delete retired
		// people who came back mid-pass, seconds after they used the app. A no-op also
		// means someone else (the reconnect worker's recoverOrRetire) got there first,
		// so the alert is theirs to send, not ours to duplicate.
		retired, err := s.store.DeleteCouncilSessionIfIdle(ctx, cs.Owner, now.Add(-s.sessionMaxAge))
		switch {
		case err != nil:
			log.Printf("scheduler: retire session %s: %v", redact.Email(cs.Owner), err)
		case retired:
			log.Printf("scheduler: session for %s idle past the re-link limit; unlinked (re-link required)", redact.Email(cs.Owner))
			// The renewal reminder (maybeRemind) is email-only and best-effort, so
			// it must not be the sole signal: tell the user their permit just
			// stopped being managed, exactly as the expired-cookie path does.
			s.alertRelink(cs.Owner)
		default:
			log.Printf("scheduler: skipped retiring %s: the account was used again, or was already unlinked", redact.Email(cs.Owner))
		}
		return
	}
	// Approaching-deadline reminder is independent of whether we renew now.
	s.maybeRemind(ctx, cs, now)
	// Warm and drift apply to any owner who manages a permit — schedulers and
	// QR-only households alike. A live session is only useful for acting on a
	// permit, so an account that linked but added none is left to lapse; everyone
	// else is kept warm (the sliding session holds indefinitely on authorize-only
	// touches, so this keeps the cookie alive and the saved password dormant rather
	// than replaying a login on each cold use).
	if has, err := s.store.OwnerHasPermit(ctx, cs.Owner); err != nil || !has {
		return
	}

	// Warm the session if it has crossed its (jittered) threshold. warmSkip means
	// it is still comfortably within its warm window — already alive.
	alive := action == warmSkip
	if action == warmRenew {
		switch err := s.council.Refresh(ctx, cs.Owner); {
		case err == nil:
			alive = true
			log.Printf("scheduler: kept session for %s warm", redact.Email(cs.Owner))
		case errors.Is(err, parking.ErrSessionExpired):
			// Hand recovery to the reconnect worker and move on — never reconnect inline
			// in the warm pass. alive stays false; the worker re-warms via a kick on a
			// successful reconnect. Bind to the generation the failure carries, falling
			// back to this pass's snapshot (older, therefore safe) if it is untagged.
			gen := cs.Generation
			if g, ok := parking.SessionGenOf(err); ok {
				gen = g
			}
			s.enqueueReconnect(ctx, cs.Owner, gen)
		case errors.Is(err, parking.ErrNotLinked):
			// Raced with an unlink; nothing to do.
		case errors.Is(err, parking.ErrCouncilBusy):
			// Portal pushing back; the client is already backing off. Stay quiet.
		default:
			log.Printf("scheduler: keep-warm %s: %v", redact.Email(cs.Owner), err)
		}
	}

	// Drift/expiry read on its OWN cadence — separate from warming — and only when
	// the session is alive to serve the read (a warm just succeeded, or it was
	// already within its warm window). checkDrift updates permit status/expiry and
	// re-arms reconcile on any external change.
	//
	// Suspend drift entirely while the fleet breaker is open: a confirmed shared
	// block is exactly when to spend nothing on the low-value read and reserve all
	// recovering capacity for warming endangered sessions and due writes. driftDue
	// stays true (the timestamp is not advanced), so the read resumes the moment
	// the block clears.
	if alive && !s.council.Blocked() && s.driftDue(cs, now) {
		if derr := s.checkDrift(ctx, cs.Owner); derr != nil {
			// drift_checked_at is deliberately NOT advanced (the check did not happen),
			// but the owner is backed off so a persistent failure cannot retry on every
			// warm tick across the whole fleet.
			if errors.Is(derr, parking.ErrPermitListPartial) {
				// Truncation is a standing condition, not a blip, so enter at the normal
				// drift cadence instead of the failure ladder. The ladder's 15m/60m/240m
				// ramp costs three EXTRA reads per owner before it settles — 4,500 extra
				// council requests at 500 owners, on the very day the council changed its
				// paging, and again after every restart because the ladder lives in memory
				// while last_drift_check stays permanently stale.
				s.noteDriftDeferred(cs.Owner)
			} else {
				s.noteDriftFailure(ctx, cs.Owner, derr)
			}
			log.Printf("scheduler: drift check %s: %v", redact.Email(cs.Owner), derr)
			// A drift read is often how we learn the cookie was killed council-side just
			// AFTER a successful warm — the churn incident's signature. Without this the
			// expiry was only logged: updated_at is fresh so keep-warm won't re-probe for
			// a whole warm interval, leaving a dead session unqueued for hours.
			if g, ok := parking.SessionGenOf(derr); ok {
				s.enqueueReconnect(ctx, cs.Owner, g)
			}
		} else {
			// Clear the backoff only once the checkpoint is DURABLE. last_drift_check is
			// what stops this owner being picked again next tick; if the write fails and
			// we have already cleared the backoff, the owner stays due forever and we
			// re-read the council every cycle — three requests an owner, against an edge
			// we may be failing precisely because it is throttling us. Treating the failed
			// write as a drift failure keeps the backoff on and lets it widen.
			if err := s.markDriftChecked(ctx, cs.Owner); err != nil {
				log.Printf("scheduler: mark drift-checked %s: %v (holding the backoff so this owner is not re-read every tick)", redact.Email(cs.Owner), err)
				s.noteDriftFailure(ctx, cs.Owner, fmt.Errorf("drift checkpoint not saved: %w", err))
			} else {
				s.noteDriftSuccess(cs.Owner) // clear any backoff from earlier failures
			}
		}
	}
}

// churnEvent records one session-lifecycle event (an expiry, or a successful
// reconnect) with the owner it happened to, so a window can be counted by DISTINCT
// owner — several different owners is systemic; one owner flapping is not.
type churnEvent struct {
	owner string
	at    time.Time
}

const (
	churnWindow = time.Hour
	// sessionChurnAlertOwners is how many DISTINCT owners must re-authenticate within
	// the window before it is treated as systemic. Mirrors the multi-user-fail
	// threshold; a healthy fleet sits at 0, so 3 is already a strong signal.
	sessionChurnAlertOwners = 3
)

// pruneChurn drops events older than churnWindow, in place.
func pruneChurn(events []churnEvent, now time.Time) []churnEvent {
	cutoff := now.Add(-churnWindow)
	kept := events[:0]
	for _, e := range events {
		if e.at.After(cutoff) {
			kept = append(kept, e)
		}
	}
	return kept
}

func distinctOwners(events []churnEvent) int {
	seen := make(map[string]struct{}, len(events))
	for _, e := range events {
		seen[e.owner] = struct{}{}
	}
	return len(seen)
}

// noteSessionExpiry records a scheduler-observed expiry and returns how many
// DISTINCT owners have expired within the last hour.
func (s *Scheduler) noteSessionExpiry(owner string) int {
	s.churnMu.Lock()
	defer s.churnMu.Unlock()
	s.churnExpiry = append(pruneChurn(s.churnExpiry, time.Now()), churnEvent{owner, time.Now()})
	return distinctOwners(s.churnExpiry)
}

// noteReconnect records a successful auto-reconnect.
func (s *Scheduler) noteReconnect(owner string) {
	s.churnMu.Lock()
	defer s.churnMu.Unlock()
	s.churnReconn = append(pruneChurn(s.churnReconn, time.Now()), churnEvent{owner, time.Now()})
}

// SessionChurn reports session-lifecycle activity over the last hour for /status:
// expiries the scheduler observed, successful auto-reconnects, and the number of
// DISTINCT owners among the expiries (the systemic signal). All near zero on a
// healthy fleet — a rise is the canary for a council-side session-lifetime change.
func (s *Scheduler) SessionChurn() (expiries1h, reconnects1h, expiredOwners1h int) {
	s.churnMu.Lock()
	defer s.churnMu.Unlock()
	now := time.Now()
	s.churnExpiry = pruneChurn(s.churnExpiry, now)
	s.churnReconn = pruneChurn(s.churnReconn, now)
	return len(s.churnExpiry), len(s.churnReconn), distinctOwners(s.churnExpiry)
}

// enqueueReconnect records that owner's expired session needs a reconnect,
// deduplicated by owner. Every ErrSessionExpired discovery (keep-warm, reconcile,
// drift) calls this and returns immediately, handing the work to the single
// reconnectLoop worker rather than reconnecting inline and blocking the convergence
// loop. The churn canary is fed HERE, at discovery — once per owner while queued — so
// it counts real distinct expiries, not repeated attempts.
// gen MUST be the generation of the session that actually failed — never a value
// re-read here. Re-reading was a real defect: an interactive re-link landing between
// the failure and the enqueue made the task bind to the user's BRAND-NEW session, and
// the worker would then retire it. A stale-old gen is safe (it simply mismatches, the
// task is discarded, and the next keep-warm pass rediscovers within ~3 min); a
// too-new one is what destroys a valid session.
func (s *Scheduler) enqueueReconnect(ctx context.Context, owner string, gen int64) {
	now := time.Now()
	s.reconnectMu.Lock()
	_, already := s.reconnectQ[owner]
	if !already {
		s.reconnectQ[owner] = reconnectItem{next: now, queuedAt: now, gen: gen}
	}
	s.reconnectMu.Unlock()
	if already {
		return
	}
	// Several different owners re-authing within the hour is the fingerprint of a
	// council-side session-lifetime/idle-window/cookie change rather than user
	// activity, and it changes no response SHAPE, so nothing else would catch it.
	if distinct := s.noteSessionExpiry(owner); distinct >= sessionChurnAlertOwners {
		s.systemAlert(ctx, "session-churn",
			"Council sessions are expiring unusually often",
			fmt.Sprintf("%d different accounts have had their council session expire within the last hour. A healthy fleet almost never re-authenticates, so this points at a council-side change — a shortened session/idle window, cookie rotation, or silent-renew disabled — not user activity. If /status shows no breaker/pushback, the edge is not refusing us, which narrows it to a session-lifetime change. Investigate before it becomes a reconnect backlog.", distinct))
	}
}

// NoteSessionExpired queues recovery for a session some OTHER component proved
// dead — the parking client's background reads, wired via OnSessionExpired in
// main. The queue's own dedup makes repeated reports (a dashboard polling every
// few seconds) free, and the generation requirement is enforced by the caller.
func (s *Scheduler) NoteSessionExpired(owner string, gen int64) {
	s.enqueueReconnect(context.Background(), owner, gen)
}

// CancelReconnect drops any queued reconnect for owner. Called after a manual link,
// unlink or account deletion so stale recovery work is discarded promptly (the
// generation check is the hard safety; this is the fast path).
func (s *Scheduler) CancelReconnect(owner string) {
	s.reconnectMu.Lock()
	delete(s.reconnectQ, owner)
	s.reconnectMu.Unlock()
	// Drop drift bookkeeping too: without this the two maps keep an entry per
	// unlinked/retired owner until the process restarts.
	s.noteDriftSuccess(owner)
}

// nextDueReconnect returns the queued owner with the earliest next-attempt time (ties
// broken by owner for determinism), its generation, and how long until it is due.
func (s *Scheduler) nextDueReconnect() (owner string, gen int64, wait time.Duration, ok bool) {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	var best reconnectItem
	for o, it := range s.reconnectQ {
		if owner == "" || it.next.Before(best.next) || (it.next.Equal(best.next) && o < owner) {
			owner, best = o, it
		}
	}
	if owner == "" {
		return "", 0, 0, false
	}
	if now := time.Now(); best.next.After(now) {
		return owner, best.gen, best.next.Sub(now), true
	}
	return owner, best.gen, 0, true
}

func (s *Scheduler) dequeueReconnect(owner string) {
	s.reconnectMu.Lock()
	delete(s.reconnectQ, owner)
	s.reconnectMu.Unlock()
}

// backoffReconnect reschedules owner after an exponential per-owner delay.
// Once the attempt count says recovery has stalled rather than hiccuped, the
// household is told — exactly once per queue residency — because every path
// that lands here retains the session and would otherwise retry forever with
// only the operator aware the schedule has stopped applying.
func (s *Scheduler) backoffReconnect(owner string) {
	s.reconnectMu.Lock()
	it, ok := s.reconnectQ[owner]
	if !ok {
		s.reconnectMu.Unlock()
		return
	}
	it.attempts++
	backoff := reconnectBackoffMin << min(it.attempts-1, 6)
	if backoff > reconnectBackoffMax {
		backoff = reconnectBackoffMax
	}
	it.next = time.Now().Add(backoff)
	s.reconnectQ[owner] = it
	attempts := it.attempts
	s.reconnectMu.Unlock()
	if attempts == reconnectStalledAlertAttempts {
		s.alertReconnectStalled(owner)
	}
}

// ReconnectBacklog reports queue health for /status: total queued, how many are due
// now, and the age of the oldest queued item in seconds (0 if empty).
func (s *Scheduler) ReconnectBacklog() (queued, due, oldestSeconds int) {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	now := time.Now()
	var oldest time.Time // earliest queuedAt — actual backlog age, not next-retry time
	for _, it := range s.reconnectQ {
		queued++
		if !it.next.After(now) {
			due++
		}
		if oldest.IsZero() || it.queuedAt.Before(oldest) {
			oldest = it.queuedAt
		}
	}
	if !oldest.IsZero() && now.After(oldest) {
		oldestSeconds = int(now.Sub(oldest) / time.Second)
	}
	return queued, due, oldestSeconds
}

// reconnectLoop is the SINGLE owner of automatic reconnects. Draining the queue one
// owner at a time — naturally paced by the globally serialized login flow — keeps
// recovery entirely out of the keep-warm and reconcile passes, so neither can be
// stalled for minutes/hours by a correlated mass expiry. It recovers from a panic so
// a single bad item can't kill the worker while the rest of the process runs healthy.
func (s *Scheduler) reconnectLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		if !s.drainOneReconnect(ctx) {
			if !sleepCtx(ctx, reconnectPoll) {
				return
			}
		}
	}
}

// drainOneReconnect processes the next DUE queued reconnect under panic recovery,
// returning false if none is due (so the caller idles). Shared by reconnectLoop and
// tests. A recovered owner is kicked so any due change applies at once.
func (s *Scheduler) drainOneReconnect(ctx context.Context) (processed bool) {
	owner, gen, wait, ok := s.nextDueReconnect()
	if !ok || wait > 0 {
		return false
	}
	processed = true // we have an item; a panic below is still "processed" (it gets a backoff)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: reconnect worker panicked on %s (recovered): %v", redact.Email(owner), r)
			s.systemAlert(ctx, "panic-reconnect", "Reconnect worker panicked",
				fmt.Sprintf("Recovering the session for %s panicked and was recovered; it will be retried. %v", owner, r))
			s.backoffReconnect(owner)
		}
	}()
	switch s.recoverOrRetire(ctx, owner, gen) {
	case reconnectRecovered:
		s.dequeueReconnect(owner)
		s.KickOwner(ctx, owner)
	case reconnectRetired:
		s.dequeueReconnect(owner)
	case reconnectDeferred:
		s.backoffReconnect(owner)
	}
	return true
}

// recoverOrRetire attempts ONE saved-password reconnect for the expired session
// generation gen and reports the outcome. On success the session is usable
// (reconnectRecovered). With no saved password or a rejected one it retires the
// session — but ONLY if it is still the same generation, so a manual relink racing
// this work is never deleted (reconnectRetired; the re-link prompt is sent only when a
// row was actually removed). Anything transient (council busy, a network blip, a
// systemic login-shape break, or a FAILED delete) keeps the task and retries later
// (reconnectDeferred).
func (s *Scheduler) recoverOrRetire(ctx context.Context, owner string, gen int64) reconnectResult {
	// Skip stale work: if the session was relinked, reconnected, renewed, or unlinked
	// since this was queued, its generation no longer matches (or it is gone) — this
	// recovery task is not ours to act on.
	switch cur, err := s.store.GetCouncilSession(ctx, owner); {
	case errors.Is(err, store.ErrNotFound):
		return reconnectRetired // the session is genuinely gone; nothing to recover
	case err != nil:
		// A TRANSIENT read failure (SQLite contention — likeliest during exactly the
		// mass-expiry this queue exists for) must not drop the task, which is the same
		// mistake the failed-delete path already corrects.
		log.Printf("scheduler: reconnect guard read for %s failed; retrying later: %v", redact.Email(owner), err)
		return reconnectDeferred
	case cur.Generation != gen:
		return reconnectRetired // superseded: the current session is not ours to touch
	}
	// A reconnect is a full headless login (several sequential round trips); bound it
	// so a slow portal can't wedge the drain worker.
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	switch rerr := s.council.Reconnect(rctx, owner); {
	case rerr == nil:
		s.noteReconnect(owner)
		log.Printf("scheduler: session for %s expired; auto-reconnected from saved password", redact.Email(owner))
		return reconnectRecovered
	case errors.Is(rerr, store.ErrSessionSuperseded):
		// The login succeeded at the council but the generation-conditioned save landed
		// nowhere — the session changed under us (a relink or a password opt-out during
		// the attempt). Discard; the current session is correct as it stands.
		log.Printf("scheduler: reconnect for %s superseded by a concurrent session change; discarding", redact.Email(owner))
		return reconnectRetired
	case errors.Is(rerr, parking.ErrNoSavedPassword):
		// No credentials to retry with → retire and prompt a manual re-link.
	case errors.Is(rerr, parking.ErrLoginRejected):
		log.Printf("scheduler: auto-reconnect for %s rejected (saved password no longer valid)", redact.Email(owner))
	case errors.Is(rerr, parking.ErrLoginFormUnrecognised):
		// The sign-in page shape changed: this breaks reconnect AND interactive
		// re-link for EVERY user, and retrying cannot fix it. Alert as systemic and
		// KEEP the session + saved password so recovery resumes on its own once the
		// login flow is repaired — a forced mass re-link would only send users at the
		// same broken form.
		s.systemAlert(ctx, "login-shape",
			"Council sign-in page shape changed (login/reconnect broken)",
			fmt.Sprintf("Reconnect for %s returned ErrLoginFormUnrecognised: the portal's sign-in HTML no longer matches the login replay, so it could not find the form it must submit. This blocks ALL reconnects and re-links until the parser is updated. Investigate promptly.", owner))
		return reconnectDeferred
	default:
		// Transient — keep the session + saved password and retry after a backoff.
		log.Printf("scheduler: auto-reconnect for %s deferred (transient): %v", redact.Email(owner), rerr)
		return reconnectDeferred
	}
	// Retire — but ONLY the generation we observed, so a relink during the attempt
	// survives. A delete FAILURE keeps the task (don't lose the recovery work).
	switch deleted, derr := s.store.DeleteCouncilSessionIfGen(ctx, owner, gen); {
	case derr != nil:
		log.Printf("scheduler: unlink expired session %s: %v", redact.Email(owner), derr)
		s.systemAlert(ctx, "retire-delete", "Could not retire an unrecoverable session",
			fmt.Sprintf("The session for %s could not be auto-reconnected and deleting it failed: %v. It will be retried; if this persists the account is stuck half-linked.", owner, derr))
		return reconnectDeferred
	case !deleted:
		// Superseded by a fresh link/reconnect during the attempt: nothing to retire.
		return reconnectRetired
	default:
		log.Printf("scheduler: session for %s expired; unlinked (re-link required)", redact.Email(owner))
		s.alertRelink(owner) // proactively tell the user, don't wait for fine time
		return reconnectRetired
	}
}

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

// alertRelink notifies a user that their council connection dropped and they
// must re-link, escalating to the operator if the user cannot be reached, so a
// lapsed session never silently stops managing their permit until fine time.
func (s *Scheduler) alertRelink(owner string) {
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
		if s.notifier.NotifyRelinkRequired(nctx, owner) == 0 {
			_ = s.notifier.NotifyAdmin(nctx, "User could not be told to re-link: "+owner,
				fmt.Sprintf("%s's council session expired, so p.stonn stopped managing their permit, but no re-link notification could be delivered to them. They may get a fine.", owner))
		}
	}()
}

// alertReconnectStalled tells a household that automatic reconnection has been
// failing long enough to count as stalled (see reconnectStalledAlertAttempts)
// while their session is deliberately retained — a council login outage or a
// changed sign-in page. Distinct from alertRelink because "re-link now" is the
// wrong instruction here: an interactive re-link goes through the same broken
// login, and recovery resumes on its own once it is repaired. What the
// household needs to know is that the schedule is paused meanwhile.
func (s *Scheduler) alertReconnectStalled(owner string) {
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
		if s.notifier.NotifyReconnectStalled(nctx, owner) == 0 {
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
	if d.Contact == "" || s.notifier == nil || !s.notifier.Enabled() {
		return false
	}
	if sup, err := s.store.SuppressedAmong(ctx, []string{d.Contact}); err != nil || len(sup) > 0 {
		if err != nil {
			log.Printf("scheduler: suppression check for %s: %v", notify.RedactEmail(d.Contact), err)
		}
		return false // undeliverable (or unknown): tell the account to pass it on
	}
	if err := s.notifier.NotifyDriverDisplaced(ctx, p.Owner, d.Contact, permitLabel(p), prev, want); err != nil {
		log.Printf("scheduler: enqueue driver-displaced for %s: %v", notify.RedactEmail(d.Contact), err)
		return false
	}
	return true
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
func (s *Scheduler) failureKeyDay() string {
	return time.Now().In(s.loc).Format("2006-01-02")
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
	// Claim this permit+outcome SYNCHRONOUSLY before spawning delivery. Under a
	// fleet-wide event the deliveries queue behind notifyConc, so without an in-flight
	// claim the NEXT pass would see the same (not-yet-written) durable key and launch a
	// duplicate for every permit — amplifying goroutines, mail, and DB reads each pass.
	// In-memory: a restart drops the claim, which is fine, the durable notified-key
	// still dedups anything already delivered.
	claim := fmt.Sprintf("%d|%s", p.ID, key)
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
			// is the fine. Leave the key unset so the next pass re-delivers.
			log.Printf("scheduler: partial notify for %s (delivered=%d): %v — not recording, will retry", redact.Email(o.Owner), delivered, err)
			return
		}
		if delivered != 0 { // >0 delivered, or -1 intentionally suppressed
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
	}, "error|"+want+"|"+reason+"|"+s.failureKeyDay())
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
func (s *Scheduler) checkDrift(ctx context.Context, owner string) error {
	// The caller (keepWarm) already spaced this call from the previous one, and the
	// transport governor spaces at the request level, so no extra sleep here.
	// Capture our belief BEFORE the council round trip. The CAS below exists to discard
	// a reading that an apply overtook mid-flight — reading the baseline afterwards
	// folded that apply INTO the expected value, so the swap succeeded and regressed the
	// record to a plate the council no longer holds.
	before, berr := s.store.ListPermitsFor(ctx, owner)
	if berr != nil {
		return berr
	}
	wasActive := make(map[int64]string, len(before))
	for _, p := range before {
		wasActive[p.ID] = p.ActiveRegistration
	}
	live, complete, err := s.council.ListPermitsComplete(ctx, owner)
	if err != nil {
		// A read failure is not evidence of drift, and — critically — it is not a
		// drift check either: report it so the caller does NOT advance
		// drift_checked_at and suppress the retry for a whole interval. Worst
		// exactly when the council is degraded and we most want to keep trying.
		return err
	}
	byCouncilID := make(map[string]parking.PermitInfo, len(live))
	// A drift round is only "done" if every required write landed. Recording a partial
	// round as complete stands the check down for the whole drift interval (hours),
	// which is exactly when it should retry soonest.
	var incomplete error
	for _, pi := range live {
		byCouncilID[pi.CouncilPermitID] = pi
		// Refresh expiry/status/type from the same response. Owner-scoped, so it
		// only touches rows this account manages.
		if err := s.store.UpdatePermitMeta(ctx, owner, pi.CouncilPermitID, pi.Status, pi.PermitNumber, pi.PermitType, pi.EndDate); err != nil {
			log.Printf("scheduler: drift meta write for permit %s: %v", pi.CouncilPermitID, err)
			incomplete = err
		}
	}

	// Re-read AFTER the meta write so Inactive below is judged on the expiry the
	// council just reported, not the one we believed a moment ago.
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return err // couldn't compare against our own record; retry rather than mark done
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
			confirmed, cerr := s.council.CurrentVehicle(ctx, owner, p)
			if cerr != nil {
				// Couldn't confirm; believe nothing — but this round did NOT answer the
				// question it was for, so it must not be recorded as a completed check.
				incomplete = cerr
				continue
			}
			actual = confirmed
		}
		if model.SamePlate(actual, p.ActiveRegistration) {
			continue // agrees with our record (incl. the common grid==cached case): no drift
		}
		log.Printf("scheduler: council drift on permit %s: cached %q, council shows %q — refreshing", p.CouncilPermitID, p.ActiveRegistration, actual)
		// Record the external change durably so it appears in the activity log
		// (nothing p.stonn does to the permit should be invisible) and so the
		// re-assertion the kicked reconcile is about to perform isn't deduped
		// away as a no-op against the pre-drift apply row.
		// Compare-and-swap against the belief this drift round READ, not a blind write:
		// the grid read above took seconds, and a guest or reconcile apply may have
		// committed a newer plate meanwhile. Writing over that would regress the record
		// to a plate the council no longer holds — a false "changed at the portal" row
		// and a duplicate "updated" notice on the way back. If it lost the race, the
		// other writer's value is the fresh one; drop ours and skip the drift row.
		// Swap against what we believed when the council read STARTED, not what the row
		// says now: an apply that landed during the read must win, not be overwritten.
		swapped, e := s.store.SetPermitActiveIfUnchanged(ctx, p.ID, wasActive[p.ID], actual)
		if e != nil || !swapped {
			if e != nil {
				log.Printf("scheduler: drift adopt for permit %s: %v", p.CouncilPermitID, e)
				incomplete = e // detected drift we failed to record: retry soon, not in 6h
			}
			continue
		}
		s.logApply(ctx, p.ID, actual, "external", "changed", "changed directly at the council portal")
		// Clear the delivered-notification fingerprint. The council now holds a plate we
		// did not set, and the reconcile this kicks will re-assert the schedule over it.
		// If the external edit RESTORED the previous plate, that re-assertion is the same
		// prev→want transition as the original apply, so the transition key alone would
		// dedup the "your permit was updated" notice away and the resident would never
		// learn their deliberate manual change was reverted — the exact fine-risk case the
		// notice exists for. Clearing forces the next apply to be treated as new.
		if e := s.store.SetPermitNotifiedKey(ctx, p.ID, ""); e != nil {
			log.Printf("scheduler: clear notified key for permit %s after drift: %v", p.CouncilPermitID, e)
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
		// from view entirely, and if the council settles into a stable first page their
		// plate drift and expiry warnings would go missing for good. Returning an error
		// leaves the checkpoint alone and puts the owner on the ordinary drift backoff,
		// so this cannot become a retry storm either.
		s.alertTruncatedList(ctx)
		// JOINED, not replaced. Whatever went wrong for the permits we DID read is still
		// the more urgent error and its identity is load-bearing: a SessionExpiredError
		// here is how we learn a cookie was killed council-side, and warmOne only queues
		// the reconnect if it can still find that error. Returning a bare marker instead
		// left dead sessions unqueued, and hid FailUnexpected from the API-shape tally so
		// the "several accounts failing the same way" alert could never fire.
		return errors.Join(incomplete, parking.ErrPermitListPartial)
	}
	// Only a fully-applied round counts as a drift check (see MarkDriftChecked).
	return incomplete
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

// warnNoReminderChannel logs the missing-SMTP warning at most hourly: this is on a
// per-owner path that runs every warm tick, so an unguarded log would be the only
// thing in the journal at fleet scale.
func (s *Scheduler) warnNoReminderChannel() {
	s.reminderWarnMu.Lock()
	defer s.reminderWarnMu.Unlock()
	now := time.Now()
	if now.Sub(s.reminderWarnAt) < time.Hour {
		return
	}
	s.reminderWarnAt = now
	log.Printf("scheduler: renewal reminders are disabled because no SMTP sender is configured " +
		"(the reminder is email-only; ntfy does not carry it). Households will not be warned before their council link expires.")
}

// maybeRemind emails the one-click renewal-confirm link once per cycle when a
// session is within ReminderLead of its re-authorise deadline.
func (s *Scheduler) maybeRemind(ctx context.Context, cs store.CouncilSession, now time.Time) {
	if s.notifier == nil {
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
	// PLACED AFTER the configuration check below, deliberately: an operator who has
	// turned reminders off (ReminderLead = 0) is not missing anything, and warning them
	// hourly about a feature they disabled is how real warnings get tuned out.
	// Gate on the channel this message actually uses, not on "any channel configured".
	// The renewal reminder is email-only, but Enabled() is also true for an ntfy-only
	// deployment — so we would mark the reminder sent and then no-op inside the mailer,
	// permanently consuming the household's one warning and letting the permit lapse in
	// silence. Skipping without recording means the reminders start working the moment
	// SMTP is configured, and the operator is told why they aren't.
	if !s.notifier.EmailAvailable() {
		s.warnNoReminderChannel()
		return
	}
	deadline := idleSince.Add(s.sessionMaxAge)
	if now.Before(deadline.Add(-s.reminderLead)) || !now.Before(deadline) {
		return // not yet in the reminder window (or already past the deadline)
	}
	token, err := randToken()
	if err != nil {
		log.Printf("scheduler: reminder token for %s: %v", redact.Email(cs.Owner), err)
		return
	}
	url := s.publicBaseURL + "/council/confirm?token=" + token
	// RECORD THE TOKEN FIRST. Sending first meant a failed write emailed a confirm link
	// that could never work — and, because reminder_sent_at stayed empty, sent another
	// broken one every warm tick. Recording first makes the emailed link valid by
	// construction; if the send then fails we roll the mark back so it can be retried.
	if err := s.store.MarkReminderSent(ctx, cs.Owner, token); err != nil {
		log.Printf("scheduler: mark reminder for %s: %v", redact.Email(cs.Owner), err)
		return
	}
	if err := s.notifier.SendRenewalReminder(ctx, cs.Owner, deadline.In(s.loc), url); err != nil {
		log.Printf("scheduler: send reminder to %s: %v", redact.Email(cs.Owner), err)
		// DETACHED context for the rollback. Using ctx here was a real defect: the most
		// likely reason the send failed is that ctx was cancelled (shutdown), and the
		// rollback would then fail for the same reason — leaving the session marked
		// reminded but never reminded, so maybeRemind's !ReminderSent.IsZero() guard
		// never fires again and the session lapses silently. That is worse than the
		// duplicate the old ordering risked.
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if cerr := s.store.ClearReminderSent(rbCtx, cs.Owner); cerr != nil {
			log.Printf("scheduler: roll back reminder mark for %s: %v", redact.Email(cs.Owner), cerr)
		}
		cancel()
		// The reminder is email-only. If it keeps failing through the window the
		// session lapses silently, so alert the operator (throttled).
		s.systemAlert(ctx, "reminder-send",
			"Renewal reminder could not be sent",
			fmt.Sprintf("Could not email the re-authorise reminder to %s: %v. If this persists their session will lapse without warning.", cs.Owner, err))
		return
	}
	log.Printf("scheduler: emailed renewal reminder to %s (deadline %s)", redact.Email(cs.Owner), deadline.In(s.loc).Format("2006-01-02"))
}

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
// the council sees a stream at half saturation instead of a saturated one.
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

// warmThresholdFor is the renew threshold for one session: the configured
// warmInterval, first clamped so it never sits within warmSafetyMargin of the
// estimated idle window, then nudged DOWNWARD by a small per-session offset.
//
// The clamp is what makes a long warm interval safe. At warmInterval near the idle
// window, a session that renewed at the interval would have almost no headroom, and
// a single failed pass could let the cookie lapse before the next attempt. Capping
// the threshold at idleWindow-warmSafetyMargin guarantees the fast recovery tick a
// fixed runway to retry, however high an operator sets COUNCIL_WARM_INTERVAL.
//
// The jitter is one-sided (only ever EARLIER than the base, never later): symmetric
// jitter would push the upper half of the band ABOVE the base and could cross the
// safety ceiling — exactly the lapse the clamp exists to prevent. It stays stable
// within a warm cycle (deterministic in owner + updatedAt, re-derived each cycle as
// updatedAt slides) so the fast recovery tick can't bias renewals low by re-rolling
// every pass, while still desyncing the fleet — each session keeps a consistent
// phase in [base*(1-jitterFrac), base].
func (s *Scheduler) warmThresholdFor(owner string, updatedAt time.Time) time.Duration {
	base := s.warmInterval
	if s.idleWindow > 0 {
		if ceil := s.idleWindow - s.warmSafetyMargin; ceil > 0 && base > ceil {
			base = ceil
		}
	}
	if s.jitterFrac <= 0 {
		return base
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(owner))
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(updatedAt.Unix()))
	_, _ = h.Write(b[:])
	u := float64(h.Sum64()>>11) / float64(uint64(1)<<53) // uniform in [0,1)
	return time.Duration(float64(base) * (1 - u*s.jitterFrac))
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
		vehByOwnerID[ownerVehicle{v.Owner, v.ID}] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email}
	}
	// The herd the rollover window is sized against. Total permits over-estimates
	// how many share any one boundary, which errs toward a wider window (gentler on
	// the council, slightly later convergence) rather than a narrower one.
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
		// hammer the council with doomed writes or alarm the user with failures.
		// It stays in the store as a copy-schedule source until removed.
		if p.Inactive(now, s.loc) {
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
	// A failure episode is ending: the scheduled plate is back in place, so nothing
	// needs the council. Close out the last logged failure so the audit trail doesn't
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
				// council blocked all day used to end exactly here at 5pm: want reverted to
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
				}, "unapplied|"+last.Registration+"|"+s.failureKeyDay())
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

// reconcilePermit applies any needed plate change for one permit. It returns
// true when it actually contacted the council (so the caller can space bursts).
func (s *Scheduler) reconcilePermit(ctx context.Context, p model.Permit, vehByOwnerID map[ownerVehicle]model.VehicleInfo, stats *passStats) (hitCouncil bool) {
	// Resolve against a FRESH clock, not the one captured at the start of the pass: a
	// governed pass over 500-1000 permits legitimately runs for minutes, and an
	// override whose StartsAt falls inside that window must be seen as started for
	// the permit being processed now — otherwise the previous plate is (re)applied
	// and only corrected next pass, leaving the wrong car on a live permit meanwhile.
	now := time.Now().In(s.loc)
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
	fresh, ferr := s.store.GetPermit(ctx, p.ID)
	if ferr != nil {
		// The permit may have been removed mid-pass. Falling through wrote a real plate
		// change to the council for a permit we no longer manage, then booked it as a
		// clean success (SetPermitActive matches 0 rows and returns nil), re-creating
		// activity and notify rows for the id DeletePermit just cleaned up and emailing
		// "your permit was updated" for the permit they just removed.
		log.Printf("scheduler: skipping permit %d: could not re-read it under the claim: %v", p.ID, ferr)
		return false
	}
	if fresh.Inactive(now, s.loc) {
		// checkDrift may have written a council-reported expiry earlier in THIS pass.
		// Writing anyway earns a council refusal that alarms the household with "the
		// council would not let p.stonn update your permit" for a permit that expired.
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
	err = s.council.SetVehicle(ctx, p.Owner, p, want)
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
		// The council confirmed the change (SetVehicle re-reads to verify), so the car
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
		// council reads on the shared egress IP (SetVehicle always pre-reads), starving
		// keep-warm and real due changes, while progress() kept the watchdog quiet.
		// Precondition is a read-OK/write-failing database (full disk, read-only remount).
		s.bumpFailStreak(ctx, p.ID)
		s.deferRetry(p.ID, 3)
		s.KickPermit(p.ID) // this permit, not the whole fleet
		return true
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
		// A CONFIRMED fleet block (breaker open) is not a blip: the change will not
		// apply until it clears, so warn sooner and firmly (act now), not with the
		// reassuring "still updating" a brief single-owner hiccup gets.
		confirmed := s.council.Blocked()
		threshold := busyNotifyThreshold
		reason, action := describeFailure(parking.FailTransient, "update your permit")
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
			key := "busy|" + want + "|" + s.failureKeyDay()
			if confirmed {
				key = "busy-blocked|" + want + "|" + s.failureKeyDay()
			}
			s.notifyUser(ctx, p, notify.ApplyOutcome{
				Owner: p.Owner, PermitLabel: permitLabel(p), Reg: want, Name: wantName,
				OK: false, CurrentReg: p.ActiveRegistration,
				Reason: reason, Action: action, Transient: true, Urgent: confirmed,
			}, key)
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
			s.enqueueReconnect(ctx, p.Owner, g)
		}
		// Recovery usually lands within a couple of reconnect attempts, but
		// "usually" was previously load-bearing: this branch wrote no activity
		// row, no fail streak and no notification, so a reconnect that kept
		// deferring (a council login outage, a changed sign-in page) left the
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
			}, "session|"+want+"|"+s.failureKeyDay())
		}
		s.deferRetry(p.ID, 3)
		return true
	default:
		s.handleApplyFailure(ctx, p, want, wantName, string(res.Source), err, stats)
		log.Printf("scheduler: permit %s apply error: %v", p.CouncilPermitID, err)
		return true
	}
}
