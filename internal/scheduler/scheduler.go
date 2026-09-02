// Package scheduler continuously reconciles each permit's allocated vehicle
// toward the desired state implied by its roster and any active override. It is
// a desired-state loop, not a cron of one-shot events: every tick it computes
// the target and corrects any drift, so a missed tick, a restart, or a failed
// tenant call simply heals on the next pass.
package scheduler

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
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
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/store"
)

// Tenant is the subset of the tenant client the scheduler needs: apply a plate
// change, and force a keep-warm session renewal. Keeping it an interface lets the
// reconcile and keep-warm logic be tested without real HTTP.
type Tenant interface {
	SetVehicle(ctx context.Context, owner string, p model.Permit, registration, region string) error
	// Refresh keeps the owner's session with one tenant (tenant) alive.
	Refresh(ctx context.Context, owner, tenantID string) error
	// CurrentVehicle reads the plate the tenant actually has on the permit right
	// now (used to detect drift from changes made directly in the tenant portal).
	CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error)
	// Reconnect re-establishes an expired session from the user's opt-in saved
	// password. Returns parking.ErrNoSavedPassword when none was saved.
	Reconnect(ctx context.Context, owner, tenantID string) error
	// ListPermitsComplete reads the owner's tenant permits (to refresh expiry/status)
	// and reports whether the list was the WHOLE account. Drift must not check an owner
	// off for another interval on the strength of one page, so the bool is not optional
	// here — the plain ListPermits the display paths use is not on this interface.
	ListPermitsComplete(ctx context.Context, owner, tenantID string) ([]parking.PermitInfo, bool, error)
	// Blocked reports whether the named tenant's fleet circuit breaker is open — a
	// CONFIRMED edge block at that portal affecting every account there, not one
	// owner's cooldown. Used to escalate the user-facing block warning (sooner,
	// firmer) once we know a due change genuinely will not apply until the block
	// clears. Per tenant, because a breaker opens on ONE portal's push-back: the
	// households of a portal that is answering fine must not be told to act.
	Blocked(tenantID string) bool
	// AuthGated is the auth-surface companion to Blocked: the named tenant's
	// sign-in is confirmed down (the auth circuit is open), so a stuck change is
	// escalated the same way a fleet block is — it will not apply until it clears.
	AuthGated(tenantID string) bool
	// Capabilities is what the named tenant's provider declares it supports —
	// whether its sessions need keeping warm and how long they may idle. A tenant
	// this process does not serve reports the zero value (nothing supported).
	Capabilities(ctx context.Context, owner, tenantID string) provider.Capabilities
	// LoginBudget is the worst-case time the tenant's request governor may hold a
	// full credential login waiting for rate tokens (0 when ungoverned), so the
	// reconnect deadline can be sized to include it rather than expire inside it.
	LoginBudget(tenantID string) time.Duration
}

// Notifier sends user-facing notifications (the re-authorise reminder, each
// applied plate change / failure, and a re-link prompt) plus operator alerts for
// systemic failures. A nil or disabled Notifier means user notices are not sent.
type Notifier interface {
	Enabled() bool
	AdminConfigured() bool
	SendRenewalReminder(ctx context.Context, to, tenantID string, deadline time.Time, confirmURL string) error
	// NotifyApply returns how many channels accepted the message (0 = the user was
	// NOT reached; -1 = intentionally suppressed, e.g. failures-only success).
	NotifyApply(ctx context.Context, o notify.ApplyOutcome) (int, error)
	// NotifyRelinkRequired tells the user to reconnect their tenant account;
	// returns the number of channels that accepted it (0 = not reached).
	NotifyRelinkRequired(ctx context.Context, owner, tenantID string) int
	// NotifyReconnectStalled tells the household automatic reconnection has been
	// failing for a sustained stretch while their session is retained, so their
	// schedule is paused; returns the number of channels that accepted it.
	NotifyReconnectStalled(ctx context.Context, owner, tenantID string) int
	// NotifyPermitExpiry warns the account that a permit is approaching expiry;
	// returns the number of channels that accepted it (0 = not reached).
	NotifyPermitExpiry(ctx context.Context, owner, tenantID, permitLabel string, expiry time.Time) int
	// NotifyAdmin sends an operator alert to every configured admin channel.
	NotifyAdmin(ctx context.Context, subject, body string) error
	// NotifyDriverDisplaced warns the driver responsible for a displaced booking
	// (a guest or a saved vehicle's attached email — no account) that their car
	// has been taken off the permit.
	// NotifyDriverDisplaced warns a reachable third-party driver that their car came
	// off a permit mid-window: how says what happened (never who), at is when.
	NotifyDriverDisplaced(ctx context.Context, owner, to, permitLabel, oldReg, how string, at time.Time) error
	// NotifyDriverAdded reassures a car's driver (email only) that their car is
	// now ON the permit. The permit's tenant supplies the council name.
	NotifyDriverAdded(ctx context.Context, owner, tenantID, to, plate, color string) error
	// SendOnboardNudge emails a stalled signup (terms accepted, tenant never
	// connected) the once-ever recovery note. Email-only, like the renewal
	// reminder: this person configured no other channel.
	SendOnboardNudge(ctx context.Context, to string) error
	// EmailAvailable reports whether an SMTP sender is configured. The renewal
	// reminder is email-only, so Enabled() (any channel) is the wrong gate for it.
	// SendFortnightNudge is the once-ever tell-a-neighbour note, a fortnight after
	// the household's first successful tenant write.
	SendFortnightNudge(ctx context.Context, to string) error
	EmailAvailable() bool
}

// Options configures the Scheduler's session-lifecycle behaviour.
type Options struct {
	SessionMaxAge time.Duration // re-authorise bound measured from the last authenticated visit by any member (0 disables)
	WarmInterval  time.Duration // how stale a session may get before renewal (default 1h45m ≈ 0.7× the safe idle window)
	ReminderLead  time.Duration // how far before the bound to email the confirm link (0 = no reminder)
	ExpiryLead    time.Duration // how far before a permit's expiry to warn the account (0 = no reminder)
	PublicBaseURL string        // absolute base for the email confirm link
	// LocationFor returns the timezone an owner's permit days are reckoned in
	// (their tenant's); nil, or a nil result, falls back to the scheduler's loc.
	LocationFor  func(owner, tenantID string) *time.Location
	Notifier     Notifier      // nil/disabled = no emails
	OpDrain      time.Duration // modelled time one tenant operation occupies the governor at its sustained rate; used ONLY to size the rollover spread (no per-call sleep — the governor paces)
	JitterFrac   float64       // ± fraction to randomise thresholds/delays (default 0.2)
	SnapshotPath string        // where to write the daily consistent DB backup snapshot ("" disables)
	// SpreadWindow staggers SCHEDULED plate changes across a window opening at the
	// schedule boundary, so a midnight roster rollover shared by every household
	// does not become one back-to-back burst of tenant writes. 0 disables it and
	// every due change is applied on the next tick. See spreadElapsed; the price is
	// that a permit can show the previous day's plate until its slot comes up.
	SpreadWindow time.Duration
	// DriftInterval is how often the owner-grid drift/expiry read runs, on its OWN
	// per-owner cadence decoupled from keep-warm. It used to piggyback on every warm
	// (~105 min), doubling keep-warm's tenant traffic for a check that catches a
	// rare event (an external portal edit). Default 6h; 0 disables drift reads.
	DriftInterval time.Duration
	// IdleWindow is the estimated tenant idle-expiry window. When >0 it anchors the
	// warm safety clamp: a session's warm threshold is never allowed within
	// WarmSafetyMargin of it, so WarmInterval can be raised toward the window without
	// risking a lapse before the first renew attempt. 0 disables the clamp.
	IdleWindow time.Duration
	// WarmSafetyMargin is the minimum gap kept between the warm threshold and
	// IdleWindow (the recovery-tick runway to retry a failed renew). Default 1h.
	WarmSafetyMargin time.Duration
}

// Scheduler reconciles permits on an interval and keeps linked tenant sessions
// warm (silent-renewing idle cookies) up to a fixed re-authorise bound, emailing
// a confirm link as that bound approaches.
type Scheduler struct {
	store *store.Store

	// markDriftChecked indirects the drift checkpoint write. Production always uses the
	// store; a test replaces it to make the write fail, which is the only way to reach
	// the branch that decides whether a failed checkpoint may clear the backoff — and
	// getting that wrong re-reads the tenant for the same owner every single tick.
	markDriftChecked func(ctx context.Context, owner, tenantID string) error
	tenant           Tenant
	loc              *time.Location
	locFor           func(owner, tenantID string) *time.Location // per-tenant timezone (Options.LocationFor)
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
	idleWindow       time.Duration // estimated tenant idle expiry; anchors the warm safety clamp (0 disables it)
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
	// reconnectPortal is the portal's share of the reconnect deadline (defaults to
	// reconnectPortalTime; a field so a test can make the governor's share matter).
	reconnectPortal time.Duration

	// applyMu guards applying, and applying holds one entry per permit that has a
	// tenant plate-write in flight right now (the channel is closed on release, so
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

	// retryMu guards nextTry: per-permit earliest-next-tenant-attempt deadlines.
	// A persistently failing SetVehicle would otherwise issue a real tenant
	// write per permit per MINUTE forever (~1,440/day from one IP) — exactly the
	// burst profile the jitter/rate-spacing works to avoid. In-memory only: a
	// restart retries immediately, which is fine (the streak itself is persisted
	// for notification thresholds).
	retryMu sync.Mutex
	nextTry map[int64]time.Time
	// parkedFor remembers, per PARKED permit, the registration the portal refused,
	// so a later tick can tell "the same doomed write" from "a different target the
	// portal has never seen". Without it a Monday refusal of plate A held Tuesday's
	// perfectly good plate B off the permit until someone edited or re-linked.
	// Guarded by retryMu and cleared together with nextTry.
	parkedFor map[int64]string

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
	// tenant-side DEFAULT change — a shortened idle window, cookie rotation, or
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
	reconnectQ  map[sessionKey]reconnectItem

	// driftMu guards the per-owner drift backoff and the shape-failure tally. A failed
	// drift read used to leave drift_checked_at alone and so retry on EVERY warm tick
	// (~3 min) indefinitely; with a fleet-wide API-shape change that is 500 owners x 3
	// requests every 3 minutes, driving the governor toward its ceiling until the
	// tenant pushes back. Failures now back off per owner, and repeated SHAPE failures
	// across distinct owners raise one operator alert.
	driftMu      sync.Mutex
	driftRetryAt map[string]time.Time
	driftFails   map[string]int
	// warmMu guards the per-session keep-warm renewal backoff. A silent-renew that
	// fails with an unexpected transient (a council-side 5xx, say) must not be
	// re-attempted every 3-minute pass: that is a fixed-rate knock on a struggling
	// upstream. Scoped to the RENEWAL only (not the owner's API path, which still
	// works on a cached token), so a permit change can still be applied meanwhile.
	warmMu      sync.Mutex
	warmRetryAt map[sessionKey]time.Time
	// driftAsap holds owners whose next drift read should run on the next warm
	// pass rather than the 6h cadence (see RequestDriftSoon). Lazily initialised:
	// tests construct Schedulers literally.
	driftAsap  map[string]struct{}
	driftShape []churnEvent

	// reminderWarnMu guards the rate limit on the "no SMTP sender" operator warning.
	reminderWarnMu sync.Mutex
	reminderWarnAt time.Time

	// notifyInFlight claims a permit+outcome key while its delivery goroutine is
	// queued/running, so a fleet-wide event can't re-launch duplicate deliveries every
	// pass before the first has written its durable dedup key. Guarded by notifyMu.
	notifyMu       sync.Mutex
	notifyInFlight map[string]struct{}
	// notifyRetryAt holds, per permit+outcome claim, the earliest time a delivery
	// that did NOT fully succeed (nobody reached, or only some members) may be
	// attempted again. The reconcile paths that call notifyUser every tick — the
	// council-busy branch has no deferRetry, deliberately — would otherwise open an
	// SMTP connection per permit per MINUTE for as long as a household stays
	// unreachable. Guarded by notifyMu; an entry is dropped once delivery succeeds.
	notifyRetryAt map[string]time.Time
	// notifyRetry is how long that hold lasts (defaults to notifyRetryBackoff; a
	// field so tests can shrink it or, at 0, switch the hold off).
	notifyRetry time.Duration
}

// failNotifyThreshold is how many consecutive failing ticks a TRANSIENT problem
// must persist before the user is alarmed (rejections alarm on the first tick).
const failNotifyThreshold = 3

// busyNotifyThreshold is how many consecutive ticks the tenant must keep
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

// notifyRetryBackoff is how long notifyUser waits before re-attempting a delivery
// that reached nobody, or not everyone. Long enough that an unreachable household
// costs a handful of dials an hour rather than sixty; short enough that a mail
// blip still gets the fine-risk notice out within minutes.
const notifyRetryBackoff = 5 * time.Minute

// systemAlertRetry is the short window a systemic alert is suppressed for after a
// FAILED delivery, so a transient outbound failure retries soon instead of muting
// the alert for the full throttle. Must be < systemAlertThrottle.
const systemAlertRetry = 5 * time.Minute

// New builds a Scheduler. loc is the timezone rosters are expressed in.
func New(st *store.Store, tenant Tenant, loc *time.Location, opts Options) *Scheduler {
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
		tenant:           tenant,
		loc:              loc,
		locFor:           opts.LocationFor,
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
		reconnectQ:       make(map[sessionKey]reconnectItem),
		driftRetryAt:     make(map[string]time.Time),
		warmRetryAt:      make(map[sessionKey]time.Time),
		driftFails:       make(map[string]int),
		notifyInFlight:   make(map[string]struct{}),
		notifyRetryAt:    make(map[string]time.Time),
		notifyRetry:      notifyRetryBackoff,
		lastAlert:        make(map[string]time.Time),
		alertRetry:       systemAlertRetry,
		nextTry:          make(map[int64]time.Time),
		parkedFor:        make(map[int64]string),
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

// KickPermit clears ONE permit's failure backoff — including a parked refusal
// (parkRetry) — and then kicks. Use it after a user action that plausibly fixed
// that permit (a schedule edit, a re-link), so they don't wait out a stretched
// retry window they just made obsolete — without disturbing anyone else's backoff.
func (s *Scheduler) KickPermit(permitID int64) {
	if permitID > 0 {
		s.clearRetry(permitID)
	}
	s.Kick()
}

// KickOwner clears the backoffs for ALL of one owner's permits, at every tenant,
// and then kicks. Prefer KickOwnerIn where the caller knows which tenant's
// session changed: a re-link at one council says nothing about a refusal the
// other council issued, and clearing that one re-runs a write the portal has
// already said no to. Kept for callers that act on the whole account.
func (s *Scheduler) KickOwner(ctx context.Context, owner string) {
	s.kickOwnerWhere(ctx, owner, func(model.Permit) bool { return true })
}

// KickOwnerIn clears the backoffs for one owner's permits AT ONE TENANT and then
// kicks. Used after a re-link with that tenant, which plausibly fixes every
// permit the account holds there — and only there.
func (s *Scheduler) KickOwnerIn(ctx context.Context, owner, tenantID string) {
	s.kickOwnerWhere(ctx, owner, func(p model.Permit) bool { return p.TenantID == tenantID })
}

func (s *Scheduler) kickOwnerWhere(ctx context.Context, owner string, match func(model.Permit) bool) {
	if permits, err := s.store.ListPermitsFor(ctx, owner); err == nil {
		for _, p := range permits {
			if match(p) {
				s.clearRetry(p.ID)
			}
		}
	}
	s.Kick()
}

// deferRetry stretches the permit's next tenant attempt exponentially in its
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

// parkRetry takes the permit out of the retry loop altogether: no further tenant
// attempt until something clears the window — a schedule edit or re-link
// (KickPermit/KickOwner), the permit settling because its target changed, or a
// restart (the window is in memory, like every deferral).
//
// For a REJECTED change. A refusal is the portal saying "no" to this exact write,
// and it does not fix itself; retrying it on the capped backoff meant ~144 council
// requests a day per permit for as long as the household left the schedule alone,
// and a fresh "we couldn't update your permit" every morning from the dated
// failure key. Parking makes the retry cost zero and the message a one-off. It
// is the same map as the backoff so every existing clear path applies unchanged.
//
// registration is the plate the portal refused. It is what makes the parking
// specific to THAT write: the schedule moving on to a different plate is a change
// the portal has never seen, and unparkIfTargetChanged lets it through.
func (s *Scheduler) parkRetry(permitID int64, registration string) {
	s.retryMu.Lock()
	s.nextTry[permitID] = time.Now().Add(parkedRetry)
	if s.parkedFor == nil {
		s.parkedFor = map[int64]string{} // literal-constructed test schedulers
	}
	s.parkedFor[permitID] = registration
	s.retryMu.Unlock()
}

// unparkIfTargetChanged clears a parked refusal once the permit's target is no
// longer the plate the portal refused. The parking exists so the SAME doomed
// write is not repeated ~144 times a day; it was never meant to hold a different
// plate off the permit. It did: reconcilePermit checked the window before knowing
// what today's target was, so Monday's refused plate A left Tuesday's valid plate
// B unapplied until an edit, a re-link or a restart. An ordinary (non-parked)
// backoff is left alone — a transient failure says nothing about the target.
func (s *Scheduler) unparkIfTargetChanged(permitID int64, want string) {
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	parked, ok := s.parkedFor[permitID]
	if !ok || model.SamePlate(parked, want) {
		return
	}
	delete(s.nextTry, permitID)
	delete(s.parkedFor, permitID)
}

// parkedRetry is the "never, until cleared" deferral parkRetry writes. A year: far
// past any process lifetime, so it reads as parked, while still a real time so
// retryDeferred needs no special case.
const parkedRetry = 365 * 24 * time.Hour

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
	delete(s.parkedFor, permitID)
	s.retryMu.Unlock()
}

// AcquireApply claims the exclusive right to change ONE permit's plate at the
// tenant, and returns the function that releases it. ok is false only when ctx
// is cancelled while waiting, in which case the caller must not apply.
//
// A tenant write and the active_registration write that records it are one
// decision, and two of them interleaving loses: the guest handler and the
// reconcile loop both call SetVehicle, so the tenant could end up holding the
// roster plate while the database recorded the guest's. Every later tick then
// compares its target against that (wrong) belief, concludes there is nothing to
// do, and leaves a car uncovered until checkDrift re-reads the portal — up to the
// ~105-minute keep-warm interval later, which for the driver is a fine.
//
// The claim is PER PERMIT, and deliberately no wider. Reconcile calls the tenant
// once per permit inside its own claim; a global lock would serialise the whole
// pass behind whichever household happens to be mid-activation, and the governor
// already paces the tenant calls. Nothing takes this lock while holding a
// database transaction (both callers claim it, then talk to the tenant, then
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
// every permit, drained at the governor's rate and each waiting on a tenant round
// trip, which is legitimately many minutes of work and used to false-alarm as a stall.
// What cannot happen legitimately is minutes of NOTHING between two permits, since
// the tenant client bounds its own calls. Kept a comfortable multiple of the tick
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

// locOf is the timezone an owner's permit days are reckoned in: their tenant's
// when known, else the scheduler's default.
func (s *Scheduler) locOf(owner, tenantID string) *time.Location {
	if s.locFor != nil {
		if loc := s.locFor(owner, tenantID); loc != nil {
			return loc
		}
	}
	return s.loc
}
