package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

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
// session over a transient failure or a changed tenant sign-in page, which
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
// sessionKey names one session: an account's link with one tenant.
type sessionKey struct{ owner, tenant string }

type reconnectItem struct {
	next     time.Time
	queuedAt time.Time
	gen      int64
	attempts int
	// countsChurn records whether this expiry fed the churn EXPIRY counter, so its
	// eventual successful reconnect feeds the RECONNECT counter to match. Background
	// discovery counts (true); a foreground interactive return does not (false), and
	// must stay out of BOTH counters — otherwise /status would show a reconnect with
	// no matching expiry, and the two sides would disagree.
	countsChurn bool
}

// reconnectResult is what one reconnect attempt did, so the drain worker knows
// whether to dequeue (recovered or gave up) or retry later (transient).
type reconnectResult int

const (
	reconnectRecovered reconnectResult = iota // session usable now
	reconnectRetired                          // gave up; session dropped, re-link prompted
	reconnectDeferred                         // transient; keep and retry after a backoff
)

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
// healthy fleet — a rise is the canary for a tenant-side session-lifetime change.
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
func (s *Scheduler) enqueueReconnect(ctx context.Context, owner, tenantID string, gen int64) {
	if !s.queueReconnectItem(owner, tenantID, gen, true) {
		return
	}
	// Several different owners re-authing within the hour is the fingerprint of a
	// tenant-side session-lifetime/idle-window/cookie change rather than user
	// activity, and it changes no response SHAPE, so nothing else would catch it.
	// The churn picture (both this expiry count and the later reconnect count) is
	// fed ONLY from background/observed expiries — this path and the client's plate
	// refresh — NOT from a foreground interactive return (QueueReconnect), where a
	// handful of ordinary users coming back after an idle lapse is not a fleet signal.
	if distinct := s.noteSessionExpiry(owner); distinct >= sessionChurnAlertOwners {
		s.systemAlert(ctx, "session-churn",
			"Council sessions are expiring unusually often",
			fmt.Sprintf("%d different accounts have had their council session expire within the last hour. A healthy fleet almost never re-authenticates, so this points at a council-side change — a shortened session/idle window, cookie rotation, or silent-renew disabled — not user activity. If /status shows no breaker/pushback, the edge is not refusing us, which narrows it to a session-lifetime change. Investigate before it becomes a reconnect backlog.", distinct))
	}
}

// queueReconnectItem inserts the queue entry, deduplicated by (owner, tenant), and
// reports whether it was newly added. countsChurn is stamped on the item so its
// eventual reconnect feeds the churn counter only if this expiry did; the callers
// set it (background discovery true, interactive false). It does NOT itself feed the
// churn canary — enqueueReconnect does that for the counted path.
func (s *Scheduler) queueReconnectItem(owner, tenantID string, gen int64, countsChurn bool) bool {
	now := time.Now()
	key := sessionKey{owner, tenantID}
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	if it, already := s.reconnectQ[key]; already {
		// A genuine BACKGROUND expiry (countsChurn=true) arriving for an item first
		// queued INTERACTIVELY (false) upgrades it and is reported as newly countable,
		// so an interactive visit can't erase a real fleet-signal data point for that
		// owner while the item sits in backoff. Never the reverse (interactive after
		// background must not downgrade). The generation stays the one already queued.
		if countsChurn && !it.countsChurn {
			it.countsChurn = true
			s.reconnectQ[key] = it
			return true
		}
		return false
	}
	s.reconnectQ[key] = reconnectItem{next: now, queuedAt: now, gen: gen, countsChurn: countsChurn}
	return true
}

// QueueReconnect enqueues a saved-password reconnect for (owner, tenant) at gen for
// a FOREGROUND, interactive expiry (the picker's returning user), without feeding
// the session-churn canary — one person coming back is not the many-distinct-owners
// fleet signal that canary watches for. Recovery itself (dedup, generation guard,
// retire-and-notify, pacing) is identical to a background enqueue.
func (s *Scheduler) QueueReconnect(owner, tenantID string, gen int64) {
	s.queueReconnectItem(owner, tenantID, gen, false)
}

// NoteSessionExpired queues recovery for a session some OTHER component proved
// dead — the parking client's background reads, wired via OnSessionExpired in
// main. The queue's own dedup makes repeated reports (a dashboard polling every
// few seconds) free, and the generation requirement is enforced by the caller.
func (s *Scheduler) NoteSessionExpired(owner, tenantID string, gen int64) {
	s.enqueueReconnect(context.Background(), owner, tenantID, gen)
}

// reconnectActiveWindow bounds how long a queued reconnect reads as "actively in
// progress" for a caller that shows an in-progress page. One attempt is portal
// time plus the governor's hold (tens of seconds); beyond this window a still-queued
// item is stuck in backoff — or deferred indefinitely by a login-shape break — and a
// caller must stop showing a spinner and offer the manual path instead. A var so a
// test can shrink it. See the picker's use in internal/server/reconnect.go.
var reconnectActiveWindow = 90 * time.Second

// ReconnectActive reports whether a saved-password reconnect for THIS (owner,
// tenant) is queued AND still plausibly in progress (queued within
// reconnectActiveWindow). The picker consults it to show its in-progress page
// instead of spending a tenant read on a session that cannot work yet — while a
// reconnect that has aged out (stuck in backoff, or a login-shape defer) reads as
// inactive, so the picker falls back to the re-link form rather than trapping the
// user on a self-refreshing page. Tenant-scoped: a reconnect queued for one council
// must not gate a different, healthy council's picker.
func (s *Scheduler) ReconnectActive(owner, tenantID string) bool {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	it, ok := s.reconnectQ[sessionKey{owner, tenantID}]
	return ok && time.Since(it.queuedAt) < reconnectActiveWindow
}

// CancelReconnect drops any queued reconnect for owner, at EVERY tenant. Called
// after an account deletion or a whole-account disconnect, where no session
// survives. A caller acting on ONE tenant's session (a link, unlink or
// password opt-out there) uses CancelReconnectIn: the queue is keyed by
// (owner, tenant), and dropping the other council's item discards recovery
// work that is still valid. The generation check is the hard safety either way;
// these are the fast path.
func (s *Scheduler) CancelReconnect(owner string) {
	s.cancelReconnectWhere(owner, func(sessionKey) bool { return true })
}

// CancelReconnectIn drops a queued reconnect for owner's session with ONE tenant.
func (s *Scheduler) CancelReconnectIn(owner, tenantID string) {
	s.cancelReconnectWhere(owner, func(k sessionKey) bool { return k.tenant == tenantID })
}

func (s *Scheduler) cancelReconnectWhere(owner string, match func(sessionKey) bool) {
	s.reconnectMu.Lock()
	for k := range s.reconnectQ {
		if k.owner == owner && match(k) {
			delete(s.reconnectQ, k)
		}
	}
	s.reconnectMu.Unlock()
	// Drop drift bookkeeping too: without this the two maps keep an entry per
	// unlinked/retired owner until the process restarts. (Owner-keyed, so the
	// tenant-scoped cancel clears it as well; a fresh session there is a fine
	// reason to let drift look again.)
	s.noteDriftSuccess(owner)
}

// reconnectQueued reports whether a reconnect for THIS session is queued at all —
// due now or waiting out a backoff. Keep-warm uses it to skip probing a session
// the queue already knows is dead.
func (s *Scheduler) reconnectQueued(owner, tenantID string) bool {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	_, ok := s.reconnectQ[sessionKey{owner, tenantID}]
	return ok
}

// nextDueReconnect returns the queued session with the earliest next-attempt time
// (ties broken by owner then tenant for determinism), a copy of its queue item,
// and how long until it is due.
func (s *Scheduler) nextDueReconnect() (key sessionKey, item reconnectItem, wait time.Duration, ok bool) {
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	found := false
	for k, it := range s.reconnectQ {
		if !found || it.next.Before(item.next) || (it.next.Equal(item.next) && (k.owner < key.owner || (k.owner == key.owner && k.tenant < key.tenant))) {
			key, item, found = k, it, true
		}
	}
	if !found {
		return sessionKey{}, reconnectItem{}, 0, false
	}
	if now := time.Now(); item.next.After(now) {
		return key, item, item.next.Sub(now), true
	}
	return key, item, 0, true
}

// sameQueued reports whether the item now under key is the one the worker copied
// out before its attempt. A CancelReconnect (a manual link or unlink landing
// mid-attempt) followed by a fresh enqueue puts a NEW item under the same key;
// the attempt that just finished knows nothing about it, so its dequeue or
// backoff must leave it untouched. The generation alone nearly always tells them
// apart; the enqueue time covers a re-queue at the same generation.
func sameQueued(cur, attempted reconnectItem) bool {
	return cur.gen == attempted.gen && cur.queuedAt.Equal(attempted.queuedAt)
}

// dequeueReconnect removes the attempted item — and only that item — from the
// queue.
func (s *Scheduler) dequeueReconnect(key sessionKey, attempted reconnectItem) {
	s.reconnectMu.Lock()
	if cur, ok := s.reconnectQ[key]; ok && sameQueued(cur, attempted) {
		delete(s.reconnectQ, key)
	}
	s.reconnectMu.Unlock()
}

// backoffReconnect reschedules the attempted item after an exponential per-owner
// delay. Once the attempt count says recovery has stalled rather than hiccuped,
// the household is told — exactly once per queue residency — because every path
// that lands here retains the session and would otherwise retry forever with
// only the operator aware the schedule has stopped applying. An item queued
// afresh during the attempt is not this attempt's to back off.
func (s *Scheduler) backoffReconnect(key sessionKey, attempted reconnectItem) {
	s.reconnectMu.Lock()
	it, ok := s.reconnectQ[key]
	if !ok || !sameQueued(it, attempted) {
		s.reconnectMu.Unlock()
		return
	}
	it.attempts++
	backoff := reconnectBackoffMin << min(it.attempts-1, 6)
	if backoff > reconnectBackoffMax {
		backoff = reconnectBackoffMax
	}
	it.next = time.Now().Add(backoff)
	s.reconnectQ[key] = it
	attempts := it.attempts
	s.reconnectMu.Unlock()
	if attempts == reconnectStalledAlertAttempts {
		s.alertReconnectStalled(key.owner, key.tenant)
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
	key, item, wait, ok := s.nextDueReconnect()
	if !ok || wait > 0 {
		return false
	}
	owner := key.owner
	processed = true // we have an item; a panic below is still "processed" (it gets a backoff)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: reconnect worker panicked on %s (recovered): %v", redact.Email(owner), r)
			s.systemAlert(ctx, "panic-reconnect", "Reconnect worker panicked",
				fmt.Sprintf("Recovering the session for %s panicked and was recovered; it will be retried. %v", owner, r))
			s.backoffReconnect(key, item)
		}
	}()
	switch s.recoverOrRetire(ctx, owner, key.tenant, item.gen, item.countsChurn) {
	case reconnectRecovered:
		s.dequeueReconnect(key, item)
		// The session that recovered is THIS tenant's; the account's other
		// councils' backoffs are their own business.
		s.KickOwnerIn(ctx, owner, key.tenant)
	case reconnectRetired:
		s.dequeueReconnect(key, item)
	case reconnectDeferred:
		s.backoffReconnect(key, item)
	}
	return true
}

// recoverOrRetire attempts ONE saved-password reconnect for the expired session
// generation gen and reports the outcome. On success the session is usable
// (reconnectRecovered). With no saved password or a rejected one it retires the
// session — but ONLY if it is still the same generation, so a manual relink racing
// this work is never deleted (reconnectRetired; the re-link prompt is sent only when a
// row was actually removed). Anything transient (tenant busy, a network blip, a
// systemic login-shape break, or a FAILED delete) keeps the task and retries later
// (reconnectDeferred). countsChurn says whether a success should feed the churn
// reconnect counter — true only if this expiry fed the churn expiry counter, so the
// two /status sides stay balanced and a foreground interactive return counts on
// neither.
func (s *Scheduler) recoverOrRetire(ctx context.Context, owner, tenantID string, gen int64, countsChurn bool) reconnectResult {
	// Skip stale work: if the session was relinked, reconnected, renewed, or unlinked
	// since this was queued, its generation no longer matches (or it is gone) — this
	// recovery task is not ours to act on.
	switch cur, err := s.store.GetTenantSessionIn(ctx, owner, tenantID); {
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
	// so a slow portal can't wedge the drain worker. The bound is the portal's time
	// PLUS whatever the request governor may hold the login for: a flat 20s expired
	// mid-login as soon as back-to-back reconnects had drained the login bucket
	// (one token per 5s at the default 12/min, six requests a login), and a login
	// cancelled between the password POST and the token exchange is a half-completed
	// IdP authentication — the one outcome worse than a slow one.
	rctx, cancel := context.WithTimeout(ctx, s.reconnectDeadline(tenantID))
	defer cancel()
	switch rerr := s.tenant.Reconnect(rctx, owner, tenantID); {
	case rerr == nil:
		if countsChurn { // balance the churn counters: only a counted expiry's reconnect counts
			s.noteReconnect(owner)
		}
		log.Printf("scheduler: session for %s expired; auto-reconnected from saved password", redact.Email(owner))
		return reconnectRecovered
	case errors.Is(rerr, store.ErrSessionSuperseded):
		// The login succeeded at the tenant but the generation-conditioned save landed
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
	switch deleted, derr := s.store.DeleteTenantSessionIfGen(ctx, owner, tenantID, gen); {
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
		s.alertRelink(owner, tenantID) // proactively tell the user, don't wait for fine time
		return reconnectRetired
	}
}

// reconnectPortalTime is how long the portal itself gets to complete a headless
// login once the governor has admitted its requests (the pre-governor 20s bound).
const reconnectPortalTime = 20 * time.Second

// reconnectDeadline is the reconnect worker's per-attempt bound for one tenant:
// the portal's allowance plus the governor's worst-case hold on a login there.
// Tests shrink the portal allowance via reconnectPortal; 0 means the default.
func (s *Scheduler) reconnectDeadline(tenantID string) time.Duration {
	portal := s.reconnectPortal
	if portal <= 0 {
		portal = reconnectPortalTime
	}
	return portal + s.tenant.LoginBudget(tenantID)
}
