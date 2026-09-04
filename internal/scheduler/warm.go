package scheduler

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// warmRetryInterval is how long a session's silent-renew waits after an unexpected
// transient before it is re-attempted. It is DERIVED FROM THE RECOVERY RUNWAY, not a
// free choice: when an idle window is known (the production config sets
// COUNCIL_IDLE_WINDOW; a provider may also declare one), warmThresholdFor clamps the
// warm threshold to idleWindow-warmSafetyMargin, so a stale session lapses at most
// warmSafetyMargin after that threshold. A quarter of that margin fits ~4 attempts
// inside the guaranteed runway — never letting the backoff push the next try past the lapse
// boundary and force the very reconnect keep-warm exists to avoid — while still
// collapsing the 3-minute fast-tick to a much gentler rate during an outage.
// Clamped so it is neither trivially short nor unsafely long. A fixed interval, not
// an escalating ladder: the runway is the hard ceiling, so there is no headroom to
// escalate into.
func (s *Scheduler) warmRetryInterval() time.Duration {
	d := s.warmSafetyMargin / 4
	if d < 5*time.Minute {
		d = 5 * time.Minute
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	// The floor/clamp must never exceed the runway itself under a pathologically
	// small safety margin (config only requires margin < idle window): keep the
	// interval strictly inside the margin so an attempt still fits before a lapse.
	if s.warmSafetyMargin > 0 && d >= s.warmSafetyMargin {
		d = s.warmSafetyMargin / 2
	}
	return d
}

// noteWarmFailure backs a session's silent-renew off after an unexpected transient
// (e.g. a council-side 5xx), so a fixed 3-minute pass does not keep knocking on a
// failing upstream. Cleared by noteWarmSuccess on the next good renew.
func (s *Scheduler) noteWarmFailure(owner, tenant string) {
	k := sessionKey{owner, tenant}
	s.warmMu.Lock()
	if s.warmRetryAt == nil { // lazily created: some tests construct a Scheduler literally
		s.warmRetryAt = make(map[sessionKey]time.Time)
	}
	s.warmRetryAt[k] = s.now().Add(s.warmRetryInterval())
	s.warmMu.Unlock()
}

func (s *Scheduler) noteWarmSuccess(owner, tenant string) {
	s.clearWarmBackoff(func(k sessionKey) bool { return k == sessionKey{owner, tenant} })
}

// clearWarmBackoff drops warm-backoff entries matching the predicate, so unlink,
// retire and re-link leave no per-session bookkeeping behind (the leak the reconnect
// cleanup exists to prevent).
func (s *Scheduler) clearWarmBackoff(match func(sessionKey) bool) {
	s.warmMu.Lock()
	for k := range s.warmRetryAt {
		if match(k) {
			delete(s.warmRetryAt, k)
		}
	}
	s.warmMu.Unlock()
}

// warmBackedOff reports whether a session's renewal is inside its failure backoff,
// so the pass skips re-attempting it (leaving the API path, which uses a cached
// token, untouched).
func (s *Scheduler) warmBackedOff(owner, tenant string, now time.Time) bool {
	k := sessionKey{owner, tenant}
	s.warmMu.Lock()
	defer s.warmMu.Unlock()
	at, ok := s.warmRetryAt[k]
	return ok && now.Before(at)
}

// warmLoop runs the keep-warm pass on its own cadence, often enough to catch a
// session crossing the (jittered) warm threshold, but far cheaper than the
// per-minute reconcile.
func (s *Scheduler) warmLoop(ctx context.Context) {
	// Recovery cadence. A renewal itself still fires only when a session passes its
	// (per-session, stably-jittered) warmInterval, and a success slides the clock —
	// so healthy sessions cost no extra tenant calls no matter how fast we tick.
	// Ticking fast only shortens how long a FAILED renew waits before its next
	// attempt. That is what lets warmInterval sit at ~0.7× the safe idle window
	// instead of ~0.5× without exposing the narrower margin to a single missed pass.
	//
	// Fast ticks are NOT free for a session that stays past its threshold, so the
	// two ways that happens are each bounded elsewhere: a portal pushing back is
	// short-circuited by the client's own cooldown/breaker before any network call,
	// and a session whose cookie is DEAD is probed once, handed to the reconnect
	// queue, and then skipped by warmOne while it sits there — otherwise every tick
	// would send a real Refresh to earn the same 401 for as long as the reconnect
	// stayed in backoff.
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

// safeKeepWarm runs one keep-warm pass, recovering from a panic so the keep-warm
// goroutine can't die and silently let every session lapse.
func (s *Scheduler) safeKeepWarm(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			alog.Errorf("keep-warm panicked (recovered): %v", r)
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

// decideWarm is the pure keep-warm policy: retire a session once the account has
// been IDLE for maxAge, otherwise renew it when the cookie has gone staler than
// warmInterval. maxAge <= 0 disables the bound.
//
// The bound is measured against lastActive — the last authenticated visit by any
// member of the account, plus a click on the "are you still there?" email —
// because its purpose is to stop holding a tenant session for a household that
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

// keepWarm silent-renews idle-but-valid sessions so their tenant cookie does not
// lapse, retires sessions that have reached the re-authorise bound, and emails a
// confirm link as that bound approaches. It also runs the owner-grid drift/expiry
// read on its OWN per-owner cadence (driftDue) — decoupled from warming, which used
// to trigger a grid read on every renew and so doubled keep-warm's tenant traffic.
// To be light on the tenant it jitters each session's thresholds (touches don't
// align or look mechanical), skips owners with no permit to act on (their
// session is left to lapse), and spaces the tenant calls within a pass.
func (s *Scheduler) keepWarm(ctx context.Context) {
	sessions, err := s.store.ListTenantSessions(ctx)
	if err != nil {
		alog.Infof("list council sessions: %v", err)
		return
	}
	for _, cs := range sessions {
		// The governor paces the actual tenant requests this pass makes (warm and
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
func (s *Scheduler) warmOne(ctx context.Context, cs store.TenantSession) {
	defer func() {
		if r := recover(); r != nil {
			alog.Errorf("keep-warm for %s panicked (recovered); skipping it: %v", redact.Email(cs.Owner), r)
			s.systemAlert(ctx, "panic-keepwarm-session", "A session panicked during keep-warm",
				fmt.Sprintf("Keep-warm for %s panicked and was skipped so the rest of the pass could continue: %v", cs.Owner, r))
		}
	}()
	if cs.Cookie == "" {
		return
	}
	now := s.now()
	// What THIS session's portal needs: whether an idle session lapses at all, and
	// how long it may idle. The global options are the operator's estimate for the
	// single-tenant deployment; the provider's declaration is per portal.
	caps := s.tenant.Capabilities(ctx, cs.Owner, cs.TenantID)
	action := decideWarm(now, cs.LastActive, cs.LinkedAt, cs.UpdatedAt, s.sessionMaxAge, s.warmThresholdFor(cs.Owner, cs.UpdatedAt, s.idleWindowFor(caps)))
	if action == warmRetire {
		// Nobody on this account has used the app for the whole bound: stop
		// renewing, drop the session, and let the dashboard prompt a re-link.
		// Re-check the idle clock inside the delete: an unconditional delete retired
		// people who came back mid-pass, seconds after they used the app. A no-op also
		// means someone else (the reconnect worker's recoverOrRetire) got there first,
		// so the alert is theirs to send, not ours to duplicate.
		retired, err := s.store.DeleteTenantSessionIfIdle(ctx, cs.Owner, cs.TenantID, now.Add(-s.sessionMaxAge))
		switch {
		case err != nil:
			alog.Infof("retire session %s: %v", redact.Email(cs.Owner), err)
		case retired:
			s.noteWarmSuccess(cs.Owner, cs.TenantID) // session gone; drop any warm backoff so it can't leak
			alog.Infof("session for %s idle past the re-link limit; unlinked (re-link required)", redact.Email(cs.Owner))
			// The renewal reminder (maybeRemind) is email-only and best-effort, so
			// it must not be the sole signal: tell the user their permit just
			// stopped being managed, exactly as the expired-cookie path does.
			s.alertRelink(cs.Owner, cs.TenantID)
		default:
			alog.Infof("skipped retiring %s: the account was used again, or was already unlinked", redact.Email(cs.Owner))
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
	if has, err := s.ownerHasPermitIn(ctx, cs.Owner, cs.TenantID); err != nil || !has {
		if err == nil && !has {
			// No permit to act on: this session is left to lapse, so a renewal
			// backoff it happens to carry is moot — drop it rather than leak the
			// entry (this path never reaches the clear below or cancelReconnectWhere).
			s.noteWarmSuccess(cs.Owner, cs.TenantID)
		}
		return
	}

	// Warm the session if it has crossed its (jittered) threshold. warmSkip means
	// it is still comfortably within its warm window — already alive.
	alive := action == warmSkip
	if action == warmRenew && !caps.NeedsKeepWarm {
		// The provider's sessions do not lapse when idle (durable refresh tokens),
		// so there is nothing to slide: no Refresh, no traffic. The session counts
		// as alive for the drift read below — it IS alive, and drift is the only
		// reason this pass still visits it. (The warm clock never advances for such
		// a session, so the branch is taken every pass; that is the cheap outcome.)
		alive = true
		s.noteWarmSuccess(cs.Owner, cs.TenantID) // durable session; drop any stale renewal backoff
	} else if action == warmRenew && s.reconnectQueued(cs.Owner, cs.TenantID) {
		// Already known dead and queued for recovery. Nothing marks a session
		// known-dead in the store, so without this every recovery tick issued a real
		// Refresh — a 401 each time — while the reconnect item waited out its
		// backoff. The queue answers instead: the worker re-warms via a kick when it
		// recovers, or the item leaves the queue and the next pass probes afresh.
		// alive stays false; there is no session to serve a drift read.
	} else if action == warmRenew && s.warmBackedOff(cs.Owner, cs.TenantID, now) {
		// A recent renew failed with an unexpected transient (e.g. a council-side
		// 5xx); wait out the backoff interval rather than re-hit a failing upstream
		// every pass. alive stays false — but the owner's API path is NOT gated by
		// this, so a due write can still be applied on a cached token. alive=false
		// also skips the drift read below, which is deliberate: a drift read whose
		// cached token has expired would itself trigger the very silent-renew we are
		// backing off, and while the council's auth is down external permit changes
		// aren't happening anyway, so the freshness cost is nil. A pass past the
		// deadline probes afresh, and a good renew clears the backoff.
	} else if action == warmRenew {
		switch err := s.tenant.Refresh(ctx, cs.Owner, cs.TenantID); {
		case err == nil:
			alive = true
			s.noteWarmSuccess(cs.Owner, cs.TenantID)
			alog.Infof("kept session for %s warm", redact.Email(cs.Owner))
		case errors.Is(err, parking.ErrSessionExpired):
			// Hand recovery to the reconnect worker and move on — never reconnect inline
			// in the warm pass. alive stays false; the worker re-warms via a kick on a
			// successful reconnect. Bind to the generation the failure carries, falling
			// back to this pass's snapshot (older, therefore safe) if it is untagged.
			gen := cs.Generation
			if g, ok := parking.SessionGenOf(err); ok {
				gen = g
			}
			s.enqueueReconnect(ctx, cs.Owner, cs.TenantID, gen)
		case errors.Is(err, parking.ErrNotLinked):
			// Raced with an unlink; nothing to do.
		case errors.Is(err, parking.ErrCouncilBusy):
			// Portal pushing back; the client is already backing off. Stay quiet.
		default:
			// An unexpected transient (a council-side 5xx, a malformed response, a
			// network blip). Back this session's renewal off (a runway-bounded fixed
			// interval) so a sustained upstream failure is not re-attempted every pass
			// — a good citizen during the other side's outage, and it self-clears on
			// recovery.
			s.noteWarmFailure(cs.Owner, cs.TenantID)
			alog.Infof("keep-warm %s: %v (backing off)", redact.Email(cs.Owner), err)
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
	if alive && !s.tenant.Blocked(cs.TenantID) && s.driftDue(cs, now) {
		if derr := s.checkDrift(ctx, cs.Owner, cs.TenantID); derr != nil {
			// drift_checked_at is deliberately NOT advanced (the check did not happen),
			// but the owner is backed off so a persistent failure cannot retry on every
			// warm tick across the whole fleet.
			if errors.Is(derr, parking.ErrPermitListPartial) {
				// Truncation is a standing condition, not a blip, so enter at the normal
				// drift cadence instead of the failure ladder. The ladder's 15m/60m/240m
				// ramp costs three EXTRA reads per owner before it settles — 4,500 extra
				// tenant requests at 500 owners, on the very day the tenant changed its
				// paging, and again after every restart because the ladder lives in memory
				// while last_drift_check stays permanently stale.
				s.noteDriftDeferred(cs.Owner)
			} else {
				s.noteDriftFailure(ctx, cs.Owner, derr)
			}
			alog.Infof("drift check %s: %v", redact.Email(cs.Owner), derr)
			// A drift read is often how we learn the cookie was killed tenant-side just
			// AFTER a successful warm — the churn incident's signature. Without this the
			// expiry was only logged: updated_at is fresh so keep-warm won't re-probe for
			// a whole warm interval, leaving a dead session unqueued for hours.
			if g, ok := parking.SessionGenOf(derr); ok {
				s.enqueueReconnect(ctx, cs.Owner, cs.TenantID, g)
			}
		} else {
			// Clear the backoff only once the checkpoint is DURABLE. last_drift_check is
			// what stops this owner being picked again next tick; if the write fails and
			// we have already cleared the backoff, the owner stays due forever and we
			// re-read the tenant every cycle — three requests an owner, against an edge
			// we may be failing precisely because it is throttling us. Treating the failed
			// write as a drift failure keeps the backoff on and lets it widen.
			if err := s.markDriftChecked(ctx, cs.Owner, cs.TenantID); err != nil {
				alog.Infof("mark drift-checked %s: %v (holding the backoff so this owner is not re-read every tick)", redact.Email(cs.Owner), err)
				s.noteDriftFailure(ctx, cs.Owner, fmt.Errorf("drift checkpoint not saved: %w", err))
			} else {
				s.noteDriftSuccess(cs.Owner)  // clear any backoff from earlier failures
				s.clearDriftRequest(cs.Owner) // any RequestDriftSoon intent is now satisfied
			}
		}
	}
}

// warnNoReminderChannel logs the missing-SMTP warning at most hourly: this is on a
// per-owner path that runs every warm tick, so an unguarded log would be the only
// thing in the journal at fleet scale.
func (s *Scheduler) warnNoReminderChannel() {
	s.reminderWarnMu.Lock()
	defer s.reminderWarnMu.Unlock()
	now := s.now()
	if now.Sub(s.reminderWarnAt) < time.Hour {
		return
	}
	s.reminderWarnAt = now
	alog.Warnf("renewal reminders are disabled because no SMTP sender is configured " +
		"(the reminder is email-only; ntfy does not carry it). Households will not be warned before their council link expires.")
}

// maybeRemind emails the one-click renewal-confirm link once per cycle when a
// session is within ReminderLead of its re-authorise deadline.
func (s *Scheduler) maybeRemind(ctx context.Context, cs store.TenantSession, now time.Time) {
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
		alog.Infof("reminder token for %s: %v", redact.Email(cs.Owner), err)
		return
	}
	url := s.publicBaseURL + "/tenant/confirm?token=" + token
	// RECORD THE TOKEN FIRST. Sending first meant a failed write emailed a confirm link
	// that could never work — and, because reminder_sent_at stayed empty, sent another
	// broken one every warm tick. Recording first makes the emailed link valid by
	// construction; if the send then fails we roll the mark back so it can be retried.
	if err := s.store.MarkReminderSent(ctx, cs.Owner, cs.TenantID, token); err != nil {
		alog.Infof("mark reminder for %s: %v", redact.Email(cs.Owner), err)
		return
	}
	if err := s.notifier.SendRenewalReminder(ctx, cs.Owner, cs.TenantID, deadline.In(s.locOf(cs.Owner, cs.TenantID)), url); err != nil {
		if errors.Is(err, notify.ErrSuppressed) {
			// Terminal, as sweepOnboardNudges treats it: the address bounced or
			// complained, and no retry improves that. Keeping the mark is what stops
			// this from rolling back, alerting and re-trying every recovery tick for
			// the whole lead window. The retirement path still tells the household
			// (and, when it cannot, the operator) once the bound is reached.
			alog.Infof("renewal reminder to %s skipped (suppressed address); marked done", redact.Email(cs.Owner))
			return
		}
		alog.Infof("send reminder to %s: %v", redact.Email(cs.Owner), err)
		// DETACHED context for the rollback. Using ctx here was a real defect: the most
		// likely reason the send failed is that ctx was cancelled (shutdown), and the
		// rollback would then fail for the same reason — leaving the session marked
		// reminded but never reminded, so maybeRemind's !ReminderSent.IsZero() guard
		// never fires again and the session lapses silently. That is worse than the
		// duplicate the old ordering risked.
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if cerr := s.store.ClearReminderSent(rbCtx, cs.Owner, cs.TenantID); cerr != nil {
			alog.Infof("roll back reminder mark for %s: %v", redact.Email(cs.Owner), cerr)
		}
		cancel()
		// The reminder is email-only. If it keeps failing through the window the
		// session lapses silently, so alert the operator (throttled).
		s.systemAlert(ctx, "reminder-send",
			"Renewal reminder could not be sent",
			fmt.Sprintf("Could not email the re-authorise reminder to %s: %v. If this persists their session will lapse without warning.", cs.Owner, err))
		return
	}
	alog.Infof("emailed renewal reminder to %s (deadline %s)", redact.Email(cs.Owner), deadline.In(s.locOf(cs.Owner, cs.TenantID)).Format("2006-01-02"))
}

// idleWindowFor is the idle-expiry estimate a session's warm threshold is clamped
// against: the provider's declared IdleWindow where it declares one, the global
// Options.IdleWindow where it does not, and the TIGHTER of the two where both
// exist. Neither side may loosen the other — the provider knows its portal, the
// operator may know something the connector does not (a portal change observed in
// production before the connector caught up) — and a too-wide window is the one
// mistake that lets a session lapse before its first renewal.
func (s *Scheduler) idleWindowFor(caps provider.Capabilities) time.Duration {
	declared := caps.IdleWindow
	switch {
	case declared > 0 && s.idleWindow > 0:
		return min(declared, s.idleWindow)
	case declared > 0:
		return declared
	default:
		return s.idleWindow
	}
}

// ownerHasPermitIn reports whether the owner manages a permit WITH THIS TENANT.
// A session is kept warm to act on a permit at its own portal; a household linked
// in two areas but managing a permit in only one has nothing for the other
// session to do, and store.OwnerHasPermit — account-wide — kept it warm anyway.
// Filtered here from the owner's permit list because the store offers no
// tenant-scoped existence query; the list is small (a handful of permits).
func (s *Scheduler) ownerHasPermitIn(ctx context.Context, owner, tenantID string) (bool, error) {
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return false, err
	}
	for _, p := range permits {
		if p.TenantID == tenantID {
			return true, nil
		}
	}
	return false, nil
}

// warmThresholdFor is the renew threshold for one session: the configured
// warmInterval, first clamped so it never sits within warmSafetyMargin of the
// idle window the session's portal is believed to have (idleWindowFor), then
// nudged DOWNWARD by a small per-session offset.
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
func (s *Scheduler) warmThresholdFor(owner string, updatedAt time.Time, idleWindow time.Duration) time.Duration {
	base := s.warmInterval
	if idleWindow > 0 {
		if ceil := idleWindow - s.warmSafetyMargin; ceil > 0 && base > ceil {
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
