package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

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
	// Referral invites name the inviter and a third party who never signed up;
	// same 90-day window as the other logs (store.ReferralInviteRetention).
	if _, err := s.store.PruneReferralInvites(ctx, time.Now().Add(-store.ReferralInviteRetention)); err != nil {
		log.Printf("scheduler: prune referral invites: %v", err)
	}
	s.sweepOnboardNudges(ctx)
	s.sweepFortnightNudges(ctx)
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
// tenant never connected) the once-ever recovery note, on the housekeeping
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

// fortnightNudgeAfter is how long after a household's first successful tenant
// write the tell-a-neighbour note goes out.
const fortnightNudgeAfter = 14 * 24 * time.Hour

// sweepFortnightNudges sends the once-ever note to each household whose first
// success is old enough. Same send-then-mark discipline as the onboarding nudge.
func (s *Scheduler) sweepFortnightNudges(ctx context.Context) {
	if s.notifier == nil || !s.notifier.EmailAvailable() {
		return
	}
	owners, err := s.store.FortnightNudgeCandidates(ctx, time.Now().Add(-fortnightNudgeAfter))
	if err != nil {
		log.Printf("scheduler: fortnight nudge candidates: %v", err)
		return
	}
	for _, owner := range owners {
		err := s.notifier.SendFortnightNudge(ctx, owner)
		if err != nil && !errors.Is(err, notify.ErrSuppressed) {
			log.Printf("scheduler: fortnight nudge to %s: %v (will retry next sweep)", redact.Email(owner), err)
			continue
		}
		if merr := s.store.MarkFortnightNudgeSent(ctx, owner); merr != nil {
			log.Printf("scheduler: fortnight nudge to %s sent but not recorded: %v", redact.Email(owner), merr)
			continue
		}
		if err != nil {
			log.Printf("scheduler: fortnight nudge to %s skipped (suppressed address); marked done", redact.Email(owner))
		} else {
			log.Printf("scheduler: fortnight nudge emailed to %s", redact.Email(owner))
		}
	}
}
