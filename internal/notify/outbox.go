package notify

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// ---- durable notification outbox ----
//
// Enqueue composes and addresses a message, then a single worker (RunOutbox)
// delivers it with retry/backoff, so a send survives a restart and a failed
// attempt is retried instead of silently dropped.

const (
	outboxMaxAttempts = 8
	outboxTick        = 15 * time.Second
	outboxBatch       = 50
)

// outMessage is a composed, addressed notification ready to enqueue.
type outMessage struct {
	Account      string // owner the message concerns (so account deletion purges it)
	DedupKey     string
	Recipients   []string
	NtfyTopic    string
	NtfyPriority string
	NtfyTag      string
	Subject      string
	Body         string
	NotBefore    time.Time // earliest delivery (quiet-hours defer); zero = immediate
	Reason       string    // "why you got this", for the mail footer
	// Critical marks safety-tier mail (see sendEmailCritical): deliver() lets it
	// past a self-service unsubscribe, exactly as the inline path would have.
	Critical bool
	// HeroPlate/HeroColor render a centred plate chip in the HTML mail (driver-on
	// notice); they ride the row because the outbox delivers after enqueue.
	HeroPlate string
	HeroColor string
}

func (s *Service) enqueue(ctx context.Context, m outMessage) error {
	it := store.OutboxItem{
		Account: m.Account, DedupKey: m.DedupKey, Reason: m.Reason, Recipients: m.Recipients, NtfyTopic: m.NtfyTopic,
		NtfyPriority: m.NtfyPriority, NtfyTag: m.NtfyTag, Subject: m.Subject, Body: m.Body,
		NotBefore: m.NotBefore, Critical: m.Critical, HeroPlate: m.HeroPlate, HeroColor: m.HeroColor,
	}
	if s.enqueueHook != nil {
		s.enqueueHook(it)
	}
	return s.store.EnqueueOutbox(ctx, it)
}

// enqueueSplit stores one outbox row per recipient per channel. A combined row
// has two failure modes the outbox cannot express: deliver() treats one accepted
// email as row success (silently dropping the other recipients forever), and a
// retry of a failed channel re-sends the channel that already succeeded
// (duplicate ntfy pushes on every attempt). One target per row makes success,
// retry, and dead-lettering exact. Dedup keys are suffixed per target so
// deduplication stays per-recipient.
func (s *Service) enqueueSplit(ctx context.Context, m outMessage) error {
	var errs []string
	for _, r := range m.Recipients {
		row := m
		row.Recipients = []string{r}
		row.NtfyTopic = ""
		if row.DedupKey != "" {
			row.DedupKey += "|email|" + r
		}
		if err := s.enqueue(ctx, row); err != nil {
			errs = append(errs, "queue email "+RedactEmail(r)+": "+errText(err, r))
		}
	}
	if m.NtfyTopic != "" {
		row := m
		row.Recipients = nil
		if row.DedupKey != "" {
			row.DedupKey += "|ntfy"
		}
		if err := s.enqueue(ctx, row); err != nil {
			errs = append(errs, "queue ntfy: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// RunOutbox drains the outbox until ctx is cancelled, retrying failed sends with
// backoff and dead-lettering (with an operator alert) after too many tries. It
// also periodically purges delivered rows. Start it once from main.
func (s *Service) RunOutbox(ctx context.Context) {
	t := time.NewTicker(outboxTick)
	defer t.Stop()
	purge := time.NewTicker(6 * time.Hour)
	defer purge.Stop()
	s.drainOutbox(ctx) // flush promptly on startup (a restart resumes pending sends)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.drainOutbox(ctx)
		case <-purge.C:
			// 24h, not 7 days: a sent or dead row is stripped of its content when it
			// settles and is only needed for the 15-minute dedup window (its key is
			// hashed at enqueue), so a day is generous.
			if _, err := s.store.PurgeSentOutbox(ctx, time.Now().Add(-24*time.Hour)); err != nil {
				log.Printf("notify: purge outbox: %v", err)
			}
		}
	}
}

// outboxUpdate is the bookkeeping the drain owes the store for a row it has
// already acted on: delivered, retired, or waiting on a backoff. It is carried as
// data rather than written inline so a write the store REFUSES can be retried on
// a later pass instead of being lost — see the unrecorded map.
//
// It deliberately holds no message content: `who` is already redacted, so parking
// a row does not keep a copy of the recipient or subject in memory.
type outboxUpdate struct {
	status   string // "sent", "dead", or "retry"
	attempts int
	next     time.Time
	lastErr  string
	who      string // redacted recipient/topic, for the dead-letter announcement
	why      string // why it was retired, for the same
}

// maxUnrecorded bounds the parked set. In practice it never exceeds one: the
// first refused write stops the rest of the pass, so nothing new is sent (and
// therefore nothing new is parked) until that one write succeeds. The cap is
// there so a pathological intermittent failure cannot grow the map without
// bound.
const maxUnrecorded = 256

func (s *Service) drainOutbox(ctx context.Context) {
	if s.unrecorded == nil {
		s.unrecorded = map[int64]outboxUpdate{}
	}
	// Settle what we already owe BEFORE sending anything new. These rows have been
	// delivered (or retired) and are still 'pending' with next_attempt in the past
	// only because the store refused the write, so DueOutbox would hand them back
	// and we would send the very same email again.
	if !s.flushUnrecorded(ctx) {
		// Still refusing writes. Send nothing at all this pass: a delayed
		// notification is recoverable, but a send loop against a live mailbox —
		// 50 rows every 15 seconds for as long as the disk stays full — is the
		// reputation event the whole suppression list exists to prevent.
		return
	}
	due, err := s.store.DueOutbox(ctx, time.Now(), outboxBatch)
	if err != nil {
		log.Printf("notify: read outbox: %v", err)
		return
	}
	for _, it := range due {
		if ctx.Err() != nil {
			return
		}
		if _, parked := s.unrecorded[it.ID]; parked {
			continue // already delivered; we just cannot say so yet
		}
		lastErr, permanent := s.deliver(ctx, it)
		upd := outboxUpdate{status: "sent", who: outboxTarget(it)}
		switch attempts := it.Attempts + 1; {
		case lastErr == "":
		case permanent || attempts >= outboxMaxAttempts:
			upd.status, upd.attempts, upd.lastErr = "dead", attempts, lastErr
			upd.why = fmt.Sprintf("after %d attempts", attempts)
			if permanent {
				upd.why = "permanently refused"
			}
		default:
			upd.status, upd.attempts, upd.lastErr = "retry", attempts, lastErr
			upd.next = time.Now().Add(outboxBackoff(attempts))
		}
		if !s.record(ctx, it.ID, upd) {
			return // the store is not accepting writes; stop sending (see flushUnrecorded)
		}
	}
}

// outboxTarget names a row's destination in redacted form, for logs and operator
// alerts. An ntfy topic is a shared secret (it is the only access control on the
// push server), so it is never written out either.
func outboxTarget(it store.OutboxItem) string {
	if len(it.Recipients) > 0 {
		return redactEmails(it.Recipients)
	}
	if it.NtfyTopic != "" {
		return "a push topic"
	}
	return "(none)"
}

// record applies one row's bookkeeping. On success the row leaves the parked set;
// on failure it enters it, and the caller must stop draining. Reports whether the
// store accepted the write.
func (s *Service) record(ctx context.Context, id int64, u outboxUpdate) bool {
	// DETACHED. mailer.Send* takes no context, so a send is uncancellable — but this
	// bookkeeping was threaded the signal context. On SIGTERM mid-send the mail goes
	// out, this write fails instantly with context.Canceled, the row stays 'pending'
	// with next_attempt in the past, and the startup drain re-sends it. The whole
	// unrecorded/flushUnrecorded machinery exists to prevent exactly that duplicate and
	// was defeated by the one failure mode guaranteed to end the process.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var err error
	switch u.status {
	case "sent":
		err = s.store.MarkOutboxSent(ctx, id)
	case "dead":
		err = s.store.MarkOutboxDead(ctx, id, u.lastErr)
	default:
		err = s.store.RescheduleOutbox(ctx, id, u.attempts, u.next, u.lastErr)
	}
	if err != nil {
		s.park(ctx, id, u, err)
		return false
	}
	delete(s.unrecorded, id)
	if u.status == "dead" {
		s.announceDead(ctx, id, u)
	}
	return true
}

// park remembers bookkeeping the store refused, so a later pass can complete it
// instead of re-delivering the row. This is the failure the drain used to discard
// silently: a read-only remount or a full disk left the row 'pending' with
// next_attempt in the past, and the same email went out every 15 seconds with
// nothing anywhere saying so.
func (s *Service) park(ctx context.Context, id int64, u outboxUpdate, err error) {
	log.Printf("notify: outbox row %d was %s but the store refused the bookkeeping write (%v) — "+
		"parking it and sending nothing further until that write lands", id, u.status, err)
	if len(s.unrecorded) < maxUnrecorded {
		s.unrecorded[id] = u
	}
	// Escalate too: an unwritable store does not fix itself (a full disk, a
	// read-only remount), and every notification is now stalled behind it. Hourly,
	// because the drain retries every 15 seconds and NotifyAdmin sends real mail.
	if now := time.Now(); now.Sub(s.lastWriteAlert) > time.Hour {
		s.lastWriteAlert = now
		if ae := s.NotifyAdmin(ctx, "Notification outbox cannot be written",
			fmt.Sprintf("A notification was delivered but the database would not record it (%v).\n"+
				"Outbox row: %d\n\nNotifications are PAUSED until the write succeeds, so that the "+
				"delivered message is not sent again on every retry. Check disk space and that the "+
				"database volume is writable.", err, id)); ae != nil {
			log.Printf("notify: outbox-write admin alert also failed: %v", ae)
		}
	}
}

// flushUnrecorded retries the bookkeeping owed for rows already acted on.
// Reports whether the store is accepting writes (true when there was nothing to
// do).
func (s *Service) flushUnrecorded(ctx context.Context) bool {
	for id, u := range s.unrecorded {
		if ctx.Err() != nil {
			return false
		}
		if !s.record(ctx, id, u) {
			return false
		}
		log.Printf("notify: outbox row %d bookkeeping recorded on retry (%s)", id, u.status)
	}
	return true
}

// announceDead surfaces a dropped notification. The DB 'dead' row is otherwise
// unsurfaced, and the escalation itself may share the very channel that failed,
// so a failure to escalate is logged as well.
//
// The row id, not the message: the subject carries the permit label (typically a
// street address) and a plate. The dead row keeps only its account, hashed dedup
// key and (redacted) last error for a day, so an operator can correlate it with
// the account but the message itself is gone.
func (s *Service) announceDead(ctx context.Context, id int64, u outboxUpdate) {
	log.Printf("notify: DROPPED outbox row %d (%s) to %s: %s", id, u.why, u.who, u.lastErr)
	if ae := s.NotifyAdmin(ctx, "Notification undeliverable (gave up)",
		fmt.Sprintf("A notification could not be delivered (%s) and was dropped.\nOutbox row: %d\nTo: %s\nLast error: %s",
			u.why, id, u.who, u.lastErr)); ae != nil {
		log.Printf("notify: dead-letter admin alert also failed: %v", ae)
	}
}

// deliver attempts every channel and returns "" if at least one accepted (or there
// was nothing addressable), else a joined error so the item is retried. permanent
// reports that every failure was a hard refusal (a 5xx), so retrying is futile
// and the caller should dead-letter immediately instead of burning eight attempts
// against an address the server has already rejected.
func (s *Service) deliver(ctx context.Context, it store.OutboxItem) (lastErr string, permanent bool) {
	var errs []string
	allPermanent := true
	// Email is the reliable channel. When the message HAS email recipients, success
	// requires at least one email to be accepted — an ntfy 200 (which the server
	// returns even with no subscriber) must not mask a total email failure and
	// silently drop the account's email. When there is no email, ntfy gates.
	emailTargets, emailOK := 0, false
	if s.mail.Enabled() {
		for _, addr := range it.Recipients {
			// A suppressed address is not a target at all: it must not count toward
			// emailTargets, or a row addressed ONLY to a dead address would retry
			// eight times and then dead-letter, which is exactly the reputation
			// damage the suppression list exists to prevent.
			// The row's tier decides whether an unsubscribe blocks it, the same
			// way the inline sender chose between sendEmail and sendEmailCritical.
			e := s.sendEmailWith(ctx, addr, it.Subject, it.Body, it.Reason, it.Critical, mailer.Hero{Plate: it.HeroPlate, Color: it.HeroColor})
			if errors.Is(e, ErrSuppressed) {
				log.Printf("notify: skipping suppressed recipient %s (outbox row %d)", RedactEmail(addr), it.ID)
				continue
			}
			emailTargets++
			if e != nil {
				// Redacted, including inside the server's own words (a rejection
				// echoes the address): this string is stored in last_error and
				// repeated in the dead-letter log and operator alert, so the full
				// address would end up in three places that all outlive the
				// notification.
				errs = append(errs, "email "+RedactEmail(addr)+": "+errText(e, addr))
				if !errors.Is(e, mailer.ErrPermanent) {
					allPermanent = false
				}
			} else {
				emailOK = true
			}
		}
	}
	// A row addressing BOTH channels cannot express partial success: the outbox
	// keeps one status per row, so an email failure sends the whole row round the
	// retry loop and re-pushes an ntfy message that already worked — up to eight
	// duplicate pushes for one event. enqueueSplit gives every target its own row
	// precisely so this shape never exists, but the invariant belongs HERE, in the
	// only code that would do the duplicating: push at most once, on the first
	// attempt, and let email decide the row's fate as usual.
	mixed := len(it.Recipients) > 0 && it.NtfyTopic != ""
	if mixed && it.Attempts == 0 {
		log.Printf("notify: outbox row %d addresses email and push in one row; "+
			"pushing once only, since a retry cannot un-push it (enqueueSplit should have split it)", it.ID)
	}
	ntfyTargets, ntfyOK := 0, false
	if it.NtfyTopic != "" && s.ntfyBase != "" && !(mixed && it.Attempts > 0) {
		ntfyTargets++
		pr := it.NtfyPriority
		if pr == "" {
			pr = "default"
		}
		if e := s.sendNtfy(ctx, it.NtfyTopic, it.Subject, it.Body, pr, it.NtfyTag); e != nil {
			errs = append(errs, "ntfy: "+e.Error())
			allPermanent = false // an ntfy failure is always worth retrying
		} else {
			ntfyOK = true
		}
	}
	switch {
	case emailTargets > 0:
		if emailOK {
			return "", false // reached via the reliable channel (ntfy is a bonus on top)
		}
	case ntfyTargets > 0:
		if ntfyOK {
			return "", false // no email configured; ntfy was all we had and it worked
		}
	default:
		// Nothing addressable: every channel is off, or every recipient is
		// suppressed. Nothing to retry.
		return "", false
	}
	return strings.Join(errs, "; "), allPermanent && len(errs) > 0
}

// outboxBackoff spaces retries: ~1m, 3m, 9m, 27m, ... capped at 3h.
func outboxBackoff(attempts int) time.Duration {
	d := time.Minute
	for i := 1; i < attempts; i++ {
		d *= 3
		if d > 3*time.Hour {
			return 3 * time.Hour
		}
	}
	return d
}
