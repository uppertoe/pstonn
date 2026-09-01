package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// NotifyPref is a user's notification-channel configuration.
type NotifyPref struct {
	Owner        string
	EmailEnabled bool
	NtfyEnabled  bool
	NtfyTopic    string
	FailuresOnly bool
	QuietFrom    int // quiet-hours window start (local hour, 0-23)
	QuietUntil   int // overnight notices held to this local hour; == QuietFrom disables
	// NtfyConfirmedAt is when a push sent to NtfyTopic was tapped on a device
	// (RFC3339 UTC), i.e. proof the channel delivers and is seen — not merely that a
	// topic was typed into the app. Empty until then, and reset by a new topic. It
	// is the precondition for turning email off: without it, a household can
	// switch to push, never subscribe (or deny the OS permission), and believe it
	// is being told about changes when nothing reaches it (observed 2026-08-31).
	NtfyConfirmedAt string
}

// NtfyConfirmed reports whether the current topic has been confirmed on a device.
func (p NotifyPref) NtfyConfirmed() bool { return p.NtfyConfirmedAt != "" }

// GetNotifyPref returns the user's notification preferences, or a sensible
// default (email on, ntfy off) when they have never set them.
func (s *Store) GetNotifyPref(ctx context.Context, owner string) (NotifyPref, error) {
	p := NotifyPref{Owner: owner, EmailEnabled: true, QuietFrom: 22, QuietUntil: 6}
	var email, ntfy, failures int
	err := s.db.QueryRowContext(ctx,
		`SELECT email_enabled, ntfy_enabled, ntfy_topic, failures_only, quiet_from, quiet_until, ntfy_confirmed_at FROM notify_pref WHERE owner = ?`, owner).
		Scan(&email, &ntfy, &p.NtfyTopic, &failures, &p.QuietFrom, &p.QuietUntil, &p.NtfyConfirmedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil // defaults
	}
	if err != nil {
		return p, err
	}
	p.EmailEnabled, p.NtfyEnabled, p.FailuresOnly = email == 1, ntfy == 1, failures == 1
	return p, nil
}

// SetNotifyPref upserts a user's notification preferences.
func (s *Store) SetNotifyPref(ctx context.Context, p NotifyPref) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO notify_pref (owner, email_enabled, ntfy_enabled, ntfy_topic, failures_only, quiet_from, quiet_until, ntfy_confirmed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(owner) DO UPDATE SET
    email_enabled = excluded.email_enabled,
    ntfy_enabled  = excluded.ntfy_enabled,
    ntfy_topic    = excluded.ntfy_topic,
    failures_only = excluded.failures_only,
    quiet_from    = excluded.quiet_from,
    quiet_until   = excluded.quiet_until,
    ntfy_confirmed_at = excluded.ntfy_confirmed_at`,
		p.Owner, boolInt(p.EmailEnabled), boolInt(p.NtfyEnabled), p.NtfyTopic, boolInt(p.FailuresOnly), p.QuietFrom, p.QuietUntil, p.NtfyConfirmedAt)
	return err
}

// ConfirmNtfy records that a push to topic reached a device and was acted on. It
// stamps only the row whose CURRENT topic is topic: a confirmation minted for an
// old topic (the user pressed "New topic" after the test went out) must not
// vouch for the new one, which no device has subscribed to yet. Reports whether
// a row was stamped; an already-confirmed row is left with its first timestamp.
func (s *Store) ConfirmNtfy(ctx context.Context, owner, topic string, at time.Time) (bool, error) {
	if topic == "" {
		return false, nil
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE notify_pref SET ntfy_confirmed_at = ? WHERE owner = ? AND ntfy_topic = ? AND ntfy_confirmed_at = ''`,
		at.UTC().Format(time.RFC3339), owner, topic)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ---- Notification outbox ----

// OutboxItem is one queued notification (composed and addressed at enqueue time).
type OutboxItem struct {
	ID           int64
	Account      string // owner the message concerns (for account-deletion purge)
	DedupKey     string
	Recipients   []string // email addresses
	NtfyTopic    string
	NtfyPriority string
	NtfyTag      string
	Subject      string
	Body         string
	Attempts     int
	NotBefore    time.Time // earliest delivery; zero = send as soon as due (quiet-hours defer)
	Reason       string    // "why you got this", rendered in the mail footer
	// Critical marks safety-tier mail: the drain sends it past a self-service
	// unsubscribe (a bounce or complaint still blocks), so a message that was
	// merely HELD for quiet hours keeps the tier it would have had inline.
	Critical bool
}

// dedupKeyPrefix tags a hashed dedup key, so the migration that hashes keys
// written by older builds can tell the two apart and stay idempotent.
const dedupKeyPrefix = "h1:"

// HashDedupKey is what the outbox stores in place of the caller's key. Callers
// build keys from the recipient, the permit label (usually a street address) and
// the plate, and a delivered row keeps its key for a day after its content is
// stripped — so the key was quietly the last copy of everything the stripping
// removed. Dedup only ever compares keys for equality, which a digest preserves
// exactly; the plaintext is never needed again.
func HashDedupKey(key string) string {
	if key == "" {
		return ""
	}
	if strings.HasPrefix(key, dedupKeyPrefix) {
		return key
	}
	sum := sha256.Sum256([]byte(key))
	return dedupKeyPrefix + hex.EncodeToString(sum[:])
}

// outboxDedupWindow bounds how long a delivered (sent) row suppresses a
// re-enqueue of the same dedup_key. It absorbs genuine duplicates — a double-tap,
// a fast double-trigger, an in-flight retry — without suppressing a legitimately
// NEW occurrence of the same logical outcome later (an alternating A/B/A roster
// re-applies "A" days apart; a failure recurs after resolving). A pending row
// always dedups (the notice is still in flight); a sent row only within this
// window; a dead row never (a previously-failed notice must be retryable).
const outboxDedupWindow = 15 * time.Minute

// EnqueueOutbox durably queues a notification. If DedupKey is non-empty and an
// equivalent row is still pending, or was delivered within outboxDedupWindow, the
// enqueue is a no-op (idempotency) so a repeated trigger can't double-send.
func (s *Store) EnqueueOutbox(ctx context.Context, it OutboxItem) error {
	now := nowUTC()
	// next_attempt defaults to now, or NotBefore when the caller defers delivery
	// (quiet hours). created_at stays "now" so ordering/purge use the real time.
	nextAttempt := now
	if !it.NotBefore.IsZero() && it.NotBefore.After(time.Now()) {
		nextAttempt = it.NotBefore.UTC().Format(time.RFC3339)
	}
	// Dedup guard and insert are ONE statement: a separate check-then-insert lets
	// two concurrent triggers (web handler + scheduler both enqueueing the same
	// outcome) each pass the check and double-insert — defeating the dedup this
	// exists for.
	_, err := s.db.ExecContext(ctx, `
INSERT INTO outbox (account, dedup_key, recipients, ntfy_topic, ntfy_priority, ntfy_tag, subject, body, status, attempts, next_attempt, created_at, reason, critical)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?10, ?12, ?13
WHERE ?2 = '' OR NOT EXISTS (SELECT 1 FROM outbox
  WHERE dedup_key = ?2
    AND (status = 'pending' OR (status = 'sent' AND sent_at > ?11)))`,
		it.Account, HashDedupKey(it.DedupKey), strings.Join(it.Recipients, "\n"), it.NtfyTopic, it.NtfyPriority, it.NtfyTag,
		it.Subject, it.Body, nextAttempt, now,
		time.Now().Add(-outboxDedupWindow).UTC().Format(time.RFC3339), it.Reason, boolInt(it.Critical))
	return err
}

// DueOutbox returns pending notifications whose next attempt is due, oldest first.
// DedupKey comes back in its stored (hashed) form.
func (s *Store) DueOutbox(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, dedup_key, recipients, ntfy_topic, ntfy_priority, ntfy_tag, subject, body, attempts, reason, critical
FROM outbox WHERE status = 'pending' AND next_attempt <= ? ORDER BY id LIMIT ?`,
		now.UTC().Format(time.RFC3339), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var it OutboxItem
		var recips string
		var critical int
		if err := rows.Scan(&it.ID, &it.DedupKey, &recips, &it.NtfyTopic, &it.NtfyPriority, &it.NtfyTag,
			&it.Subject, &it.Body, &it.Attempts, &it.Reason, &critical); err != nil {
			return nil, err
		}
		if recips != "" {
			it.Recipients = strings.Split(recips, "\n")
		}
		it.Critical = critical == 1
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkOutboxSent records a delivered notification.
func (s *Store) MarkOutboxSent(ctx context.Context, id int64) error {
	// Strip the content as well as marking it sent. A delivered row is only ever
	// consulted for dedup (dedup_key + status + sent_at, a 15-minute window), so
	// keeping the composed message — plates, the permit label, guest addresses —
	// for days afterwards is pure surplus personal data. The key itself is a
	// digest (HashDedupKey), so what remains identifies nobody.
	_, err := s.db.ExecContext(ctx, `
UPDATE outbox SET status = 'sent', sent_at = ?, last_error = '',
  recipients = '', subject = '', body = '', ntfy_topic = '', reason = ''
WHERE id = ?`, nowUTC(), id)
	return err
}

// RescheduleOutbox bumps the attempt count and defers the next try (backoff).
func (s *Store) RescheduleOutbox(ctx context.Context, id int64, attempts int, next time.Time, lastErr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET attempts = ?, next_attempt = ?, last_error = ? WHERE id = ?`,
		attempts, next.UTC().Format(time.RFC3339), lastErr, id)
	return err
}

// MarkOutboxDead retires a notification that has exhausted its retries. It
// strips the row exactly as MarkOutboxSent does: a dead row is never retried
// and never dedups (see outboxDedupWindow), so its recipients and message are
// surplus from this moment. What stays is the account (for deletion), the
// hashed key and lastErr — which the caller has already redacted — so the
// operator alert's row id still leads somewhere for a day.
func (s *Store) MarkOutboxDead(ctx context.Context, id int64, lastErr string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE outbox SET status = 'dead', attempts = attempts + 1, last_error = ?,
  recipients = '', subject = '', body = '', ntfy_topic = '', reason = ''
WHERE id = ?`, lastErr, id)
	return err
}

// PurgeSentOutbox deletes delivered AND dead rows older than cutoff. Both kinds
// are already stripped to account + hashed key + last error when they settle;
// this removes even that bookkeeping once the dedup window is long past.
// Returns rows removed.
func (s *Store) PurgeSentOutbox(ctx context.Context, cutoff time.Time) (int64, error) {
	c := cutoff.UTC().Format(time.RFC3339)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM outbox WHERE (status = 'sent' AND sent_at != '' AND sent_at < ?) OR (status = 'dead' AND created_at < ?)`,
		c, c)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PermitNotify returns the outcome fingerprints last DELIVERED to the user
// (notifiedKey) and last ALERTED to the operator (adminKey) for a permit. Empty
// strings when there is no row yet.
func (s *Store) PermitNotify(ctx context.Context, permitID int64) (notifiedKey, adminKey string, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT notified_key, admin_key FROM permit_notify WHERE permit_id = ?`, permitID).
		Scan(&notifiedKey, &adminKey)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return notifiedKey, adminKey, err
}

// SetPermitNotifiedKey records that the user was successfully notified of the
// given outcome fingerprint, so an identical repeat is not re-sent.
func (s *Store) SetPermitNotifiedKey(ctx context.Context, permitID int64, key string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO permit_notify (permit_id, notified_key) VALUES (?, ?)
ON CONFLICT(permit_id) DO UPDATE SET notified_key = excluded.notified_key`, permitID, key)
	return err
}

// SetPermitAdminKey records that the operator was alerted about the given outcome
// fingerprint, so an identical repeat is not re-alerted.
func (s *Store) SetPermitAdminKey(ctx context.Context, permitID int64, key string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO permit_notify (permit_id, admin_key) VALUES (?, ?)
ON CONFLICT(permit_id) DO UPDATE SET admin_key = excluded.admin_key`, permitID, key)
	return err
}
