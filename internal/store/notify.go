package store

import (
	"context"
	"database/sql"
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
}

// GetNotifyPref returns the user's notification preferences, or a sensible
// default (email on, ntfy off) when they have never set them.
func (s *Store) GetNotifyPref(ctx context.Context, owner string) (NotifyPref, error) {
	p := NotifyPref{Owner: owner, EmailEnabled: true, QuietFrom: 22, QuietUntil: 6}
	var email, ntfy, failures int
	err := s.db.QueryRowContext(ctx,
		`SELECT email_enabled, ntfy_enabled, ntfy_topic, failures_only, quiet_from, quiet_until FROM notify_pref WHERE owner = ?`, owner).
		Scan(&email, &ntfy, &p.NtfyTopic, &failures, &p.QuietFrom, &p.QuietUntil)
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
INSERT INTO notify_pref (owner, email_enabled, ntfy_enabled, ntfy_topic, failures_only, quiet_from, quiet_until)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(owner) DO UPDATE SET
    email_enabled = excluded.email_enabled,
    ntfy_enabled  = excluded.ntfy_enabled,
    ntfy_topic    = excluded.ntfy_topic,
    failures_only = excluded.failures_only,
    quiet_from    = excluded.quiet_from,
    quiet_until   = excluded.quiet_until`,
		p.Owner, boolInt(p.EmailEnabled), boolInt(p.NtfyEnabled), p.NtfyTopic, boolInt(p.FailuresOnly), p.QuietFrom, p.QuietUntil)
	return err
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
INSERT INTO outbox (account, dedup_key, recipients, ntfy_topic, ntfy_priority, ntfy_tag, subject, body, status, attempts, next_attempt, created_at)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9, ?10
WHERE ?2 = '' OR NOT EXISTS (SELECT 1 FROM outbox
  WHERE dedup_key = ?2
    AND (status = 'pending' OR (status = 'sent' AND sent_at > ?11)))`,
		it.Account, it.DedupKey, strings.Join(it.Recipients, "\n"), it.NtfyTopic, it.NtfyPriority, it.NtfyTag,
		it.Subject, it.Body, nextAttempt, now,
		time.Now().Add(-outboxDedupWindow).UTC().Format(time.RFC3339))
	return err
}

// DueOutbox returns pending notifications whose next attempt is due, oldest first.
func (s *Store) DueOutbox(ctx context.Context, now time.Time, limit int) ([]OutboxItem, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, dedup_key, recipients, ntfy_topic, ntfy_priority, ntfy_tag, subject, body, attempts
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
		if err := rows.Scan(&it.ID, &it.DedupKey, &recips, &it.NtfyTopic, &it.NtfyPriority, &it.NtfyTag,
			&it.Subject, &it.Body, &it.Attempts); err != nil {
			return nil, err
		}
		if recips != "" {
			it.Recipients = strings.Split(recips, "\n")
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkOutboxSent records a delivered notification.
func (s *Store) MarkOutboxSent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET status = 'sent', sent_at = ?, last_error = '' WHERE id = ?`, nowUTC(), id)
	return err
}

// RescheduleOutbox bumps the attempt count and defers the next try (backoff).
func (s *Store) RescheduleOutbox(ctx context.Context, id int64, attempts int, next time.Time, lastErr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET attempts = ?, next_attempt = ?, last_error = ? WHERE id = ?`,
		attempts, next.UTC().Format(time.RFC3339), lastErr, id)
	return err
}

// MarkOutboxDead retires a notification that has exhausted its retries.
func (s *Store) MarkOutboxDead(ctx context.Context, id int64, lastErr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE outbox SET status = 'dead', attempts = attempts + 1, last_error = ? WHERE id = ?`, lastErr, id)
	return err
}

// PurgeSentOutbox deletes delivered AND dead rows older than cutoff, so recipient/
// content PII isn't kept indefinitely (dead rows were previously retained forever).
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
