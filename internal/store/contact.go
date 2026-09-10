package store

import (
	"context"
	"time"
)

// ContactMessage is one submission of the public contact form, kept for the
// operator to read on /admin.
type ContactMessage struct {
	ID         int64
	Message    string
	ReplyTo    string // optional; the submitter's own claim, never verified
	ReceivedAt time.Time
}

// ContactMessageRetention bounds how long a contact message is kept. A message
// names a third party (its reply address) and the only reader is the operator's
// dashboard, so it goes with the other operator logs at 180 days: long enough to
// still find a conversation from last season, not an indefinite record.
const ContactMessageRetention = 180 * 24 * time.Hour

// AddContactMessage stores a contact-form submission and returns its id.
func (s *Store) AddContactMessage(ctx context.Context, message, replyTo string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO contact_message (message, reply_to, received_at) VALUES (?, ?, ?)`,
		message, replyTo, nowUTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListContactMessages returns the newest messages first, at most limit of them.
func (s *Store) ListContactMessages(ctx context.Context, limit int) ([]ContactMessage, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, message, reply_to, received_at
FROM contact_message ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContactMessage
	for rows.Next() {
		var m ContactMessage
		var at string
		if err := rows.Scan(&m.ID, &m.Message, &m.ReplyTo, &at); err != nil {
			return nil, err
		}
		m.ReceivedAt, _ = time.Parse(time.RFC3339, at)
		out = append(out, m)
	}
	return out, rows.Err()
}

// PruneContactMessages deletes messages received before the cutoff.
func (s *Store) PruneContactMessages(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM contact_message WHERE received_at < ?`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
