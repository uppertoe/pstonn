package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"
)

// MailRetention bounds how long a message to or from hello@stonn.org is kept.
// Like a contact message it names a third party and only the operator reads it,
// so it goes at the same 180 days (ContactMessageRetention).
const MailRetention = 180 * 24 * time.Hour

// MailMessage is one row of the operator's mailbox.
type MailMessage struct {
	ID           int64
	ThreadID     int64
	Inbound      bool
	SESMessageID string
	FromAddr     string
	FromName     string
	ToAddr       string
	Subject      string
	Body         string
	MessageID    string   // the Message-ID header
	References   []string // the References chain, oldest first
	Verdict      string
	Flagged      bool
	Truncated    bool
	At           time.Time
}

// AddMail stores one message and returns its id and thread. An inbound message
// joins the thread of any stored message its threading headers name (refs, the
// In-Reply-To first); otherwise, and for an outbound message with ThreadID 0, it
// starts its own. A redelivered inbound message (the same SES id) is
// ErrDuplicate, so an SNS retry stores nothing twice.
func (s *Store) AddMail(ctx context.Context, m MailMessage, inReplyTo string) (id, thread int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	thread = m.ThreadID
	if thread == 0 {
		ids := append([]string{inReplyTo}, reversed(m.References)...)
		for _, ref := range ids {
			if ref == "" {
				continue
			}
			err := tx.QueryRowContext(ctx,
				`SELECT thread_id FROM mail_message WHERE header_msgid = ? ORDER BY id LIMIT 1`, ref).Scan(&thread)
			if err == nil {
				break
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return 0, 0, err
			}
		}
	}
	dir := "out"
	if m.Inbound {
		dir = "in"
	}
	res, err := tx.ExecContext(ctx, `
INSERT INTO mail_message (thread_id, direction, ses_message_id, from_addr, from_name, to_addr, subject, body,
                          header_msgid, refs, verdict, flagged, truncated, at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		thread, dir, m.SESMessageID, m.FromAddr, m.FromName, m.ToAddr, m.Subject, m.Body,
		m.MessageID, strings.Join(m.References, " "), m.Verdict, boolInt(m.Flagged), boolInt(m.Truncated), nowUTC())
	if err != nil {
		if isUniqueViolation(err) {
			return 0, 0, ErrDuplicate
		}
		return 0, 0, err
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, 0, err
	}
	if thread == 0 {
		thread = id
		if _, err := tx.ExecContext(ctx, `UPDATE mail_message SET thread_id = ? WHERE id = ?`, id, id); err != nil {
			return 0, 0, err
		}
	}
	return id, thread, tx.Commit()
}

func reversed(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}

// MailThreads returns the newest threads first, each with its messages oldest
// first. limit bounds the number of threads.
func (s *Store) MailThreads(ctx context.Context, limit int) ([][]MailMessage, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, thread_id, direction, ses_message_id, from_addr, from_name, to_addr, subject, body,
       header_msgid, refs, verdict, flagged, truncated, at
FROM mail_message
WHERE thread_id IN (SELECT thread_id FROM mail_message GROUP BY thread_id ORDER BY MAX(id) DESC LIMIT ?)
ORDER BY thread_id, id`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byThread := map[int64][]MailMessage{}
	latest := map[int64]int64{}
	for rows.Next() {
		m, err := scanMail(rows)
		if err != nil {
			return nil, err
		}
		byThread[m.ThreadID] = append(byThread[m.ThreadID], m)
		latest[m.ThreadID] = m.ID
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([][]MailMessage, 0, len(byThread))
	for _, t := range byThread {
		out = append(out, t)
	}
	// Newest activity first.
	sort.Slice(out, func(i, j int) bool { return latest[out[i][0].ThreadID] > latest[out[j][0].ThreadID] })
	return out, nil
}

// MailByID returns one message.
func (s *Store) MailByID(ctx context.Context, id int64) (MailMessage, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, thread_id, direction, ses_message_id, from_addr, from_name, to_addr, subject, body,
       header_msgid, refs, verdict, flagged, truncated, at
FROM mail_message WHERE id = ?`, id)
	m, err := scanMail(row)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// UnansweredMail counts threads whose latest message is inbound and not
// flagged: the ones still waiting on the operator.
func (s *Store) UnansweredMail(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM mail_message m
WHERE m.id = (SELECT MAX(id) FROM mail_message WHERE thread_id = m.thread_id)
  AND m.direction = 'in' AND m.flagged = 0`).Scan(&n)
	return n, err
}

// PruneMail deletes messages older than the cutoff.
func (s *Store) PruneMail(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM mail_message WHERE at < ?`, before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanMail(r rowScanner) (MailMessage, error) {
	var m MailMessage
	var dir, refs, at string
	var flagged, truncated int
	if err := r.Scan(&m.ID, &m.ThreadID, &dir, &m.SESMessageID, &m.FromAddr, &m.FromName, &m.ToAddr, &m.Subject,
		&m.Body, &m.MessageID, &refs, &m.Verdict, &flagged, &truncated, &at); err != nil {
		return m, err
	}
	m.Inbound, m.Flagged, m.Truncated = dir == "in", flagged != 0, truncated != 0
	m.References = strings.Fields(refs)
	m.At, _ = time.Parse(time.RFC3339, at)
	return m, nil
}
