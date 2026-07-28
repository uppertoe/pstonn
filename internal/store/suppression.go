package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Suppression reasons. A complaint ("this is spam") is the most serious: the
// recipient asked to stop, so only they should ever undo it.
const (
	SuppressBounce    = "bounce"
	SuppressComplaint = "complaint"
	SuppressManual    = "manual"
	// SuppressUnsubscribed is a recipient's own request to stop. Unlike a bounce or
	// a complaint it is theirs to reverse: an account member re-enabling email in
	// Settings clears it (see UnsuppressIfUnsubscribed), while a bounce or complaint
	// stays until the operator intervenes.
	SuppressUnsubscribed = "unsubscribed"
)

// Suppression is one address we must not email.
type Suppression struct {
	Address   string
	Reason    string
	Detail    string
	FirstSeen time.Time
	LastSeen  time.Time
	Hits      int
}

// normaliseAddr lower-cases and trims an address so suppression matches
// regardless of how it was typed. Deliberately does NOT do provider-specific
// canonicalisation (gmail dots, plus-tags): those are different mailboxes as far
// as any standard is concerned, and over-matching would silently mute mail the
// user expects.
func normaliseAddr(a string) string { return strings.ToLower(strings.TrimSpace(a)) }

// SuppressAddress records that an address must not be emailed. Repeated reports
// bump the counter and refresh last_seen, and the STRONGEST reason seen wins.
//
// Strength is complaint > bounce > unsubscribed/manual, and it is not merely
// cosmetic — each rank unlocks a different escape route, so a reason that is too
// weak resumes mail that should have stopped:
//
//   - complaint is never pruned and never user-clearable (they reported us);
//   - bounce survives the user re-enabling email in Settings (the mailbox is
//     broken, and only the mailbox can fix that);
//   - unsubscribed is cleared by re-enabling email, because that IS the person
//     asking for mail again.
//
// So an address that unsubscribes and is LATER found dead must end up at
// 'bounce'. Leaving it at 'unsubscribed' let one click in Settings delete the row
// and resume hammering a dead address — the reputation damage this list exists to
// prevent. The detail column follows the winning reason rather than always taking
// the newest, so a complaint's feedback type is not overwritten by a later
// bounce's SMTP diagnostic while the reason still reads 'complaint'.
func (s *Store) SuppressAddress(ctx context.Context, address, reason, detail string) error {
	addr := normaliseAddr(address)
	if addr == "" {
		return nil
	}
	now := nowUTC()
	// Ties (the same reason reported again) go to the incoming row, refreshing the
	// diagnostic. SQLite evaluates every RHS against the pre-update row, so these
	// two assignments always agree on which side won.
	const rank = `CASE %s.reason WHEN 'complaint' THEN 3 WHEN 'bounce' THEN 2 ELSE 1 END`
	stmt := fmt.Sprintf(`
INSERT INTO mail_suppression (address, reason, detail, first_seen, last_seen, hits)
VALUES (?, ?, ?, ?, ?, 1)
ON CONFLICT(address) DO UPDATE SET
  reason    = CASE WHEN (%[1]s) >= (%[2]s) THEN excluded.reason ELSE mail_suppression.reason END,
  detail    = CASE WHEN (%[1]s) >= (%[2]s) THEN excluded.detail ELSE mail_suppression.detail END,
  last_seen = excluded.last_seen,
  hits      = mail_suppression.hits + 1`,
		fmt.Sprintf(rank, "excluded"), fmt.Sprintf(rank, "mail_suppression"))
	_, err := s.db.ExecContext(ctx, stmt, addr, reason, detail, now, now)
	return err
}

// IsSuppressed reports whether an address is on the list, with the reason.
func (s *Store) IsSuppressed(ctx context.Context, address string) (bool, string, error) {
	addr := normaliseAddr(address)
	if addr == "" {
		return false, "", nil
	}
	var reason string
	err := s.db.QueryRowContext(ctx,
		`SELECT reason FROM mail_suppression WHERE address = ?`, addr).Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, reason, nil
}

// SuppressedAmong returns the subset of addresses that are suppressed, mapped to
// their reason. Used to annotate a list (e.g. a guest pass's recipients) without
// a query per address.
func (s *Store) SuppressedAmong(ctx context.Context, addresses []string) (map[string]string, error) {
	out := map[string]string{}
	if len(addresses) == 0 {
		return out, nil
	}
	// Materialise the rows before issuing any follow-up query: the store runs on a
	// single connection, so a nested query while a cursor is open would deadlock.
	rows, err := s.db.QueryContext(ctx, `SELECT address, reason FROM mail_suppression`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	all := map[string]string{}
	for rows.Next() {
		var a, r string
		if err := rows.Scan(&a, &r); err != nil {
			return nil, err
		}
		all[a] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, a := range addresses {
		if r, ok := all[normaliseAddr(a)]; ok {
			out[a] = r
		}
	}
	return out, nil
}

// ListSuppressions returns the whole list, most recently reported first.
func (s *Store) ListSuppressions(ctx context.Context) ([]Suppression, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT address, reason, detail, first_seen, last_seen, hits
FROM mail_suppression ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Suppression
	for rows.Next() {
		var e Suppression
		var first, last string
		if err := rows.Scan(&e.Address, &e.Reason, &e.Detail, &first, &last, &e.Hits); err != nil {
			return nil, err
		}
		e.FirstSeen, _ = time.Parse(time.RFC3339, first)
		e.LastSeen, _ = time.Parse(time.RFC3339, last)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Unsuppress removes an address from the list, so mail to it resumes. Callers
// must not offer this for a complaint: the recipient asked us to stop, and only
// the operator should ever override that.
func (s *Store) Unsuppress(ctx context.Context, address string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM mail_suppression WHERE address = ?`, normaliseAddr(address))
	return err
}

// PruneSuppressions bounds the do-not-email list. Suppression is genuinely
// needed — re-sending to a dead address damages the sending domain for everyone,
// and someone who asked us to stop must stay stopped — but "we keep your address
// forever because you once unsubscribed" is not a defensible permanent record.
//
// Bounces and unsubscribes age out after bounceAge (an address that has been dead
// for two years is not evidence about the address that replaces it). COMPLAINTS
// ARE KEPT: someone who reported us as spam must never start receiving mail again
// through mere expiry. Provider diagnostics are cleared earlier, since their only
// use is short-term support.
func (s *Store) PruneSuppressions(ctx context.Context, bounceBefore, detailBefore time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM mail_suppression WHERE reason IN (?, ?) AND last_seen < ?`,
		SuppressBounce, SuppressUnsubscribed, bounceBefore.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE mail_suppression SET detail = '' WHERE detail != '' AND last_seen < ?`,
		detailBefore.UTC().Format(time.RFC3339)); err != nil {
		return n, err
	}
	return n, nil
}

// UnsuppressIfUnsubscribed clears ONLY a self-service unsubscribe, so a user who
// changes their mind can resubscribe by re-enabling email in Settings. It
// deliberately will not clear a bounce (the address is broken — sending again
// just damages the domain) or a complaint (they reported us as spam; quietly
// resuming would be indefensible). Reports whether a row was cleared.
func (s *Store) UnsuppressIfUnsubscribed(ctx context.Context, address string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM mail_suppression WHERE address = ? AND reason = ?`,
		normaliseAddr(address), SuppressUnsubscribed)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
