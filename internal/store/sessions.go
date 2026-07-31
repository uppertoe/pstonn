package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Session epochs are how a stateless signed cookie becomes revocable.
//
// The app's own login (OIDC mode) issues a cookie carrying the identity AND the
// groups, with no server-side record. That means "you are no longer an admin" and
// "your account is gone" could not take effect until the cookie expired on its own.
// A per-person counter, stamped into the cookie at issue and checked on every
// decode, closes that: bump it and every cookie issued before now fails.
//
// The counter is deliberately per EMAIL rather than per account, because it revokes a
// person's sessions, and a person may be a secondary on someone else's account.

// SessionEpoch returns the person's current session generation. An absent row means
// zero — nothing has ever been revoked for them, which is the common case and costs
// no row.
func (s *Store) SessionEpoch(ctx context.Context, email string) (int64, error) {
	email = normaliseAddr(email)
	if email == "" {
		return 0, nil
	}
	var epoch int64
	err := s.db.QueryRowContext(ctx, `SELECT epoch FROM session_epoch WHERE email = ?`, email).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return epoch, err
}

// BumpSessionEpoch invalidates every session already issued to this person, and
// returns the new epoch. Idempotent in effect: calling it twice simply revokes twice.
//
// Call it wherever authority is taken away — account deletion, losing shared access,
// declining terms — not on ordinary sign-out, which only needs the cookie cleared in
// that one browser.
func (s *Store) BumpSessionEpoch(ctx context.Context, email string) (int64, error) {
	email = normaliseAddr(email)
	if email == "" {
		return 0, nil
	}
	var epoch int64
	err := s.db.QueryRowContext(ctx, `
INSERT INTO session_epoch (email, epoch, updated_at) VALUES (?, 1, ?)
ON CONFLICT(email) DO UPDATE SET epoch = session_epoch.epoch + 1, updated_at = excluded.updated_at
RETURNING epoch`, email, nowUTC()).Scan(&epoch)
	return epoch, err
}

// AllSessionEpochs loads every non-zero epoch, so the process can answer decode-time
// questions from memory instead of querying the single shared SQLite connection on
// every request. Only people who have had something revoked appear here, so it stays
// small.
func (s *Store) AllSessionEpochs(ctx context.Context) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email, epoch FROM session_epoch WHERE epoch != 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var email string
		var epoch int64
		if err := rows.Scan(&email, &epoch); err != nil {
			return nil, err
		}
		out[strings.ToLower(strings.TrimSpace(email))] = epoch
	}
	return out, rows.Err()
}
