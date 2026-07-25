package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// CouncilSession is one app-user's linked council login. The council issues no
// refresh tokens, so durability rests on the IdentityServer session cookie; the
// access token is a short-lived (1h) cache re-minted via silent-renew. All
// secret fields are sealed (secretbox). Keyed by Owner = app-user email.
type CouncilSession struct {
	Owner        string
	Sub          string
	CouncilEmail string
	Cookie       string // sealed session cookie header; empty if not linked
	AccessToken  string // sealed cached access token
	TokenExpiry  time.Time
	UpdatedAt    time.Time // last renew/save; slides as keep-warm refreshes
	LinkedAt     time.Time // last interactive link/re-link; the re-authorise clock
	ReminderSent time.Time // when the approaching-expiry email was sent (zero = not this cycle)
	ConfirmToken string    // single-use token for the email confirm link (empty = none outstanding)
	Password     string    // sealed council password for opt-in auto-reconnect (empty = not saved)
}

// ---- Council session (per app user) ----

// GetCouncilSession returns the linked council session for an app user, or
// ErrNotFound.
func (s *Store) GetCouncilSession(ctx context.Context, owner string) (CouncilSession, error) {
	var cs CouncilSession
	var expiry, updated, linked, reminded string
	err := s.db.QueryRowContext(ctx, `
SELECT owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, password_sealed
FROM council_session WHERE owner = ?`, owner).
		Scan(&cs.Owner, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken, &cs.Password)
	if errors.Is(err, sql.ErrNoRows) {
		return cs, ErrNotFound
	}
	if err != nil {
		return cs, err
	}
	cs.TokenExpiry, _ = time.Parse(time.RFC3339, expiry)
	cs.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
	cs.LinkedAt, _ = time.Parse(time.RFC3339, linked)
	cs.ReminderSent, _ = time.Parse(time.RFC3339, reminded)
	return cs, nil
}

// ListCouncilSessions returns every linked session (owner, timestamps, and
// whether a cookie is present) for the keep-warm loop to reconcile. Sealed
// secrets are included so callers can renew without a second lookup.
func (s *Store) ListCouncilSessions(ctx context.Context) ([]CouncilSession, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token
FROM council_session`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CouncilSession
	for rows.Next() {
		var cs CouncilSession
		var expiry, updated, linked, reminded string
		if err := rows.Scan(&cs.Owner, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken); err != nil {
			return nil, err
		}
		cs.TokenExpiry, _ = time.Parse(time.RFC3339, expiry)
		cs.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		cs.LinkedAt, _ = time.Parse(time.RFC3339, linked)
		cs.ReminderSent, _ = time.Parse(time.RFC3339, reminded)
		out = append(out, cs)
	}
	return out, rows.Err()
}

// MarkReminderSent records that the approaching-expiry email was sent and stores
// the single-use token embedded in its confirm link.
func (s *Store) MarkReminderSent(ctx context.Context, owner, token string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET reminder_sent_at = ?, confirm_token = ? WHERE owner = ?`,
		nowUTC(), token, owner)
	return err
}

// ConfirmSession consumes a confirm token: it resets the re-authorise clock
// (linked_at = now), extending the session another full SessionMaxAge, and clears
// the reminder state so the next cycle can fire. Returns the owner it belonged to,
// or ErrNotFound if the token matches no session.
func (s *Store) ConfirmSession(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", ErrNotFound
	}
	var owner string
	err := s.db.QueryRowContext(ctx,
		`SELECT owner FROM council_session WHERE confirm_token = ?`, token).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE council_session SET linked_at = ?, reminder_sent_at = '', confirm_token = '' WHERE owner = ?`,
		nowUTC(), owner)
	return owner, err
}

// OwnerHasSchedule reports whether the owner has anything the scheduler could act
// on, at least one weekly rule or override on one of their permits. Sessions for
// users who have linked but not set up a schedule need not be kept warm.
func (s *Store) OwnerHasSchedule(ctx context.Context, owner string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM weekly_rule wr JOIN permit p ON wr.permit_id = p.id WHERE p.owner = ?) +
  (SELECT COUNT(*) FROM override o     JOIN permit p ON o.permit_id  = p.id WHERE p.owner = ?)`,
		owner, owner).Scan(&n)
	return n > 0, err
}

// SaveCouncilSession upserts a user's session from an interactive link, sealing
// already done by the caller. It stamps linked_at = now (resetting the
// re-authorise clock) and clears any stale cached access token (a fresh cookie
// invalidates the old token pairing).
func (s *Store) SaveCouncilSession(ctx context.Context, cs CouncilSession) error {
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO council_session (owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, password_sealed)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)
ON CONFLICT(owner) DO UPDATE SET
    sub                 = excluded.sub,
    council_email       = excluded.council_email,
    cookie_sealed       = excluded.cookie_sealed,
    access_token_sealed = excluded.access_token_sealed,
    token_expiry        = excluded.token_expiry,
    updated_at          = excluded.updated_at,
    linked_at           = excluded.linked_at,
    reminder_sent_at    = '',
    confirm_token       = '',
    password_sealed     = excluded.password_sealed`,
		cs.Owner, cs.Sub, cs.CouncilEmail, cs.Cookie, cs.AccessToken,
		cs.TokenExpiry.UTC().Format(time.RFC3339), now, now, cs.Password)
	return err
}

// SaveReconnectedSession writes the fresh cookie + (re-sealed) saved password
// after a silent auto-reconnect, WITHOUT advancing linked_at — the re-authorise
// clock only moves on an interactive re-link. A no-op if the row is gone.
func (s *Store) SaveReconnectedSession(ctx context.Context, cs CouncilSession) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE council_session
SET cookie_sealed = ?, password_sealed = ?, updated_at = ?
WHERE owner = ?`,
		cs.Cookie, cs.Password, nowUTC(), cs.Owner)
	return err
}

// UpdateCouncilToken refreshes just the cached access token and the (possibly
// rotated) session cookie after a silent-renew.
func (s *Store) UpdateCouncilToken(ctx context.Context, owner, sealedCookie, sealedAccess string, expiry time.Time) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE council_session
SET cookie_sealed = ?, access_token_sealed = ?, token_expiry = ?, updated_at = ?
WHERE owner = ?`,
		sealedCookie, sealedAccess, expiry.UTC().Format(time.RFC3339), nowUTC(), owner)
	return err
}

// ClearCouncilPassword drops a saved (sealed) council password without unlinking
// the session — used by the settings "stop auto-reconnecting" action. If the
// session later expires it will require a manual re-link, as if never saved.
func (s *Store) ClearCouncilPassword(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET password_sealed = '' WHERE owner = ?`, owner)
	return err
}

// DeleteCouncilSession removes a user's linked session (e.g. on unlink or after
// the cookie expires and re-linking is required). The user's permits, vehicles
// and schedule are kept so a later re-link resumes exactly where they left off.
func (s *Store) DeleteCouncilSession(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM council_session WHERE owner = ?`, owner)
	return err
}
