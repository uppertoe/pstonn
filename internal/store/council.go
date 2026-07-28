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
	// ReconnectedAt is when the saved password was last replayed to sign back in
	// (zero = never). Surfaced in Settings so credential use is visible to the
	// user, not just the operator's server log.
	ReconnectedAt time.Time
	// LastActive is the last authenticated visit by ANY member of the account —
	// the idle clock the re-authorise bound is measured against. The bound exists
	// to stop serving households that have left; a household that opens the app
	// has plainly not left, so their visit resets it. Zero falls back to LinkedAt.
	LastActive time.Time
}

// ---- Council session (per app user) ----

// GetCouncilSession returns the linked council session for an app user, or
// ErrNotFound.
func (s *Store) GetCouncilSession(ctx context.Context, owner string) (CouncilSession, error) {
	var cs CouncilSession
	var expiry, updated, linked, reminded, reconnected, lastActive string
	err := s.db.QueryRowContext(ctx, `
SELECT owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, password_sealed, reconnected_at, last_active_at
FROM council_session WHERE owner = ?`, owner).
		Scan(&cs.Owner, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken, &cs.Password, &reconnected, &lastActive)
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
	cs.ReconnectedAt, _ = time.Parse(time.RFC3339, reconnected)
	cs.LastActive, _ = time.Parse(time.RFC3339, lastActive)
	return cs, nil
}

// ListCouncilSessions returns every linked session (owner, timestamps, and
// whether a cookie is present) for the keep-warm loop to reconcile. Sealed
// secrets are included so callers can renew without a second lookup.
func (s *Store) ListCouncilSessions(ctx context.Context) ([]CouncilSession, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, last_active_at
FROM council_session`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CouncilSession
	for rows.Next() {
		var cs CouncilSession
		var expiry, updated, linked, reminded, lastActive string
		if err := rows.Scan(&cs.Owner, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken, &lastActive); err != nil {
			return nil, err
		}
		cs.TokenExpiry, _ = time.Parse(time.RFC3339, expiry)
		cs.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		cs.LinkedAt, _ = time.Parse(time.RFC3339, linked)
		cs.ReminderSent, _ = time.Parse(time.RFC3339, reminded)
		cs.LastActive, _ = time.Parse(time.RFC3339, lastActive)
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
// or ErrNotFound if the token matches no session or has aged out.
//
// maxAge bounds how long a token stays usable after its reminder was sent (0
// disables the bound). Without it, a token minted for one reminder remains a
// live "keep managing my permit for another SessionMaxAge" capability forever,
// sitting in a mailbox — which is precisely the human-liveness check this flow
// exists to make.
func (s *Store) ConfirmSession(ctx context.Context, token string, maxAge time.Duration) (string, error) {
	if token == "" {
		return "", ErrNotFound
	}
	var owner, sentAt string
	err := s.db.QueryRowContext(ctx,
		`SELECT owner, reminder_sent_at FROM council_session WHERE confirm_token = ?`, token).Scan(&owner, &sentAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if maxAge > 0 && sentAt != "" {
		if sent, perr := time.Parse(time.RFC3339, sentAt); perr == nil && time.Since(sent) > maxAge {
			// Aged out: clear it so the row can't be probed again, and report it as
			// not-found (the caller's reassuring copy is correct either way).
			_, _ = s.db.ExecContext(ctx,
				`UPDATE council_session SET confirm_token = '' WHERE owner = ?`, owner)
			return "", ErrNotFound
		}
	}
	// A click is a person confirming they are still here, so it resets the idle
	// clock as well as the link clock.
	_, err = s.db.ExecContext(ctx,
		`UPDATE council_session SET linked_at = ?, last_active_at = ?, reminder_sent_at = '', confirm_token = '' WHERE owner = ?`,
		nowUTC(), nowUTC(), owner)
	return owner, err
}

// ClearStaleConfirmTokens drops confirm tokens whose reminder went out before the
// cutoff. Consuming one is what normally clears it, so a token nobody ever
// clicked otherwise sits in the row as a live "keep managing my permit" capability
// until something happens to probe it.
func (s *Store) ClearStaleConfirmTokens(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
UPDATE council_session SET confirm_token = ''
WHERE confirm_token != '' AND reminder_sent_at != '' AND reminder_sent_at < ?`,
		before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// TouchAccountActive records that someone on the account used the app, resetting
// the idle clock the re-authorise bound is measured against. Any member counts:
// the bound exists to stop serving households that have left, and a secondary
// opening the app is the household still being here.
//
// It also clears the reminder flag, so a later idle stretch can trigger a fresh
// "are you still there?" email rather than being suppressed by one sent months
// ago — and it clears any outstanding confirm token with it.
//
// Clearing the token is not optional tidying. Both of its expiry mechanisms are
// gated on reminder_sent_at being set: ClearStaleConfirmTokens only matches rows
// that have it, and ConfirmSession skips its TTL check when it is empty. Blanking
// the flag while leaving the token would therefore make that emailed link
// IMMORTAL — a permanent "keep managing my permit" capability sitting in a
// mailbox, defeating the human-liveness check the whole flow exists to make.
// Nothing is lost by revoking it: the visit that got us here already reset the
// same idle clock the link would have, so the link has nothing left to do, and a
// later click lands on copy that says exactly that.
//
// No-op when the account has no linked session — there is nothing to keep alive.
func (s *Store) TouchAccountActive(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET last_active_at = ?, reminder_sent_at = '', confirm_token = '' WHERE owner = ?`,
		nowUTC(), owner)
	return err
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
INSERT INTO council_session (owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, password_sealed, last_active_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?)
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
    password_sealed     = excluded.password_sealed,
    last_active_at      = excluded.last_active_at`,
		cs.Owner, cs.Sub, cs.CouncilEmail, cs.Cookie, cs.AccessToken,
		cs.TokenExpiry.UTC().Format(time.RFC3339), now, now, cs.Password, now)
	return err
}

// SaveReconnectedSession writes the fresh cookie + (re-sealed) saved password
// after a silent auto-reconnect, WITHOUT advancing linked_at — the re-authorise
// clock only moves on an interactive re-link. It stamps reconnected_at: this is
// the only path that replays the saved password (silent cookie renews go through
// UpdateCouncilToken), so the stamp is exactly "your password was used". A no-op
// if the row is gone.
func (s *Store) SaveReconnectedSession(ctx context.Context, cs CouncilSession) error {
	now := nowUTC()
	_, err := s.db.ExecContext(ctx, `
UPDATE council_session
SET cookie_sealed = ?, password_sealed = ?, updated_at = ?, reconnected_at = ?
WHERE owner = ?`,
		cs.Cookie, cs.Password, now, now, cs.Owner)
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

// DeleteCouncilSessionIfIdle retires a session only if it is STILL idle past the
// cutoff, reporting whether it actually deleted anything.
//
// The keep-warm pass reads every session up front and then works through them
// with a rate-limit sleep between council calls, so by the time it reaches a given
// account its decision can be minutes stale. An unconditional delete therefore
// retired people who came back mid-pass — landing them on "reconnect your council
// account" seconds after they used the app. Re-checking the clock inside the
// delete closes that window.
//
// It also makes the retire idempotent: if the reconcile loop already dropped this
// session, this affects no rows and the caller can skip a second "you need to
// reconnect" notice.
//
// The COALESCE mirrors decideWarm's fallback exactly: last activity, else the link
// time, and an unknown clock (both empty) sorts before any timestamp, so it
// retires — matching "an unknown clock cannot be shown to be recent".
//
// `<=` rather than `<` because decideWarm retires on `now.Sub(idle) >= maxAge`,
// i.e. idle exactly AT the cutoff is already past the bound. Timestamps are stored
// at second precision, so a strict `<` also disagreed with decideWarm for any
// session inside the cutoff's own second.
func (s *Store) DeleteCouncilSessionIfIdle(ctx context.Context, owner string, before time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
DELETE FROM council_session
WHERE owner = ?
  AND COALESCE(NULLIF(last_active_at, ''), linked_at) <= ?`,
		owner, before.UTC().Format(time.RFC3339))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
