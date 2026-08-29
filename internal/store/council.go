package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// hashConfirmToken is what actually goes in the confirm_token column.
//
// The token is a bearer capability: clicking its link extends a council session
// by another full SessionMaxAge. Every other secret in the row is sealed, and this
// one additionally rides in a GET query string, so it lands in proxy access logs
// and browser history as well as the database. Storing only the hash means a
// read-only leak of either the DB or those logs no longer yields something
// replayable — the column holds a value that cannot be turned back into a link.
//
// A plain SHA-256 is the right primitive here rather than a password hash: the
// token is 32 bytes of randToken output, so there is no dictionary to attack, and
// the lookup sits on the single shared SQLite connection where a deliberately slow
// KDF would be a self-inflicted denial of service.
//
// Tokens minted BEFORE this change stop working: their column holds the plaintext,
// which no longer matches the hash of what arrives. That is acceptable — they are
// short-lived by design (ClearStaleConfirmTokens sweeps them, ConfirmSession
// bounds them by maxAge), a click on one lands on the same reassuring
// already-handled copy as any expired token, and the next reminder cycle mints a
// fresh one.
//
// The empty string is preserved as-is, never hashed: it is the "no token
// outstanding" marker that the partial index (confirm_token not empty) and both
// expiry paths key on, and a hex hash is never empty, so that distinction still
// holds.
func hashConfirmToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CouncilSession is one app-user's linked council login. The council issues no
// refresh tokens, so durability rests on the IdentityServer session cookie; the
// access token is a short-lived (1h) cache re-minted via silent-renew. All
// secret fields are sealed (secretbox). Keyed by Owner = app-user email.
type CouncilSession struct {
	Owner        string
	CouncilID    string // the council this session is with
	Sub          string
	CouncilEmail string
	Cookie       string // sealed session cookie header; empty if not linked
	AccessToken  string // sealed cached access token
	TokenExpiry  time.Time
	UpdatedAt    time.Time // last renew/save; slides as keep-warm refreshes
	LinkedAt     time.Time // last interactive link/re-link; the re-authorise clock
	ReminderSent time.Time // when the approaching-expiry email was sent (zero = not this cycle)
	ConfirmToken string    // hex SHA-256 of the single-use email-confirm token (empty = none outstanding)
	Password     string    // sealed council password for opt-in auto-reconnect (empty = not saved)
	// ReconnectedAt is when the saved password was last replayed to sign back in
	// (zero = never). Surfaced in Settings so credential use is visible to the
	// user, not just the operator's server log.
	ReconnectedAt time.Time
	// LastActive is the last USE of the account — an authenticated visit by any
	// member, a guest opening/using the household's pass link, or a member
	// deciding a request via the emailed one-tap link. It is the idle clock the
	// re-authorise bound is measured against. The bound exists to stop serving
	// households that have LEFT; a guest scanning the QR on their door is as
	// much proof they haven't as a sign-in (and the happiest usage pattern —
	// set up once, let guests self-serve — produces no sign-ins at all).
	// Zero falls back to LinkedAt.
	LastActive time.Time
	// DriftCheckedAt is when the owner-grid drift/expiry read last ran. It has its
	// own cadence (hours), decoupled from keep-warm (which slides UpdatedAt every
	// ~105 min): a warm keeps the SESSION alive, a drift read is a separate, much
	// rarer question — did the permit change outside p.stonn — and coupling them
	// doubled keep-warm's council traffic for no session-survival benefit.
	DriftCheckedAt time.Time
	// Generation is a monotonic-per-OWNER version of the session MATERIAL
	// (cookie/password), bumped by every successful write: interactive link,
	// auto-reconnect, silent renew, cookie rotation, password opt-out. It is the
	// compare-and-swap token for asynchronous work — recovery captures the generation
	// it FAILED at and conditions its save/delete on it, so that work can never act on
	// a session that has since changed. linked_at cannot serve this purpose: it is a
	// business clock (the re-authorise deadline) and is deliberately preserved across
	// an auto-reconnect. A fresh row seeds the generation from the clock rather than
	// from 1 (see newSessionGeneration), so an unlink+relink cannot restart the counter
	// and let work bound to the OLD row match the recreated one (an ABA defeating the CAS).
	Generation int64
}

// ---- Council session (per app user) ----

// GetCouncilSession returns the linked council session for an app user, or
// ErrNotFound.
func (s *Store) GetCouncilSession(ctx context.Context, owner string) (CouncilSession, error) {
	var cs CouncilSession
	var expiry, updated, linked, reminded, reconnected, lastActive, driftChecked string
	err := s.db.QueryRowContext(ctx, `
SELECT owner, council_id, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, password_sealed, reconnected_at, last_active_at, drift_checked_at, session_generation
FROM council_session WHERE owner = ?`, owner).
		Scan(&cs.Owner, &cs.CouncilID, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken, &cs.Password, &reconnected, &lastActive, &driftChecked, &cs.Generation)
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
	cs.DriftCheckedAt, _ = time.Parse(time.RFC3339, driftChecked)
	return cs, nil
}

// ListCouncilSessions returns every linked session (owner, timestamps, and
// whether a cookie is present) for the keep-warm loop to reconcile. Sealed
// secrets are included so callers can renew without a second lookup.
func (s *Store) ListCouncilSessions(ctx context.Context) ([]CouncilSession, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT owner, council_id, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, last_active_at, drift_checked_at, session_generation
FROM council_session`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CouncilSession
	for rows.Next() {
		var cs CouncilSession
		var expiry, updated, linked, reminded, lastActive, driftChecked string
		if err := rows.Scan(&cs.Owner, &cs.CouncilID, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken, &lastActive, &driftChecked, &cs.Generation); err != nil {
			return nil, err
		}
		cs.TokenExpiry, _ = time.Parse(time.RFC3339, expiry)
		cs.UpdatedAt, _ = time.Parse(time.RFC3339, updated)
		cs.LinkedAt, _ = time.Parse(time.RFC3339, linked)
		cs.ReminderSent, _ = time.Parse(time.RFC3339, reminded)
		cs.LastActive, _ = time.Parse(time.RFC3339, lastActive)
		cs.DriftCheckedAt, _ = time.Parse(time.RFC3339, driftChecked)
		out = append(out, cs)
	}
	return out, rows.Err()
}

// MarkDriftChecked records that the owner-grid drift/expiry read just ran, so its
// own cadence (see scheduler.driftDue) can pace it independently of keep-warm.
func (s *Store) MarkDriftChecked(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET drift_checked_at = ? WHERE owner = ?`, nowUTC(), owner)
	return err
}

// ClearReminderSent undoes MarkReminderSent, so a reminder whose token was recorded
// but whose email then failed to send can be retried instead of being marked done.
func (s *Store) ClearReminderSent(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET reminder_sent_at = '', confirm_token = '' WHERE owner = ?`, owner)
	return err
}

// MarkReminderSent records that the approaching-expiry email was sent and stores
// the single-use token embedded in its confirm link — as a hash, so the row cannot
// be read for a working link. The caller keeps the plaintext only long enough to
// put it in the email.
func (s *Store) MarkReminderSent(ctx context.Context, owner, token string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET reminder_sent_at = ?, confirm_token = ? WHERE owner = ?`,
		nowUTC(), hashConfirmToken(token), owner)
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
	// Matched on the hash: the column stores hashConfirmToken(token), so the
	// plaintext from the link is hashed here rather than compared directly.
	err := s.db.QueryRowContext(ctx,
		`SELECT owner, reminder_sent_at FROM council_session WHERE confirm_token = ?`,
		hashConfirmToken(token)).Scan(&owner, &sentAt)
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

// OwnerHasPermit reports whether the owner manages at least one permit. A linked
// account with no permit has nothing for a live council session to act on — keep-warm
// exists to serve a permit — so such sessions are left to lapse. Covers schedulers
// AND QR-only households (both hold a permit); excludes accounts that linked but
// never added one (e.g. a resident with no visitor permit to manage).
func (s *Store) OwnerHasPermit(ctx context.Context, owner string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM permit WHERE owner = ?)`, owner).Scan(&exists)
	return exists == 1, err
}

// OwnersWithPermit returns the set of owners that manage at least one permit — the
// owners keep-warm actually maintains. The warm-margin status metrics use it to
// ignore intentionally un-warmed sessions (a linked account with NO permit is left
// to lapse), which would otherwise read as a perpetual near-expiry alarm. One
// batched query, not one per session.
func (s *Store) OwnersWithPermit(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT owner FROM permit`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var owner string
		if err := rows.Scan(&owner); err != nil {
			return nil, err
		}
		out[owner] = struct{}{}
	}
	return out, rows.Err()
}

// SaveCouncilSession upserts a user's session from an interactive link, sealing
// already done by the caller. It stamps linked_at = now (resetting the
// re-authorise clock) and clears any stale cached access token (a fresh cookie
// invalidates the old token pairing).
func (s *Store) SaveCouncilSession(ctx context.Context, cs CouncilSession) error {
	now := nowUTC()
	if cs.CouncilID == "" {
		id, err := s.CouncilIDFor(ctx, cs.Owner)
		if err != nil {
			return err
		}
		cs.CouncilID = id
	}
	// Refuse to write a council session for someone who is now an ACCEPTED secondary.
	// AcceptInvite already refuses to make a linker into a secondary, but that only
	// closes one direction: a council link started before the invite was accepted lands
	// after it, and the two guards together must hold whichever way the race falls.
	// Otherwise the address ends up both sharing the primary's permits and holding its
	// own council session — where a member sees two sets of permits and the scheduler
	// warms a session nothing owns.
	res, err := s.db.ExecContext(ctx, `
INSERT INTO council_session (owner, council_id, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token, password_sealed, last_active_at, session_generation)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM account_member WHERE member_email = ? AND invite_pending = 0)
ON CONFLICT(owner) DO UPDATE SET
    council_id          = excluded.council_id,
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
    last_active_at      = excluded.last_active_at,
    session_generation  = council_session.session_generation + 1`,
		cs.Owner, cs.CouncilID, cs.Sub, cs.CouncilEmail, cs.Cookie, cs.AccessToken,
		cs.TokenExpiry.UTC().Format(time.RFC3339), now, now, cs.Password, now, s.newSessionGeneration(),
		cs.Owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSecondaryAccount
	}
	return nil
}

// ErrSecondaryAccount means the address joined another household while its council
// link was in flight, so the link must not be saved: it uses the primary's permits now.
var ErrSecondaryAccount = errors.New("store: this address has joined another household, so it cannot hold its own council link")

// newSessionGeneration seeds a FRESH session row's generation. A relink is a
// delete+insert, so a counter restarting at 1 would let work bound to the old row's
// generation match the new row (ABA) and act on a session it never observed.
//
// The seed is wall-clock milliseconds, forced STRICTLY above the last one this process
// issued. The clock alone is not enough — two saves can land in the same millisecond —
// and a bare counter is not enough either, since it would restart at process boundaries.
// Together they are strictly increasing within a run and far above any prior value
// across restarts (the per-write increments only ever add small amounts).
func (s *Store) newSessionGeneration() int64 {
	s.genMu.Lock()
	defer s.genMu.Unlock()
	gen := time.Now().UTC().UnixMilli()
	if gen <= s.lastGen {
		gen = s.lastGen + 1
	}
	s.lastGen = gen
	return gen
}

// ErrSessionSuperseded means a generation-conditioned session write matched no row:
// the session material changed (a relink, unlink, another reconnect, or a password
// opt-out) since the generation was captured, so this write must be treated as
// superseded rather than applied.
var ErrSessionSuperseded = errors.New("store: council session superseded since generation captured")

// SaveReconnectedSessionIfGen writes the fresh cookie + (re-sealed) saved password
// after a silent auto-reconnect — but ONLY if the row is still at expectedGen, so an
// in-flight reconnect can never overwrite a session the user has since changed (a
// relink, or a "stop auto-reconnecting" opt-out that cleared the password). It bumps
// the generation and (deliberately) does NOT advance linked_at — the re-authorise
// clock moves only on an interactive re-link — but stamps reconnected_at, the one path
// that replays the saved password. Returns whether a row was written.
func (s *Store) SaveReconnectedSessionIfGen(ctx context.Context, cs CouncilSession, expectedGen int64) (bool, error) {
	now := nowUTC()
	res, err := s.db.ExecContext(ctx, `
UPDATE council_session
SET cookie_sealed = ?, password_sealed = ?, updated_at = ?, reconnected_at = ?,
    session_generation = session_generation + 1
WHERE owner = ? AND session_generation = ?`,
		cs.Cookie, cs.Password, now, now, cs.Owner, expectedGen)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// UpdateCouncilToken refreshes just the cached access token and the (possibly
// rotated) session cookie after a silent-renew.
// It is conditioned on expectedGen — the generation of the session the renew was
// started from. A silent renew takes seconds; if an interactive re-link landed in
// that window the row now holds a DIFFERENT, valid cookie, and writing the re-sealed
// old one over it would silently undo the user's re-link (and lose the new cookie for
// good, since keep-warm would then happily keep the old one alive). Returns
// ErrSessionSuperseded when the row moved on.
func (s *Store) UpdateCouncilToken(ctx context.Context, owner, sealedCookie, sealedAccess string, expiry time.Time, expectedGen int64) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE council_session
SET cookie_sealed = ?, access_token_sealed = ?, token_expiry = ?, updated_at = ?,
    session_generation = session_generation + 1
WHERE owner = ? AND session_generation = ?`,
		sealedCookie, sealedAccess, expiry.UTC().Format(time.RFC3339), nowUTC(), owner, expectedGen)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrSessionSuperseded
	}
	return nil
}

// UpdateCouncilCookie persists a (re-sealed) session cookie from an authorize-only
// keep-warm, leaving the access token and its expiry untouched — keep-warm mints no
// token. updated_at IS bumped because it is keep-warm's freshness clock (see
// scheduler.decideWarm): without it, every warm pass would judge the session still
// stale and immediately renew it again.
// Conditioned on expectedGen for the same reason as UpdateCouncilToken: a keep-warm
// probe spans seconds, and an interactive re-link inside that window must not be
// overwritten by the re-sealed older cookie. Returns ErrSessionSuperseded if so.
func (s *Store) UpdateCouncilCookie(ctx context.Context, owner, sealedCookie string, expectedGen int64) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE council_session
SET cookie_sealed = ?, updated_at = ?, session_generation = session_generation + 1
WHERE owner = ? AND session_generation = ?`,
		sealedCookie, nowUTC(), owner, expectedGen)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrSessionSuperseded
	}
	return nil
}

// ClearCouncilPassword drops a saved (sealed) council password without unlinking
// the session — used by the settings "stop auto-reconnecting" action. If the
// session later expires it will require a manual re-link, as if never saved.
func (s *Store) ClearCouncilPassword(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE council_session SET password_sealed = '', session_generation = session_generation + 1 WHERE owner = ?`, owner)
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

// DeleteCouncilSessionIfGen removes the session ONLY if its session_generation still
// equals gen — the generation observed when a reconnect was queued. Any successful
// session write since (a relink, an auto-reconnect, a renew, a password opt-out) has
// bumped the generation, so this deletes nothing and the current session survives:
// stale recovery work can never retire a session that has since changed. Returns
// whether a row was actually deleted.
func (s *Store) DeleteCouncilSessionIfGen(ctx context.Context, owner string, gen int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM council_session WHERE owner = ? AND session_generation = ?`,
		owner, gen)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// BreakerState is the persisted fleet-circuit-breaker pause. OpenUntil in the
// future on boot means the breaker should start paused (a block that a restart
// must not clear); Generation is carried forward to stay monotonic.
type BreakerState struct {
	OpenUntil    time.Time
	Generation   uint64
	LastPushback time.Time
}

// LoadBreakerState reads the persisted breaker pause (zero-value times when never
// set). Errors are returned so a boot can log and proceed closed rather than crash.
func (s *Store) LoadBreakerState(ctx context.Context, councilID string) (BreakerState, error) {
	var openUntil, lastPushback string
	var gen int64
	err := s.db.QueryRowContext(ctx,
		`SELECT open_until, generation, last_pushback FROM breaker_state WHERE council_id = ?`, councilID).
		Scan(&openUntil, &gen, &lastPushback)
	if errors.Is(err, sql.ErrNoRows) {
		return BreakerState{}, nil // never paused: start closed
	}
	if err != nil {
		return BreakerState{}, err
	}
	bs := BreakerState{Generation: uint64(gen)}
	bs.OpenUntil, _ = time.Parse(time.RFC3339, openUntil)
	bs.LastPushback, _ = time.Parse(time.RFC3339, lastPushback)
	return bs, nil
}

// SaveBreakerState persists the breaker pause on every open/close/pushback
// transition, so a restart resumes from the real state rather than a clean slate.
func (s *Store) SaveBreakerState(ctx context.Context, councilID string, b BreakerState) error {
	// Generation-guarded, so an older snapshot cannot overwrite a newer one even if two
	// transitions race to the database. That makes ordering safe WITHOUT holding a lock
	// across this write — which matters because /status reads the persist health under
	// the same mutex, and a fleet block is exactly when both are busiest.
	_, err := s.db.ExecContext(ctx, `
INSERT INTO breaker_state (council_id, open_until, last_pushback, generation)
VALUES (?, ?, ?, ?)
ON CONFLICT(council_id) DO UPDATE SET
    open_until    = excluded.open_until,
    last_pushback = excluded.last_pushback,
    generation    = excluded.generation
WHERE excluded.generation >= breaker_state.generation`,
		councilID, b.OpenUntil.UTC().Format(time.RFC3339), b.LastPushback.UTC().Format(time.RFC3339), b.Generation)
	return err
}

// CouncilIDFor resolves which council an account belongs to: the choice made at
// sign-up (account_flags), else the council of its linked session, else the
// process default. One council per account, by design.
func (s *Store) CouncilIDFor(ctx context.Context, owner string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(
    NULLIF((SELECT council_id FROM account_flags WHERE owner = ?), ''),
    NULLIF((SELECT council_id FROM council_session WHERE owner = ?), ''),
    '')`, owner, owner).Scan(&id)
	if err != nil {
		return "", err
	}
	if id == "" {
		id = s.DefaultCouncil
	}
	return id, nil
}

// SetAccountCouncil records the council an account chose at sign-up. Refused if
// the account already holds a session with a DIFFERENT council: switching means
// disconnecting first, so a permit is never left filed under the wrong portal.
func (s *Store) SetAccountCouncil(ctx context.Context, owner, councilID string) error {
	cs, err := s.GetCouncilSession(ctx, owner)
	if err == nil && cs.CouncilID != "" && cs.CouncilID != councilID {
		return ErrCouncilMismatch
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, council_id) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET council_id = excluded.council_id`, owner, councilID)
	return err
}

// ErrCouncilMismatch: the account is linked to a different council than asked for.
var ErrCouncilMismatch = errors.New("store: account is linked to a different council")
