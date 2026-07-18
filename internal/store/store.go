// Package store is the SQLite persistence layer. It uses the pure-Go
// modernc.org/sqlite driver (CGO_ENABLED=0), matching the vps-scaffold-auth
// build, and keeps WAL mode on for safe hot backups.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Store wraps the database handle.
type Store struct {
	db *sql.DB
}

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
}

// ApplyRecord is one row of the apply audit log.
type ApplyRecord struct {
	ID           int64
	PermitID     int64
	Registration string
	Source       string
	Status       string // "success" | "error" | "noop"
	Detail       string
	At           time.Time
}

// OpenSQLite opens (creating if needed) the database and runs migrations.
func OpenSQLite(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite writer is single; avoids "database is locked".
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %q: %w", pragma, err)
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS council_session (
    owner                TEXT PRIMARY KEY,        -- app-user email
    sub                  TEXT NOT NULL DEFAULT '',
    council_email        TEXT NOT NULL DEFAULT '',
    cookie_sealed        TEXT NOT NULL DEFAULT '',
    access_token_sealed  TEXT NOT NULL DEFAULT '',
    token_expiry         TEXT NOT NULL DEFAULT '',
    updated_at           TEXT NOT NULL DEFAULT '',
    linked_at            TEXT NOT NULL DEFAULT '',   -- last interactive link; the re-authorise clock
    reminder_sent_at     TEXT NOT NULL DEFAULT '',   -- when the approaching-expiry email was sent
    confirm_token        TEXT NOT NULL DEFAULT ''    -- single-use token for the email confirm link
);

CREATE TABLE IF NOT EXISTS vehicle (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner        TEXT NOT NULL DEFAULT '',   -- app-user email that owns this vehicle
    registration TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    UNIQUE(owner, registration)
);

CREATE TABLE IF NOT EXISTS permit (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    owner               TEXT NOT NULL DEFAULT '',   -- app-user email that owns this permit
    council_permit_id   TEXT NOT NULL UNIQUE,
    permit_type_id      TEXT NOT NULL DEFAULT '',
    label               TEXT NOT NULL DEFAULT '',
    active_registration TEXT NOT NULL DEFAULT '',
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS weekly_rule (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id  INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    weekday    INTEGER NOT NULL,          -- 0=Sunday .. 6=Saturday (time.Weekday)
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    UNIQUE(permit_id, weekday)
);

CREATE TABLE IF NOT EXISTS override (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id  INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    starts_at  TEXT NOT NULL,             -- RFC3339 UTC
    ends_at    TEXT,                      -- RFC3339 UTC, NULL = open-ended
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_override_permit ON override(permit_id);

CREATE TABLE IF NOT EXISTS apply_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id    INTEGER NOT NULL,
    registration TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apply_permit ON apply_log(permit_id, at);

-- Tracks the last apply outcome we SUCCESSFULLY notified the user about, and the
-- last one we alerted the operator about, both keyed on the outcome fingerprint
-- (status|registration|detail). This lets the scheduler keep retrying an
-- UNDELIVERED notification instead of the apply-log row silently suppressing it,
-- while still not spamming a repeating identical outcome.
CREATE TABLE IF NOT EXISTS permit_notify (
    permit_id    INTEGER PRIMARY KEY,
    notified_key TEXT NOT NULL DEFAULT '',  -- outcome fingerprint delivered to the user
    admin_key    TEXT NOT NULL DEFAULT ''   -- outcome fingerprint alerted to the operator
);

CREATE TABLE IF NOT EXISTS consent (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    owner      TEXT NOT NULL,             -- app-user email
    version    TEXT NOT NULL,             -- terms version accepted
    hash       TEXT NOT NULL,             -- fingerprint of the exact terms text
    agreed_at  TEXT NOT NULL              -- RFC3339 UTC
);
CREATE INDEX IF NOT EXISTS idx_consent_owner ON consent(owner, id);

CREATE TABLE IF NOT EXISTS notify_pref (
    owner         TEXT PRIMARY KEY,          -- app-user email
    email_enabled INTEGER NOT NULL DEFAULT 1,
    ntfy_enabled  INTEGER NOT NULL DEFAULT 0,
    ntfy_topic    TEXT NOT NULL DEFAULT '',
    failures_only INTEGER NOT NULL DEFAULT 0  -- 1 = only notify on failures, not every change
);

CREATE TABLE IF NOT EXISTS oauth_state (
    state      TEXT PRIMARY KEY,
    verifier   TEXT NOT NULL,
    nonce      TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '',   -- "app" (the OIDC provider login) | "council" (permit link)
    created_at TEXT NOT NULL
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Additive migrations for databases created before a column existed. Each
	// ADD COLUMN is idempotent-by-tolerance: a "duplicate column" error means it
	// is already present.
	for _, stmt := range []string{
		`ALTER TABLE council_session ADD COLUMN linked_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE council_session ADD COLUMN reminder_sent_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE council_session ADD COLUMN confirm_token TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate %q: %w", stmt, err)
		}
	}
	// Backfill the re-authorise clock for pre-existing sessions so they are not
	// treated as instantly past-bound on first keep-warm pass.
	if _, err := s.db.Exec(
		`UPDATE council_session SET linked_at = updated_at WHERE linked_at = '' AND updated_at != ''`); err != nil {
		return err
	}
	return nil
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// ---- Vehicles ----

// ListVehicles returns every vehicle across all owners (used by the scheduler to
// map vehicle IDs to registrations for permits it reconciles).
func (s *Store) ListVehicles(ctx context.Context) ([]model.Vehicle, error) {
	return s.queryVehicles(ctx, `SELECT id, registration, label FROM vehicle ORDER BY label, registration`)
}

// VehicleRef is a vehicle plus its owner, used by the scheduler to resolve a
// permit's scheduled vehicle_id ONLY against vehicles owned by that permit's
// owner (defence-in-depth against a rule/override that references a foreign id).
type VehicleRef struct {
	ID           int64
	Owner        string
	Registration string
}

// ListVehicleRefs returns every vehicle with its owner, for owner-scoped
// resolution in the scheduler.
func (s *Store) ListVehicleRefs(ctx context.Context) ([]VehicleRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, owner, registration FROM vehicle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VehicleRef
	for rows.Next() {
		var v VehicleRef
		if err := rows.Scan(&v.ID, &v.Owner, &v.Registration); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VehicleOwnedBy reports whether vehicle id exists and belongs to owner. Used to
// reject a rule/override that points at another user's vehicle (IDOR guard).
func (s *Store) VehicleOwnedBy(ctx context.Context, owner string, id int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM vehicle WHERE id = ? AND owner = ?`, id, owner).Scan(&n)
	return n > 0, err
}

// ListVehiclesFor returns the vehicles owned by one app user.
func (s *Store) ListVehiclesFor(ctx context.Context, owner string) ([]model.Vehicle, error) {
	return s.queryVehicles(ctx,
		`SELECT id, registration, label FROM vehicle WHERE owner = ? ORDER BY label, registration`, owner)
}

func (s *Store) queryVehicles(ctx context.Context, query string, args ...any) ([]model.Vehicle, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Vehicle
	for rows.Next() {
		var v model.Vehicle
		if err := rows.Scan(&v.ID, &v.Registration, &v.Label); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) CreateVehicle(ctx context.Context, owner, registration, label string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO vehicle (owner, registration, label, created_at) VALUES (?, ?, ?, ?)`,
		owner, registration, label, nowUTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteVehicle removes a vehicle, scoped to its owner (so one user cannot delete
// another's vehicle by guessing an id).
func (s *Store) DeleteVehicle(ctx context.Context, owner string, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vehicle WHERE id = ? AND owner = ?`, id, owner)
	return err
}

// ---- Permits ----

// ListPermits returns every permit across all owners (used by the scheduler,
// which reconciles each permit using its owner's council session).
func (s *Store) ListPermits(ctx context.Context) ([]model.Permit, error) {
	return s.queryPermits(ctx,
		`SELECT id, owner, council_permit_id, permit_type_id, label, active_registration FROM permit ORDER BY label, council_permit_id`)
}

// ListPermitsFor returns the permits owned by one app user.
func (s *Store) ListPermitsFor(ctx context.Context, owner string) ([]model.Permit, error) {
	return s.queryPermits(ctx,
		`SELECT id, owner, council_permit_id, permit_type_id, label, active_registration FROM permit WHERE owner = ? ORDER BY label, council_permit_id`, owner)
}

func (s *Store) queryPermits(ctx context.Context, query string, args ...any) ([]model.Permit, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Permit
	for rows.Next() {
		var p model.Permit
		if err := rows.Scan(&p.ID, &p.Owner, &p.CouncilPermitID, &p.PermitTypeID, &p.Label, &p.ActiveRegistration); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPermit(ctx context.Context, id int64) (model.Permit, error) {
	var p model.Permit
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, council_permit_id, permit_type_id, label, active_registration FROM permit WHERE id = ?`, id).
		Scan(&p.ID, &p.Owner, &p.CouncilPermitID, &p.PermitTypeID, &p.Label, &p.ActiveRegistration)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// PermitByCouncilID looks up a permit by its globally-unique council permit id,
// so a caller can check whether it is already managed (and by whom) before
// claiming it. Returns ErrNotFound when no row exists.
func (s *Store) PermitByCouncilID(ctx context.Context, councilPermitID string) (model.Permit, error) {
	var p model.Permit
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, council_permit_id, permit_type_id, label, active_registration FROM permit WHERE council_permit_id = ?`, councilPermitID).
		Scan(&p.ID, &p.Owner, &p.CouncilPermitID, &p.PermitTypeID, &p.Label, &p.ActiveRegistration)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// UpsertPermit inserts a permit, or updates the label/type of one the SAME owner
// already holds. It never reassigns ownership: the ON CONFLICT update is guarded
// by owner, so one user can never take over another user's permit row by
// re-submitting its council permit id. Callers must confirm the permit belongs
// to the owner's council account first (see addPermit); this is the last line of
// defence. Returns the row id.
func (s *Store) UpsertPermit(ctx context.Context, owner, councilPermitID, permitTypeID, label string) (int64, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO permit (owner, council_permit_id, permit_type_id, label, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(council_permit_id) DO UPDATE SET
    permit_type_id = excluded.permit_type_id,
    label          = excluded.label,
    updated_at     = excluded.updated_at
WHERE permit.owner = excluded.owner`,
		owner, councilPermitID, permitTypeID, label, nowUTC())
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRowContext(ctx, `SELECT id FROM permit WHERE council_permit_id = ?`, councilPermitID).Scan(&id)
	return id, err
}

func (s *Store) SetPermitActive(ctx context.Context, id int64, registration string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET active_registration = ?, updated_at = ? WHERE id = ?`,
		registration, nowUTC(), id)
	return err
}

// ---- Weekly rules ----

func (s *Store) ListRules(ctx context.Context, permitID int64) ([]model.WeeklyRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, permit_id, weekday, vehicle_id FROM weekly_rule WHERE permit_id = ? ORDER BY weekday`, permitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.WeeklyRule
	for rows.Next() {
		var r model.WeeklyRule
		var wd int
		if err := rows.Scan(&r.ID, &r.PermitID, &wd, &r.VehicleID); err != nil {
			return nil, err
		}
		r.Weekday = time.Weekday(wd)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetRule sets (or replaces) the vehicle for a permit on a weekday.
func (s *Store) SetRule(ctx context.Context, permitID int64, weekday time.Weekday, vehicleID int64) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, weekday, vehicle_id) VALUES (?, ?, ?)
ON CONFLICT(permit_id, weekday) DO UPDATE SET vehicle_id = excluded.vehicle_id`,
		permitID, int(weekday), vehicleID)
	return err
}

// ClearRule removes any rule for a permit on a weekday.
func (s *Store) ClearRule(ctx context.Context, permitID int64, weekday time.Weekday) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM weekly_rule WHERE permit_id = ? AND weekday = ?`, permitID, int(weekday))
	return err
}

// ---- Overrides ----

func (s *Store) CreateOverride(ctx context.Context, permitID, vehicleID int64, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	var endsStr sql.NullString
	if endsAt != nil {
		endsStr = sql.NullString{String: endsAt.UTC().Format(time.RFC3339), Valid: true}
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, starts_at, ends_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		permitID, vehicleID, startsAt.UTC().Format(time.RFC3339), endsStr, createdBy, nowUTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListOverrides returns a permit's active and upcoming overrides (those not yet
// ended, however far in the future), soonest first, a chronological list the
// user can scan and manage.
func (s *Store) ListOverrides(ctx context.Context, permitID int64, now time.Time) ([]model.Override, error) {
	nowStr := now.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, permit_id, vehicle_id, starts_at, ends_at, created_by
FROM override
WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)
ORDER BY starts_at ASC`, permitID, nowStr)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Override
	for rows.Next() {
		var o model.Override
		var starts string
		var ends sql.NullString
		if err := rows.Scan(&o.ID, &o.PermitID, &o.VehicleID, &starts, &ends, &o.CreatedBy); err != nil {
			return nil, err
		}
		if o.StartsAt, err = time.Parse(time.RFC3339, starts); err != nil {
			return nil, err
		}
		if ends.Valid {
			t, err := time.Parse(time.RFC3339, ends.String)
			if err != nil {
				return nil, err
			}
			o.EndsAt = &t
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// DeleteOverride removes an override, scoped to the owner of its permit (guards
// against deleting another user's override by id).
func (s *Store) DeleteOverride(ctx context.Context, owner string, id int64) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM override
WHERE id = ? AND permit_id IN (SELECT id FROM permit WHERE owner = ?)`, id, owner)
	return err
}

// ---- Council session (per app user) ----

// GetCouncilSession returns the linked council session for an app user, or
// ErrNotFound.
func (s *Store) GetCouncilSession(ctx context.Context, owner string) (CouncilSession, error) {
	var cs CouncilSession
	var expiry, updated, linked, reminded string
	err := s.db.QueryRowContext(ctx, `
SELECT owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token
FROM council_session WHERE owner = ?`, owner).
		Scan(&cs.Owner, &cs.Sub, &cs.CouncilEmail, &cs.Cookie, &cs.AccessToken, &expiry, &updated, &linked, &reminded, &cs.ConfirmToken)
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
INSERT INTO council_session (owner, sub, council_email, cookie_sealed, access_token_sealed, token_expiry, updated_at, linked_at, reminder_sent_at, confirm_token)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '')
ON CONFLICT(owner) DO UPDATE SET
    sub                 = excluded.sub,
    council_email       = excluded.council_email,
    cookie_sealed       = excluded.cookie_sealed,
    access_token_sealed = excluded.access_token_sealed,
    token_expiry        = excluded.token_expiry,
    updated_at          = excluded.updated_at,
    linked_at           = excluded.linked_at,
    reminder_sent_at    = '',
    confirm_token       = ''`,
		cs.Owner, cs.Sub, cs.CouncilEmail, cs.Cookie, cs.AccessToken,
		cs.TokenExpiry.UTC().Format(time.RFC3339), now, now)
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

// DeleteCouncilSession removes a user's linked session (e.g. on unlink or after
// the cookie expires and re-linking is required). The user's permits, vehicles
// and schedule are kept so a later re-link resumes exactly where they left off.
func (s *Store) DeleteCouncilSession(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM council_session WHERE owner = ?`, owner)
	return err
}

// DeleteAllForOwner erases every trace of an app user: their council session,
// permits (cascading rules and overrides), vehicles, and apply-log rows. Used by
// the self-service "delete my data" action. Runs in one transaction so a partial
// failure leaves nothing half-deleted.
func (s *Store) DeleteAllForOwner(ctx context.Context, owner string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// apply_log and permit_notify have no FK cascade; clear the owner's rows
	// before their permits go.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM apply_log WHERE permit_id IN (SELECT id FROM permit WHERE owner = ?)`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM permit_notify WHERE permit_id IN (SELECT id FROM permit WHERE owner = ?)`, owner); err != nil {
		return err
	}
	// Deleting permits cascades weekly_rule and override (ON DELETE CASCADE).
	if _, err := tx.ExecContext(ctx, `DELETE FROM permit WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vehicle WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM council_session WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM consent WHERE owner = ?`, owner); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- Apply log ----

// Consent is one recorded acceptance of the terms.
type Consent struct {
	Owner    string
	Version  string
	Hash     string
	AgreedAt time.Time
}

// RecordConsent appends an acceptance of the given terms version/hash.
func (s *Store) RecordConsent(ctx context.Context, owner, version, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO consent (owner, version, hash, agreed_at) VALUES (?, ?, ?, ?)`,
		owner, version, hash, nowUTC())
	return err
}

// LatestConsent returns the user's most recent acceptance, or ErrNotFound.
func (s *Store) LatestConsent(ctx context.Context, owner string) (Consent, error) {
	var c Consent
	var at string
	err := s.db.QueryRowContext(ctx,
		`SELECT owner, version, hash, agreed_at FROM consent WHERE owner = ? ORDER BY id DESC LIMIT 1`, owner).
		Scan(&c.Owner, &c.Version, &c.Hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.AgreedAt, _ = time.Parse(time.RFC3339, at)
	return c, nil
}

// NotifyPref is a user's notification-channel configuration.
type NotifyPref struct {
	Owner        string
	EmailEnabled bool
	NtfyEnabled  bool
	NtfyTopic    string
	FailuresOnly bool
}

// GetNotifyPref returns the user's notification preferences, or a sensible
// default (email on, ntfy off) when they have never set them.
func (s *Store) GetNotifyPref(ctx context.Context, owner string) (NotifyPref, error) {
	p := NotifyPref{Owner: owner, EmailEnabled: true}
	var email, ntfy, failures int
	err := s.db.QueryRowContext(ctx,
		`SELECT email_enabled, ntfy_enabled, ntfy_topic, failures_only FROM notify_pref WHERE owner = ?`, owner).
		Scan(&email, &ntfy, &p.NtfyTopic, &failures)
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
INSERT INTO notify_pref (owner, email_enabled, ntfy_enabled, ntfy_topic, failures_only)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(owner) DO UPDATE SET
    email_enabled = excluded.email_enabled,
    ntfy_enabled  = excluded.ntfy_enabled,
    ntfy_topic    = excluded.ntfy_topic,
    failures_only = excluded.failures_only`,
		p.Owner, b2i(p.EmailEnabled), b2i(p.NtfyEnabled), p.NtfyTopic, b2i(p.FailuresOnly))
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// LastApply returns the most recent apply-log row for a permit, or ErrNotFound.
// Used to suppress duplicate notifications when the same outcome repeats.
func (s *Store) LastApply(ctx context.Context, permitID int64) (ApplyRecord, error) {
	var a ApplyRecord
	var at string
	err := s.db.QueryRowContext(ctx, `
SELECT id, permit_id, registration, source, status, detail, at
FROM apply_log WHERE permit_id = ? ORDER BY id DESC LIMIT 1`, permitID).
		Scan(&a.ID, &a.PermitID, &a.Registration, &a.Source, &a.Status, &a.Detail, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.At, _ = time.Parse(time.RFC3339, at)
	return a, nil
}

func (s *Store) RecordApply(ctx context.Context, permitID int64, registration, source, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO apply_log (permit_id, registration, source, status, detail, at)
VALUES (?, ?, ?, ?, ?, ?)`,
		permitID, registration, source, status, detail, nowUTC())
	return err
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

// ListApplyLogFor returns recent apply-log rows for the given app user's permits.
func (s *Store) ListApplyLogFor(ctx context.Context, owner string, limit int) ([]ApplyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT a.id, a.permit_id, a.registration, a.source, a.status, a.detail, a.at
FROM apply_log a JOIN permit p ON a.permit_id = p.id
WHERE p.owner = ?
ORDER BY a.at DESC LIMIT ?`, owner, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApplyRecord
	for rows.Next() {
		var r ApplyRecord
		var at string
		if err := rows.Scan(&r.ID, &r.PermitID, &r.Registration, &r.Source, &r.Status, &r.Detail, &at); err != nil {
			return nil, err
		}
		r.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- OAuth PKCE state ----

// OAuthState is a stored, single-use authorization request (state → PKCE
// verifier + nonce), shared by the app-login and council-link flows.
type OAuthState struct {
	Verifier string
	Nonce    string
	Kind     string
}

func (s *Store) PutOAuthState(ctx context.Context, state, verifier, nonce, kind string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oauth_state (state, verifier, nonce, kind, created_at) VALUES (?, ?, ?, ?, ?)`,
		state, verifier, nonce, kind, nowUTC())
	return err
}

// TakeOAuthState returns and deletes the stored state (single use).
func (s *Store) TakeOAuthState(ctx context.Context, state string) (OAuthState, error) {
	var os OAuthState
	err := s.db.QueryRowContext(ctx,
		`SELECT verifier, nonce, kind FROM oauth_state WHERE state = ?`, state).
		Scan(&os.Verifier, &os.Nonce, &os.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return os, ErrNotFound
	}
	if err != nil {
		return os, err
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM oauth_state WHERE state = ?`, state)
	return os, nil
}
