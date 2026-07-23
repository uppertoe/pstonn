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

// ErrDuplicate is returned when an insert violates a uniqueness constraint.
var ErrDuplicate = errors.New("already exists")

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
	Password     string    // sealed council password for opt-in auto-reconnect (empty = not saved)
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
	// Pin foreign_keys ON in the DSN, not just as a post-open PRAGMA: the pragma is
	// per-connection and defaults OFF, so if database/sql ever replaces the pooled
	// connection the ON-DELETE-CASCADE cleanups (guest tokens, rules, overrides on
	// account/permit deletion) would silently stop firing. The DSN applies it to
	// every connection modernc opens.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
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
    confirm_token        TEXT NOT NULL DEFAULT '',   -- single-use token for the email confirm link
    password_sealed      TEXT NOT NULL DEFAULT ''    -- opt-in sealed council password for auto-reconnect (empty = not saved)
);

CREATE TABLE IF NOT EXISTS vehicle (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner        TEXT NOT NULL DEFAULT '',   -- app-user email that owns this vehicle
    registration TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT '',
    color        TEXT NOT NULL DEFAULT '',   -- stable per-plate colour, assigned at creation
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
    end_date            TEXT NOT NULL DEFAULT '',   -- permit expiry (RFC3339) from the council record
    status              TEXT NOT NULL DEFAULT '',   -- council permit status, e.g. "Granted"
    expiry_reminded     TEXT NOT NULL DEFAULT '',   -- '1' once an expiry reminder is sent (cleared when end_date changes)
    permit_number       TEXT NOT NULL DEFAULT '',   -- council permit number, e.g. "VPP24714"
    permit_type         TEXT NOT NULL DEFAULT '',   -- council permit type, e.g. "(A) 1st Visitor Permit"
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
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id      INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    vehicle_id     INTEGER REFERENCES vehicle(id) ON DELETE CASCADE,  -- NULL for an ad-hoc plate
    registration   TEXT NOT NULL DEFAULT '',   -- literal plate used when vehicle_id IS NULL (not a saved car)
    starts_at      TEXT NOT NULL,              -- RFC3339 UTC
    ends_at        TEXT,                       -- RFC3339 UTC, NULL = open-ended
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    guest_token_id INTEGER NOT NULL DEFAULT 0  -- which guest link created it (0 = not a guest change); lets a guest revert exactly their own changes
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
    failures_only INTEGER NOT NULL DEFAULT 0,  -- 1 = only notify on failures, not every change
    quiet_from    INTEGER NOT NULL DEFAULT 22, -- quiet-hours window start (local hour); == quiet_until disables
    quiet_until   INTEGER NOT NULL DEFAULT 6   -- overnight notices are held and delivered at this local hour
);

-- Shared access: a primary account owner may grant up to two other verified
-- emails access to their account. member_email is the secondary's verified
-- email; owner is the primary account it belongs to. member_email is the primary
-- key, so a person can be a secondary on at most one account at a time.
CREATE TABLE IF NOT EXISTS account_member (
    member_email TEXT PRIMARY KEY,
    owner        TEXT NOT NULL,
    added_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_member_owner ON account_member(owner);

CREATE TABLE IF NOT EXISTS oauth_state (
    state      TEXT PRIMARY KEY,
    verifier   TEXT NOT NULL,
    nonce      TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '',   -- "app" (the OIDC provider login) | "council" (permit link)
    created_at TEXT NOT NULL
);

-- Guest passes: a link that lets a non-account person put one of a permitted set
-- of the account's registered cars onto a permit, for the day (or overnight).
CREATE TABLE IF NOT EXISTS guest_grant (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    owner           TEXT NOT NULL,             -- account (primary owner) that created it
    permit_id       INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    label           TEXT NOT NULL DEFAULT '',
    allow_overnight INTEGER NOT NULL DEFAULT 0,
    allow_plate     INTEGER NOT NULL DEFAULT 0,  -- visitor may type an arbitrary plate
    on_screen       INTEGER NOT NULL DEFAULT 0,  -- ephemeral QR grant (hidden from the pass list)
    request_only    INTEGER NOT NULL DEFAULT 0,  -- printed QR: scanning only REQUESTS; holder must approve
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_guest_grant_owner ON guest_grant(owner);

-- The cars a grant is allowed to activate (all belong to the grant's owner).
CREATE TABLE IF NOT EXISTS guest_grant_vehicle (
    grant_id   INTEGER NOT NULL REFERENCES guest_grant(id) ON DELETE CASCADE,
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    PRIMARY KEY (grant_id, vehicle_id)
);

-- One row per recipient of a grant: the emailed link carries a random token, and
-- only its sha256 hash is stored here (the raw token is never persisted).
CREATE TABLE IF NOT EXISTS guest_token (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id        INTEGER NOT NULL REFERENCES guest_grant(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL DEFAULT '',
    token_hash      TEXT NOT NULL UNIQUE,
    token_sealed    TEXT NOT NULL DEFAULT '',   -- printed door QR only: the raw token, encrypted at rest, so the SAME code can be reprinted (inert artifact; a scan can only request approval)
    revoked_at      TEXT NOT NULL DEFAULT '',
    last_used_at    TEXT NOT NULL DEFAULT '',
    expires_at      TEXT NOT NULL DEFAULT '',   -- RFC3339 UTC; '' = never (persistent email link)
    created_at      TEXT NOT NULL,
    baseline_plate  TEXT NOT NULL DEFAULT '',   -- what was on the permit before this link's current run of activations ('' = unknown)
    baseline_until  TEXT NOT NULL DEFAULT ''    -- RFC3339 UTC end of that run's window; '' = no run captured
);
CREATE INDEX IF NOT EXISTS idx_guest_token_grant ON guest_token(grant_id);

-- A visitor's request to use a printed-QR permit: created inert on scan, it does
-- nothing until the account holder approves it live (the security boundary).
CREATE TABLE IF NOT EXISTS guest_request (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id     INTEGER NOT NULL REFERENCES guest_grant(id) ON DELETE CASCADE,
    owner        TEXT NOT NULL,             -- account owner (scopes approvals)
    permit_id    INTEGER NOT NULL,
    plate        TEXT NOT NULL,
    nonce        TEXT NOT NULL DEFAULT '',  -- per-request secret so the visitor can poll status without enumeration
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | denied
    requested_at TEXT NOT NULL,
    decided_at   TEXT NOT NULL DEFAULT '',
    until_at     TEXT NOT NULL DEFAULT ''   -- human when-it-ends, set on approval
);
CREATE INDEX IF NOT EXISTS idx_guest_request_owner ON guest_request(owner, status);

-- Per-account flags. guests_enabled is the global kill-switch for guest passes.
CREATE TABLE IF NOT EXISTS account_flags (
    owner          TEXT PRIMARY KEY,
    guests_enabled INTEGER NOT NULL DEFAULT 1
);

-- Durable notification outbox: a message is enqueued (composed + addressed) and a
-- worker delivers it with retry/backoff, so a send survives a restart and a failed
-- attempt is retried instead of dropped. Rows are purged after delivery.
CREATE TABLE IF NOT EXISTS outbox (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account       TEXT NOT NULL DEFAULT '',        -- owner the message concerns, so account deletion can purge it
    dedup_key     TEXT NOT NULL DEFAULT '',        -- idempotency; skip if a live/sent row shares a non-empty key
    recipients    TEXT NOT NULL DEFAULT '',        -- newline-separated email addresses
    ntfy_topic    TEXT NOT NULL DEFAULT '',
    ntfy_priority TEXT NOT NULL DEFAULT '',
    ntfy_tag      TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL,
    body          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending', -- pending | sent | dead
    attempts      INTEGER NOT NULL DEFAULT 0,
    next_attempt  TEXT NOT NULL,                   -- RFC3339 UTC; earliest next try
    last_error    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    sent_at       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox(status, next_attempt);
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
		`ALTER TABLE council_session ADD COLUMN password_sealed TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN end_date TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN status TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN expiry_reminded TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN permit_number TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN permit_type TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE notify_pref ADD COLUMN quiet_from INTEGER NOT NULL DEFAULT 22`,
		`ALTER TABLE notify_pref ADD COLUMN quiet_until INTEGER NOT NULL DEFAULT 6`,
		`ALTER TABLE vehicle ADD COLUMN color TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE vehicle ADD COLUMN email TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE guest_grant ADD COLUMN allow_plate INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE guest_grant ADD COLUMN on_screen INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE guest_grant ADD COLUMN request_only INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE guest_token ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE guest_token ADD COLUMN token_sealed TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN fail_streak INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE outbox ADD COLUMN account TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE override ADD COLUMN guest_token_id INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE guest_token ADD COLUMN baseline_plate TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE guest_token ADD COLUMN baseline_until TEXT NOT NULL DEFAULT ''`,
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
	// Rebuild `override` if it predates the ad-hoc-plate columns: SQLite cannot
	// relax vehicle_id's NOT NULL/foreign key in place, so redefine the table and
	// copy the rows. Nothing references override, so this is safe; foreign keys are
	// toggled off around it per the SQLite table-redefinition guidance.
	if has, err := s.columnExists("override", "registration"); err != nil {
		return err
	} else if !has {
		if err := s.rebuildOverrideTable(); err != nil {
			return fmt.Errorf("migrate override table: %w", err)
		}
	}
	return nil
}

// columnExists reports whether table has a column named col.
func (s *Store) columnExists(table, col string) (bool, error) {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}

// rebuildOverrideTable redefines override with a nullable vehicle_id and a
// registration column, preserving existing rows.
func (s *Store) rebuildOverrideTable() error {
	if _, err := s.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer s.db.Exec(`PRAGMA foreign_keys=ON`)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`CREATE TABLE override_new (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id    INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    vehicle_id   INTEGER REFERENCES vehicle(id) ON DELETE CASCADE,
    registration TEXT NOT NULL DEFAULT '',
    starts_at    TEXT NOT NULL,
    ends_at      TEXT,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
)`,
		`INSERT INTO override_new (id, permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at)
    SELECT id, permit_id, vehicle_id, '', starts_at, ends_at, created_by, created_at FROM override`,
		`DROP TABLE override`,
		`ALTER TABLE override_new RENAME TO override`,
		`CREATE INDEX IF NOT EXISTS idx_override_permit ON override(permit_id)`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

// ---- Vehicles ----

// ListVehicles returns every vehicle across all owners (used by the scheduler to
// map vehicle IDs to registrations for permits it reconciles).
func (s *Store) ListVehicles(ctx context.Context) ([]model.Vehicle, error) {
	return s.queryVehicles(ctx, `SELECT id, registration, label, email, color FROM vehicle ORDER BY label, registration`)
}

// VehicleRef is a vehicle plus its owner, used by the scheduler to resolve a
// permit's scheduled vehicle_id ONLY against vehicles owned by that permit's
// owner (defence-in-depth against a rule/override that references a foreign id).
type VehicleRef struct {
	ID           int64
	Owner        string
	Registration string
	Label        string
}

// ListVehicleRefs returns every vehicle with its owner, for owner-scoped
// resolution in the scheduler.
func (s *Store) ListVehicleRefs(ctx context.Context) ([]VehicleRef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, owner, registration, label FROM vehicle`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VehicleRef
	for rows.Next() {
		var v VehicleRef
		if err := rows.Scan(&v.ID, &v.Owner, &v.Registration, &v.Label); err != nil {
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
		`SELECT id, registration, label, email, color FROM vehicle WHERE owner = ? ORDER BY label, registration`, owner)
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
		if err := rows.Scan(&v.ID, &v.Registration, &v.Label, &v.Email, &v.Color); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// vehiclePalette is a small, accessible categorical palette. A vehicle's colour
// is assigned ONCE at creation and stored, so the same car reads identically
// everywhere and adding/removing other cars never re-colours it.
var vehiclePalette = []string{
	"#2f6feb", "#127a49", "#b54708", "#7a5af8",
	"#0e7490", "#be185d", "#4d7c0f", "#9333ea",
}

// pickVehicleColor returns the first palette colour not already used by this
// owner, so a household's cars stay visually distinct; once the palette is
// exhausted it wraps by count (unavoidable collision, but stable).
func pickVehicleColor(used map[string]bool) string {
	for _, c := range vehiclePalette {
		if !used[c] {
			return c
		}
	}
	return vehiclePalette[len(used)%len(vehiclePalette)]
}

func (s *Store) CreateVehicle(ctx context.Context, owner, registration, label string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Assign a stable colour: the first palette entry this owner isn't using yet.
	used := map[string]bool{}
	rows, err := tx.QueryContext(ctx, `SELECT color FROM vehicle WHERE owner = ? AND color != ''`, owner)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return 0, err
		}
		used[c] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO vehicle (owner, registration, label, color, created_at) VALUES (?, ?, ?, ?, ?)`,
		owner, registration, label, pickVehicleColor(used), nowUTC())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return 0, ErrDuplicate
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// BackfillVehicleColors assigns a stored colour to any vehicle still missing one
// (pre-migration rows), preserving each owner's CURRENT on-screen colours: it
// walks their vehicles in the same order the UI lists them (label, registration)
// and hands out palette colours in that order. Idempotent — a no-op once done.
func (s *Store) BackfillVehicleColors(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner FROM vehicle WHERE color = '' ORDER BY owner, label, registration`)
	if err != nil {
		return err
	}
	type ov struct {
		id    int64
		owner string
	}
	var todo []ov
	for rows.Next() {
		var r ov
		if err := rows.Scan(&r.id, &r.owner); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	i, prev := 0, ""
	for _, r := range todo {
		if r.owner != prev {
			i, prev = 0, r.owner
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE vehicle SET color = ? WHERE id = ?`,
			vehiclePalette[i%len(vehiclePalette)], r.id); err != nil {
			return err
		}
		i++
	}
	return nil
}

// SetVehicleEmail sets (or clears) the optional driver email on a vehicle,
// scoped to its owner.
func (s *Store) SetVehicleEmail(ctx context.Context, owner string, id int64, email string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE vehicle SET email = ? WHERE id = ? AND owner = ?`, email, id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
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
		`SELECT `+permitCols+` FROM permit ORDER BY label, council_permit_id`)
}

// ListPermitsFor returns the permits owned by one app user.
func (s *Store) ListPermitsFor(ctx context.Context, owner string) ([]model.Permit, error) {
	return s.queryPermits(ctx,
		`SELECT `+permitCols+` FROM permit WHERE owner = ? ORDER BY label, council_permit_id`, owner)
}

// permitCols is the column list backing scanPermit; keep the two in lockstep.
const permitCols = `id, owner, council_permit_id, permit_type_id, label, active_registration, end_date, status, expiry_reminded, permit_number, permit_type`

// scanPermit reads one permit row (permitCols order), parsing the stored strings.
func scanPermit(sc interface{ Scan(...any) error }) (model.Permit, error) {
	var p model.Permit
	var endDate, reminded string
	err := sc.Scan(&p.ID, &p.Owner, &p.CouncilPermitID, &p.PermitTypeID, &p.Label,
		&p.ActiveRegistration, &endDate, &p.Status, &reminded, &p.PermitNumber, &p.PermitType)
	if err != nil {
		return p, err
	}
	if endDate != "" {
		p.EndDate, _ = time.Parse(time.RFC3339, endDate)
	}
	p.ExpiryReminded = reminded == "1"
	return p, nil
}

func (s *Store) queryPermits(ctx context.Context, query string, args ...any) ([]model.Permit, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Permit
	for rows.Next() {
		p, err := scanPermit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPermit(ctx context.Context, id int64) (model.Permit, error) {
	p, err := scanPermit(s.db.QueryRowContext(ctx,
		`SELECT `+permitCols+` FROM permit WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// PermitByCouncilID looks up a permit by its globally-unique council permit id,
// so a caller can check whether it is already managed (and by whom) before
// claiming it. Returns ErrNotFound when no row exists.
func (s *Store) PermitByCouncilID(ctx context.Context, councilPermitID string) (model.Permit, error) {
	p, err := scanPermit(s.db.QueryRowContext(ctx,
		`SELECT `+permitCols+` FROM permit WHERE council_permit_id = ?`, councilPermitID))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// UpsertPermit inserts a permit, or refreshes the type of one the SAME owner
// already holds. It never reassigns ownership: the ON CONFLICT update is guarded
// by owner, so one user can never take over another user's permit row by
// re-submitting its council permit id. Callers must confirm the permit belongs
// to the owner's council account first (see addPermit); this is the last line of
// defence. The label is only set on first insert — re-adding a permit keeps any
// name the user has since chosen (see SetPermitLabel). Returns the row id.
func (s *Store) UpsertPermit(ctx context.Context, owner, councilPermitID, permitTypeID, label string) (int64, error) {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO permit (owner, council_permit_id, permit_type_id, label, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(council_permit_id) DO UPDATE SET
    permit_type_id = excluded.permit_type_id,
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

// UpdatePermitMeta writes the expiry and status pulled from the council record.
// If the expiry date changes (a renewal, or a first read), the expiry-reminded
// flag is cleared so the approaching-expiry reminder re-arms for the new date.
// Owner-scoped and a no-op if the permit isn't the owner's.
func (s *Store) UpdatePermitMeta(ctx context.Context, owner, councilPermitID, status, permitNumber, permitType string, endDate time.Time) error {
	var ed string
	if !endDate.IsZero() {
		ed = endDate.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE permit
SET status = ?, end_date = ?, permit_number = ?, permit_type = ?,
    expiry_reminded = CASE WHEN end_date = ? THEN expiry_reminded ELSE '' END,
    updated_at = ?
WHERE council_permit_id = ? AND owner = ?`,
		status, ed, permitNumber, permitType, ed, nowUTC(), councilPermitID, owner)
	return err
}

// MarkPermitExpiryReminded records that an approaching-expiry reminder has gone
// out for the permit's current end date, so it isn't sent again until the date
// changes (see UpdatePermitMeta, which clears the flag on renewal).
func (s *Store) MarkPermitExpiryReminded(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET expiry_reminded = '1' WHERE id = ?`, id)
	return err
}

// SetPermitLabel renames a permit (owner-scoped) to a name the user chooses, shown
// everywhere the permit appears. Returns ErrNotFound if it isn't the owner's.
func (s *Store) SetPermitLabel(ctx context.Context, owner string, id int64, label string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE permit SET label = ?, updated_at = ? WHERE id = ? AND owner = ?`,
		label, nowUTC(), id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// BumpFailStreak increments a permit's consecutive-failure counter (persisted so
// a restart doesn't reset the grace window before a failure is escalated) and
// returns the new value. ClearFailStreak resets it after a success.
func (s *Store) BumpFailStreak(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`UPDATE permit SET fail_streak = fail_streak + 1 WHERE id = ? RETURNING fail_streak`, id).Scan(&n)
	return n, err
}

func (s *Store) ClearFailStreak(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE permit SET fail_streak = 0 WHERE id = ? AND fail_streak != 0`, id)
	return err
}

func (s *Store) SetPermitActive(ctx context.Context, id int64, registration string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE permit SET active_registration = ?, updated_at = ? WHERE id = ?`,
		registration, nowUTC(), id)
	return err
}

// DeletePermit stops administering one permit: it removes the permit row (its
// weekly_rule + override schedule cascade via ON DELETE CASCADE) plus the
// apply-log history and notify bookkeeping, neither of which has an FK cascade.
// Scoped to owner, and returns ErrNotFound if no such permit belongs to them, so
// a member can only remove a permit their own account manages. The council
// permit itself is untouched — p.stonn simply stops changing its plate.
func (s *Store) DeletePermit(ctx context.Context, id int64, owner string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM permit WHERE id = ? AND owner = ?`, id, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM apply_log WHERE permit_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM permit_notify WHERE permit_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
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

// CopySchedule REPLACES a permit's weekly roster and active/upcoming overrides
// with a copy of another permit's — the "I renewed my permit and re-added it, put
// my schedule back" flow. Both permits must belong to owner. It clears the
// target's existing rules and live overrides first, so it is idempotent (running
// it twice yields the same result, not duplicates) and matches the "replaces this
// permit's schedule" wording in the UI. Overrides that have already ended are not
// carried (nothing left to apply); the target's past overrides are left as
// history. Vehicle references are account-scoped, so they stay valid on the
// target. Returns the number of rules + overrides copied.
func (s *Store) CopySchedule(ctx context.Context, owner string, srcID, dstID int64, now time.Time) (int, error) {
	if srcID == dstID {
		return 0, errors.New("store: cannot copy a schedule onto itself")
	}
	nowStr := now.UTC().Format(time.RFC3339)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Both permits must belong to the owner (defence in depth over the handler).
	var owned int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM permit WHERE id IN (?, ?) AND owner = ?`, srcID, dstID, owner).Scan(&owned); err != nil {
		return 0, err
	}
	if owned != 2 {
		return 0, ErrNotFound
	}

	// Clear the target's current roster + live overrides so this is a clean replace.
	if _, err := tx.ExecContext(ctx, `DELETE FROM weekly_rule WHERE permit_id = ?`, dstID); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM override WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)`, dstID, nowStr); err != nil {
		return 0, err
	}

	rres, err := tx.ExecContext(ctx, `
INSERT INTO weekly_rule (permit_id, weekday, vehicle_id)
SELECT ?, weekday, vehicle_id FROM weekly_rule WHERE permit_id = ?`, dstID, srcID)
	if err != nil {
		return 0, err
	}
	ores, err := tx.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at)
SELECT ?, vehicle_id, registration, starts_at, ends_at, created_by, created_at
FROM override WHERE permit_id = ? AND (ends_at IS NULL OR ends_at > ?)`,
		dstID, srcID, nowStr)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	rn, _ := rres.RowsAffected()
	on, _ := ores.RowsAffected()
	return int(rn + on), nil
}

// ---- Overrides ----

func (s *Store) CreateOverride(ctx context.Context, permitID, vehicleID int64, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	return s.CreateGuestOverride(ctx, permitID, vehicleID, startsAt, endsAt, createdBy, 0)
}

// CreateGuestOverride is CreateOverride tagged with the guest link that made it,
// so a guest's revert can remove exactly their own changes.
func (s *Store) CreateGuestOverride(ctx context.Context, permitID, vehicleID int64, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
VALUES (?, ?, '', ?, ?, ?, ?, ?)`,
		permitID, vehicleID, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), guestTokenID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// CreatePlateOverride books a one-off using a literal, unsaved number plate
// (vehicle_id IS NULL). The plate is normalised by the caller.
func (s *Store) CreatePlateOverride(ctx context.Context, permitID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string) (int64, error) {
	return s.CreateGuestPlateOverride(ctx, permitID, registration, startsAt, endsAt, createdBy, 0)
}

// CreateGuestPlateOverride is CreatePlateOverride tagged with the guest link
// that made it (see CreateGuestOverride).
func (s *Store) CreateGuestPlateOverride(ctx context.Context, permitID int64, registration string, startsAt time.Time, endsAt *time.Time, createdBy string, guestTokenID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO override (permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
VALUES (?, NULL, ?, ?, ?, ?, ?, ?)`,
		permitID, registration, startsAt.UTC().Format(time.RFC3339), endsAtSQL(endsAt), createdBy, nowUTC(), guestTokenID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteGuestOverrides removes every override a guest link created on a permit
// (the sweep behind a guest's "put it back" revert). A zero tokenID is refused:
// it would match every non-guest override.
func (s *Store) DeleteGuestOverrides(ctx context.Context, permitID, guestTokenID int64) error {
	if guestTokenID == 0 {
		return errors.New("store: DeleteGuestOverrides requires a guest token id")
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM override WHERE permit_id = ? AND guest_token_id = ?`, permitID, guestTokenID)
	return err
}

func endsAtSQL(endsAt *time.Time) sql.NullString {
	if endsAt == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: endsAt.UTC().Format(time.RFC3339), Valid: true}
}

// ListOverrides returns a permit's active and upcoming overrides (those not yet
// ended, however far in the future), soonest first, a chronological list the
// user can scan and manage.
func (s *Store) ListOverrides(ctx context.Context, permitID int64, now time.Time) ([]model.Override, error) {
	nowStr := now.UTC().Format(time.RFC3339)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at
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
		var starts, created string
		var ends sql.NullString
		var vid sql.NullInt64
		if err := rows.Scan(&o.ID, &o.PermitID, &vid, &o.Registration, &starts, &ends, &o.CreatedBy, &created); err != nil {
			return nil, err
		}
		o.VehicleID = vid.Int64 // 0 when NULL (an ad-hoc plate)
		if o.StartsAt, err = time.Parse(time.RFC3339, starts); err != nil {
			return nil, err
		}
		if o.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
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

// ActiveGuestOverridePlate returns the registration of the currently-active
// override this guest link created on a permit (started, not yet ended), newest
// first, and whether one exists. Used to decide whether a guest's "put it back"
// revert is still meaningful: if the link no longer has a live override, the
// guest's activation has already been superseded (e.g. by a later owner booking)
// and revert must not be offered — reverting would displace that booking.
func (s *Store) ActiveGuestOverridePlate(ctx context.Context, permitID, guestTokenID int64, now time.Time) (string, bool) {
	if guestTokenID == 0 {
		return "", false
	}
	var reg string
	err := s.db.QueryRowContext(ctx, `
SELECT registration FROM override
WHERE permit_id = ? AND guest_token_id = ? AND registration != ''
  AND starts_at <= ? AND (ends_at IS NULL OR ends_at > ?)
ORDER BY created_at DESC, id DESC LIMIT 1`,
		permitID, guestTokenID, now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)).Scan(&reg)
	if err != nil {
		return "", false
	}
	return reg, reg != ""
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
	// Notification prefs are per-person: drop this account owner's own row AND the
	// rows of its secondaries (still present in account_member at this point), so a
	// deleted account leaves no member's channel prefs behind.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM notify_pref WHERE owner = ? OR owner IN (SELECT member_email FROM account_member WHERE owner = ?)`,
		owner, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM consent WHERE owner = ?`, owner); err != nil {
		return err
	}
	// Guest passes / door QRs (cascades their tokens, vehicle joins and requests via
	// FK) and the per-account guest flags, so a deleted account leaves nothing behind
	// that could still resolve a token, and drops off the outage-notify roster.
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_grant WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_request WHERE owner = ?`, owner); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_flags WHERE owner = ?`, owner); err != nil {
		return err
	}
	// Queued/sent/dead notifications about this account (they carry the user's email
	// and plate), so nothing pending is delivered to a deleted user and no PII lingers.
	if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE account = ?`, owner); err != nil {
		return err
	}
	// Remove this account's secondary members, and any membership this user held.
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_member WHERE owner = ? OR member_email = ?`, owner, owner); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- Account members (shared access) ----

// AccountMember is a secondary email with access to a primary's account.
type AccountMember struct {
	Email   string
	AddedAt time.Time
}

// MemberAccount returns the primary account owner that memberEmail is a secondary
// of, or ok=false when they are their own account.
func (s *Store) MemberAccount(ctx context.Context, memberEmail string) (owner string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT owner FROM account_member WHERE member_email = ?`, memberEmail).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return owner, true, nil
}

// AccountEmails returns every email that should be notified for an account: the
// owner plus any secondaries. Always includes the owner, even if listing the
// secondaries fails.
func (s *Store) AccountEmails(ctx context.Context, owner string) ([]string, error) {
	emails := []string{owner}
	ms, err := s.ListMembers(ctx, owner)
	if err != nil {
		return emails, err
	}
	for _, m := range ms {
		emails = append(emails, m.Email)
	}
	return emails, nil
}

// AdminAccount is a per-owner operational summary for the admin dashboard and the
// machine-readable status endpoint the outage watchdog polls.
type AdminAccount struct {
	Owner           string
	MemberOf        string    // non-empty: this owner is a secondary on another account
	Linked          bool      // has a stored council session cookie
	LinkedAt        time.Time // last interactive link (the re-authorise clock start)
	WarmedAt        time.Time // last keep-warm / refresh (council_session.updated_at)
	TokenExpiry     time.Time
	EmailEnabled    bool
	NtfyEnabled     bool
	NtfyTopic       string
	ConsentVersion  string
	PermitCount     int
	MemberCount     int
	Plates          []string // active plate on each managed permit
	LastApplyAt     time.Time
	LastApplyStatus string // status of the most recent apply_log row for the account
}

// AdminAccounts returns an operational summary for every known account (anyone who
// has consented, linked the council, holds a permit, or set notify prefs), newest
// council activity aside. It is read-only and owner-agnostic — callers must gate it
// to admins.
func (s *Store) AdminAccounts(ctx context.Context) ([]AdminAccount, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT o.owner,
  COALESCE((SELECT owner FROM account_member WHERE member_email = o.owner LIMIT 1), ''),
  COALESCE(cs.cookie_sealed, ''), COALESCE(cs.linked_at, ''), COALESCE(cs.updated_at, ''), COALESCE(cs.token_expiry, ''),
  COALESCE(np.email_enabled, 1), COALESCE(np.ntfy_enabled, 0), COALESCE(np.ntfy_topic, ''),
  COALESCE((SELECT version FROM consent c WHERE c.owner = o.owner ORDER BY id DESC LIMIT 1), ''),
  (SELECT COUNT(*) FROM permit p WHERE p.owner = o.owner),
  (SELECT COUNT(*) FROM account_member m WHERE m.owner = o.owner),
  COALESCE((SELECT al.status FROM apply_log al JOIN permit p ON p.id = al.permit_id WHERE p.owner = o.owner ORDER BY al.id DESC LIMIT 1), ''),
  COALESCE((SELECT al.at     FROM apply_log al JOIN permit p ON p.id = al.permit_id WHERE p.owner = o.owner ORDER BY al.id DESC LIMIT 1), '')
FROM (
  SELECT owner FROM council_session
  UNION SELECT owner FROM permit
  UNION SELECT owner FROM consent
  UNION SELECT owner FROM notify_pref
) o
LEFT JOIN council_session cs ON cs.owner = o.owner
LEFT JOIN notify_pref np ON np.owner = o.owner
ORDER BY o.owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminAccount
	byOwner := map[string]*AdminAccount{}
	for rows.Next() {
		var a AdminAccount
		var cookie, linked, warmed, expiry, lastAt string
		var emailEn, ntfyEn int
		if err := rows.Scan(&a.Owner, &a.MemberOf, &cookie, &linked, &warmed, &expiry,
			&emailEn, &ntfyEn, &a.NtfyTopic, &a.ConsentVersion, &a.PermitCount, &a.MemberCount,
			&a.LastApplyStatus, &lastAt); err != nil {
			return nil, err
		}
		a.Linked = cookie != ""
		a.EmailEnabled = emailEn == 1
		a.NtfyEnabled = ntfyEn == 1
		a.LinkedAt, _ = time.Parse(time.RFC3339, linked)
		a.WarmedAt, _ = time.Parse(time.RFC3339, warmed)
		a.TokenExpiry, _ = time.Parse(time.RFC3339, expiry)
		a.LastApplyAt, _ = time.Parse(time.RFC3339, lastAt)
		out = append(out, a)
		byOwner[a.Owner] = &out[len(out)-1]
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Fold in each account's active plates in a single extra query.
	prows, err := s.db.QueryContext(ctx,
		`SELECT owner, active_registration FROM permit WHERE active_registration != '' ORDER BY owner, id`)
	if err != nil {
		return nil, err
	}
	defer prows.Close()
	for prows.Next() {
		var owner, reg string
		if err := prows.Scan(&owner, &reg); err != nil {
			return nil, err
		}
		if a := byOwner[owner]; a != nil {
			a.Plates = append(a.Plates, reg)
		}
	}
	return out, prows.Err()
}

// RosterEntry is one account's outage-notification contact.
type RosterEntry struct {
	Email string `json:"email"`
	Ntfy  string `json:"ntfy,omitempty"` // topic, only when ntfy is enabled
}

// NotifyRoster returns the contact list an outage watchdog would use: every
// consented account, with its ntfy topic when enabled. Email is the baseline
// channel, so it is always the account email.
func (s *Store) NotifyRoster(ctx context.Context) ([]RosterEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.owner,
  CASE WHEN COALESCE(np.ntfy_enabled,0)=1 THEN COALESCE(np.ntfy_topic,'') ELSE '' END
FROM (SELECT DISTINCT owner FROM consent) c
LEFT JOIN notify_pref np ON np.owner = c.owner
ORDER BY c.owner`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RosterEntry
	for rows.Next() {
		var e RosterEntry
		if err := rows.Scan(&e.Email, &e.Ntfy); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListMembers returns the secondaries with access to owner's account, oldest first.
func (s *Store) ListMembers(ctx context.Context, owner string) ([]AccountMember, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT member_email, added_at FROM account_member WHERE owner = ? ORDER BY added_at`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountMember
	for rows.Next() {
		var m AccountMember
		var at string
		if err := rows.Scan(&m.Email, &at); err != nil {
			return nil, err
		}
		m.AddedAt, _ = time.Parse(time.RFC3339, at)
		out = append(out, m)
	}
	return out, rows.Err()
}

// CountMembers returns how many secondaries owner's account already has.
func (s *Store) CountMembers(ctx context.Context, owner string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM account_member WHERE owner = ?`, owner).Scan(&n)
	return n, err
}

// AddMember grants memberEmail access to owner's account. It fails if memberEmail
// already has access somewhere (member_email is unique); callers enforce the
// per-account cap and the not-self / not-a-primary checks.
func (s *Store) AddMember(ctx context.Context, owner, memberEmail string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO account_member (member_email, owner, added_at) VALUES (?, ?, ?)`,
		memberEmail, owner, nowUTC())
	return err
}

// ErrMemberLimit means the account already has the maximum number of secondaries.
var ErrMemberLimit = errors.New("store: shared-access member limit reached")

// AddMemberCapped adds a secondary only if the account is below max, atomically:
// the count check and insert are one statement, so concurrent adds can't slip
// past the cap. Returns ErrMemberLimit when full, or the underlying error (e.g. a
// unique-constraint violation when the email is already a member somewhere).
func (s *Store) AddMemberCapped(ctx context.Context, owner, memberEmail string, max int) error {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO account_member (member_email, owner, added_at)
SELECT ?, ?, ?
WHERE (SELECT COUNT(1) FROM account_member WHERE owner = ?) < ?`,
		memberEmail, owner, nowUTC(), owner, max)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrMemberLimit
	}
	return nil
}

// RemoveMember revokes a secondary's access, scoped to the owner so one account
// cannot remove another's member.
func (s *Store) RemoveMember(ctx context.Context, owner, memberEmail string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM account_member WHERE member_email = ? AND owner = ?`, memberEmail, owner); err != nil {
		return err
	}
	// Their personal notification prefs go with their access.
	_, err := s.db.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, memberEmail)
	return err
}

// RemoveMembership lets a secondary leave whatever account they belong to.
func (s *Store) RemoveMembership(ctx context.Context, memberEmail string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM account_member WHERE member_email = ?`, memberEmail); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM notify_pref WHERE owner = ?`, memberEmail)
	return err
}

// IsPrimary reports whether owner is a primary of any shared account (has at
// least one secondary). Used to stop a primary being added as someone's
// secondary while people still depend on their account.
func (s *Store) IsPrimary(ctx context.Context, owner string) (bool, error) {
	n, err := s.CountMembers(ctx, owner)
	return n > 0, err
}

// HasOwnData reports whether email already runs their own p.stonn account, i.e.
// has a linked council session, a managed permit, or a saved vehicle. Adding
// such a person as a secondary would hide their own setup, so the caller blocks
// it. A brand-new user who has only signed in (no data yet) returns false.
func (s *Store) HasOwnData(ctx context.Context, email string) (bool, error) {
	var has int
	err := s.db.QueryRowContext(ctx, `SELECT
        EXISTS(SELECT 1 FROM council_session WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM permit WHERE owner = ?)
     OR EXISTS(SELECT 1 FROM vehicle WHERE owner = ?)`,
		email, email, email).Scan(&has)
	return has == 1, err
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
		p.Owner, b2i(p.EmailEnabled), b2i(p.NtfyEnabled), p.NtfyTopic, b2i(p.FailuresOnly), p.QuietFrom, p.QuietUntil)
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
	if it.DedupKey != "" {
		var exists int
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM outbox
			  WHERE dedup_key = ?
			    AND (status = 'pending' OR (status = 'sent' AND sent_at > ?)))`,
			it.DedupKey, time.Now().Add(-outboxDedupWindow).UTC().Format(time.RFC3339)).
			Scan(&exists); err != nil {
			return err
		}
		if exists == 1 {
			return nil
		}
	}
	now := nowUTC()
	// next_attempt defaults to now, or NotBefore when the caller defers delivery
	// (quiet hours). created_at stays "now" so ordering/purge use the real time.
	nextAttempt := now
	if !it.NotBefore.IsZero() && it.NotBefore.After(time.Now()) {
		nextAttempt = it.NotBefore.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO outbox (account, dedup_key, recipients, ntfy_topic, ntfy_priority, ntfy_tag, subject, body, status, attempts, next_attempt, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?)`,
		it.Account, it.DedupKey, strings.Join(it.Recipients, "\n"), it.NtfyTopic, it.NtfyPriority, it.NtfyTag,
		it.Subject, it.Body, nextAttempt, now)
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

// ---- Guest passes ----

// GuestGrant is a link-based permission the account holder creates: it lets a
// non-account recipient put one of a permitted set of the account's cars onto a
// permit. Tokens (one per recipient) live in guest_token.
type GuestGrant struct {
	ID             int64
	Owner          string
	PermitID       int64
	Label          string
	AllowOvernight bool
	AllowPlate     bool // visitor may type an arbitrary plate (tradie / on-screen QR)
	RequestOnly    bool // printed QR: a scan only requests; the holder approves live
	Enabled        bool
	CreatedAt      time.Time
}

// GuestRequest is a visitor's pending/approved/denied request to use a
// printed-QR permit.
type GuestRequest struct {
	ID          int64
	GrantID     int64
	Owner       string
	PermitID    int64
	Plate       string
	Status      string // pending | approved | denied
	RequestedAt time.Time
	DecidedAt   time.Time // when the holder approved/denied ("" while pending)
	Until       string    // human "until …" text, set on approval
}

// GuestToken is one recipient's link to a grant; the raw token is never stored,
// only its hash.
type GuestToken struct {
	ID             int64
	GrantID        int64
	RecipientEmail string
	Revoked        bool
	CreatedAt      time.Time
}

// GuestRecipient is a (recipient, token-hash) pair passed to CreateGuestGrant;
// the caller generates the raw token, keeps it to build the link, and hands the
// store only the hash.
type GuestRecipient struct {
	Email     string
	TokenHash string
}

// GuestContext is everything the public activation page needs, resolved from a
// presented token hash. It is only returned when the token is live (not revoked),
// its grant enabled, and the owner's kill-switch on — otherwise ErrNotFound.
type GuestContext struct {
	Grant     GuestGrant
	TokenID   int64
	Recipient string
	Vehicles  []model.Vehicle
	// BaselinePlate is what was on the permit before this link's current run of
	// activations began ('' = unknown), and BaselineUntil is when that run's
	// window ends (zero = no run captured). Together they let the guest revert
	// their changes back to the pre-existing plate.
	BaselinePlate string
	BaselineUntil time.Time
}

// GuestGrantDetail is a grant with its allowed cars and recipient links, for the
// account holder's management UI.
type GuestGrantDetail struct {
	Grant    GuestGrant
	Vehicles []model.Vehicle
	Tokens   []GuestToken
}

// CreateGuestGrant creates a grant, its allowed-vehicle set, and one token per
// recipient, all in a transaction. Every vehicle must belong to owner (IDOR
// guard). Returns the new grant id.
func (s *Store) CreateGuestGrant(ctx context.Context, owner string, permitID int64, label string, allowOvernight bool, vehicleIDs []int64, recipients []GuestRecipient) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// The permit must belong to the owner.
	var permitOK int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&permitOK); err != nil {
		return 0, err
	}
	if permitOK == 0 {
		return 0, ErrNotFound
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)`,
		owner, permitID, label, boolInt(allowOvernight), nowUTC())
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, vid := range vehicleIDs {
		// Insert only if the vehicle belongs to the owner; a foreign id inserts
		// nothing rather than binding a stranger's car into the grant.
		r, err := tx.ExecContext(ctx,
			`INSERT INTO guest_grant_vehicle (grant_id, vehicle_id)
			 SELECT ?, ? WHERE EXISTS(SELECT 1 FROM vehicle WHERE id = ? AND owner = ?)`,
			grantID, vid, vid, owner)
		if err != nil {
			return 0, err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return 0, ErrNotFound
		}
	}
	for _, rc := range recipients {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO guest_token (grant_id, recipient_email, token_hash, created_at) VALUES (?, ?, ?, ?)`,
			grantID, rc.Email, rc.TokenHash, nowUTC()); err != nil {
			return 0, err
		}
	}
	return grantID, tx.Commit()
}

// UpdateGuestGrant changes a grant's label, overnight policy, and allowed-vehicle
// set (replacing it wholesale), scoped to owner. The permit is not changed — its
// tokens are bound to it. Every vehicle must belong to owner.
func (s *Store) UpdateGuestGrant(ctx context.Context, owner string, grantID int64, label string, allowOvernight bool, vehicleIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE guest_grant SET label = ?, allow_overnight = ? WHERE id = ? AND owner = ?`,
		label, boolInt(allowOvernight), grantID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM guest_grant_vehicle WHERE grant_id = ?`, grantID); err != nil {
		return err
	}
	for _, vid := range vehicleIDs {
		r, err := tx.ExecContext(ctx,
			`INSERT INTO guest_grant_vehicle (grant_id, vehicle_id)
			 SELECT ?, ? WHERE EXISTS(SELECT 1 FROM vehicle WHERE id = ? AND owner = ?)`,
			grantID, vid, vid, owner)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit()
}

// AddGuestTokens adds recipient tokens to an existing grant (scoped to owner),
// skipping any email that already has a live token on it. Returns the emails
// actually added, so the caller can email and display just those links.
func (s *Store) AddGuestTokens(ctx context.Context, owner string, grantID int64, recipients []GuestRecipient) ([]string, error) {
	var ok int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM guest_grant WHERE id = ? AND owner = ?)`, grantID, owner).Scan(&ok); err != nil {
		return nil, err
	}
	if ok == 0 {
		return nil, ErrNotFound
	}
	var added []string
	for _, rc := range recipients {
		var live int
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM guest_token WHERE grant_id = ? AND recipient_email = ? AND revoked_at = '')`,
			grantID, rc.Email).Scan(&live); err != nil {
			return added, err
		}
		if live == 1 {
			continue
		}
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO guest_token (grant_id, recipient_email, token_hash, created_at) VALUES (?, ?, ?, ?)`,
			grantID, rc.Email, rc.TokenHash, nowUTC()); err != nil {
			return added, err
		}
		added = append(added, rc.Email)
	}
	return added, nil
}

// ResetGuestToken issues a fresh link for one existing recipient of an emailed
// grant: it revokes their current token(s) and inserts a new one with newHash, so
// exactly one link is live per recipient. Used by the "re-send" action — the
// original link can't be re-sent (only its hash is stored), so re-sending
// necessarily supersedes it. Owner-scoped; ErrNotFound if the grant isn't the
// owner's or the recipient was never on it.
func (s *Store) ResetGuestToken(ctx context.Context, owner string, grantID int64, recipientEmail, newHash string) (permitID int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx,
		`SELECT permit_id FROM guest_grant WHERE id = ? AND owner = ? AND on_screen = 0 AND request_only = 0`,
		grantID, owner).Scan(&permitID)
	if err == sql.ErrNoRows {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	var wasRecipient int
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM guest_token WHERE grant_id = ? AND recipient_email = ?)`,
		grantID, recipientEmail).Scan(&wasRecipient); err != nil {
		return 0, err
	}
	if wasRecipient == 0 {
		return 0, ErrNotFound
	}
	// Drop the recipient's old token(s) and issue one fresh link, so the old link
	// dies and the recipient still shows exactly once in the management list. The
	// old link genuinely stops working — it can't be re-sent (hash-only storage).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_token WHERE grant_id = ? AND recipient_email = ?`,
		grantID, recipientEmail); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guest_token (grant_id, recipient_email, token_hash, created_at) VALUES (?, ?, ?, ?)`,
		grantID, recipientEmail, newHash, nowUTC()); err != nil {
		return 0, err
	}
	return permitID, tx.Commit()
}

// CreateQRGrant creates an ephemeral "on-screen QR" grant for a permit: it allows
// a visitor to type an arbitrary plate, has no saved cars or email recipients,
// and its single token expires after ttl. It is hidden from the pass list. Expired
// on-screen grants for the owner are pruned first so they do not accumulate.
// Returns the token hash to store (caller keeps the raw token for the QR URL).
func (s *Store) CreateQRGrant(ctx context.Context, owner string, permitID int64, tokenHash string, ttl time.Duration) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var permitOK int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&permitOK); err != nil {
		return 0, err
	}
	if permitOK == 0 {
		return 0, ErrNotFound
	}
	// Prune the owner's already-expired on-screen grants (cascades their tokens).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE owner = ? AND on_screen = 1
		 AND id IN (SELECT grant_id FROM guest_token WHERE expires_at != '' AND expires_at <= ?)`,
		owner, nowUTC()); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, allow_plate, on_screen, enabled, created_at)
		 VALUES (?, ?, 'Visitor QR', 0, 1, 1, 1, ?)`,
		owner, permitID, nowUTC())
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	expires := time.Now().UTC().Add(ttl).Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guest_token (grant_id, recipient_email, token_hash, expires_at, created_at) VALUES (?, '', ?, ?, ?)`,
		grantID, tokenHash, expires, nowUTC()); err != nil {
		return 0, err
	}
	return grantID, tx.Commit()
}

// PrintedGrant is a durable door-QR pass: one per permit, reprintable because its
// token is kept (sealed) so the SAME code can be shown again. TokenSealed is the
// raw token encrypted at rest; the caller opens it to rebuild the activation URL.
type PrintedGrant struct {
	GrantID     int64
	PermitID    int64
	PermitLabel string
	TokenSealed string
	CreatedAt   time.Time
}

// CreatePrintedGrant mints (or replaces) the printed door QR for a permit: it drops
// any existing printed grant for that permit and inserts a fresh one. tokenSealed is
// the raw token encrypted at rest so the same code can be reprinted later; tokenHash
// is the lookup key used when a visitor scans.
func (s *Store) CreatePrintedGrant(ctx context.Context, owner string, permitID int64, tokenHash, tokenSealed string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var permitOK int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM permit WHERE id = ? AND owner = ?)`, permitID, owner).Scan(&permitOK); err != nil {
		return 0, err
	}
	if permitOK == 0 {
		return 0, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE owner = ? AND permit_id = ? AND request_only = 1`, owner, permitID); err != nil {
		return 0, err
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO guest_grant (owner, permit_id, label, allow_overnight, allow_plate, on_screen, request_only, enabled, created_at)
		 VALUES (?, ?, 'Printed QR', 0, 1, 0, 1, 1, ?)`, owner, permitID, nowUTC())
	if err != nil {
		return 0, err
	}
	grantID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO guest_token (grant_id, recipient_email, token_hash, token_sealed, created_at) VALUES (?, '', ?, ?, ?)`,
		grantID, tokenHash, tokenSealed, nowUTC()); err != nil {
		return 0, err
	}
	return grantID, tx.Commit()
}

// PrintedGrantByID returns a single owner-scoped printed grant (for the reprint /
// poster view), including its sealed token so the URL can be rebuilt.
func (s *Store) PrintedGrantByID(ctx context.Context, owner string, grantID int64) (PrintedGrant, error) {
	var g PrintedGrant
	var created string
	err := s.db.QueryRowContext(ctx, `
SELECT g.id, g.permit_id, COALESCE(p.label, ''), t.token_sealed, g.created_at
FROM guest_grant g
JOIN permit p ON p.id = g.permit_id
JOIN guest_token t ON t.grant_id = g.id
WHERE g.id = ? AND g.owner = ? AND g.request_only = 1`, grantID, owner).
		Scan(&g.GrantID, &g.PermitID, &g.PermitLabel, &g.TokenSealed, &created)
	if err == sql.ErrNoRows {
		return PrintedGrant{}, ErrNotFound
	}
	if err != nil {
		return PrintedGrant{}, err
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return g, nil
}

// PrintedGrantForPermit returns the existing door QR for a permit, or ErrNotFound —
// so creating one can be idempotent (reuse rather than rotate the token).
func (s *Store) PrintedGrantForPermit(ctx context.Context, owner string, permitID int64) (PrintedGrant, error) {
	var g PrintedGrant
	var created string
	err := s.db.QueryRowContext(ctx, `
SELECT g.id, g.permit_id, COALESCE(p.label, ''), t.token_sealed, g.created_at
FROM guest_grant g
JOIN permit p ON p.id = g.permit_id
JOIN guest_token t ON t.grant_id = g.id
WHERE g.owner = ? AND g.permit_id = ? AND g.request_only = 1`, owner, permitID).
		Scan(&g.GrantID, &g.PermitID, &g.PermitLabel, &g.TokenSealed, &created)
	if err == sql.ErrNoRows {
		return PrintedGrant{}, ErrNotFound
	}
	if err != nil {
		return PrintedGrant{}, err
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return g, nil
}

// ListPrintedGrants returns an owner's durable door QRs, newest first, for the
// management list on the Guests page.
func (s *Store) ListPrintedGrants(ctx context.Context, owner string) ([]PrintedGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT g.id, g.permit_id, COALESCE(p.label, ''), t.token_sealed, g.created_at
FROM guest_grant g
JOIN permit p ON p.id = g.permit_id
JOIN guest_token t ON t.grant_id = g.id
WHERE g.owner = ? AND g.request_only = 1
ORDER BY g.id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrintedGrant
	for rows.Next() {
		var g PrintedGrant
		var created string
		if err := rows.Scan(&g.GrantID, &g.PermitID, &g.PermitLabel, &g.TokenSealed, &created); err != nil {
			return nil, err
		}
		g.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokePrintedGrant deletes an owner's door QR (cascading its token and any pending
// requests), retiring the printed code for good.
func (s *Store) RevokePrintedGrant(ctx context.Context, owner string, grantID int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM guest_grant WHERE id = ? AND owner = ? AND request_only = 1`, grantID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateGuestRequest records a pending request from a printed-QR scan. nonce is a
// per-request secret the visitor keeps, so they can poll its status without being
// able to read other requests.
// CreateGuestRequest records a pending printed-QR request, or reuses an existing
// still-pending one for the same grant+plate so a double-scan/submit doesn't stack
// duplicate requests (and duplicate approval nudges). Returns the request id, the
// effective nonce (the reused row's, so its status page keeps working), and
// whether a NEW request was created (the caller only notifies when it did).
func (s *Store) CreateGuestRequest(ctx context.Context, grantID, permitID int64, owner, plate, nonce string) (id int64, effNonce string, created bool, err error) {
	var existingID int64
	var existingNonce string
	e := s.db.QueryRowContext(ctx,
		`SELECT id, nonce FROM guest_request WHERE grant_id = ? AND plate = ? AND status = 'pending' ORDER BY id DESC LIMIT 1`,
		grantID, plate).Scan(&existingID, &existingNonce)
	if e == nil {
		return existingID, existingNonce, false, nil
	}
	if e != sql.ErrNoRows {
		return 0, "", false, e
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO guest_request (grant_id, owner, permit_id, plate, nonce, status, requested_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)`,
		grantID, owner, permitID, plate, nonce, nowUTC())
	if err != nil {
		return 0, "", false, err
	}
	id, err = res.LastInsertId()
	return id, nonce, true, err
}

// GuestRequestForPoll returns a request only if the nonce matches — the visitor's
// status check, safe against request-id enumeration.
func (s *Store) GuestRequestForPoll(ctx context.Context, id int64, nonce string) (GuestRequest, error) {
	var r GuestRequest
	var requested, decided string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, decided_at, until_at FROM guest_request WHERE id = ? AND nonce = ? AND nonce != ''`, id, nonce).
		Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.Status, &requested, &decided, &r.Until)
	if err == sql.ErrNoRows {
		return GuestRequest{}, ErrNotFound
	}
	if err != nil {
		return GuestRequest{}, err
	}
	r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
	r.DecidedAt, _ = time.Parse(time.RFC3339, decided)
	return r, nil
}

// GuestRequestByID returns a request (used by the visitor's polling status page).
func (s *Store) GuestRequestByID(ctx context.Context, id int64) (GuestRequest, error) {
	var r GuestRequest
	var requested string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, until_at FROM guest_request WHERE id = ?`, id).
		Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.Status, &requested, &r.Until)
	if err == sql.ErrNoRows {
		return GuestRequest{}, ErrNotFound
	}
	if err != nil {
		return GuestRequest{}, err
	}
	r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
	return r, nil
}

// ListPendingRequests returns an owner's still-pending printed-QR requests, newest
// first (the approvals queue).
func (s *Store) ListPendingRequests(ctx context.Context, owner string) ([]GuestRequest, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, owner, permit_id, plate, status, requested_at, until_at FROM guest_request
		 WHERE owner = ? AND status = 'pending' ORDER BY id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestRequest
	for rows.Next() {
		var r GuestRequest
		var requested string
		if err := rows.Scan(&r.ID, &r.GrantID, &r.Owner, &r.PermitID, &r.Plate, &r.Status, &requested, &r.Until); err != nil {
			return nil, err
		}
		r.RequestedAt, _ = time.Parse(time.RFC3339, requested)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideGuestRequest approves or denies a pending request, scoped to owner. It
// returns the request (so the caller can apply the plate on approval) or
// ErrNotFound if it is not the owner's or no longer pending.
func (s *Store) DecideGuestRequest(ctx context.Context, owner string, id int64, approve bool, until string) (GuestRequest, error) {
	status := "denied"
	if approve {
		status = "approved"
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE guest_request SET status = ?, decided_at = ?, until_at = ?
		 WHERE id = ? AND owner = ? AND status = 'pending'`,
		status, nowUTC(), until, id, owner)
	if err != nil {
		return GuestRequest{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return GuestRequest{}, ErrNotFound
	}
	return s.GuestRequestByID(ctx, id)
}

// GuestContextByTokenHash resolves a presented token hash to the grant, recipient
// and allowed vehicles — only if the token is live, its grant enabled, and the
// owner's guest passes are not globally paused. Any failed gate returns
// ErrNotFound so the caller can show one neutral "no longer active" page.
func (s *Store) GuestContextByTokenHash(ctx context.Context, tokenHash string) (GuestContext, error) {
	var gc GuestContext
	var created, blUntil string
	var overnight, plate, reqOnly, enabled int
	err := s.db.QueryRowContext(ctx, `
SELECT t.id, t.recipient_email, g.id, g.owner, g.permit_id, g.label, g.allow_overnight, g.allow_plate, g.request_only, g.enabled, g.created_at, t.baseline_plate, t.baseline_until
FROM guest_token t
JOIN guest_grant g ON g.id = t.grant_id
WHERE t.token_hash = ? AND t.revoked_at = '' AND g.enabled = 1
  AND (t.expires_at = '' OR t.expires_at > ?)
  AND COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = g.owner), 1) = 1`,
		tokenHash, nowUTC()).Scan(&gc.TokenID, &gc.Recipient, &gc.Grant.ID, &gc.Grant.Owner, &gc.Grant.PermitID,
		&gc.Grant.Label, &overnight, &plate, &reqOnly, &enabled, &created, &gc.BaselinePlate, &blUntil)
	if err == sql.ErrNoRows {
		return GuestContext{}, ErrNotFound
	}
	if err != nil {
		return GuestContext{}, err
	}
	gc.Grant.AllowOvernight = overnight == 1
	gc.Grant.AllowPlate = plate == 1
	gc.Grant.RequestOnly = reqOnly == 1
	gc.Grant.Enabled = enabled == 1
	if gc.Grant.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
		return GuestContext{}, err
	}
	if blUntil != "" {
		// A malformed timestamp reads as "no baseline" rather than failing the link.
		gc.BaselineUntil, _ = time.Parse(time.RFC3339, blUntil)
	}
	gc.Vehicles, err = s.queryVehicles(ctx, `
SELECT v.id, v.registration, v.label, v.email, v.color FROM vehicle v
JOIN guest_grant_vehicle gv ON gv.vehicle_id = v.id
WHERE gv.grant_id = ? ORDER BY v.label, v.registration`, gc.Grant.ID)
	return gc, err
}

// ListGuestGrants returns the owner's grants with their cars and recipient tokens.
func (s *Store) ListGuestGrants(ctx context.Context, owner string) ([]GuestGrantDetail, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, permit_id, label, allow_overnight, enabled, created_at FROM guest_grant WHERE owner = ? AND on_screen = 0 AND request_only = 0 ORDER BY id DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestGrantDetail
	for rows.Next() {
		var d GuestGrantDetail
		var overnight, enabled int
		var created string
		if err := rows.Scan(&d.Grant.ID, &d.Grant.PermitID, &d.Grant.Label, &overnight, &enabled, &created); err != nil {
			return nil, err
		}
		d.Grant.Owner = owner
		d.Grant.AllowOvernight = overnight == 1
		d.Grant.Enabled = enabled == 1
		if d.Grant.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		g := &out[i]
		g.Vehicles, err = s.queryVehicles(ctx, `
SELECT v.id, v.registration, v.label, v.email, v.color FROM vehicle v
JOIN guest_grant_vehicle gv ON gv.vehicle_id = v.id
WHERE gv.grant_id = ? ORDER BY v.label, v.registration`, g.Grant.ID)
		if err != nil {
			return nil, err
		}
		g.Tokens, err = s.listGuestTokens(ctx, g.Grant.ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) listGuestTokens(ctx context.Context, grantID int64) ([]GuestToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, grant_id, recipient_email, revoked_at, created_at FROM guest_token WHERE grant_id = ? ORDER BY id`, grantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GuestToken
	for rows.Next() {
		var t GuestToken
		var revoked, created string
		if err := rows.Scan(&t.ID, &t.GrantID, &t.RecipientEmail, &revoked, &created); err != nil {
			return nil, err
		}
		t.Revoked = revoked != ""
		if t.CreatedAt, err = time.Parse(time.RFC3339, created); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeGuestToken revokes one recipient's link, scoped to the grant's owner.
func (s *Store) RevokeGuestToken(ctx context.Context, owner string, tokenID int64) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE guest_token SET revoked_at = ?
WHERE id = ? AND revoked_at = '' AND grant_id IN (SELECT id FROM guest_grant WHERE owner = ?)`,
		nowUTC(), tokenID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGuestGrant removes a grant (its vehicles and tokens cascade), scoped to
// owner.
func (s *Store) DeleteGuestGrant(ctx context.Context, owner string, grantID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM guest_grant WHERE id = ? AND owner = ?`, grantID, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchGuestTokenUsed records the last time a token successfully activated a car.
func (s *Store) TouchGuestTokenUsed(ctx context.Context, tokenID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE guest_token SET last_used_at = ? WHERE id = ?`, nowUTC(), tokenID)
	return err
}

// SetGuestBaseline remembers what was on the permit before a guest link's run of
// activations (and how long that run's window lasts), so the guest can revert.
func (s *Store) SetGuestBaseline(ctx context.Context, tokenID int64, plate string, until time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE guest_token SET baseline_plate = ?, baseline_until = ? WHERE id = ?`,
		plate, until.UTC().Format(time.RFC3339), tokenID)
	return err
}

// ClearGuestBaseline forgets a link's captured baseline (after a revert), so the
// next activation captures a fresh one.
func (s *Store) ClearGuestBaseline(ctx context.Context, tokenID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE guest_token SET baseline_plate = '', baseline_until = '' WHERE id = ?`, tokenID)
	return err
}

// GuestsEnabled reports the owner's global kill-switch (default on).
func (s *Store) GuestsEnabled(ctx context.Context, owner string) (bool, error) {
	var v int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE((SELECT guests_enabled FROM account_flags WHERE owner = ?), 1)`, owner).Scan(&v)
	return v == 1, err
}

// SetGuestsEnabled flips the owner's global kill-switch for guest passes.
func (s *Store) SetGuestsEnabled(ctx context.Context, owner string, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO account_flags (owner, guests_enabled) VALUES (?, ?)
ON CONFLICT(owner) DO UPDATE SET guests_enabled = excluded.guests_enabled`, owner, boolInt(enabled))
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
