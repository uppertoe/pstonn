package store

import (
	"fmt"
	"strings"
)

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
    password_sealed      TEXT NOT NULL DEFAULT '',   -- opt-in sealed council password for auto-reconnect (empty = not saved)
    reconnected_at       TEXT NOT NULL DEFAULT ''    -- last saved-password auto-reconnect; shown to the user in Settings
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
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL DEFAULT ''    -- member who minted it ('' = the account owner / pre-dates the column)
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
    decided_by   TEXT NOT NULL DEFAULT '',  -- which account member decided ('' = expired unanswered)
    until_at     TEXT NOT NULL DEFAULT '',  -- human when-it-ends, set on approval
    until_ts     TEXT NOT NULL DEFAULT ''   -- RFC3339 UTC end of the approved window; the source of truth for "has this pass lapsed" (until_at is only display text)
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
    sent_at       TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT ''   -- "why you got this", shown in the mail footer
);
CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox(status, next_attempt);

-- Addresses we must stop emailing: hard bounces and spam complaints, learned
-- either from the SMTP conversation (a 5xx at send time) or asynchronously from
-- the provider's bounce/complaint feed. Consulted before every send. Sending to
-- a known-dead address repeatedly is what gets a sending domain suspended, and
-- a complaint means the recipient asked us to stop.
CREATE TABLE IF NOT EXISTS mail_suppression (
    address    TEXT PRIMARY KEY,                -- lower-cased
    reason     TEXT NOT NULL,                   -- bounce | complaint | manual
    detail     TEXT NOT NULL DEFAULT '',        -- provider diagnostic, for support
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 1       -- times we've been told
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
		`ALTER TABLE council_session ADD COLUMN reconnected_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE guest_request ADD COLUMN decided_by TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE guest_request ADD COLUMN until_ts TEXT NOT NULL DEFAULT ''`,
		// Which member minted a guest pass. Needed to revoke a departing member's
		// passes without touching the primary's: a pass is a bearer capability over
		// the permit, so losing account access must also lose the passes you made.
		// Rows predating this column have '' and are treated as the account's own.
		`ALTER TABLE guest_grant ADD COLUMN created_by TEXT NOT NULL DEFAULT ''`,
		// Why this address is receiving this message, for the mail's own footer.
		// Recipients with no account (a guest, a displaced driver) otherwise have no
		// idea who we are or how we got their address.
		`ALTER TABLE outbox ADD COLUMN reason TEXT NOT NULL DEFAULT ''`,
	} {
		// String match is unavoidable here: SQLite reports a duplicate column as a
		// generic SQLITE_ERROR (code 1), so there is no numeric code to key on.
		// The message text comes from SQLite core itself and is stable.
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
	// Indexes that depend on ADD COLUMN-ed columns, or on the rebuilt override
	// table, must come AFTER both: creating them in the schema block above would
	// fail on a database predating the column.
	for _, stmt := range []string{
		// The confirm-link lookup is by token alone, on a public unauthenticated
		// route: without this, every probe scans council_session on the single
		// connection the scheduler shares. Partial, so consumed (empty) tokens
		// cost nothing.
		`CREATE INDEX IF NOT EXISTS idx_council_confirm ON council_session(confirm_token) WHERE confirm_token != ''`,
		// Expired-override pruning scans by ends_at (see PruneOverrides).
		`CREATE INDEX IF NOT EXISTS idx_override_ends ON override(ends_at)`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate %q: %w", stmt, err)
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
		// Must mirror the base schema exactly: the ALTER loop has already run, so
		// omitting a column it added (guest_token_id, once) would silently drop it
		// from the rebuilt table and break every guest-override insert until the
		// next restart re-added it.
		`CREATE TABLE override_new (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id      INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    vehicle_id     INTEGER REFERENCES vehicle(id) ON DELETE CASCADE,
    registration   TEXT NOT NULL DEFAULT '',
    starts_at      TEXT NOT NULL,
    ends_at        TEXT,
    created_by     TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    guest_token_id INTEGER NOT NULL DEFAULT 0
)`,
		`INSERT INTO override_new (id, permit_id, vehicle_id, registration, starts_at, ends_at, created_by, created_at, guest_token_id)
    SELECT id, permit_id, vehicle_id, '', starts_at, ends_at, created_by, created_at, guest_token_id FROM override`,
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
