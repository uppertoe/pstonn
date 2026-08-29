package store

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// schemaVersion is the migration set this build knows how to apply. It is
// RECORDED after a successful run, for the operator and for a future "this file
// was written by a newer binary" check — it is deliberately NOT used to skip the
// migrations. Skipping on a version match would mean that forgetting to bump this
// constant silently stops a newly added ALTER from ever reaching an existing
// database, which is a far worse failure than re-running statements that are all
// idempotent and cost microseconds on an already-migrated file.
const schemaVersion = 4

// migrationLockTTL bounds how long a dead migrator keeps the next start out. A
// process killed mid-migration leaves the row claimed, and with no takeover window
// the app could never boot again without manual surgery on the database — so the
// lock expires. It is set well above a real migration (milliseconds) and well
// below any plausible restart loop.
const migrationLockTTL = 5 * time.Minute

// migrationLockWait is how long to wait for another process to finish migrating
// before giving up. Losing the race is normal and harmless (the winner's work is
// what this process needs); waiting forever is not, because a stuck peer would
// turn into a container that never reports healthy and never says why.
const migrationLockWait = 30 * time.Second

// migratorSeq distinguishes migration-lock holders within one process; see
// lockMigrations.
var migratorSeq atomic.Uint64

// migrate brings the schema up to date, holding an exclusive migration lock for
// the whole run.
//
// The lock is the point. Two processes can share a data volume — a rolling deploy
// that overlaps by a second, a stray `docker compose run`, an operator's one-off
// container — and several migrations here are read-then-write: they probe with
// columnExists and then act. rebuildOverrideTable is the dangerous one, because
// acting means PRAGMA foreign_keys=OFF followed by DROP and RENAME on a live
// table. Two processes that both pass the probe run that twice, and the second one
// copies rows out of a table the first has already replaced.
//
// The lock is a claimed row rather than BEGIN EXCLUSIVE for two reasons: the pool
// is capped at one connection, so holding a transaction open would deadlock every
// statement below it (see the invariant in OpenSQLite), and PRAGMA foreign_keys is
// a no-op inside a transaction, which rebuildOverrideTable depends on. A single
// conditional UPDATE is atomic in SQLite, which is all mutual exclusion needs.
func (s *Store) migrate() error {
	release, err := s.lockMigrations()
	if err != nil {
		return err
	}
	defer release()
	if err := s.applyMigrations(); err != nil {
		return err
	}
	// Recorded only on success, so a failed boot does not leave the file claiming a
	// version it never reached.
	if _, err := s.db.Exec(
		`UPDATE schema_migration SET version = ?, applied_at = ? WHERE id = 1`,
		schemaVersion, nowUTC()); err != nil {
		return fmt.Errorf("migrate: record schema version: %w", err)
	}
	return nil
}

// lockMigrations claims the single migration lock row, waiting for a concurrent
// migrator to finish. The returned function releases the claim and must always be
// called, including on failure: a migration that errors takes the app down anyway,
// and leaving the row claimed would add migrationLockTTL of confusion to the next
// attempt.
func (s *Store) lockMigrations() (func(), error) {
	// The lock table has to exist before it can be claimed, so this one statement
	// is necessarily unsynchronised. It is safe to race on: CREATE TABLE IF NOT
	// EXISTS and INSERT OR IGNORE are both no-ops for the loser, and neither
	// touches any other table.
	const bootstrap = `
CREATE TABLE IF NOT EXISTS schema_migration (
    id         INTEGER PRIMARY KEY CHECK (id = 1),  -- one row, ever
    version    INTEGER NOT NULL DEFAULT 0,          -- last schemaVersion applied
    applied_at TEXT NOT NULL DEFAULT '',
    locked_by  TEXT NOT NULL DEFAULT '',            -- host/pid currently migrating ('' = free)
    locked_at  TEXT NOT NULL DEFAULT ''             -- RFC3339 UTC; the claim expires after migrationLockTTL
);
INSERT OR IGNORE INTO schema_migration (id, version) VALUES (1, 0);
`
	if _, err := s.db.Exec(bootstrap); err != nil {
		return nil, fmt.Errorf("migrate: schema_migration table: %w", err)
	}
	// Host and pid identify the migrator for a human reading the row. The sequence
	// number is what makes it UNIQUE: without it two Store instances in one process
	// (tests today, an in-process second store tomorrow) would share a holder
	// string, and the release below — which only clears a claim it owns — could clear
	// the other one's.
	host, _ := os.Hostname()
	holder := fmt.Sprintf("%s/%d/%d", host, os.Getpid(), migratorSeq.Add(1))

	deadline := time.Now().Add(migrationLockWait)
	for {
		// One conditional UPDATE decides it: SQLite serialises writers, so of two
		// processes reaching this at the same instant exactly one matches the WHERE
		// clause and exactly one gets RowsAffected == 1.
		now := time.Now().UTC()
		res, err := s.db.Exec(
			`UPDATE schema_migration SET locked_by = ?, locked_at = ?
			   WHERE id = 1 AND (locked_by = '' OR locked_at <= ?)`,
			holder, now.Format(time.RFC3339), now.Add(-migrationLockTTL).Format(time.RFC3339))
		if err != nil {
			return nil, fmt.Errorf("migrate: claim migration lock: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("migrate: claim migration lock: %w", err)
		}
		if n == 1 {
			return func() {
				if _, err := s.db.Exec(
					`UPDATE schema_migration SET locked_by = '', locked_at = '' WHERE id = 1 AND locked_by = ?`,
					holder); err != nil {
					log.Printf("migrate: could not release the migration lock: %v", err)
				}
			}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("migrate: another process has held the migration lock for over %s; "+
				"check for a second container on this data volume", migrationLockWait)
		}
		log.Printf("migrate: another process is migrating this database; waiting")
		time.Sleep(500 * time.Millisecond)
	}
}

// applyMigrations is the migration set itself. Every statement in it is written to
// be safe to re-run against an already-migrated database, because it runs on every
// start (see schemaVersion).
func (s *Store) applyMigrations() error {
	const schema = `
CREATE TABLE IF NOT EXISTS council_session (
    owner                TEXT NOT NULL,           -- app-user email
    council_id           TEXT NOT NULL DEFAULT '', -- which tenant (council) this session is with — one row per tenant an account is linked to
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
    reconnected_at       TEXT NOT NULL DEFAULT '',   -- last saved-password auto-reconnect; shown to the user in Settings
    last_active_at       TEXT NOT NULL DEFAULT '',    -- last use of the account by ANY member OR their guests (visits, guest-link use, emailed decisions); the idle clock (see decideWarm)
    drift_checked_at     TEXT NOT NULL DEFAULT '',    -- last owner-grid drift/expiry read; its own cadence, decoupled from keep-warm
    session_generation   INTEGER NOT NULL DEFAULT 1,   -- monotonic version of the session material; the async reconnect queue's compare-and-swap token
    PRIMARY KEY (owner, council_id)
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
    council_id          TEXT NOT NULL DEFAULT '',   -- the council whose permit this is
    council_permit_id   TEXT NOT NULL,              -- the council's own id; unique only WITHIN a council
    permit_type_id      TEXT NOT NULL DEFAULT '',
    label               TEXT NOT NULL DEFAULT '',
    active_registration TEXT NOT NULL DEFAULT '',
    end_date            TEXT NOT NULL DEFAULT '',   -- permit expiry (RFC3339) from the council record
    status              TEXT NOT NULL DEFAULT '',   -- council permit status, e.g. "Granted"
    expiry_reminded     TEXT NOT NULL DEFAULT '',   -- '1' once an expiry reminder is sent (cleared when end_date changes)
    permit_number       TEXT NOT NULL DEFAULT '',   -- council permit number, e.g. "VPP24714"
    permit_type         TEXT NOT NULL DEFAULT '',   -- council permit type, e.g. "(A) 1st Visitor Permit"
    updated_at          TEXT NOT NULL,
    UNIQUE(council_id, council_permit_id)
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

-- Per-person session generation. The app's own login issues a stateless signed
-- cookie, so there is nothing server-side to invalidate: removing someone's admin
-- group, revoking their shared access, or deleting their account left their existing
-- cookie fully valid — admin and all — until it aged out. Bumping the epoch here
-- makes every cookie issued before the bump fail to decode, which is the only way a
-- stateless session can be revoked at all.
--
-- Absent row means epoch 0, so a person who has never had anything revoked needs no
-- row and the common case costs nothing.
CREATE TABLE IF NOT EXISTS session_epoch (
    email      TEXT PRIMARY KEY,
    epoch      INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_state (
    state      TEXT PRIMARY KEY,
    verifier   TEXT NOT NULL,
    nonce      TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT '',   -- "app" (the OIDC provider login) | "council" (permit link)
    created_at TEXT NOT NULL
);
-- Every login sweeps expired states by created_at before inserting a new one. The
-- state primary key does not help that scan, so without this index an anonymous
-- hit on the login route costs a full table scan on the single shared connection —
-- the one every handler and both work loops queue behind.
CREATE INDEX IF NOT EXISTS idx_oauth_state_created ON oauth_state(created_at);

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
    guests_enabled INTEGER NOT NULL DEFAULT 1,
    council_id     TEXT NOT NULL DEFAULT ''     -- the council chosen at sign-up, before any link exists
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

-- Who changed what, for the account holder to read. The apply log records what
-- p.stonn DID to a permit; this records what PEOPLE did to the setup — and those
-- are invisible otherwise, because notifications only fire on council apply
-- outcomes. Clearing a roster day produces no apply at all, so without this a
-- shared-account change (a housemate, or someone who should no longer have
-- access) leaves no trace the owner can find.
CREATE TABLE IF NOT EXISTS account_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    owner  TEXT NOT NULL,             -- account the change belongs to
    actor  TEXT NOT NULL DEFAULT '',  -- signed-in person who made it ('' = the system)
    action TEXT NOT NULL,             -- stable slug, e.g. "roster.set" (see store/changelog.go)
    target TEXT NOT NULL DEFAULT '',  -- what it applied to (a plate, a permit name, an email)
    detail TEXT NOT NULL DEFAULT '',  -- extra context, already human-readable
    at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_log_owner ON account_log(owner, id);

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

-- The fleet circuit breaker's pause, persisted so a restart cannot clear it. If
-- Azure Front Door blocks our egress IP the breaker opens; a deploy that recreates
-- the container would otherwise wipe that in-memory state and resume full traffic
-- straight into the block — escalating it. One row: on boot, if open_until is still
-- in the future the breaker starts paused. generation is carried forward so it stays
-- monotonic across restarts.
CREATE TABLE IF NOT EXISTS breaker_state (
    council_id    TEXT PRIMARY KEY,                  -- one row per council: edge blocks are per portal host
    open_until    TEXT NOT NULL DEFAULT '',            -- RFC3339 UTC; while now < this, traffic is paused
    generation    INTEGER NOT NULL DEFAULT 0,
    last_pushback TEXT NOT NULL DEFAULT '',            -- RFC3339 UTC of the most recent pushback
    updated_at    TEXT NOT NULL DEFAULT ''
);
-- One row per referral invitation a signed-in account asked p.stonn to send:
-- the per-account daily cap reads this, so a compromised or over-keen account
-- cannot turn the invite form into a mailer.
CREATE TABLE IF NOT EXISTS referral_invite (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    owner     TEXT NOT NULL,
    recipient TEXT NOT NULL,
    sent_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_referral_owner ON referral_invite(owner, sent_at);

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
		`ALTER TABLE council_session ADD COLUMN drift_checked_at TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE council_session ADD COLUMN session_generation INTEGER NOT NULL DEFAULT 1`,
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
		// Whether this membership is still awaiting the invited person's own consent. A
		// pending row grants NOTHING: adding a member used to bind an arbitrary address
		// to an account on one person's say-so, which showed the invitee someone else's
		// household, blocked them from linking their own tenant account, and filed
		// everything they then created under the inviter's ownership.
		//
		// The flag is "pending" rather than "accepted" deliberately, so its DEFAULT 0
		// makes every membership that predates this column active. Those people already
		// have working access; making them re-accept would revoke a household's shared
		// access on deploy. Expressing it this way needs no backfill, which matters
		// because a backfill here would re-run on every startup and silently accept
		// invites nobody had answered.
		`ALTER TABLE account_member ADD COLUMN invite_pending INTEGER NOT NULL DEFAULT 0`,
		// The re-authorise clock is now IDLE-based: it measures time since anyone on
		// the account last used the app, not time since a password was typed. The
		// point of the bound is to stop serving households that have left, and a
		// household that visits regularly has plainly not left.
		`ALTER TABLE council_session ADD COLUMN last_active_at TEXT NOT NULL DEFAULT ''`,
		// When the once-ever "you signed up but never connected" email went out
		// (RFC3339; '' = never). A column rather than an outbox dedup key because
		// delivered outbox rows are purged — the only durable proof this mail was
		// sent must live somewhere that isn't.
		`ALTER TABLE account_flags ADD COLUMN onboard_nudge_sent TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE account_flags ADD COLUMN fortnight_nudge_sent TEXT NOT NULL DEFAULT ''`,
		// Whether the "renewed this permit? copy your schedule" pitch has been
		// answered (dismissed, copied, or a roster day set). DEFAULT 0 re-offers it
		// on existing permits, which is safe: any permit with a roster already
		// renders the quiet button, not the pitch.
		`ALTER TABLE permit ADD COLUMN copy_offer_done INTEGER NOT NULL DEFAULT 0`,
		// Which tenant a row belongs to (docs/tenant-connections.md). Every row that
		// predates the column is the City of Stonnington's — the only tenant the app
		// has ever served — which the backfill below records.
		`ALTER TABLE council_session ADD COLUMN council_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE permit ADD COLUMN council_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE account_flags ADD COLUMN council_id TEXT NOT NULL DEFAULT ''`,
	} {
		// String match is unavoidable here: SQLite reports a duplicate column as a
		// generic SQLITE_ERROR (code 1), so there is no numeric code to key on.
		// The message text comes from SQLite core itself and is stable.
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate %q: %w", stmt, err)
		}
	}
	// Backfill tenant_id on rows that predate multi-tenant support: they are all
	// Stonnington's. Idempotent (only '' rows are touched).
	for _, stmt := range []string{
		`UPDATE council_session SET council_id = 'stonnington' WHERE council_id = ''`,
		`UPDATE permit SET council_id = 'stonnington' WHERE council_id = ''`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate %q: %w", stmt, err)
		}
	}
	// Rebuild `permit` if its uniqueness is still the global UNIQUE(tenant_permit_id):
	// two registry' permit id spaces overlap, so the constraint must be per tenant.
	// SQLite cannot change a constraint in place; redefine the table and copy the rows.
	if scoped, err := s.permitUniqueIsScoped(); err != nil {
		return err
	} else if !scoped {
		if err := s.rebuildPermitTable(); err != nil {
			return fmt.Errorf("migrate permit table: %w", err)
		}
	}
	// Rebuild `council_session` if it is still keyed by owner alone: an account may
	// be linked to several tenants, one session each.
	if scoped, err := s.sessionKeyIsScoped(); err != nil {
		return err
	} else if !scoped {
		if err := s.rebuildSessionTable(); err != nil {
			return fmt.Errorf("migrate council_session table: %w", err)
		}
	}
	// Rebuild `breaker_state` from the single-row shape to one row per tenant,
	// carrying the existing pause across under Stonnington.
	if has, err := s.columnExists("breaker_state", "council_id"); err != nil {
		return err
	} else if !has {
		if err := s.rebuildBreakerTable(); err != nil {
			return fmt.Errorf("migrate breaker_state table: %w", err)
		}
	}
	// Backfill the re-authorise clock for pre-existing sessions so they are not
	// treated as instantly past-bound on first keep-warm pass.
	if _, err := s.db.Exec(
		`UPDATE council_session SET linked_at = updated_at WHERE linked_at = '' AND updated_at != ''`); err != nil {
		return err
	}
	// Seed the idle clock from the old link-time clock, so switching to idle-based
	// expiry does not retire an existing session earlier than its owner expects.
	if _, err := s.db.Exec(
		`UPDATE council_session SET last_active_at = linked_at WHERE last_active_at = '' AND linked_at != ''`); err != nil {
		return err
	}
	// Drop guest_token.last_used_at. It recorded when a named guest last parked,
	// was read by nothing, and was kept forever — so it is a third party's movement
	// history with no purpose. Removing the writer (and the column from the schema
	// above) was not enough on its own: an existing production database still
	// carries the column AND its historical values, which is exactly what the
	// retention pass claimed to have removed.
	//
	// Attempted rather than asserted. DROP COLUMN needs SQLite >= 3.35, and a
	// migration that hard-fails takes the whole app down at boot; blanking the
	// values achieves the privacy goal on any version, which is the part that
	// actually matters.
	if has, err := s.columnExists("guest_token", "last_used_at"); err != nil {
		return err
	} else if has {
		if _, err := s.db.Exec(`ALTER TABLE guest_token DROP COLUMN last_used_at`); err != nil {
			log.Printf("migrate: could not drop guest_token.last_used_at (%v); clearing its values instead", err)
			if _, err := s.db.Exec(`UPDATE guest_token SET last_used_at = '' WHERE last_used_at != ''`); err != nil {
				return fmt.Errorf("migrate: clear guest_token.last_used_at: %w", err)
			}
		}
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
		// route: without this, every probe scans tenant_session on the single
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

// permitUniqueIsScoped reports whether the permit table already carries the
// per-tenant uniqueness constraint (read from its stored definition).
func (s *Store) permitUniqueIsScoped() (bool, error) {
	var sqlText string
	err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'permit'`).Scan(&sqlText)
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(sqlText), "unique(council_id, council_permit_id)"), nil
}

// rebuildPermitTable redefines permit with UNIQUE(tenant_id, tenant_permit_id),
// preserving rows and ids. Tables that reference permit(id) (weekly_rule,
// override, apply_log, permit_notify, guest_grant) keep referencing "permit" by
// name, which the renamed table satisfies; foreign keys are toggled off around
// the DROP/RENAME per the SQLite table-redefinition guidance, and the migration
// lock guarantees a single migrator.
func (s *Store) rebuildPermitTable() error {
	// Copy only the columns the existing table actually has (a very old database
	// may predate some), defaulting the rest, so the rebuild never fails on shape.
	existing := map[string]bool{}
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('permit')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	cols := []struct{ name, def string }{
		{"id", "NULL"}, {"owner", "''"}, {"council_id", "''"}, {"council_permit_id", "''"},
		{"permit_type_id", "''"}, {"label", "''"}, {"active_registration", "''"}, {"end_date", "''"},
		{"status", "''"}, {"expiry_reminded", "''"}, {"permit_number", "''"}, {"permit_type", "''"},
		{"updated_at", "''"}, {"fail_streak", "0"}, {"copy_offer_done", "0"},
	}
	var names, selects []string
	for _, c := range cols {
		names = append(names, c.name)
		if existing[c.name] {
			selects = append(selects, c.name)
		} else {
			selects = append(selects, c.def)
		}
	}

	if _, err := s.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		return err
	}
	defer s.db.Exec(`PRAGMA foreign_keys=ON`)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Mirrors the base schema PLUS every ALTER-added column, in the same order the
	// ALTER loop (which has already run) leaves them.
	for _, stmt := range []string{
		`CREATE TABLE permit_new (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    owner               TEXT NOT NULL DEFAULT '',
    council_id          TEXT NOT NULL DEFAULT '',
    council_permit_id   TEXT NOT NULL,
    permit_type_id      TEXT NOT NULL DEFAULT '',
    label               TEXT NOT NULL DEFAULT '',
    active_registration TEXT NOT NULL DEFAULT '',
    end_date            TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT '',
    expiry_reminded     TEXT NOT NULL DEFAULT '',
    permit_number       TEXT NOT NULL DEFAULT '',
    permit_type         TEXT NOT NULL DEFAULT '',
    updated_at          TEXT NOT NULL,
    fail_streak         INTEGER NOT NULL DEFAULT 0,
    copy_offer_done     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(council_id, council_permit_id)
)`,
		`INSERT INTO permit_new (` + strings.Join(names, ", ") + `) SELECT ` + strings.Join(selects, ", ") + ` FROM permit`,
		`DROP TABLE permit`,
		`ALTER TABLE permit_new RENAME TO permit`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// rebuildBreakerTable converts the single-row breaker_state into one row per
// tenant, carrying any existing pause across as Stonnington's.
func (s *Store) rebuildBreakerTable() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		`CREATE TABLE breaker_state_new (
    council_id    TEXT PRIMARY KEY,
    open_until    TEXT NOT NULL DEFAULT '',
    generation    INTEGER NOT NULL DEFAULT 0,
    last_pushback TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT ''
)`,
		`INSERT INTO breaker_state_new (council_id, open_until, generation, last_pushback, updated_at)
    SELECT 'stonnington', open_until, generation, last_pushback, updated_at FROM breaker_state WHERE id = 1`,
		`DROP TABLE breaker_state`,
		`ALTER TABLE breaker_state_new RENAME TO breaker_state`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// sessionKeyIsScoped reports whether tenant_session is keyed by (owner, tenant_id).
func (s *Store) sessionKeyIsScoped() (bool, error) {
	var sqlText string
	err := s.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'council_session'`).Scan(&sqlText)
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(sqlText), "primary key (owner, council_id)"), nil
}

// rebuildSessionTable re-keys tenant_session by (owner, tenant_id), preserving
// rows and the columns the existing table has. Nothing references the table by
// foreign key; foreign keys are toggled off around the DROP/RENAME as for the
// other rebuilds, and the migration lock guarantees a single migrator.
func (s *Store) rebuildSessionTable() error {
	existing := map[string]bool{}
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('council_session')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	cols := []struct{ name, def string }{
		{"owner", "''"}, {"council_id", "''"}, {"sub", "''"}, {"council_email", "''"}, {"cookie_sealed", "''"},
		{"access_token_sealed", "''"}, {"token_expiry", "''"}, {"updated_at", "''"}, {"linked_at", "''"},
		{"reminder_sent_at", "''"}, {"confirm_token", "''"}, {"password_sealed", "''"}, {"reconnected_at", "''"},
		{"last_active_at", "''"}, {"drift_checked_at", "''"}, {"session_generation", "1"},
	}
	var names, selects []string
	for _, c := range cols {
		names = append(names, c.name)
		if existing[c.name] {
			selects = append(selects, c.name)
		} else {
			selects = append(selects, c.def)
		}
	}
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
		`CREATE TABLE council_session_new (
    owner                TEXT NOT NULL,
    council_id           TEXT NOT NULL DEFAULT '',
    sub                  TEXT NOT NULL DEFAULT '',
    council_email        TEXT NOT NULL DEFAULT '',
    cookie_sealed        TEXT NOT NULL DEFAULT '',
    access_token_sealed  TEXT NOT NULL DEFAULT '',
    token_expiry         TEXT NOT NULL DEFAULT '',
    updated_at           TEXT NOT NULL DEFAULT '',
    linked_at            TEXT NOT NULL DEFAULT '',
    reminder_sent_at     TEXT NOT NULL DEFAULT '',
    confirm_token        TEXT NOT NULL DEFAULT '',
    password_sealed      TEXT NOT NULL DEFAULT '',
    reconnected_at       TEXT NOT NULL DEFAULT '',
    last_active_at       TEXT NOT NULL DEFAULT '',
    drift_checked_at     TEXT NOT NULL DEFAULT '',
    session_generation   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (owner, council_id)
)`,
		`INSERT INTO council_session_new (` + strings.Join(names, ", ") + `) SELECT ` + strings.Join(selects, ", ") + ` FROM council_session`,
		`DROP TABLE council_session`,
		`ALTER TABLE council_session_new RENAME TO council_session`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}
