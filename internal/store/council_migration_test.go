package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// The multi-council migration against a database in the PRE-change shape: the
// permit table with its global UNIQUE(council_permit_id), council_session and
// account_flags without council_id, and the single-row breaker_state. The
// fixture is the old schema verbatim (the CREATE statements as they stood before
// docs/council-connections.md phase 1), with rows that must survive intact and be
// filed under Stonnington — the only council the app had ever served.
const preCouncilSchema = `
CREATE TABLE council_session (
    owner                TEXT PRIMARY KEY,
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
    session_generation   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE vehicle (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner        TEXT NOT NULL DEFAULT '',
    registration TEXT NOT NULL DEFAULT '',
    label        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT '',
    color        TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE permit (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    owner               TEXT NOT NULL DEFAULT '',
    council_permit_id   TEXT NOT NULL UNIQUE,
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
    copy_offer_done     INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE weekly_rule (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id  INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    weekday    INTEGER NOT NULL,
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    UNIQUE(permit_id, weekday)
);
CREATE TABLE account_flags (
    owner          TEXT PRIMARY KEY,
    guests_enabled INTEGER NOT NULL DEFAULT 1,
    onboard_nudge_sent TEXT NOT NULL DEFAULT '',
    fortnight_nudge_sent TEXT NOT NULL DEFAULT ''
);
CREATE TABLE breaker_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    open_until    TEXT NOT NULL DEFAULT '',
    generation    INTEGER NOT NULL DEFAULT 0,
    last_pushback TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT ''
);
INSERT INTO council_session (owner, cookie_sealed, updated_at, linked_at, session_generation) VALUES ('lily@example.com', 'sealed', '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z', 7);
INSERT INTO vehicle (id, owner, registration, label, created_at) VALUES (5, 'lily@example.com', 'ABC123', 'Van', '2026-08-01T00:00:00Z');
INSERT INTO permit (id, owner, council_permit_id, permit_type_id, label, active_registration, permit_number, updated_at, fail_streak) VALUES (42, 'lily@example.com', '14576', '14', 'Visitor', 'ABC123', 'VPP24714', '2026-08-01T00:00:00Z', 2);
INSERT INTO weekly_rule (permit_id, weekday, vehicle_id) VALUES (42, 1, 5);
INSERT INTO account_flags (owner, guests_enabled) VALUES ('lily@example.com', 0);
INSERT INTO breaker_state (id, open_until, generation, last_pushback) VALUES (1, '2099-01-01T00:00:00Z', 3, '2026-08-20T00:00:00Z');
`

func TestMigrateFromPreCouncilSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(preCouncilSchema); err != nil {
		t.Fatalf("build old schema: %v", err)
	}
	raw.Close()

	st, err := OpenSQLite(path) // runs the migrations
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer st.Close()
	st.DefaultCouncil = "stonnington" // as main sets it from the registry

	// Rows are backfilled under Stonnington and otherwise untouched.
	cs, err := st.GetCouncilSession(ctx, "lily@example.com")
	if err != nil || cs.CouncilID != "stonnington" || cs.Cookie != "sealed" || cs.Generation != 7 {
		t.Fatalf("session after migrate: %+v, %v", cs, err)
	}
	if id, err := st.CouncilIDFor(ctx, "lily@example.com"); err != nil || id != "stonnington" {
		t.Fatalf("CouncilIDFor = %q, %v", id, err)
	}
	p, err := st.GetPermit(ctx, 42)
	if err != nil || p.CouncilID != "stonnington" || p.CouncilPermitID != "14576" || p.ActiveRegistration != "ABC123" || p.FailStreak != 2 || p.PermitNumber != "VPP24714" {
		t.Fatalf("permit after migrate: %+v, %v", p, err)
	}
	// The rebuilt table kept its id, so dependents still point at it.
	rules, err := st.ListRules(ctx, 42)
	if err != nil || len(rules) != 1 || rules[0].VehicleID != 5 {
		t.Fatalf("rules after migrate: %+v, %v", rules, err)
	}
	// Uniqueness is now per council: the same council permit id in another
	// council is a different permit; in the same council it is still refused.
	if err := st.SetAccountCouncil(ctx, "bob@example.com", "othertown"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPermit(ctx, "bob@example.com", "14576", "1", "Theirs"); err != nil {
		t.Fatalf("same id in another council must be a separate permit: %v", err)
	}
	if _, err := st.UpsertPermit(ctx, "eve@example.com", "14576", "1", "Mine"); err == nil {
		t.Fatal("a second account in the same (default) council took over 14576")
	}
	if got, err := st.PermitInCouncil(ctx, "othertown", "14576"); err != nil || got.Owner != "bob@example.com" {
		t.Fatalf("PermitInCouncil(othertown) = %+v, %v", got, err)
	}
	if got, err := st.PermitInCouncil(ctx, "stonnington", "14576"); err != nil || got.Owner != "lily@example.com" {
		t.Fatalf("PermitInCouncil(stonnington) = %+v, %v", got, err)
	}
	// The breaker pause carried across as Stonnington's; another council starts closed.
	bs, err := st.LoadBreakerState(ctx, "stonnington")
	if err != nil || bs.Generation != 3 || bs.OpenUntil.Year() != 2099 {
		t.Fatalf("breaker after migrate: %+v, %v", bs, err)
	}
	if bs, err := st.LoadBreakerState(ctx, "othertown"); err != nil || bs.Generation != 0 || !bs.OpenUntil.IsZero() {
		t.Fatalf("other council's breaker: %+v, %v", bs, err)
	}
	// Guests flag survived the account_flags ALTER.
	if on, err := st.GuestsEnabled(ctx, "lily@example.com"); err != nil || on {
		t.Fatalf("guests_enabled after migrate = %v, %v", on, err)
	}
	// Re-running the migrations on the migrated file is a no-op.
	st.Close()
	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	defer st2.Close()
	if p2, err := st2.GetPermit(ctx, 42); err != nil || p2.CouncilID != "stonnington" {
		t.Fatalf("permit after re-migrate: %+v, %v", p2, err)
	}
}

// A choice recorded at sign-up files the first permit under that council, and a
// linked account cannot be re-pointed at another council without disconnecting.
func TestAccountCouncilChoice(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.DefaultCouncil = "stonnington"
	if id, _ := st.CouncilIDFor(ctx, "new@example.com"); id != "stonnington" {
		t.Fatalf("default council = %q", id)
	}
	if err := st.SetAccountCouncil(ctx, "new@example.com", "bayside"); err != nil {
		t.Fatal(err)
	}
	if id, _ := st.CouncilIDFor(ctx, "new@example.com"); id != "bayside" {
		t.Fatalf("chosen council = %q", id)
	}
	if err := st.SaveCouncilSession(ctx, CouncilSession{Owner: "new@example.com", Cookie: "s"}); err != nil {
		t.Fatal(err)
	}
	cs, _ := st.GetCouncilSession(ctx, "new@example.com")
	if cs.CouncilID != "bayside" {
		t.Fatalf("session inherited council %q, want the sign-up choice", cs.CouncilID)
	}
	if err := st.SetAccountCouncil(ctx, "new@example.com", "hume"); err != ErrCouncilMismatch {
		t.Fatalf("re-pointing a linked account = %v, want ErrCouncilMismatch", err)
	}
	id, _ := st.UpsertPermit(ctx, "new@example.com", "9", "14", "V")
	if p, _ := st.GetPermit(ctx, id); p.CouncilID != "bayside" {
		t.Fatalf("permit filed under %q", p.CouncilID)
	}
}

// Precedence: the sign-up choice wins over the session's council (the state an
// unlink/re-link can leave behind), and the default only fills a blank.
func TestCouncilIDForPrecedence(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	st.DefaultCouncil = "stonnington"
	if _, err := st.db.ExecContext(ctx, `INSERT INTO council_session (owner, council_id, cookie_sealed, updated_at) VALUES ('p@x', 'bayside', 's', '')`); err != nil {
		t.Fatal(err)
	}
	if id, _ := st.CouncilIDFor(ctx, "p@x"); id != "bayside" {
		t.Fatalf("session council not used: %q", id)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO account_flags (owner, council_id) VALUES ('p@x', 'hume')`); err != nil {
		t.Fatal(err)
	}
	st.forgetCouncil("p@x")
	if id, _ := st.CouncilIDFor(ctx, "p@x"); id != "hume" {
		t.Fatalf("the sign-up choice must win: %q", id)
	}
	// The memo is invalidated by the writes that can change the answer.
	if err := st.DeleteCouncilSession(ctx, "p@x"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAllForOwner(ctx, "p@x"); err != nil {
		t.Fatal(err)
	}
	if id, _ := st.CouncilIDFor(ctx, "p@x"); id != "stonnington" {
		t.Fatalf("after deletion the default applies: %q", id)
	}
}

// An old database whose breaker_state holds no row migrates and starts closed.
func TestMigrateBreakerTableWithoutARow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old2.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	schema := preCouncilSchema[:strings.Index(preCouncilSchema, "INSERT INTO breaker_state")]
	if _, err := raw.Exec(schema); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer st.Close()
	if bs, err := st.LoadBreakerState(ctx, "stonnington"); err != nil || !bs.OpenUntil.IsZero() || bs.Generation != 0 {
		t.Fatalf("breaker after migrate without a row: %+v, %v", bs, err)
	}
}
