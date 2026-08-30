package store

import (
	"database/sql"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Every table a migration rebuilds is redefined from a hand-written column list,
// and a rebuild runs AFTER the ALTER loop — so a column added by ALTER but
// missing from the list is silently dropped from the rebuilt table. This holds
// each list to the live table's shape, on a fresh database (the base CREATE
// statements, which had drifted from the ALTER-added columns) and on the legacy
// fixture that actually exercises the rebuilds.
func TestRebuildColumnListsMatchLiveTables(t *testing.T) {
	check := func(t *testing.T, s *Store) {
		t.Helper()
		for table, cols := range rebuiltTables {
			live, err := s.tableColumns(table)
			if err != nil {
				t.Fatal(err)
			}
			want := make([]string, 0, len(cols))
			for _, c := range cols {
				want = append(want, c.name)
			}
			sort.Strings(live)
			sort.Strings(want)
			if strings.Join(live, ",") != strings.Join(want, ",") {
				t.Errorf("%s: rebuild column list %v does not match the live table %v", table, want, live)
			}
		}
	}
	t.Run("fresh", func(t *testing.T) { check(t, newTestStore(t)) })
	t.Run("legacy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "old.db")
		raw, err := sql.Open("sqlite", "file:"+path)
		if err != nil {
			t.Fatal(err)
		}
		// The pre-tenant fixture, plus an override table in its oldest shape so
		// rebuildOverrideTable runs too.
		if _, err := raw.Exec(preTenantSchema + `
CREATE TABLE override (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    permit_id  INTEGER NOT NULL REFERENCES permit(id) ON DELETE CASCADE,
    vehicle_id INTEGER NOT NULL REFERENCES vehicle(id) ON DELETE CASCADE,
    starts_at  TEXT NOT NULL,
    ends_at    TEXT,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
INSERT INTO override (permit_id, vehicle_id, starts_at, ends_at, created_by, created_at)
VALUES (42, 5, '2026-08-01T00:00:00Z', NULL, 'lily@example.com', '2026-08-01T00:00:00Z');
`); err != nil {
			t.Fatal(err)
		}
		raw.Close()
		s, err := OpenSQLite(path)
		if err != nil {
			t.Fatalf("migrate: %v", err)
		}
		defer s.Close()
		check(t, s)
		// The rebuilt override kept its row and gained the new columns' defaults.
		var reg string
		var tokenID int64
		if err := s.db.QueryRow(`SELECT registration, guest_token_id FROM override WHERE permit_id = 42`).Scan(&reg, &tokenID); err != nil {
			t.Fatalf("override row after rebuild: %v", err)
		}
		if reg != "" || tokenID != 0 {
			t.Fatalf("override defaults after rebuild: registration=%q guest_token_id=%d", reg, tokenID)
		}
	})
}

// The fresh CREATE statements must produce every column the code writes, so a
// brand-new deployment is not quietly relying on the ALTER loop to finish the
// job. Spot-checked on the columns that had drifted.
func TestFreshSchemaCarriesEveryColumn(t *testing.T) {
	s := newTestStore(t)
	for table, cols := range map[string][]string{
		"vehicle":        {"email", "color", "state"},
		"permit":         {"fail_streak", "copy_offer_done", "council_id"},
		"account_flags":  {"onboard_nudge_sent", "fortnight_nudge_sent", "council_id"},
		"account_member": {"invite_pending"},
		"outbox":         {"account", "reason", "critical"},
	} {
		for _, c := range cols {
			if has, err := s.columnExists(table, c); err != nil || !has {
				t.Errorf("%s.%s missing from a fresh database (%v)", table, c, err)
			}
		}
	}
}

// Two migrators on one file: the second waits for the first, and gives up with a
// clear message if the first never lets go — and a claim older than the TTL is a
// dead process, which the next start takes over from.
func TestMigrationLockContentionAndTakeover(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Shorten the waits so the test does not take half a minute. The TTL stays
	// comfortably above the wait plus the one-second granularity of the RFC3339
	// timestamps the claim is compared on, or a live claim would look expired.
	oldWait, oldTTL := migrationLockWait, migrationLockTTL
	migrationLockWait, migrationLockTTL = 1200*time.Millisecond, 6*time.Second
	t.Cleanup(func() { migrationLockWait, migrationLockTTL = oldWait, oldTTL })

	release, err := s.lockMigrations()
	if err != nil {
		t.Fatal(err)
	}
	// A second store on the same file cannot open while the lock is held.
	start := time.Now()
	if _, err := OpenSQLite(path); err == nil || !strings.Contains(err.Error(), "migration lock") {
		t.Fatalf("second migrator should have timed out on the lock, got: %v", err)
	}
	if waited := time.Since(start); waited < migrationLockWait {
		t.Fatalf("second migrator gave up after %s, before the %s wait", waited, migrationLockWait)
	}
	// Released: the second one now gets in.
	release()
	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	s2.Close()

	// A stale claim (its holder died mid-migration) is taken over once the TTL
	// has passed, without waiting on it further.
	if _, err := s.db.Exec(`UPDATE schema_migration SET locked_by = 'ghost/1/1', locked_at = ? WHERE id = 1`,
		time.Now().Add(-migrationLockTTL-time.Second).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	s3, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("takeover of an expired lock failed: %v", err)
	}
	s3.Close()
	if waited := time.Since(start); waited > migrationLockWait {
		t.Fatalf("takeover waited %s; an expired claim should be taken immediately", waited)
	}
	var lockedBy string
	if err := s.db.QueryRow(`SELECT locked_by FROM schema_migration WHERE id = 1`).Scan(&lockedBy); err != nil {
		t.Fatal(err)
	}
	if lockedBy != "" {
		t.Fatalf("lock left claimed by %q after a completed migration", lockedBy)
	}
	// A FRESH claim is not taken over: the release of one holder must not clear
	// another's, or the rebuilds could run twice.
	release, err = s.lockMigrations()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := OpenSQLite(path); err == nil {
		t.Fatal("a live claim within its TTL was taken over")
	}
}
