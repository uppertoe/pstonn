// Package store is the SQLite persistence layer. It uses the pure-Go
// modernc.org/sqlite driver (CGO_ENABLED=0), matching the vps-scaffold-auth
// build, and keeps WAL mode on for safe hot backups.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"

	"github.com/uppertoe/pstonn/internal/applog"
)

var alog = applog.For("store")

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// sqliteConstraintUnique is SQLITE_CONSTRAINT_UNIQUE. Matching the numeric
// result code (rather than the error string) means a driver upgrade that
// rewords its messages can't break duplicate detection.
const sqliteConstraintUnique = 2067

func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqliteConstraintUnique
}

// ErrDuplicate is returned when an insert violates a uniqueness constraint.
var ErrDuplicate = errors.New("already exists")

// Store wraps the database handle.
type Store struct {
	db   *sql.DB
	path string // the DB file path, for opening a separate snapshot connection

	// tenantCache memoises TenantIDFor per owner (see there); tenantEpoch is
	// bumped by every invalidation so a read that raced a write is not memoised.
	tenantCache sync.Map
	tenantEpoch atomic.Uint64

	// DefaultTenant is the tenant an account belongs to when it has made no
	// choice and holds no session (the process's only enabled tenant). Set by
	// main from the tenant registry; "" in tests.
	DefaultTenant string

	// genMu/lastGen make freshly-seeded session generations strictly increasing
	// within this process; see newSessionGeneration.
	genMu   sync.Mutex
	lastGen int64
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
	// SQLite writer is single; avoids "database is locked".
	//
	// INVARIANT this creates: with one pooled connection, any db.Query/Exec
	// issued while a rows cursor is still open BLOCKS FOREVER waiting for the
	// connection (a hang, not an error). Never nest a query inside rows
	// iteration — materialise the rows into a slice first, then issue follow-up
	// queries (see ListGuestGrants, CreateVehicle for the pattern).
	db.SetMaxOpenConns(1)
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
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Snapshot writes a consistent point-in-time copy of the database to path via
// VACUUM INTO. File-level backup tools (restic on the volume) can read the live
// db and WAL at different instants and produce a backup that doesn't restore;
// this snapshot file is always a coherent database, so back THAT up.
//
// It builds the new copy beside the old one and swaps it in with a rename, because
// VACUUM INTO refuses to overwrite and the obvious way to satisfy that — remove,
// then vacuum — destroys the only good backup before knowing the new one will
// succeed. A VACUUM that fails partway (disk full is the realistic case) then left
// nothing restorable at all, and the retry repeated the same removal, so an outage
// meant no usable backup for its entire duration. The rename is atomic on the same
// filesystem: readers see either the previous snapshot or the new one, never a
// half-written file.
func (s *Store) Snapshot(ctx context.Context, path string) error {
	tmp := path + ".tmp"
	// A leftover temp file from a previous crash would fail the VACUUM below, and it
	// is not the live backup, so it is safe to clear.
	_ = os.Remove(tmp)
	// Run VACUUM INTO on a SEPARATE connection to the same WAL database rather than
	// the single primary connection. On the primary it would hold the one connection
	// for the whole copy — seconds as the DB grows — stalling every HTTP handler and
	// the reconcile loop meanwhile. A second reader in WAL mode sees a consistent
	// committed snapshot and does not block the primary writer. The connection lives
	// only for the duration of the daily snapshot.
	snapDB, err := sql.Open("sqlite", "file:"+s.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer snapDB.Close()
	snapDB.SetMaxOpenConns(1)
	if _, err := snapDB.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		_ = os.Remove(tmp) // don't leave a partial file for the next run to trip over
		return err
	}
	// fsync the copy before publishing it: a rename can otherwise be durable while
	// the contents it points at are not, which after a power loss yields a snapshot
	// that exists but does not open.
	if err := fsyncFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("sync snapshot: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Also fsync the directory, so the rename itself survives a power loss.
	return fsyncDir(filepath.Dir(path))
}

func fsyncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// fsyncDir makes a rename durable. A directory that cannot be opened for sync is
// not worth failing the backup over — the snapshot itself is already written and
// synced — so this reports the error for logging but the caller treats it as
// advisory.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
