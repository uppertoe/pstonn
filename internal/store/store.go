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
	"time"

	"modernc.org/sqlite"
)

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
	db *sql.DB
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
	s := &Store{db: db}
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
func (s *Store) Snapshot(ctx context.Context, path string) error {
	_ = os.Remove(path) // VACUUM INTO refuses to overwrite an existing file
	_, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
