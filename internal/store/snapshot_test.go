package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// openWithRow builds a store with one recognisable row, so a snapshot can be
// checked for actually containing data rather than merely existing.
func openWithRow(t *testing.T, dir, name, owner string) *Store {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.RecordConsent(context.Background(), owner, "v1", "hash"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return st
}

// snapshotOwner reads the seeded row back out of a snapshot file, proving it is a
// coherent database and not a truncated copy.
func snapshotOwner(t *testing.T, path, owner string) bool {
	t.Helper()
	snap, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open snapshot %s: %v", path, err)
	}
	defer snap.Close()
	c, err := snap.LatestConsent(context.Background(), owner)
	if err != nil {
		return false
	}
	return c.Owner == owner
}

func TestSnapshotWritesACoherentCopy(t *testing.T) {
	dir := t.TempDir()
	st := openWithRow(t, dir, "live.db", "a@example.com")
	path := filepath.Join(dir, "backup-snapshot.db")

	if err := st.Snapshot(context.Background(), path); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !snapshotOwner(t, path, "a@example.com") {
		t.Error("the snapshot does not contain the seeded row")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("a .tmp file was left behind after a successful snapshot")
	}
}

// The daily run overwrites yesterday's file, so this is the ordinary path and must
// not fail the way a bare VACUUM INTO would.
func TestSnapshotReplacesAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	st := openWithRow(t, dir, "live.db", "a@example.com")
	path := filepath.Join(dir, "backup-snapshot.db")

	if err := os.WriteFile(path, []byte("stale contents from yesterday"), 0o600); err != nil {
		t.Fatalf("pre-write: %v", err)
	}
	if err := st.Snapshot(context.Background(), path); err != nil {
		t.Fatalf("snapshot over an existing file: %v", err)
	}
	if !snapshotOwner(t, path, "a@example.com") {
		t.Error("the snapshot did not replace the stale file with a real database")
	}
}

// This is the regression test for the finding: the old code removed the snapshot
// and only then ran the VACUUM, so a failure (disk full, in practice) destroyed the
// last restorable backup and left nothing in its place — and the retry did it again.
// The previous good snapshot must survive a failed run untouched.
func TestFailedSnapshotKeepsThePreviousGoodOne(t *testing.T) {
	dir := t.TempDir()
	st := openWithRow(t, dir, "live.db", "a@example.com")
	path := filepath.Join(dir, "backup-snapshot.db")

	if err := st.Snapshot(context.Background(), path); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}

	// Force the next VACUUM to fail: a non-empty directory sitting on the temp path
	// can neither be removed nor written to as a file.
	blocker := path + ".tmp"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blocker, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("fill blocker: %v", err)
	}

	if err := st.Snapshot(context.Background(), path); err == nil {
		t.Fatal("expected the snapshot to fail while the temp path is blocked")
	}
	if !snapshotOwner(t, path, "a@example.com") {
		t.Fatal("a failed snapshot destroyed the previous good backup — the exact bug this guards")
	}
}

// A crash can leave a partial temp file; the next run must clear it rather than
// failing forever because the target already exists.
func TestSnapshotClearsALeftoverTempFile(t *testing.T) {
	dir := t.TempDir()
	st := openWithRow(t, dir, "live.db", "a@example.com")
	path := filepath.Join(dir, "backup-snapshot.db")

	if err := os.WriteFile(path+".tmp", []byte("partial write from a crashed run"), 0o600); err != nil {
		t.Fatalf("pre-write: %v", err)
	}
	if err := st.Snapshot(context.Background(), path); err != nil {
		t.Fatalf("snapshot with a leftover temp file: %v", err)
	}
	if !snapshotOwner(t, path, "a@example.com") {
		t.Error("the snapshot is not a coherent database")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temp file should be gone after a successful snapshot")
	}
}
