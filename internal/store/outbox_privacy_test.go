package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A settled outbox row — sent or dead — keeps nothing that names anyone. The
// dedup key is the subtle one: callers build it from the recipient, the permit
// label and the plate, and a sent row kept it in plaintext for a day after the
// message it belonged to had been stripped.
func TestSettledOutboxRowsHoldNoPersonalData(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const owner, guest, plate = "owner@example.com", "guest@example.com", "ABC123"
	key := "apply|" + guest + "|" + owner + "|12 Smith St|" + plate + "|true"

	for i, settle := range []func(id int64) error{
		func(id int64) error { return s.MarkOutboxSent(ctx, id) },
		func(id int64) error { return s.MarkOutboxDead(ctx, id, "email g***@example.com: 550 user unknown") },
	} {
		if err := s.EnqueueOutbox(ctx, OutboxItem{
			Account: owner, DedupKey: key + string(rune('a'+i)), Recipients: []string{guest}, NtfyTopic: "pstonn-secret-topic",
			Subject: "Permit updated: 12 Smith St now shows " + plate, Body: "body naming " + plate, Reason: "because",
		}); err != nil {
			t.Fatal(err)
		}
		due, err := s.DueOutbox(ctx, time.Now(), 10)
		if err != nil || len(due) != 1 {
			t.Fatalf("due = %v, %v", due, err)
		}
		if err := settle(due[0].ID); err != nil {
			t.Fatal(err)
		}
		var status, dedup, recips, topic, subject, body, reason, lastErr string
		if err := s.db.QueryRowContext(ctx,
			`SELECT status, dedup_key, recipients, ntfy_topic, subject, body, reason, last_error FROM outbox WHERE id = ?`, due[0].ID).
			Scan(&status, &dedup, &recips, &topic, &subject, &body, &reason, &lastErr); err != nil {
			t.Fatal(err)
		}
		if recips != "" || topic != "" || subject != "" || body != "" || reason != "" {
			t.Fatalf("%s row still holds content: recipients=%q topic=%q subject=%q body=%q reason=%q", status, recips, topic, subject, body, reason)
		}
		for _, secret := range []string{guest, plate, "Smith"} {
			if strings.Contains(dedup, secret) {
				t.Fatalf("%s row's dedup key still contains %q: %q", status, secret, dedup)
			}
		}
		if !strings.HasPrefix(dedup, dedupKeyPrefix) {
			t.Fatalf("dedup key is not stored hashed: %q", dedup)
		}
		if status == "dead" && lastErr == "" {
			t.Fatal("a dead row should keep its (redacted) last error for the operator")
		}
	}
}

// Keys written in plaintext by older builds are hashed on migration, so a
// pending row keeps deduping against the enqueues a new build makes, and a
// second start leaves the already-hashed keys alone.
func TestMigrationHashesLegacyDedupKeys(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	const key = "apply|guest@example.com|owner@example.com|Visitor|ABC123|true"
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO outbox (dedup_key, recipients, subject, body, status, next_attempt, created_at)
VALUES (?, 'guest@example.com', 'S', 'B', 'pending', '2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z')`, key); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = OpenSQLite(path) // migrates
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT dedup_key FROM outbox`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != HashDedupKey(key) {
		t.Fatalf("legacy key not hashed: %q", stored)
	}
	// Dedup still holds against the plaintext a new build enqueues.
	if err := s.EnqueueOutbox(ctx, OutboxItem{DedupKey: key, Subject: "dup", Body: "dup"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbox`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("a hashed legacy key no longer dedups: %d rows", n)
	}
	// Idempotent: re-hashing a hash would break the equality the dedup relies on.
	if HashDedupKey(stored) != stored {
		t.Fatal("HashDedupKey re-hashed an already-hashed key")
	}
}

// SuppressedAmong is keyed by the caller's spelling, matches case-insensitively,
// tolerates duplicates and blanks, and — the point of the rewrite — asks only
// about the candidates rather than reading the whole list.
func TestSuppressedAmongQueriesOnlyCandidates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, a := range []string{"dead@example.com", "spam@example.com", "other@example.com"} {
		if err := s.SuppressAddress(ctx, a, SuppressBounce, ""); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SuppressedAmong(ctx, []string{"DEAD@example.com", "  ", "fine@example.com", "dead@example.com", "Spam@Example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["DEAD@example.com"] != SuppressBounce || got["dead@example.com"] != SuppressBounce || got["Spam@Example.com"] != SuppressBounce {
		t.Fatalf("SuppressedAmong = %+v", got)
	}
	if _, ok := got["fine@example.com"]; ok {
		t.Fatal("an unsuppressed address was reported")
	}
	if got, err := s.SuppressedAmong(ctx, []string{"", " "}); err != nil || len(got) != 0 {
		t.Fatalf("blank-only input = %+v, %v", got, err)
	}
	// Well past one IN-list chunk, to exercise the chunking.
	many := make([]string, 0, 1203)
	for i := 0; i < 1200; i++ {
		many = append(many, "nobody"+string(rune('a'+i%26))+strings.Repeat("x", i%7)+"@example.com")
	}
	many = append(many, "dead@example.com", "spam@example.com", "other@example.com")
	got, err = s.SuppressedAmong(ctx, many)
	if err != nil || len(got) != 3 {
		t.Fatalf("chunked SuppressedAmong = %d hits, %v; want 3", len(got), err)
	}
}

// A file written by a newer build must not be opened by an older one: the older
// binary would run its own (subset of) migrations against columns it has never
// seen and then fail on the first query that finds one missing.
func TestRefusesNewerSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE schema_migration SET version = ? WHERE id = 1`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = OpenSQLite(path)
	if err == nil || !strings.Contains(err.Error(), "newer build") {
		t.Fatalf("opening a newer schema should refuse with a clear message, got: %v", err)
	}
	// The lock must have been released by the refusing process, or the operator
	// who then runs the right binary waits out the TTL for nothing.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var lockedBy string
	if err := raw.QueryRow(`SELECT locked_by FROM schema_migration WHERE id = 1`).Scan(&lockedBy); err != nil {
		t.Fatal(err)
	}
	if lockedBy != "" {
		t.Fatalf("the refusing process left the migration lock claimed by %q", lockedBy)
	}
	// The same file at THIS version (or older) opens fine.
	if _, err := raw.Exec(`UPDATE schema_migration SET version = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatalf("an older recorded version must open and migrate: %v", err)
	}
	s.Close()
}
