package scheduler

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestCheckDriftClearsNotifiedKey (S16): when an external portal edit is adopted,
// checkDrift must clear the delivered-notification fingerprint. Otherwise, if the edit
// RESTORED the previous plate, the re-assertion is the same prev->want transition as the
// original apply, the transition key matches the stored one, and the "your permit was
// updated" notice is deduped away — so the resident is never told their deliberate manual
// change was reverted, the exact fine-risk case the notice exists for. Asserted directly
// (the notify delivery itself is async).
func TestCheckDriftClearsNotifiedKey(t *testing.T) {
	ctx := context.Background()
	const owner, tenantID = "drift@example.com", "drift-notify"
	// Roster wants BBB222 and we believe BBB222, but the tenant shows AAA111: a resident
	// put the previous plate back in the portal.
	st, _, _, s, pid := driftSetup(t, owner, tenantID, "BBB222", "BBB222", "AAA111")
	// Seed the fingerprint as though we had already notified for the AAA111->BBB222 apply.
	if err := st.SetPermitNotifiedKey(ctx, pid, "success|AAA111>BBB222"); err != nil {
		t.Fatal(err)
	}
	if err := s.checkDrift(ctx, owner, ""); err != nil {
		t.Fatal(err)
	}
	key, _, err := st.PermitNotify(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		t.Fatalf("notified_key after drift = %q, want empty: a restored-previous-plate re-assertion would be deduped and go unreported", key)
	}
}

// TestSnapshotBacksOffOnFailure (S22): a failing snapshot must not retry a full-size
// VACUUM every housekeeping tick (15 min). It stamps an attempt time on every try and,
// once one has failed (lastSnapshot not advanced), backs off to hourly.
func TestSnapshotBacksOffOnFailure(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: &fakeNotifier{on: true, admin: true}})
	// A parent directory that does not exist makes store.Snapshot fail deterministically.
	s.snapshotPath = filepath.Join(t.TempDir(), "no-such-dir", "snap.db")
	s.lastSnapshot = time.Now().Add(-25 * time.Hour) // due for a daily snapshot

	s.maybeSnapshot(ctx)
	if s.lastSnapshotAttempt.IsZero() {
		t.Fatal("a snapshot attempt must be stamped even on failure")
	}
	if !s.lastSnapshot.Before(time.Now().Add(-24 * time.Hour)) {
		t.Fatal("a failed snapshot must not advance lastSnapshot (that would suppress the retry entirely)")
	}
	firstAttempt := s.lastSnapshotAttempt

	// A second immediate call must NOT retry within the hour: the guard returns before
	// stamping, so the attempt time is unchanged.
	s.maybeSnapshot(ctx)
	if !s.lastSnapshotAttempt.Equal(firstAttempt) {
		t.Fatal("a failing snapshot retried within the hour instead of backing off to hourly")
	}
}
