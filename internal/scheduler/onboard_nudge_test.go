package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
)

// nudgeScheduler builds a scheduler whose nudge window admits a consent recorded
// this instant: production waits a day before emailing, but a test cannot.
// nudgeAfter is negative so the newest bound sits in the future.
func nudgeScheduler(t *testing.T, fn Notifier) *Scheduler {
	t.Helper()
	st := newStore(t)
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})
	s.nudgeAfter = -time.Hour
	if err := st.RecordConsent(context.Background(), "stalled@example.com", "v1", "hash"); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestOnboardNudgeSentOnce pins the sweep's core promise — the recovery email
// goes out exactly once, however many housekeeping passes follow — because the
// email itself tells the recipient "this is the only reminder p.stonn sends".
func TestOnboardNudgeSentOnce(t *testing.T) {
	ctx := context.Background()
	fn := &fakeNotifier{on: true}
	s := nudgeScheduler(t, fn)

	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 1 || got[0] != "stalled@example.com" {
		t.Fatalf("nudged = %v, want exactly the stalled signup", got)
	}
	s.sweepOnboardNudges(ctx)
	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 1 {
		t.Fatalf("repeat sweeps re-sent the once-ever email: %v", got)
	}
}

// TestOnboardNudgeRetriesTransientFailure: a failed SMTP send must NOT burn the
// one shot — the mark is written only after a settled send, so the next sweep
// tries again.
func TestOnboardNudgeRetriesTransientFailure(t *testing.T) {
	ctx := context.Background()
	fn := &fakeNotifier{on: true, nudgeErr: fmt.Errorf("smtp: connection refused")}
	s := nudgeScheduler(t, fn)

	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 1 {
		t.Fatalf("attempts = %v, want one", got)
	}
	// The failure healed; the same person is still owed their email.
	fn.mu.Lock()
	fn.nudgeErr = nil
	fn.mu.Unlock()
	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 2 {
		t.Fatalf("attempts after recovery = %v, want a retry", got)
	}
	// And once delivered, it is done.
	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 2 {
		t.Fatalf("delivered nudge repeated: %v", got)
	}
}

// TestOnboardNudgeSuppressedMarksDone: a suppressed address (bounce, complaint,
// unsubscribe) never improves by retrying — the sweep marks it settled instead
// of relitigating an address that asked to be left alone every 15 minutes.
func TestOnboardNudgeSuppressedMarksDone(t *testing.T) {
	ctx := context.Background()
	fn := &fakeNotifier{on: true, nudgeErr: fmt.Errorf("wrapped: %w", notify.ErrSuppressed)}
	s := nudgeScheduler(t, fn)

	s.sweepOnboardNudges(ctx)
	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 1 {
		t.Fatalf("suppressed address retried: %v attempts", len(got))
	}
}

// TestOnboardNudgeNeedsEmail: the nudge is email-only (its audience configured
// no other channel), so an ntfy-only deployment must neither send nor — worse —
// mark anyone done against a channel that silently no-ops.
func TestOnboardNudgeNeedsEmail(t *testing.T) {
	ctx := context.Background()
	fn := &ntfyOnlyNotifier{}
	s := nudgeScheduler(t, fn)

	s.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 0 {
		t.Fatalf("email-less deployment attempted a nudge: %v", got)
	}
	// SMTP arrives later (config change + restart): the person is still owed
	// their email — the wait must not have burned it.
	fn.fakeNotifier.on = true
	s2 := New(s.store, &fakeCouncil{}, time.UTC, Options{Notifier: &fn.fakeNotifier})
	s2.nudgeAfter = -time.Hour
	s2.sweepOnboardNudges(ctx)
	if got := fn.nudgedSnap(); len(got) != 1 {
		t.Fatalf("nudge after SMTP arrived = %v, want one send", got)
	}
}
