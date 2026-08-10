package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
)

// TestSessionExpiredTellsTheUserEventually: an expired council session hit on
// the RECONCILE path (a wanted change that cannot apply) used to be completely
// silent — no activity row, no fail streak, no notification, however long the
// reconnect worker kept deferring. The keep-warm path had six tests; this path
// had none. A brief expiry should still stay quiet (auto-reconnect usually
// heals it in minutes), but a sustained one has to reach the person whose
// permit is wrong.
func TestSessionExpiredTellsTheUserEventually(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "expired@example.com"
	pid, _ := seedActivePermit(t, st, owner, "sess-1", "AAA111", "OLD999")

	fc := &fakeCouncil{setErr: parking.ErrSessionExpired}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, Notifier: nf})

	// Below the threshold: quiet, but already visible in the activity log. Each
	// tick defers the permit ~8 minutes; clear the deferral to simulate time
	// passing rather than ticks being skipped.
	for i := 0; i < sessionNotifyThreshold-1; i++ {
		s.reconcileAll(ctx)
		s.clearRetry(pid)
	}
	if n := len(nf.appliedSnap()); n != 0 {
		t.Fatalf("a brief session expiry notified the user %d time(s); it should stay quiet while reconnect recovers", n)
	}
	logs, err := st.ListApplyLogFor(ctx, owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || logs[0].Status != "error" {
		t.Fatalf("a session-expired apply should be recorded in the activity log, got %+v", logs)
	}

	// One more failing attempt crosses the threshold: now they hear about it,
	// urgently (quiet hours must not sit on a wrong plate for a further night).
	s.reconcileAll(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for len(nf.appliedSnap()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a sustained session expiry never reached the user")
		}
		time.Sleep(5 * time.Millisecond)
	}
	out := nf.outcomeSnap()[0]
	if out.OK || !out.Transient || !out.Urgent {
		t.Fatalf("a stalled session expiry should read as a transient, URGENT failure, got OK=%v Transient=%v Urgent=%v",
			out.OK, out.Transient, out.Urgent)
	}
	if out.CurrentReg != "OLD999" {
		t.Fatalf("the notice should say what is still on the permit, got %q", out.CurrentReg)
	}
}

// TestStalledReconnectAlertsHouseholdOnce: recoverOrRetire deliberately keeps
// the session (and retries forever) for transient failures and for a changed
// council sign-in page — states that used to reach only the operator while the
// household's schedule silently stopped applying. Once the backoff count says
// the reconnect has stalled, the household is told exactly once per queue
// residency.
func TestStalledReconnectAlertsHouseholdOnce(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "stalled@example.com"
	seedSession(t, st, owner)

	fc := &fakeCouncil{}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, Notifier: nf})

	s.enqueueReconnect(ctx, owner, 1)
	for i := 0; i < reconnectStalledAlertAttempts-1; i++ {
		s.backoffReconnect(owner)
	}
	time.Sleep(20 * time.Millisecond) // alerts fire from goroutines
	if n := len(nf.stalledSnap()); n != 0 {
		t.Fatalf("stalled alert fired after only %d attempts (%d notices); backoff is still routine there",
			reconnectStalledAlertAttempts-1, n)
	}

	// The attempt that crosses the line alerts...
	s.backoffReconnect(owner)
	deadline := time.Now().Add(2 * time.Second)
	for len(nf.stalledSnap()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a stalled reconnect never alerted the household")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// ...and further deferrals do not repeat it.
	s.backoffReconnect(owner)
	s.backoffReconnect(owner)
	time.Sleep(20 * time.Millisecond)
	if got := nf.stalledSnap(); len(got) != 1 || got[0] != owner {
		t.Fatalf("stalled alert should fire exactly once per queue residency, got %v", got)
	}
}
