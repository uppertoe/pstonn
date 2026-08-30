package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// settle is handed the permit as ListPermits snapshotted it at the START of the
// pass, and the early-return paths in reconcilePermit hand it that snapshot
// unchanged. Judging the close-out on a stale streak logged "recovered" twice —
// the pass that ended the episode and the next one, still holding a snapshot
// with the old streak — and a stale plate could close an episode that had just
// reopened. settle must re-read and act only on a belief that still holds.
func TestSettleReReadsBeforeClosingEpisode(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "settle@example.com"
	pid, _ := seedActivePermit(t, st, owner, "settle-1", "ROSTER1", "ROSTER1")
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: &fakeNotifier{on: true}})

	// A failure episode that has ALREADY been closed durably (streak 0)...
	s.logApply(ctx, pid, "ROSTER1", "roster", "error", "boom")
	stale := model.Permit{ID: pid, Owner: owner, CouncilPermitID: "settle-1", ActiveRegistration: "ROSTER1", FailStreak: failNotifyThreshold}
	s.settle(ctx, stale)
	if last, _ := st.LastApply(ctx, pid); last.Status != "error" {
		t.Fatalf("settle acted on a stale snapshot: last row is %q, want the untouched error", last.Status)
	}

	// ...versus a live one: the durable streak says the episode is open, so the
	// recovery is recorded — exactly once, however many passes hold the old snapshot.
	for i := 0; i < failNotifyThreshold; i++ {
		if _, err := st.BumpFailStreak(ctx, pid); err != nil {
			t.Fatal(err)
		}
	}
	s.settle(ctx, stale)
	s.settle(ctx, stale) // the next pass, same snapshot, streak now 0 in the store
	logs, err := st.ListApplyLogFor(ctx, owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	recovered := 0
	for _, r := range logs {
		if r.Status == "success" {
			recovered++
		}
	}
	if recovered != 1 {
		t.Fatalf("recovered rows = %d, want exactly 1: %+v", recovered, logs)
	}
	if p, _ := st.GetPermit(ctx, pid); p.FailStreak != 0 {
		t.Fatalf("streak = %d after settle, want 0", p.FailStreak)
	}

	// A plate that moved under the snapshot is not this pass's call to settle.
	for i := 0; i < failNotifyThreshold; i++ {
		_, _ = st.BumpFailStreak(ctx, pid)
	}
	if err := st.SetPermitActive(ctx, pid, "GUEST22"); err != nil {
		t.Fatal(err)
	}
	s.settle(ctx, stale) // snapshot still says ROSTER1
	if p, _ := st.GetPermit(ctx, pid); p.FailStreak == 0 {
		t.Fatal("settle closed an episode on a plate belief that no longer held")
	}
}
