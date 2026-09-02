package scheduler

import (
	"context"
	"strings"
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

// settle closes an episode whose target went away unapplied with a notice, and
// that notice used to describe itself as correcting "the earlier notice that
// p.stonn was still trying" whenever the streak reached failNotifyThreshold (3).
// But the council-busy path only speaks at busyNotifyThreshold (15) and the
// expired-session path at sessionNotifyThreshold (4), so a household could be
// told a notice was being corrected that they never received. The wording must
// follow what was actually DELIVERED (the durable notified key); the fact that
// the car was never covered is sent either way.
func TestSettleCorrectionWordingFollowsWhatWasDelivered(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "settle-wording@example.com"
	fn := &fakeNotifier{on: true}
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: fn})

	// One permit per scenario, so each close-out has its own notify key. Each
	// holds ROSTER1 with a three-tick failure to put GUEST22 on — a busy episode
	// short of busyNotifyThreshold, so nothing was necessarily sent.
	open := func(cid string) model.Permit {
		pid, err := st.UpsertPermit(ctx, owner, cid, "14", "Permit")
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetPermitActive(ctx, pid, "ROSTER1"); err != nil {
			t.Fatal(err)
		}
		s.logApply(ctx, pid, "GUEST22", "override", "error", "The council is refusing p.stonn's connection right now.")
		for i := 0; i < failNotifyThreshold; i++ {
			if _, err := st.BumpFailStreak(ctx, pid); err != nil {
				t.Fatal(err)
			}
		}
		return model.Permit{ID: pid, Owner: owner, CouncilPermitID: cid, ActiveRegistration: "ROSTER1", FailStreak: failNotifyThreshold}
	}
	// Scenarios run one after another and each sends exactly one close-out, so
	// the i-th outcome is the i-th scenario's.
	actionOf := func(i int) string {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if outs := fn.outcomeSnap(); len(outs) > i {
				if o := outs[i]; o.Reg != "GUEST22" {
					t.Fatalf("outcome %d is about %q, want the GUEST22 close-out: %+v", i, o.Reg, o)
				}
				return outs[i].Action
			}
			if time.Now().After(deadline) {
				t.Fatalf("close-out notice %d never arrived; outcomes: %+v", i, fn.outcomeSnap())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Nothing was ever delivered: the close-out must not claim to correct a notice.
	s.settle(ctx, open("wording-1"))
	got := actionOf(0)
	if !strings.Contains(got, "Nothing to apply now") || !strings.Contains(got, "GUEST22") {
		t.Fatalf("the never-applied fact must still be sent, got %q", got)
	}
	if strings.Contains(got, "corrects the earlier notice") {
		t.Fatalf("the close-out refers to a notice that was never sent: %q", got)
	}

	// The same episode, but the busy notice for GUEST22 WAS delivered (the durable
	// key records exactly that): now the close-out is a correction.
	pTold := open("wording-2")
	if err := st.SetPermitNotifiedKey(ctx, pTold.ID, "busy|GUEST22|"+s.failureKeyDay(pTold)); err != nil {
		t.Fatal(err)
	}
	s.settle(ctx, pTold)
	if got := actionOf(1); !strings.Contains(got, "corrects the earlier notice") {
		t.Fatalf("a delivered notice must be corrected, got %q", got)
	}

	// A delivered notice about a DIFFERENT plate is not the one being corrected.
	pOther := open("wording-3")
	if err := st.SetPermitNotifiedKey(ctx, pOther.ID, "session|OTHER99|"+s.failureKeyDay(pOther)); err != nil {
		t.Fatal(err)
	}
	s.settle(ctx, pOther)
	if got := actionOf(2); strings.Contains(got, "corrects the earlier notice") {
		t.Fatalf("a notice about another plate was treated as the one being corrected: %q", got)
	}
}
