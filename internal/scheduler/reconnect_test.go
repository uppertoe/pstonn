package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// Under a mass expiry, keep-warm must NOT reconnect inline (which would block the pass
// on the serialized login flow for minutes/hours). It enqueues every expired owner —
// deduplicated — and returns fast; the reconnect worker drains the queue separately.
func TestKeepWarmEnqueuesReconnectsWithoutBlocking(t *testing.T) {
	st := newStore(t)
	const n = 30
	for i := 0; i < n; i++ {
		owner := fmt.Sprintf("exp%02d@example.com", i)
		seedSession(t, st, owner)
		seedSchedule(t, st, owner)
	}
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: &fakeNotifier{on: true, admin: true}})
	time.Sleep(2 * time.Millisecond)

	done := make(chan struct{})
	go func() { s.keepWarm(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keepWarm blocked instead of enqueuing reconnects")
	}

	if len(fc.reconnected) != 0 {
		t.Fatalf("keepWarm reconnected inline (%d) instead of enqueuing", len(fc.reconnected))
	}
	s.reconnectMu.Lock()
	queued := len(s.reconnectQ)
	s.reconnectMu.Unlock()
	if queued != n {
		t.Fatalf("queued %d owners, want %d", queued, n)
	}
}

// The reconnect worker drains the queue: a successful reconnect empties the owner and
// kicks their permits. A re-enqueue of an already-queued owner is a no-op (dedup).
func TestReconnectLoopDrainsQueue(t *testing.T) {
	st := newStore(t)
	const owner = "drain@example.com"
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	fc := &fakeCouncil{reconnectSet: true} // reconnect succeeds
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})
	ctx := context.Background()

	g := genOf(t, st, owner)
	s.enqueueReconnect(ctx, owner, g)
	s.enqueueReconnect(ctx, owner, g) // dedup: still one entry
	s.reconnectMu.Lock()
	q := len(s.reconnectQ)
	s.reconnectMu.Unlock()
	if q != 1 {
		t.Fatalf("queue holds %d, want 1 (deduped by owner)", q)
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.reconnectLoop(rctx)

	deadline := time.After(2 * time.Second)
	for {
		s.reconnectMu.Lock()
		q := len(s.reconnectQ)
		s.reconnectMu.Unlock()
		if q == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("reconnect worker did not drain the queue")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if len(fc.reconnected) == 0 {
		t.Fatal("reconnect worker did not attempt the reconnect")
	}
}

// The high-severity regression: a queued reconnect whose generation no longer matches
// the current session (the user manually relinked in the meantime) must do NOTHING —
// not attempt a login, and above all not delete the fresh session.
func TestStaleReconnectDoesNotTouchAFreshSession(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "relink@example.com"
	seedSession(t, st, owner)
	cur, _ := st.GetCouncilSession(ctx, owner)
	fc := &fakeCouncil{reconnectSet: true} // would "succeed" if it ever ran
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})

	stale := cur.Generation + 1 // a generation that no longer matches (a session change happened)
	if got := s.recoverOrRetire(ctx, owner, stale); got != reconnectRetired {
		t.Fatalf("a stale-generation task should be discarded, got %v", got)
	}
	if len(fc.reconnected) != 0 {
		t.Fatal("a stale reconnect must not attempt a login on the fresh session")
	}
	if _, err := st.GetCouncilSession(ctx, owner); err != nil {
		t.Fatalf("the fresh session must survive a stale reconnect task: %v", err)
	}
}

// genOf returns an owner's current session generation — what a real discovery would
// have captured at the moment of failure.
func genOf(t *testing.T, st *store.Store, owner string) int64 {
	t.Helper()
	cs, err := st.GetCouncilSession(context.Background(), owner)
	if err != nil {
		t.Fatalf("read session generation for %s: %v", owner, err)
	}
	return cs.Generation
}
