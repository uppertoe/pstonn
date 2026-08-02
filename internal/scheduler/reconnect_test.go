package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
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
	queued := len(s.reconnectAt)
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

	s.enqueueReconnect(ctx, owner)
	s.enqueueReconnect(ctx, owner) // dedup: still one entry
	s.reconnectMu.Lock()
	q := len(s.reconnectAt)
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
		q := len(s.reconnectAt)
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
