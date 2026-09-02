package scheduler

import (
	"context"
	"errors"
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
	fc := &fakeTenant{refreshErr: parking.ErrSessionExpired}
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
	fc := &fakeTenant{reconnectSet: true} // reconnect succeeds
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})
	ctx := context.Background()

	g := genOf(t, st, owner)
	s.enqueueReconnect(ctx, owner, "", g)
	s.enqueueReconnect(ctx, owner, "", g) // dedup: still one entry
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
	cur, _ := st.GetTenantSession(ctx, owner)
	fc := &fakeTenant{reconnectSet: true} // would "succeed" if it ever ran
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})

	stale := cur.Generation + 1 // a generation that no longer matches (a session change happened)
	if got := s.recoverOrRetire(ctx, owner, "", stale, true); got != reconnectRetired {
		t.Fatalf("a stale-generation task should be discarded, got %v", got)
	}
	if len(fc.reconnected) != 0 {
		t.Fatal("a stale reconnect must not attempt a login on the fresh session")
	}
	if _, err := st.GetTenantSession(ctx, owner); err != nil {
		t.Fatalf("the fresh session must survive a stale reconnect task: %v", err)
	}
}

// TestReconnectQueueCompletesUnderGovernorHold: back-to-back reconnects drain the
// login governor's burst, after which every login first WAITS for tokens. The
// worker's deadline must cover that wait — a flat portal-only bound expired inside
// it and cancelled logins mid-flow (a half-completed IdP authentication). The fake
// models the hold as a ctx-honouring wait longer than the portal allowance alone;
// with the governor's budget added, a queue of several reconnects all recover.
func TestReconnectQueueCompletesUnderGovernorHold(t *testing.T) {
	ctx := context.Background()
	run := func(budget time.Duration) (*fakeTenant, *Scheduler, int) {
		st := newStore(t)
		fc := &fakeTenant{reconnectSet: true, reconnectWait: 40 * time.Millisecond, loginBudget: budget}
		s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})
		s.reconnectPortal = 15 * time.Millisecond // the portal's share alone is not enough
		const n = 4
		for i := 0; i < n; i++ {
			owner := fmt.Sprintf("gov%d@example.com", i)
			seedSession(t, st, owner)
			s.enqueueReconnect(ctx, owner, "", genOf(t, st, owner))
		}
		for i := 0; i < n; i++ {
			if !s.drainOneReconnect(ctx) {
				break
			}
		}
		return fc, s, n
	}

	// Without the budget the deadline expires inside the hold: nothing recovers.
	fc, s, _ := run(0)
	if queued, _, _ := s.ReconnectBacklog(); queued == 0 {
		t.Fatal("control: a portal-only deadline should have expired inside the governor hold and deferred the reconnects")
	}
	// With it, every queued owner recovers in one drain each.
	fc, s, n := run(60 * time.Millisecond)
	if queued, _, _ := s.ReconnectBacklog(); queued != 0 {
		t.Fatalf("queue still holds %d after draining %d reconnects under the governor hold", queued, n)
	}
	if len(fc.reconnected) != n {
		t.Fatalf("reconnect attempts = %d, want %d", len(fc.reconnected), n)
	}
	if !fc.reconnectHadDeadline {
		t.Fatal("the reconnect must still be bounded")
	}
	// The deadline is the portal allowance PLUS the governor's budget.
	if got := s.reconnectDeadline(""); got != 15*time.Millisecond+60*time.Millisecond {
		t.Fatalf("reconnect deadline = %v, want portal+budget", got)
	}
	// And the default portal allowance holds when no test override is set.
	s.reconnectPortal = 0
	if got := s.reconnectDeadline(""); got != reconnectPortalTime+60*time.Millisecond {
		t.Fatalf("default reconnect deadline = %v, want %v", got, reconnectPortalTime+60*time.Millisecond)
	}
}

// genOf returns an owner's current session generation — what a real discovery would
// have captured at the moment of failure.
func genOf(t *testing.T, st *store.Store, owner string) int64 {
	t.Helper()
	cs, err := st.GetTenantSession(context.Background(), owner)
	if err != nil {
		t.Fatalf("read session generation for %s: %v", owner, err)
	}
	return cs.Generation
}

// ReconnectActive is tenant-scoped and ages out: it reports true only for THIS
// (owner, tenant) while the queued item is still within reconnectActiveWindow, so
// a caller's in-progress page can't gate a different council's page and can't trap
// a user on a spinner once the reconnect is stuck in backoff.
func TestReconnectActiveScopeAndWindow(t *testing.T) {
	st := newStore(t)
	s := New(st, &fakeTenant{}, time.UTC, Options{})
	const owner = "a@example.com"

	s.NoteSessionExpired(owner, "councilA", 1)
	if !s.ReconnectActive(owner, "councilA") {
		t.Fatal("a freshly queued reconnect should be active for its tenant")
	}
	// A different tenant, and a different owner, must not read as active.
	if s.ReconnectActive(owner, "councilB") {
		t.Fatal("a reconnect queued for councilA must not gate councilB")
	}
	if s.ReconnectActive("other@example.com", "councilA") {
		t.Fatal("another owner's picker must not be gated")
	}

	// Age the queued item past the active window (as a stuck-in-backoff item would):
	// still queued, but no longer "in flight", so the caller falls back to the form.
	s.reconnectMu.Lock()
	it := s.reconnectQ[sessionKey{owner, "councilA"}]
	it.queuedAt = time.Now().Add(-2 * reconnectActiveWindow)
	s.reconnectQ[sessionKey{owner, "councilA"}] = it
	s.reconnectMu.Unlock()
	if s.ReconnectActive(owner, "councilA") {
		t.Fatal("a reconnect aged past the window must read as inactive")
	}
	// It is still queued — the item was not dropped, only aged.
	s.reconnectMu.Lock()
	_, stillQueued := s.reconnectQ[sessionKey{owner, "councilA"}]
	s.reconnectMu.Unlock()
	if !stillQueued {
		t.Fatal("aging must not dequeue the item")
	}
}

// QueueReconnect (the picker's foreground path) must recover the session WITHOUT
// feeding the session-churn canary — ordinary returning users are not the
// many-distinct-owners fleet signal that canary watches for. NoteSessionExpired
// (background discovery) still feeds it.
func TestQueueReconnectDoesNotFeedChurn(t *testing.T) {
	st := newStore(t)
	s := New(st, &fakeTenant{}, time.UTC, Options{})

	s.QueueReconnect("a@example.com", "councilA", 1)
	s.QueueReconnect("b@example.com", "councilA", 1)
	if exp, _, owners := s.SessionChurn(); exp != 0 || owners != 0 {
		t.Fatalf("interactive QueueReconnect fed the churn canary: expiries=%d owners=%d", exp, owners)
	}
	if !s.ReconnectActive("a@example.com", "councilA") {
		t.Fatal("QueueReconnect must still queue the recovery")
	}
	// Background discovery of a genuine expiry does feed it.
	s.NoteSessionExpired("c@example.com", "councilA", 1)
	if exp, _, owners := s.SessionChurn(); exp != 1 || owners != 1 {
		t.Fatalf("NoteSessionExpired should feed the canary once: expiries=%d owners=%d", exp, owners)
	}
}

// queuedItem reads the current queue entry for key — the identity the worker
// copies out before an attempt.
func queuedItem(t *testing.T, s *Scheduler, key sessionKey) reconnectItem {
	t.Helper()
	s.reconnectMu.Lock()
	defer s.reconnectMu.Unlock()
	it, ok := s.reconnectQ[key]
	if !ok {
		t.Fatalf("no reconnect queued for %v", key)
	}
	return it
}

// The worker copies (key, generation) out of the queue, attempts the reconnect,
// and then dequeues or backs off whatever the key holds. A CancelReconnect plus
// a fresh enqueue inside that window (a manual link landing mid-attempt, then
// the new session's own expiry being noticed) put a NEW, never-attempted item
// under the same key, which the old code then deleted — or backed off by five
// minutes and counted toward the stalled alert. The finished attempt must leave
// an item it did not attempt alone.
func TestDrainLeavesAnItemRequeuedDuringTheAttempt(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		err  error // what the in-flight reconnect returns
	}{
		{"deferred attempt must not back off the new item", errors.New("council busy 503")},
		{"recovered attempt must not dequeue the new item", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(t)
			const owner = "midflight@example.com"
			seedSession(t, st, owner)
			gen := genOf(t, st, owner)
			fc := &fakeTenant{reconnectSet: true, reconnectWait: 150 * time.Millisecond, reconnectErr: tc.err}
			s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})
			key := sessionKey{owner, ""}

			s.enqueueReconnect(ctx, owner, "", gen)
			done := make(chan struct{})
			go func() { defer close(done); s.drainOneReconnect(ctx) }()
			time.Sleep(30 * time.Millisecond) // inside the attempt window
			s.CancelReconnect(owner)
			s.QueueReconnect(owner, "", gen+1) // a fresh item the attempt knows nothing about
			<-done

			it := queuedItem(t, s, key)
			if it.gen != gen+1 {
				t.Fatalf("queued gen = %d, want the fresh item's %d", it.gen, gen+1)
			}
			if it.attempts != 0 || it.next.After(time.Now()) {
				t.Fatalf("the never-attempted item was backed off: attempts=%d next in %s", it.attempts, time.Until(it.next))
			}
		})
	}
}

// CancelReconnectIn drops only the named tenant's item; the owner-wide
// CancelReconnect still clears every tenant, for the account-deletion callers.
func TestCancelReconnectInIsTenantScoped(t *testing.T) {
	st := newStore(t)
	s := New(st, &fakeTenant{}, time.UTC, Options{})
	const owner = "twoareas@example.com"
	s.NoteSessionExpired(owner, "councilA", 1)
	s.NoteSessionExpired(owner, "councilB", 1)

	s.CancelReconnectIn(owner, "councilA")
	if s.reconnectQueued(owner, "councilA") {
		t.Fatal("councilA's reconnect should have been cancelled")
	}
	if !s.reconnectQueued(owner, "councilB") {
		t.Fatal("cancelling councilA's reconnect dropped councilB's — valid recovery work discarded")
	}
	s.CancelReconnect(owner)
	if s.reconnectQueued(owner, "councilB") {
		t.Fatal("the owner-wide cancel must clear every tenant")
	}
}
