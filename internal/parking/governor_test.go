package parking

import (
	"context"
	"testing"
	"time"
)

// The token bucket must hand out its burst immediately, then refill at the
// configured rate — no faster (or it would not cap) and no slower (or it would
// starve the fleet). Driven with an injected clock so it is deterministic.
func TestTokenBucketRefill(t *testing.T) {
	tb := newTokenBucket(60, 3) // 60/min = 1/s, burst 3
	t0 := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)

	// Burst of 3 available at once.
	for i := 0; i < 3; i++ {
		if ok, _ := tb.tryTake(t0); !ok {
			t.Fatalf("burst token %d should be available immediately", i+1)
		}
	}
	// Fourth is refused, and asks to wait ~1s (the 1/s refill).
	ok, wait := tb.tryTake(t0)
	if ok {
		t.Fatal("bucket handed out more than its burst without refill")
	}
	if wait < 900*time.Millisecond || wait > 1100*time.Millisecond {
		t.Fatalf("expected ~1s wait for the next token, got %s", wait)
	}
	// After 1s exactly one token has accrued.
	if ok, _ := tb.tryTake(t0.Add(time.Second)); !ok {
		t.Fatal("a token should have accrued after 1s")
	}
	if ok, _ := tb.tryTake(t0.Add(time.Second)); ok {
		t.Fatal("only one token should accrue per second")
	}
	// It never accrues beyond the burst, however long it idles.
	tb.tryTake(t0.Add(time.Hour)) // refill (capped) + take one
	full := 0
	for {
		if ok, _ := tb.tryTake(t0.Add(time.Hour)); !ok {
			break
		}
		full++
		if full > 10 {
			t.Fatal("bucket refilled past its burst")
		}
	}
}

// The concurrency cap must bound simultaneous requests: with a cap of 2, a third
// acquire blocks until one releases.
func TestGovernorConcurrencyCap(t *testing.T) {
	g := newGovernor(6000, 100, 6000, 100, 2) // rates generous so only concurrency bites
	ctx := context.Background()

	r1, err := g.acquire(ctx, "/ssp-svc/api/x")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := g.acquire(ctx, "/ssp-svc/api/x")
	if err != nil {
		t.Fatal(err)
	}

	// A third acquire must block until a slot frees.
	done := make(chan struct{})
	go func() {
		r3, err := g.acquire(ctx, "/ssp-svc/api/x")
		if err == nil {
			r3()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("third acquire proceeded past a concurrency cap of 2")
	case <-time.After(20 * time.Millisecond):
	}
	r1() // free a slot
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("third acquire did not proceed after a slot freed")
	}
	r2()
}

// A cancelled context must unblock a waiting acquire rather than hang.
func TestGovernorRespectsContext(t *testing.T) {
	g := newGovernor(0.001, 0, 0.001, 0, 1) // effectively no tokens
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.acquire(ctx, "/ssp-svc/api/x"); err == nil {
		t.Fatal("acquire should fail when the context expires before a token")
	}
}

// A nil governor is a no-op, so the feature disables cleanly (and tests without one
// are unbounded).
func TestNilGovernorAllows(t *testing.T) {
	var g *governor
	release, err := g.acquire(context.Background(), "/idm/Account/Login")
	if err != nil {
		t.Fatalf("nil governor should allow: %v", err)
	}
	release() // must not panic
}

// TestLoginBudgetCoversDrainedBuckets: under the DEFAULT limits a full credential
// login (6 requests) needs 30s of login-bucket accrual once the burst is spent
// (12/min = one token per 5s) plus 6s in the total bucket, so a reconnect deadline
// sized without it would expire mid-login on the second back-to-back reconnect.
// A nil governor (request-free providers, bare test clients) budgets nothing.
func TestLoginBudgetCoversDrainedBuckets(t *testing.T) {
	tr := NewTransport(Limits{})
	if got, want := tr.gov.loginBudget(), 36*time.Second; got != want {
		t.Fatalf("default login budget = %v, want %v", got, want)
	}
	if got := (*governor)(nil).loginBudget(); got != 0 {
		t.Fatalf("nil governor budget = %v, want 0", got)
	}
	if got := NewClientFor("t", nil, nil, nil, nil).LoginBudget(); got != 0 {
		t.Fatalf("ungoverned client budget = %v, want 0", got)
	}
	if got := NewClientFor("t", nil, nil, nil, tr).LoginBudget(); got != 36*time.Second {
		t.Fatalf("governed client budget = %v, want 36s", got)
	}
}
