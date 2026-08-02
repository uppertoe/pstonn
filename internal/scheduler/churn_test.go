package scheduler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
)

func hasAdmin(fn *fakeNotifier, substr string) bool {
	for _, s := range fn.adminSnap() {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// pruneChurn/distinctOwners are the window arithmetic behind the canary; test them
// directly with controlled times (the live path uses time.Now()).
func TestChurnWindowArithmetic(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	events := []churnEvent{
		{"a", now.Add(-90 * time.Minute)}, // outside the 1h window
		{"b", now.Add(-30 * time.Minute)},
		{"b", now.Add(-10 * time.Minute)}, // same owner again
		{"c", now.Add(-1 * time.Minute)},
	}
	kept := pruneChurn(events, now)
	if len(kept) != 3 {
		t.Fatalf("pruned len = %d, want 3 (the 90m-old event dropped)", len(kept))
	}
	if d := distinctOwners(kept); d != 2 {
		t.Fatalf("distinct owners = %d, want 2 (b and c)", d)
	}
}

// The canary: several DIFFERENT owners re-authing within the hour is systemic and
// alerts the operator; the same owner flapping is not. A transient reconnect error
// keeps the session in place, so the only admin note that can appear is the canary.
func TestSessionChurnAlertsOnDistinctOwners(t *testing.T) {
	st := newStore(t)
	fn := &fakeNotifier{on: true, admin: true}
	fc := &fakeCouncil{reconnectSet: true, reconnectErr: errors.New("503 busy")}
	s := New(st, fc, time.UTC, Options{Notifier: fn})
	ctx := context.Background()
	for _, o := range []string{"flap@example.com", "a@example.com", "b@example.com", "c@example.com"} {
		seedSession(t, st, o) // enqueueReconnect reads the session for its generation
	}

	// The same owner three times must NOT alert (the queue dedups by owner, so the
	// churn is noted once — one flapping account is not systemic).
	for i := 0; i < 3; i++ {
		s.enqueueReconnect(ctx, "flap@example.com")
	}
	time.Sleep(40 * time.Millisecond)
	if hasAdmin(fn, "expiring unusually often") {
		t.Fatalf("one flapping owner should not trip the churn alert: %v", fn.adminSnap())
	}

	// Three DIFFERENT owners within the window → systemic.
	for _, o := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		s.enqueueReconnect(ctx, o)
	}
	time.Sleep(60 * time.Millisecond)
	if !hasAdmin(fn, "expiring unusually often") {
		t.Fatalf("three distinct owners re-authing should alert, got %v", fn.adminSnap())
	}

	// And the churn is visible on the metric surface (flap deduped to 1, plus a/b/c).
	exp, _, owners := s.SessionChurn()
	if owners < 3 {
		t.Errorf("expired_owners_1h = %d, want >=3", owners)
	}
	if exp < 4 {
		t.Errorf("expiries_1h = %d, want >=4 (flap once + three owners)", exp)
	}
}

// A login-page-shape change during reconnect is raised as SYSTEMIC while the session
// + saved password are KEPT: recovery must resume automatically once the flow is
// fixed, not force a mass re-link that would hit the same broken form.
func TestLoginShapeChangeAlertsAndKeepsSession(t *testing.T) {
	ctx := context.Background()
	const owner = "shape@example.com"
	st := newStore(t)
	seedSession(t, st, owner)
	fn := &fakeNotifier{on: true, admin: true}
	fc := &fakeCouncil{reconnectSet: true, reconnectErr: parking.ErrLoginFormUnrecognised}
	s := New(st, fc, time.UTC, Options{Notifier: fn})

	cs, _ := st.GetCouncilSession(ctx, owner)
	if got := s.recoverOrRetire(ctx, owner, cs.Generation); got != reconnectDeferred {
		t.Fatalf("a login-shape failure should defer (keep the session), got %v", got)
	}
	if _, err := st.GetCouncilSession(ctx, owner); err != nil {
		t.Fatalf("session was retired on a login-shape change (recovery could not resume): %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if !hasAdmin(fn, "sign-in page shape changed") {
		t.Fatalf("expected a login-shape systemic alert, got %v", fn.adminSnap())
	}
}

// A successful auto-reconnect is counted on the reconnects_1h surface.
func TestReconnectCounted(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedSession(t, st, "ok@example.com")
	fc := &fakeCouncil{reconnectSet: true} // reconnectErr nil = success
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})

	s.enqueueReconnect(ctx, "ok@example.com") // discovery notes the expiry
	if !s.drainOneReconnect(ctx) {            // the worker reconnects
		t.Fatal("expected a queued reconnect to process")
	}
	exp, reconns, _ := s.SessionChurn()
	if reconns != 1 {
		t.Errorf("reconnects_1h = %d, want 1", reconns)
	}
	if exp != 1 {
		t.Errorf("expiries_1h = %d, want 1 (the expiry that triggered the reconnect)", exp)
	}
}
