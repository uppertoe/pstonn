package scheduler

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// TestRequestDriftSoon pins the early-drift mechanism: observed evidence of
// divergence (a guest page's council read disagreeing with the stored belief)
// makes the owner's drift read due on the next warm pass instead of in ~6h —
// but never bypasses the failure backoff, and the intent survives until a
// drift round actually completes.
func TestRequestDriftSoon(t *testing.T) {
	s := New(newStore(t), &fakeCouncil{}, time.UTC, Options{DriftInterval: 6 * time.Hour})
	now := time.Now()
	cs := store.CouncilSession{Owner: "o@example.com", DriftCheckedAt: now.Add(-time.Minute), UpdatedAt: now}

	// Freshly checked: not due on the cadence.
	if s.driftDue(cs, now) {
		t.Fatal("fresh check reported due")
	}
	// A divergence observation makes it due immediately…
	s.RequestDriftSoon(cs.Owner)
	if !s.driftDue(cs, now) {
		t.Fatal("requested drift not due")
	}
	// …idempotently…
	s.RequestDriftSoon(cs.Owner)
	if !s.driftDue(cs, now) {
		t.Fatal("repeat request lost the intent")
	}
	// …without touching anyone else…
	other := store.CouncilSession{Owner: "x@example.com", DriftCheckedAt: now.Add(-time.Minute), UpdatedAt: now}
	if s.driftDue(other, now) {
		t.Fatal("request leaked to another owner")
	}
	// …and the intent clears only once a round completes for the owner.
	s.clearDriftRequest(cs.Owner)
	if s.driftDue(cs, now) {
		t.Fatal("cleared request still due")
	}

	// The failure backoff still paces a requested read: hammering a council that
	// is failing (or throttling us) is worse than a briefly stale belief.
	s.RequestDriftSoon(cs.Owner)
	s.driftMu.Lock()
	s.driftRetryAt[cs.Owner] = now.Add(30 * time.Minute)
	s.driftMu.Unlock()
	if s.driftDue(cs, now) {
		t.Fatal("request bypassed the failure backoff")
	}
	// Backoff elapsed: the intent was kept, not lost.
	if !s.driftDue(cs, now.Add(31*time.Minute)) {
		t.Fatal("intent lost while backed off")
	}
}
