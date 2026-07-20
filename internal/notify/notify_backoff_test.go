package notify

import (
	"testing"
	"time"
)

func TestOutboxBackoff(t *testing.T) {
	// Grows, and is capped at 3h.
	if d := outboxBackoff(1); d != time.Minute {
		t.Fatalf("attempt 1 = %v, want 1m", d)
	}
	if d := outboxBackoff(2); d != 3*time.Minute {
		t.Fatalf("attempt 2 = %v, want 3m", d)
	}
	if d := outboxBackoff(3); d != 9*time.Minute {
		t.Fatalf("attempt 3 = %v, want 9m", d)
	}
	for a := 6; a < 20; a++ {
		if d := outboxBackoff(a); d > 3*time.Hour {
			t.Fatalf("attempt %d = %v, exceeds 3h cap", a, d)
		}
	}
}
