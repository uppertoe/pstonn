package parking

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// The connector state feeds operator email (via the watchdog), so its false-
// positive behaviour is the contract under test: every alarming state must
// require breadth (distinct owners) or a structural signal, and every signal
// must age out. One household's typo'd password, one glitched response, or one
// challenge page must never flip the state on their own.

var (
	tTransient  = errors.New("boom")                                                         // unclassified -> FailTransient
	tUnexpected = provider.Fail(provider.FailUnexpected, provider.OpListPermits, tTransient) // shape we could not read
)

func healthState(h *connectorHealth, now time.Time) string {
	return h.state(now, false, PushbackEvent{})
}

func TestConnectorHealthStates(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)

	t.Run("nothing seen yet is idle", func(t *testing.T) {
		h := &connectorHealth{}
		if got := healthState(h, now); got != StateIdle {
			t.Fatalf("state = %q, want idle", got)
		}
	})

	t.Run("a recent success is healthy, and stale attempts fall back to idle", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", nil, now)
		if got := healthState(h, now.Add(time.Minute)); got != StateHealthy {
			t.Fatalf("state = %q, want healthy", got)
		}
		if got := healthState(h, now.Add(healthIdleAfter+time.Minute)); got != StateIdle {
			t.Fatalf("state = %q after %s of silence, want idle", got, healthIdleAfter)
		}
	})

	t.Run("one owner's rejected login is their password, not the connector", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", nil, now)
		h.noteAt("a@x", provider.ErrLoginRejected, now.Add(time.Minute))
		h.noteAt("a@x", provider.ErrLoginRejected, now.Add(2*time.Minute)) // retries don't add breadth
		if got := healthState(h, now.Add(3*time.Minute)); got == StateAuthFailed {
			t.Fatal("a single owner's rejections must never read as connector auth failure")
		}
	})

	t.Run("rejected logins across distinct owners are the connector", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", provider.ErrLoginRejected, now)
		h.noteAt("b@x", provider.ErrLoginRejected, now.Add(time.Minute))
		if got := healthState(h, now.Add(2*time.Minute)); got != StateAuthFailed {
			t.Fatalf("state = %q, want auth_failed", got)
		}
		// One of them then logging in fine clears their reject: back below the bar.
		h.noteAt("b@x", nil, now.Add(3*time.Minute))
		if got := healthState(h, now.Add(4*time.Minute)); got == StateAuthFailed {
			t.Fatal("a success must clear that owner's reject and drop the alarm")
		}
		// And the signal ages out entirely.
		h.noteAt("c@x", provider.ErrLoginRejected, now.Add(5*time.Minute))
		if got := healthState(h, now.Add(5*time.Minute).Add(healthSignalWindow+time.Minute)); got == StateAuthFailed {
			t.Fatal("aged-out rejects must not keep the alarm up")
		}
	})

	t.Run("an unrecognised sign-in page is upstream_changed on first sight", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", provider.ErrLoginFormUnrecognised, now)
		if got := healthState(h, now.Add(time.Minute)); got != StateUpstreamChanged {
			t.Fatalf("state = %q, want upstream_changed (this is the CAPTCHA-on-login signature)", got)
		}
		if got := healthState(h, now.Add(healthSignalWindow+2*time.Minute)); got == StateUpstreamChanged {
			t.Fatal("the login-shape signal must age out")
		}
	})

	t.Run("one unexpected response is a glitch; two are a change", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", nil, now)
		h.noteAt("a@x", tUnexpected, now.Add(time.Minute))
		if got := healthState(h, now.Add(2*time.Minute)); got == StateUpstreamChanged {
			t.Fatal("a single unexpected shape must not flip the state")
		}
		h.noteAt("b@x", tUnexpected, now.Add(3*time.Minute))
		if got := healthState(h, now.Add(4*time.Minute)); got != StateUpstreamChanged {
			t.Fatalf("state = %q, want upstream_changed after %d unexpected shapes", got, healthUnexpectedMin)
		}
	})

	t.Run("consecutive transient failures degrade; any success resets", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", nil, now)
		for i := 0; i < healthDegradedAfter-1; i++ {
			h.noteAt("a@x", tTransient, now.Add(time.Duration(i+1)*time.Minute))
		}
		if got := healthState(h, now.Add(5*time.Minute)); got != StateHealthy {
			t.Fatalf("state = %q below the streak threshold, want healthy", got)
		}
		h.noteAt("b@x", tTransient, now.Add(6*time.Minute))
		if got := healthState(h, now.Add(7*time.Minute)); got != StateDegraded {
			t.Fatalf("state = %q, want degraded at %d consecutive failures", got, healthDegradedAfter)
		}
		h.noteAt("c@x", nil, now.Add(8*time.Minute)) // ANY owner's success ends the streak
		if got := healthState(h, now.Add(9*time.Minute)); got != StateHealthy {
			t.Fatalf("state = %q after a success, want healthy", got)
		}
	})

	t.Run("an open breaker is blocked, over everything else", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", provider.ErrLoginRejected, now)
		h.noteAt("b@x", provider.ErrLoginRejected, now)
		if got := h.state(now.Add(time.Minute), true, PushbackEvent{}); got != StateBlocked {
			t.Fatalf("state = %q with the breaker open, want blocked", got)
		}
	})

	t.Run("a recent 429 is rate_limited; other pushbacks are not", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", nil, now)
		pb := PushbackEvent{At: now.Add(time.Minute), Status: 429}
		if got := h.state(now.Add(2*time.Minute), false, pb); got != StateRateLimited {
			t.Fatalf("state = %q, want rate_limited", got)
		}
		pb.Status = 403
		if got := h.state(now.Add(2*time.Minute), false, pb); got != StateHealthy {
			t.Fatalf("state = %q for a lone 403, want healthy (below every threshold)", got)
		}
		pb.Status = 429
		if got := h.state(now.Add(time.Minute).Add(healthSignalWindow+time.Minute), false, pb); got == StateRateLimited {
			t.Fatal("an old 429 must not keep the state rate_limited")
		}
	})

	t.Run("a cancelled context is the caller, not the portal", func(t *testing.T) {
		h := &connectorHealth{}
		h.noteAt("a@x", context.Canceled, now)
		att, _, fails := h.clock()
		if !att.IsZero() || fails != 0 {
			t.Fatalf("a cancellation was counted: attempt=%v fails=%d", att, fails)
		}
	})
}

func TestWorseConnectorState(t *testing.T) {
	order := []string{StateIdle, StateHealthy, StateDegraded, StateRateLimited, StateUpstreamChanged, StateAuthFailed, StateBlocked}
	for i, a := range order {
		for j, b := range order {
			want := a
			if j > i {
				want = b
			}
			if got := WorseConnectorState(a, b); got != want {
				t.Errorf("WorseConnectorState(%q, %q) = %q, want %q", a, b, got, want)
			}
		}
	}
	// Activity beats silence: one healthy tenant outweighs an idle one.
	if got := WorseConnectorState(StateHealthy, StateIdle); got != StateHealthy {
		t.Errorf("healthy vs idle = %q, want healthy", got)
	}
	// An unknown word can only under-report, never alarm.
	if got := WorseConnectorState("garbled", StateHealthy); got != StateHealthy {
		t.Errorf("unknown state must rank lowest, got %q", got)
	}
}
