package parking

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestRollingCounterWindows(t *testing.T) {
	r := newRollingCounter(8)
	base := time.Date(2026, 8, 1, 9, 0, 30, 0, time.UTC) // mid-minute

	// Three requests this minute, two in the previous minute.
	r.add(base)
	r.add(base.Add(1 * time.Second))
	r.add(base.Add(2 * time.Second))
	r.add(base.Add(-1 * time.Minute))
	r.add(base.Add(-1 * time.Minute).Add(1 * time.Second))

	if got := r.window(base, 1); got != 3 {
		t.Errorf("last-1-minute = %d, want 3", got)
	}
	if got := r.window(base, 5); got != 5 {
		t.Errorf("last-5-minute = %d, want 5", got)
	}

	// A request six minutes ago must have aged out of the 5-minute window (and out
	// of the ring — its slot is reused by a fresher minute).
	r.add(base.Add(-6 * time.Minute))
	if got := r.window(base, 5); got != 5 {
		t.Errorf("a 6-minute-old request leaked into the 5-minute window: got %d, want 5", got)
	}

	// Far in the future, nothing is in window.
	if got := r.window(base.Add(time.Hour), 5); got != 0 {
		t.Errorf("stale buckets counted an hour later: got %d, want 0", got)
	}
}

// The Client must actually consult the breaker at its gate — not just hold one.
// Three distinct owners pushed back opens the circuit, and the gate then refuses.
func TestClientBreakerGate(t *testing.T) {
	c := &Client{breaker: newBreaker(3, 2*time.Minute, 5*time.Minute, 30*time.Second)}
	if _, err := c.breakerGate(); err != nil {
		t.Fatalf("gate blocked with a fresh breaker: %v", err)
	}
	now := time.Now()
	c.breaker.onPushback(now, "a@x", 0)
	c.breaker.onPushback(now, "b@x", 0)
	if _, err := c.breakerGate(); err != nil {
		t.Fatalf("gate tripped on two owners: %v", err)
	}
	c.breaker.onPushback(now, "c@x", 0)
	if _, err := c.breakerGate(); err == nil {
		t.Fatal("gate did not refuse after three distinct owners opened the circuit")
	}
}

// A pushback must be captured for the operator: the X-Azure-Ref correlation id, the
// status, and the surface, surfaced through Stats() for the status endpoint.
func TestRecordPushbackDiagnostics(t *testing.T) {
	c := &Client{}
	resp := &http.Response{
		StatusCode: 429,
		Header: http.Header{
			"X-Azure-Ref":  {"20260801T000000Z-abc123"},
			"Content-Type": {"text/html"},
			"Retry-After":  {"120"},
		},
		Request: &http.Request{URL: &url.URL{Path: "/idm/connect/authorize"}},
	}
	c.recordPushback(resp)

	s := c.Stats()
	if s.LastPushbackRef != "20260801T000000Z-abc123" {
		t.Errorf("X-Azure-Ref not captured: %q", s.LastPushbackRef)
	}
	if s.LastPushbackStatus != 429 {
		t.Errorf("status not captured: %d", s.LastPushbackStatus)
	}
	if s.LastPushbackSurface != "auth" { // /connect/ → auth surface
		t.Errorf("surface = %q, want auth", s.LastPushbackSurface)
	}
	if s.LastPushbackAt.IsZero() {
		t.Error("pushback timestamp not set")
	}
}
