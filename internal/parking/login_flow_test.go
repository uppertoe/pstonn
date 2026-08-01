package parking

import (
	"context"
	"testing"
	"time"
)

// The transport governor bounds individual requests; this serialises whole
// credential flows. The risk it addresses is many DISTINCT authentication flows
// on our shared IP at once, so only one may hold the login slot.
func TestLoginFlowSerialises(t *testing.T) {
	c := &Client{loginFlow: make(chan struct{}, 1)}
	ctx := context.Background()

	// Flow A claims the slot.
	relA, err := c.acquireLoginFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Flow B must block until A releases.
	entered := make(chan struct{})
	go func() {
		relB, err := c.acquireLoginFlow(ctx)
		if err == nil {
			close(entered)
			relB()
		}
	}()
	select {
	case <-entered:
		t.Fatal("a second login flow entered while the first held the slot")
	case <-time.After(20 * time.Millisecond):
	}

	relA() // A finishes...
	select {
	case <-entered: // ...and B proceeds.
	case <-time.After(time.Second):
		t.Fatal("the second flow did not proceed after the first released")
	}
}

// A flow waiting for the slot must fail cleanly when its context expires, rather
// than hang — so a stuck login can't wedge every later one indefinitely.
func TestLoginFlowRespectsContext(t *testing.T) {
	c := &Client{loginFlow: make(chan struct{}, 1)}
	hold, _ := c.acquireLoginFlow(context.Background()) // occupy the slot
	defer hold()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	if _, err := c.acquireLoginFlow(ctx); err == nil {
		t.Fatal("a waiting flow should fail once its context expires")
	}
}

// The slot must be freed on EVERY exit path — including an early error — so one
// failed login (e.g. a user link that errors out) never wedges the next. This
// models the defer-release in Link: acquire, return an error, and the next flow
// must still get in.
func TestLoginFlowReleasedAfterError(t *testing.T) {
	c := &Client{loginFlow: make(chan struct{}, 1)}
	failingFlow := func() {
		release, err := c.acquireLoginFlow(context.Background())
		if err != nil {
			return
		}
		defer release()
		_ = "pretend the login errors out here"
	}
	failingFlow() // errors and releases via defer

	// A subsequent flow must acquire without blocking.
	done := make(chan struct{})
	go func() {
		r, err := c.acquireLoginFlow(context.Background())
		if err == nil {
			r()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the slot was not released after the failing flow returned")
	}
}

// A nil channel (a bare Client in tests) is a no-op, never blocking.
func TestLoginFlowNilIsNoop(t *testing.T) {
	c := &Client{}
	r, err := c.acquireLoginFlow(context.Background())
	if err != nil {
		t.Fatalf("nil login flow should not block: %v", err)
	}
	r()
}
