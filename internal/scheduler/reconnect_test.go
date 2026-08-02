package scheduler

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
)

// Under a mass expiry (a shortened council idle window), one keep-warm pass must not
// try to reconnect every expired session inline — each reconnect is a serialized
// headless login, so an unbounded pass would block for many minutes and starve
// healthy sessions from re-warming. The per-pass budget caps reconnect attempts; the
// backlog drains across passes.
func TestReconnectBudgetBoundsOnePass(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const n = maxReconnectsPerPass + 8
	for i := 0; i < n; i++ {
		owner := fmt.Sprintf("exp%02d@example.com", i)
		seedSession(t, st, owner)
		seedSchedule(t, st, owner)
	}
	// Every warm reports the session expired; the reconnect is a transient failure,
	// so the session is kept (not retired) and each attempt is counted.
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired, reconnectSet: true, reconnectErr: errors.New("503 busy")}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: nf})
	time.Sleep(2 * time.Millisecond)

	s.keepWarm(ctx)
	if got := len(fc.reconnected); got != maxReconnectsPerPass {
		t.Fatalf("one pass attempted %d reconnects, want the %d-per-pass budget", got, maxReconnectsPerPass)
	}

	// The budget resets: a second pass drains more of the backlog.
	fc.reconnected = nil
	s.keepWarm(ctx)
	if got := len(fc.reconnected); got != maxReconnectsPerPass {
		t.Fatalf("second pass attempted %d reconnects, want another %d", got, maxReconnectsPerPass)
	}
}
