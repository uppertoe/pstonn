package server

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// TestGuestActivityResetsIdleClock pins the retention fix: guest-driven use of
// an account (a visitor opening the pass link, an emailed one-tap decision)
// resets the 90-day idle clock, because the happiest usage pattern — set up
// once, let guests self-serve, never sign in again — must not walk into idle
// retirement while the household is actively relying on the service.
//
// The write is observed through the reminder flag rather than the timestamp:
// TouchAccountActive clears reminder_sent_at + confirm_token as one decision
// with the clock reset (see its doc), and unlike "now vs slightly-newer now",
// a cleared flag is unambiguous in a test.
func TestGuestActivityResetsIdleClock(t *testing.T) {
	ctx := context.Background()
	s := newAuthzServer(t)
	const owner = "household@example.com"

	if err := s.store.SaveTenantSession(ctx, store.TenantSession{Owner: owner}); err != nil {
		t.Fatal(err)
	}
	// The account is idle enough that the re-authorise reminder went out.
	if err := s.store.MarkReminderSent(ctx, owner, "", "tok-1"); err != nil {
		t.Fatal(err)
	}

	// A guest uses the household's link: the account is demonstrably alive, so
	// the clock resets and the outstanding reminder/token are withdrawn.
	s.touchGuestActivity(ctx, owner)
	cs, err := s.store.GetTenantSession(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.ReminderSent.IsZero() || cs.ConfirmToken != "" {
		t.Fatalf("guest activity did not reset the idle machinery: %+v", cs)
	}
	if time.Since(cs.LastActive) > time.Minute {
		t.Fatalf("idle clock not reset: last active %v", cs.LastActive)
	}

	// Throttled: within the hour, a second touch is a no-op — a re-sent reminder
	// stays outstanding, which is how we can SEE the skip.
	if err := s.store.MarkReminderSent(ctx, owner, "", "tok-2"); err != nil {
		t.Fatal(err)
	}
	s.touchGuestActivity(ctx, owner)
	cs, err = s.store.GetTenantSession(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if cs.ReminderSent.IsZero() || cs.ConfirmToken == "" { // token is stored hashed; presence is the signal
		t.Fatal("second touch inside the throttle window wrote anyway")
	}

	// The guest throttle key must be distinct from the signed-in one: a guest
	// touch must not eat the OWNER's own visit-touch (or vice versa).
	s.touchMu.Lock()
	_, collided := s.lastTouch[owner]
	s.touchMu.Unlock()
	if collided {
		t.Fatal("guest touch used the signed-in throttle key; owner visits would be swallowed")
	}

	// An account with no linked session is a no-op, never an error.
	s.touchGuestActivity(ctx, "nolink@example.com")
}
