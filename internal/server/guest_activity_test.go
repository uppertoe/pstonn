package server

import (
	"context"
	"net/url"
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

// TestGuestIdleTouchOnlyOnHumanAction: resolving a token is the funnel every
// guest surface passes through — including a mail scanner prefetching the
// emailed link and the 2.5-second live poll from a tab left open — so it must
// NOT reset the 90-day idle clock. Only the POST (a person asking for a plate)
// does, consistent with tenantConfirm refusing link-following as liveness.
func TestGuestIdleTouchOnlyOnHumanAction(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "household@example.com"
	_, _, raw := seedDoorQR(t, s, owner, "Idle")
	if err := s.store.SaveTenantSession(ctx, store.TenantSession{Owner: owner}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.MarkReminderSent(ctx, owner, "", "tok-idle"); err != nil {
		t.Fatal(err)
	}
	reminderOutstanding := func() bool {
		t.Helper()
		cs, err := s.store.GetTenantSession(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		return !cs.ReminderSent.IsZero()
	}

	if w := s.getGuest("/g/" + raw); w.Code != 200 {
		t.Fatalf("GET menu = %d", w.Code)
	}
	if !reminderOutstanding() {
		t.Fatal("a bare GET of the link reset the idle clock (a scanner prefetch would too)")
	}
	if w := s.getGuest("/g/live/" + raw); w.Code == 500 {
		t.Fatalf("GET live poll = %d", w.Code)
	}
	if !reminderOutstanding() {
		t.Fatal("the live poll reset the idle clock")
	}

	if w := s.postGuest("/g/"+raw, "203.0.113.20", "", url.Values{"plate": {"HUM4N1"}}); w.Code != 200 {
		t.Fatalf("POST request = %d %s", w.Code, w.Body.String())
	}
	if reminderOutstanding() {
		t.Fatal("a visitor's request (a human act at the door) did not reset the idle clock")
	}
}
