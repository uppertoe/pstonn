package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider"
)

// TestFlappingFailureReasonIsOneNoticeADay: during a council outage the failing
// operation flaps between attempts (a timeout keeping the sign-in warm, then one
// writing the plate). Each has its own reason text, and the failure key used to
// carry it, so every swap minted a fresh "we couldn't update your permit" — up
// to one per capped retry, ~48 a day. One family of failure, one plate, one
// episode: one notice, however the reason wobbles.
func TestFlappingFailureReasonIsOneNoticeADay(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "u@example.com", "14576", "14", "Permit")
	p := model.Permit{ID: pid, Owner: "u@example.com", CouncilPermitID: "14576", Label: "Permit"}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: fn})
	s.notifyRetry = 0

	refresh := provider.Fail(provider.FailTransient, provider.OpRefresh, errors.New("timeout"))
	write := provider.Fail(provider.FailTransient, provider.OpSetVehicle, errors.New("timeout"))
	for i := 0; i < 12; i++ {
		err := refresh
		if i%2 == 1 {
			err = write
		}
		s.handleApplyFailure(ctx, p, "AVS619", "", "roster", err, nil)
		time.Sleep(20 * time.Millisecond) // let the async delivery record its key
	}
	if n := len(fn.appliedSnap()); n != 1 {
		t.Fatalf("notices for one flapping outage = %d, want exactly 1", n)
	}
	// A refusal of the SAME plate is the same episode: the household already knows
	// this plate is not on the permit, and the cause is content, not a trigger.
	s.handleApplyFailure(ctx, p, "AVS619", "", "roster", rejectedErr(), nil)
	time.Sleep(20 * time.Millisecond)
	if n := len(fn.appliedSnap()); n != 1 {
		t.Fatalf("a refusal after a transient run = %d notices, want still 1 (same episode, same plate)", n)
	}
	// A DIFFERENT plate failing mid-episode is a new exposure, and is told.
	s.handleApplyFailure(ctx, p, "NEW222", "", "roster", rejectedErr(), nil)
	time.Sleep(20 * time.Millisecond)
	if n := len(fn.appliedSnap()); n != 2 {
		t.Fatalf("a different plate failing = %d notices, want 2", n)
	}
}
