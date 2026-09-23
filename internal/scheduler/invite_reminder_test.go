package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// inviteRig seeds one pending invitation made `age` ago.
func inviteRig(t *testing.T, owner, member string, age time.Duration) (*store.Store, *fakeNotifier, *Scheduler) {
	t.Helper()
	ctx := context.Background()
	st := newStore(t)
	if err := st.AddMemberCapped(ctx, owner, member, 2); err != nil {
		t.Fatal(err)
	}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: nf})
	s.clock = func() time.Time { return time.Now().Add(age) }
	return st, nf, s
}

// Both sides hear once: the invited person is asked to accept, the owner is told
// it has not been accepted. A second sweep says nothing more.
func TestInviteReminderTellsBothSidesOnce(t *testing.T) {
	ctx := context.Background()
	const owner, member = "owner@example.com", "invitee@example.com"
	_, nf, s := inviteRig(t, owner, member, 4*24*time.Hour)

	s.sweepInviteReminders(ctx)
	if got := nf.inviteRemindedSnap(); len(got) != 1 || got[0] != owner+"|"+member {
		t.Fatalf("reminders to the invited person = %v, want one", got)
	}
	if got := nf.inviteUnacceptedSnap(); len(got) != 1 || got[0] != owner+"|"+member {
		t.Fatalf("notes to the account holder = %v, want one", got)
	}

	s.sweepInviteReminders(ctx)
	if got := nf.inviteRemindedSnap(); len(got) != 1 {
		t.Fatalf("reminders after a second sweep = %v, want still one", got)
	}
	if got := nf.inviteUnacceptedSnap(); len(got) != 1 {
		t.Fatalf("owner notes after a second sweep = %v, want still one", got)
	}
}

// An invitation made this morning is not chased: the person may simply not have
// opened their email yet.
func TestInviteReminderWaitsBeforeChasing(t *testing.T) {
	ctx := context.Background()
	const owner, member = "owner2@example.com", "fresh@example.com"
	_, nf, s := inviteRig(t, owner, member, time.Hour)

	s.sweepInviteReminders(ctx)
	if got := nf.inviteRemindedSnap(); len(got) != 0 {
		t.Fatalf("a day-old invitation was chased: %v", got)
	}
}

// There is no lower bound on age on purpose: an invitation from months ago is
// still live and still shows in Settings as waiting, so it is exactly the one
// worth chasing.
func TestInviteReminderChasesAnOldInvitation(t *testing.T) {
	ctx := context.Background()
	const owner, member = "owner3@example.com", "august@example.com"
	_, nf, s := inviteRig(t, owner, member, 60*24*time.Hour)

	s.sweepInviteReminders(ctx)
	if got := nf.inviteRemindedSnap(); len(got) != 1 {
		t.Fatalf("reminders for a two-month-old invitation = %v, want one", got)
	}
}

// An accepted invitation is nobody's business any more.
func TestInviteReminderSkipsAnAcceptedInvitation(t *testing.T) {
	ctx := context.Background()
	const owner, member = "owner4@example.com", "joined@example.com"
	st, nf, s := inviteRig(t, owner, member, 4*24*time.Hour)
	if err := st.AcceptInvite(ctx, member, owner); err != nil {
		t.Fatal(err)
	}

	s.sweepInviteReminders(ctx)
	if got := nf.inviteRemindedSnap(); len(got) != 0 {
		t.Fatalf("an accepted invitation was chased: %v", got)
	}
}

// One side failing must not re-mail the side that already heard, so the mark is
// written when either send landed.
func TestInviteReminderMarksDoneWhenOnlyOneSideLands(t *testing.T) {
	ctx := context.Background()
	const owner, member = "owner5@example.com", "half@example.com"
	_, nf, s := inviteRig(t, owner, member, 4*24*time.Hour)
	nf.inviteUnacceptedErr = errors.New("smtp down")

	s.sweepInviteReminders(ctx)
	nf.inviteUnacceptedErr = nil
	s.sweepInviteReminders(ctx)

	if got := nf.inviteRemindedSnap(); len(got) != 1 {
		t.Fatalf("the invited person was mailed %d times, want once", len(got))
	}
}
