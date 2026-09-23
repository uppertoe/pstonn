package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// passRig seeds one permit with an emailed guest pass to two people, created
// `age` ago, that nobody has used.
func passRig(t *testing.T, owner string, age time.Duration) (*store.Store, *fakeNotifier, *Scheduler, int64) {
	t.Helper()
	ctx := context.Background()
	st := newStore(t)
	seedSession(t, st, owner)
	pid, err := st.UpsertPermit(ctx, owner, "", "14", "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := st.CreateGuestGrant(ctx, owner, owner, pid, "", false, nil, []store.GuestRecipient{
		{Email: "nanny@example.com", TokenHash: "h1"},
		{Email: "gran@example.com", TokenHash: "h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, &fakeTenant{}, time.UTC, Options{Notifier: nf})
	s.clock = func() time.Time { return time.Now().Add(age) }
	return st, nf, s, gid
}

// The holder is told once, and only the holder: the guest has already had one
// cold email and is not chased again.
func TestUnusedPassTellsTheHolderOnce(t *testing.T) {
	ctx := context.Background()
	const owner = "pass@example.com"
	_, nf, s, _ := passRig(t, owner, 10*24*time.Hour)

	s.sweepUnusedPassNudges(ctx)
	got := nf.passNudgedSnap()
	if len(got) != 1 || got[0] != owner+"|nanny@example.com,gran@example.com" {
		t.Fatalf("notes = %v, want one to the holder naming both recipients", got)
	}
	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 1 {
		t.Fatalf("notes after a second sweep = %v, want still one", got)
	}
}

// A pass sent yesterday has not had its occasion yet.
func TestUnusedPassWaitsAWeek(t *testing.T) {
	ctx := context.Background()
	_, nf, s, _ := passRig(t, "fresh@example.com", 24*time.Hour)
	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 0 {
		t.Fatalf("a day-old pass was chased: %v", got)
	}
}

// One recipient using it answers the question for the whole pass: the household
// learned what it does, so there is nothing to tell them.
func TestUnusedPassSkippedOnceAnyoneHasUsedIt(t *testing.T) {
	ctx := context.Background()
	const owner = "used@example.com"
	st, nf, s, gid := passRig(t, owner, 10*24*time.Hour)
	grants, err := st.ListGuestGrants(ctx, owner)
	if err != nil || len(grants) == 0 || len(grants[0].Tokens) == 0 {
		t.Fatalf("grants: %v %+v", err, grants)
	}
	if grants[0].Grant.ID != gid {
		t.Fatalf("grant id = %d, want %d", grants[0].Grant.ID, gid)
	}
	// One recipient activates: the baseline capture is what every activation runs,
	// and it is where used_at is stamped.
	if _, _, err := st.CaptureOrExtendGuestBaseline(ctx, grants[0].Tokens[0].ID, "AAA111", s.now().Add(time.Hour), s.now()); err != nil {
		t.Fatal(err)
	}

	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 0 {
		t.Fatalf("notes = %v, want none once a recipient has used the pass", got)
	}
}

// The two "someone has not acted" notes do not land together.
func TestUnusedPassHeldWhileAnInviteNoteIsRecent(t *testing.T) {
	ctx := context.Background()
	const owner = "both@example.com"
	st, nf, s, _ := passRig(t, owner, 10*24*time.Hour)
	if err := st.MarkInactionNudged(ctx, owner, s.now()); err != nil {
		t.Fatal(err)
	}

	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 0 {
		t.Fatalf("notes = %v, want none while another inaction note is recent", got)
	}
	// Held, not dropped: once the gap has passed the note still goes.
	s.clock = func() time.Time { return time.Now().Add(10*24*time.Hour + inactionNudgeGap + time.Hour) }
	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 1 {
		t.Fatalf("notes after the gap = %v, want the held note sent", got)
	}
}

// A failed send leaves the one shot unspent.
func TestUnusedPassRetriesAfterAFailedSend(t *testing.T) {
	ctx := context.Background()
	_, nf, s, _ := passRig(t, "retry@example.com", 10*24*time.Hour)
	nf.passErr = errors.New("smtp down")
	s.sweepUnusedPassNudges(ctx)
	nf.passErr = nil
	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 2 {
		t.Fatalf("notes = %v, want the failed send retried", got)
	}
}

// Two passes to the same people are one silence, so the household hears once.
func TestUnusedPassGroupsAHouseholdsPasses(t *testing.T) {
	ctx := context.Background()
	const owner = "two-passes@example.com"
	st, nf, s, _ := passRig(t, owner, 10*24*time.Hour)
	grants, err := st.ListGuestGrants(ctx, owner)
	if err != nil || len(grants) == 0 {
		t.Fatal(err)
	}
	// A second pass on the same permit, moments after the first.
	if _, err := st.CreateGuestGrant(ctx, owner, owner, grants[0].Grant.PermitID, "", false, nil,
		[]store.GuestRecipient{{Email: "nanny@example.com", TokenHash: "h3"}}); err != nil {
		t.Fatal(err)
	}

	s.sweepUnusedPassNudges(ctx)
	got := nf.passNudgedSnap()
	if len(got) != 1 || got[0] != owner+"|nanny@example.com,gran@example.com" {
		t.Fatalf("notes = %v, want ONE note covering both passes", got)
	}
	// Both are marked, so a later sweep says nothing more.
	s.sweepUnusedPassNudges(ctx)
	if got := nf.passNudgedSnap(); len(got) != 1 {
		t.Fatalf("notes after a second sweep = %v, want still one", got)
	}
}
