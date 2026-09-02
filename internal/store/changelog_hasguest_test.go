package store

import (
	"context"
	"testing"
)

// TestHasGuestActivity: the "nothing scheduled yet" nudge is suppressed once a
// household has used the visitor-code path. Any guest.* / doorqr.* / request.*
// change-log entry counts; scheduling and other actions do not.
func TestHasGuestActivity(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const owner = "a@b.com"

	if has, err := st.HasGuestActivity(ctx, owner); err != nil || has {
		t.Fatalf("fresh account: got (%v, %v), want (false, nil)", has, err)
	}
	// A non-guest action must NOT flip it.
	if err := st.RecordChange(ctx, owner, owner, ActionRosterSet, "Mon", "Van"); err != nil {
		t.Fatal(err)
	}
	if has, _ := st.HasGuestActivity(ctx, owner); has {
		t.Fatal("roster.set should not count as guest activity")
	}
	// Showing a visitor QR does.
	if err := st.RecordChange(ctx, owner, owner, ActionDoorQRShow, "VPP-1", ""); err != nil {
		t.Fatal(err)
	}
	if has, err := st.HasGuestActivity(ctx, owner); err != nil || !has {
		t.Fatalf("after doorqr.show: got (%v, %v), want (true, nil)", has, err)
	}
	// Scoped to the owner: another household's guest use doesn't leak in.
	if has, _ := st.HasGuestActivity(ctx, "other@b.com"); has {
		t.Fatal("guest activity leaked across accounts")
	}
}

// TestCountChanges: the guest-pass hint's trigger counts one action for one
// owner — other actions and other households must not inflate it.
func TestCountChanges(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const owner = "a@b.com"

	if n, err := st.CountChanges(ctx, owner, ActionOverrideAdd); err != nil || n != 0 {
		t.Fatalf("fresh account: got (%d, %v), want (0, nil)", n, err)
	}
	for i := 0; i < 3; i++ {
		if err := st.RecordChange(ctx, owner, owner, ActionOverrideAdd, "VPP-1", "one-off"); err != nil {
			t.Fatal(err)
		}
	}
	// A different action and a different owner both stay out of the count.
	if err := st.RecordChange(ctx, owner, owner, ActionRosterSet, "Mon", "Van"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordChange(ctx, "other@b.com", "other@b.com", ActionOverrideAdd, "VPP-2", ""); err != nil {
		t.Fatal(err)
	}
	if n, err := st.CountChanges(ctx, owner, ActionOverrideAdd); err != nil || n != 3 {
		t.Fatalf("after three one-offs: got (%d, %v), want (3, nil)", n, err)
	}
}
