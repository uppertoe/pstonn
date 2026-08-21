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
