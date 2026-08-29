package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func inviteStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "invite.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// This is the regression test for the finding: adding a member used to bind an
// arbitrary address to an account immediately, so the invited person's next sign-in
// showed them someone else's household, blocked them from linking their own tenant
// account, and filed everything they created under the inviter. An invite must grant
// nothing at all until its subject accepts.
func TestPendingInviteGrantsNothing(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	const owner, invitee = "owner@example.com", "invitee@example.com"

	if err := st.AddMemberCapped(ctx, owner, invitee, 2); err != nil {
		t.Fatalf("invite: %v", err)
	}

	// The invitee still runs their own account.
	if got, ok, err := st.MemberAccount(ctx, invitee); err != nil || ok {
		t.Fatalf("MemberAccount = (%q, %v, %v); a pending invite must not resolve account scope", got, ok, err)
	}
	// They are not part of the household for notification purposes.
	emails, err := st.AccountEmails(ctx, owner)
	if err != nil {
		t.Fatalf("AccountEmails: %v", err)
	}
	for _, e := range emails {
		if e == invitee {
			t.Fatal("a pending invitee must not receive the account's notifications")
		}
	}
	// But the owner can see the outstanding invite, flagged as such.
	ms, err := st.ListMembers(ctx, owner)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(ms) != 1 || ms[0].Email != invitee || !ms[0].Pending {
		t.Fatalf("ListMembers = %+v, want one pending row for the invitee", ms)
	}
	// And the invitee can see it, so they can answer it.
	if from, ok, err := st.PendingInvite(ctx, invitee); err != nil || !ok || from != owner {
		t.Fatalf("PendingInvite = (%q, %v, %v), want the inviting owner", from, ok, err)
	}
}

func TestAcceptInviteGrantsAccess(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	const owner, invitee = "owner@example.com", "invitee@example.com"

	if err := st.AddMemberCapped(ctx, owner, invitee, 2); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := st.AcceptInvite(ctx, invitee, owner); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got, ok, err := st.MemberAccount(ctx, invitee); err != nil || !ok || got != owner {
		t.Fatalf("MemberAccount = (%q, %v, %v), want the owner", got, ok, err)
	}
	emails, err := st.AccountEmails(ctx, owner)
	if err != nil {
		t.Fatalf("AccountEmails: %v", err)
	}
	if len(emails) != 2 || emails[1] != invitee {
		t.Fatalf("AccountEmails = %v, want the owner plus the accepted member", emails)
	}
	// The invite is no longer outstanding.
	if _, ok, _ := st.PendingInvite(ctx, invitee); ok {
		t.Error("an accepted invite must no longer read as pending")
	}
	if ms, _ := st.ListMembers(ctx, owner); len(ms) != 1 || ms[0].Pending {
		t.Errorf("ListMembers = %+v, want one accepted row", ms)
	}
}

// A stale form must not enrol someone into an account they were never shown.
func TestAcceptInviteIsScopedToTheOfferedOwner(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	if err := st.AddMemberCapped(ctx, "owner@example.com", "invitee@example.com", 2); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := st.AcceptInvite(ctx, "invitee@example.com", "attacker@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("accept against another owner = %v, want ErrNotFound", err)
	}
	if _, ok, _ := st.MemberAccount(ctx, "invitee@example.com"); ok {
		t.Fatal("the invitee must not have joined anything")
	}
}

// A replayed submit is a no-op rather than a second acceptance.
func TestAcceptInviteIsIdempotent(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	const owner, invitee = "owner@example.com", "invitee@example.com"
	if err := st.AddMemberCapped(ctx, owner, invitee, 2); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := st.AcceptInvite(ctx, invitee, owner); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if err := st.AcceptInvite(ctx, invitee, owner); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second accept = %v, want ErrNotFound", err)
	}
}

func TestDeclineInviteFreesTheAddress(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	const owner, invitee = "owner@example.com", "invitee@example.com"
	if err := st.AddMemberCapped(ctx, owner, invitee, 2); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := st.DeclineInvite(ctx, invitee); err != nil {
		t.Fatalf("decline: %v", err)
	}
	if _, ok, _ := st.PendingInvite(ctx, invitee); ok {
		t.Error("a declined invite must be gone")
	}
	if ms, _ := st.ListMembers(ctx, owner); len(ms) != 0 {
		t.Errorf("ListMembers = %+v, want none after a decline", ms)
	}
	// Declining frees the slot and the address, so a fresh invite is possible.
	if err := st.AddMemberCapped(ctx, owner, invitee, 2); err != nil {
		t.Fatalf("re-invite after decline: %v", err)
	}
}

// Decline is the invitee's refusal of an offer, not a way out of a membership they
// already accepted — that is RemoveMembership, which also cleans up their prefs and
// the guest passes they created.
func TestDeclineDoesNotRemoveAnAcceptedMembership(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	const owner, invitee = "owner@example.com", "invitee@example.com"
	if err := st.AddMemberCapped(ctx, owner, invitee, 2); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := st.AcceptInvite(ctx, invitee, owner); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := st.DeclineInvite(ctx, invitee); err != nil {
		t.Fatalf("decline: %v", err)
	}
	if got, ok, _ := st.MemberAccount(ctx, invitee); !ok || got != owner {
		t.Fatal("declining must not revoke an already-accepted membership")
	}
}

// Outstanding offers count toward the cap: each one is an email somebody else has to
// deal with, so an account cannot hold open an unlimited number of them.
func TestPendingInvitesCountTowardTheCap(t *testing.T) {
	st := inviteStore(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	if err := st.AddMemberCapped(ctx, owner, "a@example.com", 2); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := st.AddMemberCapped(ctx, owner, "b@example.com", 2); err != nil {
		t.Fatalf("second: %v", err)
	}
	if err := st.AddMemberCapped(ctx, owner, "c@example.com", 2); !errors.Is(err, ErrMemberLimit) {
		t.Fatalf("third = %v, want ErrMemberLimit even though none has accepted", err)
	}
}
