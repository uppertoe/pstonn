package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This is the regression test for the finding that account deletion reached into
// OTHER households' audit logs. The old cleanup was
// `DELETE FROM account_log WHERE actor = ? OR target = ?`, which removed a row
// recording something the departing person did on someone else's account, and a
// guest-pass row whose sole recipient was their address. Those are the other
// household's record of their own actions; erasing them leaves an unexplained gap.
// The address must be de-identified, not the row destroyed.
func TestDeleteAccountKeepsOtherHouseholdsLogRows(t *testing.T) {
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "del.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	const leaver = "leaver@example.com"
	const other = "neighbour@example.com"

	// A row on the OTHER household's account, recording something the leaver did
	// there (as a secondary), and one naming them as the sole recipient of a pass.
	if err := st.RecordChange(ctx, other, leaver, ActionGuestCreate, leaver, "a pass"); err != nil {
		t.Fatalf("seed acted-elsewhere row: %v", err)
	}
	// A row on the leaver's own account, which should go with the account.
	if err := st.RecordChange(ctx, leaver, leaver, ActionMemberAdd, "someone@example.com", ""); err != nil {
		t.Fatalf("seed own row: %v", err)
	}

	if err := st.DeleteAllForOwner(ctx, leaver); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	// The other household keeps its row.
	rows, err := st.ListChanges(ctx, other, 50)
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the other household has %d log rows, want 1 — deletion punched a hole in their audit trail", len(rows))
	}
	// ...but with the departed address scrubbed from it.
	if strings.Contains(rows[0].Actor, leaver) || strings.Contains(rows[0].Target, leaver) {
		t.Errorf("the departed address is still present: actor=%q target=%q", rows[0].Actor, rows[0].Target)
	}
	if rows[0].Actor == "" || rows[0].Target == "" {
		t.Errorf("the row should read as a former member, not become blank: actor=%q target=%q", rows[0].Actor, rows[0].Target)
	}

	// The leaver's own log is gone with their account.
	own, err := st.ListChanges(ctx, leaver, 50)
	if err != nil {
		t.Fatalf("list own: %v", err)
	}
	if len(own) != 0 {
		t.Errorf("the deleted account still has %d log rows", len(own))
	}
}

// Deleting an account tears down the notify_pref rows of its members, and the
// member list used to be read without the invite_pending gate RemoveMember is built
// around. So an unanswered invite — which grants nothing, and whose subject may run
// their own household — was enough for the inviter's self-delete to wipe that
// stranger's channel config. Only an ACCEPTED member's prefs go with the account.
func TestDeleteAccountLeavesPendingInviteesPrefsAlone(t *testing.T) {
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "del.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	const owner = "owner@example.com"
	const stranger = "stranger@example.com" // invited, never answered
	const member = "member@example.com"     // invited and accepted

	if err := st.SetNotifyPref(ctx, NotifyPref{Owner: stranger, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: "pstonn-stranger"}); err != nil {
		t.Fatalf("seed stranger prefs: %v", err)
	}
	if err := st.SetNotifyPref(ctx, NotifyPref{Owner: member, EmailEnabled: true, NtfyEnabled: true, NtfyTopic: "pstonn-member"}); err != nil {
		t.Fatalf("seed member prefs: %v", err)
	}
	if err := st.AddMemberCapped(ctx, owner, stranger, 2); err != nil {
		t.Fatalf("invite stranger: %v", err)
	}
	if err := st.AddMemberCapped(ctx, owner, member, 2); err != nil {
		t.Fatalf("invite member: %v", err)
	}
	if err := st.AcceptInvite(ctx, member, owner); err != nil {
		t.Fatalf("accept: %v", err)
	}

	if err := st.DeleteAllForOwner(ctx, owner); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	// The stranger's prefs are untouched: they were never part of this household.
	got, err := st.GetNotifyPref(ctx, stranger)
	if err != nil {
		t.Fatalf("stranger prefs: %v", err)
	}
	if got.NtfyTopic != "pstonn-stranger" || !got.NtfyEnabled {
		t.Errorf("a pending invitee's prefs were wiped by the inviter's account deletion: %+v", got)
	}
	// The accepted member's prefs go with the account, as before.
	if got, _ := st.GetNotifyPref(ctx, member); got.NtfyTopic != "" {
		t.Errorf("an accepted member's prefs survived the account deletion: %+v", got)
	}
}

// A secondary who approves or declines a door-QR request has their email written
// to guest_request.decided_by, which the household's guests page renders ("by
// alice@…"). Deleting that person's account de-identified their traces in the
// household's log and overrides but left this one, so the address outlived the
// account on someone else's page. Same treatment: the decision stays, the name goes.
func TestDeleteAccountRedactsDecisionsOnOtherHouseholds(t *testing.T) {
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "del.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	ctx := context.Background()

	const household = "household@example.com"
	const leaver = "leaver@example.com"

	permit, err := st.UpsertPermit(ctx, household, "P1", "14", "Permit")
	if err != nil {
		t.Fatalf("permit: %v", err)
	}
	grant, err := st.CreatePrintedGrant(ctx, household, "", permit, "doorhash", "sealed")
	if err != nil {
		t.Fatalf("printed grant: %v", err)
	}
	reqID, _, _, err := st.CreateGuestRequest(ctx, grant, permit, household, "TRADIE1", "", "nonce")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := st.DecideGuestRequest(ctx, household, reqID, true, "until 6pm", leaver, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("decide: %v", err)
	}

	if err := st.DeleteAllForOwner(ctx, leaver); err != nil {
		t.Fatalf("delete account: %v", err)
	}

	rq, err := st.GuestRequestByID(ctx, reqID)
	if err != nil {
		t.Fatalf("the household's request must survive a decider's account deletion: %v", err)
	}
	if rq.Status != "approved" {
		t.Errorf("the decision itself changed: status=%q", rq.Status)
	}
	if strings.Contains(rq.DecidedBy, leaver) {
		t.Errorf("the departed address is still on the household's request: decided_by=%q", rq.DecidedBy)
	}
	if rq.DecidedBy == "" {
		t.Errorf("the request should read as decided by a former member, not as expired unanswered")
	}
}
