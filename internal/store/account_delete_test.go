package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
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
