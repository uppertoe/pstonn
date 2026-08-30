package store

import (
	"context"
	"testing"
	"time"
)

// A referral row names a third party the account asked us to write to. It must
// go with the account, and age out on its own for everyone else — it used to do
// neither, so the table was the one place a recipient address lived forever.
func TestReferralInvitesAreDeletedAndPruned(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const sender, other, friend = "sender@example.com", "other@example.com", "friend@example.com"

	for _, o := range []string{sender, other} {
		if err := s.RecordReferralInvite(ctx, o, friend); err != nil {
			t.Fatal(err)
		}
	}
	// The sender was also once invited BY the other account.
	if err := s.RecordReferralInvite(ctx, other, sender); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAllForOwner(ctx, sender); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountReferralInvitesSince(ctx, sender, time.Time{}); n != 0 {
		t.Fatalf("the deleted account's referral rows survived: %d", n)
	}
	// The other account's rows stay (its cap still counts them), but the deleted
	// person's address is gone from them.
	if n, _ := s.CountReferralInvitesSince(ctx, other, time.Time{}); n != 2 {
		t.Fatalf("the other account's rows were touched: %d, want 2", n)
	}
	var named int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM referral_invite WHERE recipient = ?`, sender).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 {
		t.Fatalf("a deleted account is still named as a recipient in %d rows", named)
	}

	// Retention: rows older than the cutoff go, newer ones stay.
	if _, err := s.db.ExecContext(ctx, `UPDATE referral_invite SET sent_at = ? WHERE recipient = ?`,
		time.Now().Add(-ReferralInviteRetention-time.Hour).UTC().Format(time.RFC3339), friend); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneReferralInvites(ctx, time.Now().Add(-ReferralInviteRetention))
	if err != nil || n != 1 {
		t.Fatalf("PruneReferralInvites = %d, %v; want 1 old row removed", n, err)
	}
	if n, _ := s.CountReferralInvitesSince(ctx, other, time.Time{}); n != 1 {
		t.Fatalf("after prune the other account has %d rows, want 1 (the recent, blanked one)", n)
	}
}
