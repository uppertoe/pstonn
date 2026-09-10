package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestContactMessagesRoundTripAndPrune(t *testing.T) {
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if _, err := st.AddContactMessage(ctx, "first message", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddContactMessage(ctx, "second message", "who@example.com"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListContactMessages(ctx, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("list = %v, %v", got, err)
	}
	if got[0].Message != "second message" || got[0].ReplyTo != "who@example.com" || got[1].ReplyTo != "" {
		t.Fatalf("order/fields wrong: %+v", got)
	}
	if time.Since(got[0].ReceivedAt) > time.Minute {
		t.Fatalf("received_at not set: %v", got[0].ReceivedAt)
	}
	if one, _ := st.ListContactMessages(ctx, 1); len(one) != 1 {
		t.Fatalf("limit ignored: %d", len(one))
	}
	// Nothing is old enough yet; then everything is.
	if n, _ := st.PruneContactMessages(ctx, time.Now().Add(-time.Hour)); n != 0 {
		t.Fatalf("pruned %d fresh rows", n)
	}
	if n, _ := st.PruneContactMessages(ctx, time.Now().Add(time.Hour)); n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}
}
