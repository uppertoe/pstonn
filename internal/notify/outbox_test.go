package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// countingNtfy stands in for the push server and counts deliveries, which is the
// quantity the outbox tests are really about: how many times one queued message
// actually goes out.
func countingNtfy(t *testing.T, before func()) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if before != nil {
			before()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// TestOutboxStopsWhenBookkeepingFails is the regression test for the worst failure
// in the notification path: a delivered row whose "sent" write is refused stays
// 'pending' with next_attempt in the past, so the drain used to re-deliver it on
// every 15-second tick, for as long as the disk stayed full — and said nothing.
// The store is closed from inside the delivery itself, which is as close as a test
// can get to a read-only remount landing mid-pass.
func TestOutboxStopsWhenBookkeepingFails(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// Break the store at the moment of delivery: the push succeeds, then the write
	// that records it cannot happen.
	var closeOnce atomic.Bool
	srv, pushes := countingNtfy(t, func() {
		if closeOnce.CompareAndSwap(false, true) {
			st.Close()
		}
	})
	svc := New(st, nil, srv.URL, "", "", "", "", time.UTC, nil, nil)

	if err := svc.enqueue(ctx, outMessage{
		Account: "owner@example.com", NtfyTopic: "pstonn-test", Subject: "Permit updated", Body: "body",
	}); err != nil {
		t.Fatal(err)
	}

	svc.drainOutbox(ctx)
	if got := pushes.Load(); got != 1 {
		t.Fatalf("first pass delivered %d times, want 1", got)
	}
	if len(svc.unrecorded) != 1 {
		t.Fatalf("unrecorded = %d rows, want 1 (the delivered row must be parked)", len(svc.unrecorded))
	}

	// Every later pass must send NOTHING while the write is still failing. This is
	// the loop that gets a sending domain blocked.
	for i := 0; i < 5; i++ {
		svc.drainOutbox(ctx)
	}
	if got := pushes.Load(); got != 1 {
		t.Fatalf("%d deliveries after the bookkeeping write failed, want 1 — the drain is re-sending", got)
	}
}

// TestOutboxRecordsParkedRowOnRecovery: parking a row must not lose it. When the
// store accepts writes again the outstanding bookkeeping is completed, and the row
// is NOT delivered a second time to get there.
func TestOutboxRecordsParkedRowOnRecovery(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv, pushes := countingNtfy(t, nil)
	svc := New(st, nil, srv.URL, "", "", "", "", time.UTC, nil, nil)
	if err := svc.enqueue(ctx, outMessage{
		Account: "owner@example.com", NtfyTopic: "pstonn-test", Subject: "Permit updated", Body: "body",
	}); err != nil {
		t.Fatal(err)
	}
	due, err := st.DueOutbox(ctx, time.Now(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %v, %v; want one row", due, err)
	}
	// Stand where the previous test left off: delivered, bookkeeping owed.
	svc.unrecorded[due[0].ID] = outboxUpdate{status: "sent", who: "a push topic"}

	svc.drainOutbox(ctx)
	if got := pushes.Load(); got != 0 {
		t.Fatalf("a parked row was delivered again (%d pushes); the send already happened", got)
	}
	if len(svc.unrecorded) != 0 {
		t.Fatalf("unrecorded = %d rows, want 0 once the store accepts writes", len(svc.unrecorded))
	}
	rest, err := st.DueOutbox(ctx, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("outbox still holds %d pending rows, want 0 (the row should now read 'sent')", len(rest))
	}
}

// TestDeliverPushesMixedRowOnce locks the invariant in the delivery switch: a row
// addressing both channels cannot express partial success, so a retry must not
// re-push what already worked. enqueueSplit should prevent the shape; deliver is
// where the damage would happen if it ever did.
func TestDeliverPushesMixedRowOnce(t *testing.T) {
	ctx := context.Background()
	srv, pushes := countingNtfy(t, nil)
	svc := New(nil, nil, srv.URL, "", "", "", "", time.UTC, nil, nil)

	mixed := store.OutboxItem{
		ID: 1, Recipients: []string{"someone@example.com"}, NtfyTopic: "pstonn-test",
		Subject: "Permit updated", Body: "body",
	}
	if lastErr, _ := svc.deliver(ctx, mixed); lastErr != "" {
		t.Fatalf("first attempt: %s", lastErr)
	}
	if got := pushes.Load(); got != 1 {
		t.Fatalf("first attempt pushed %d times, want 1", got)
	}
	mixed.Attempts = 3 // a later retry of the same row
	svc.deliver(ctx, mixed)
	if got := pushes.Load(); got != 1 {
		t.Fatalf("a retry re-pushed a message that had already been delivered (%d pushes)", got)
	}
}
