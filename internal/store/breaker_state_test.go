package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// The breaker pause must survive a restart: save it, reopen the SAME file, and it
// must load back. Otherwise a deploy mid-block resumes full traffic into the block.
func TestBreakerStatePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "brk.db")

	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh DB starts closed (zero times, generation 0).
	if bs, err := st.LoadBreakerState(ctx, "stonnington"); err != nil || !bs.OpenUntil.IsZero() || bs.Generation != 0 {
		t.Fatalf("fresh breaker state = %+v, err=%v; want zero", bs, err)
	}

	until := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	last := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	if err := st.SaveBreakerState(ctx, "stonnington", BreakerState{OpenUntil: until, Generation: 9, LastPushback: last}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Reopen the same file (a "restart") and the pause is still there.
	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	bs, err := st2.LoadBreakerState(ctx, "stonnington")
	if err != nil {
		t.Fatal(err)
	}
	if !bs.OpenUntil.Equal(until) || bs.Generation != 9 || !bs.LastPushback.Equal(last) {
		t.Fatalf("reloaded breaker state = %+v, want open_until=%s gen=9 last=%s", bs, until, last)
	}
}
