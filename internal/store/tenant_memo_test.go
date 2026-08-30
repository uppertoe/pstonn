package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
)

// TestTenantIDForMemoNeverPinsAStaleAnswer hammers the memo with concurrent reads
// while the selection flips, then checks the memo agrees with the last write.
// Without the epoch check a read that queried before a write and memoised after
// its invalidation pinned the old tenant until the next write.
func TestTenantIDForMemoNeverPinsAStaleAnswer(t *testing.T) {
	ctx := context.Background()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "memo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.DefaultTenant = "stonnington"
	const owner = "flip@example.com"
	for round := 0; round < 50; round++ {
		want := "a"
		if round%2 == 1 {
			want = "b"
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = s.TenantIDFor(ctx, owner)
			}()
		}
		if err := s.SetAccountTenant(ctx, owner, want); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		// Whatever the readers memoised, a read AFTER the write must see the write:
		// either the memo holds the new value, or it holds nothing and re-queries.
		if got, err := s.TenantIDFor(ctx, owner); err != nil || got != want {
			t.Fatalf("round %d: TenantIDFor = %q (%v), want %q", round, got, err, want)
		}
	}
	// The epoch moves on every invalidation, so a concurrent reader can tell.
	before := s.tenantEpoch.Load()
	s.forgetTenant(owner)
	if s.tenantEpoch.Load() == before {
		t.Fatal("forgetTenant did not bump the epoch")
	}
}
