package parking

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestCurrentVehicleCachedNeverBlocks locks in the stale-while-revalidate
// contract: the call must answer from cache (fresh or stale) or report a miss —
// never a synchronous tenant round trip, which would let a slow portal stall a
// page render past the HTTP server's WriteTimeout (a 502 at the proxy).
func TestCurrentVehicleCachedNeverBlocks(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := NewClient(nil, st, nil, nil) // no session stored: any background refresh fails fast
	ctx := context.Background()
	p := model.Permit{CouncilPermitID: "14576"}
	const owner = "o@example.com"
	key := regKey{owner, p.CouncilPermitID}

	// Nothing cached yet: a miss, not a blocking fetch.
	if _, _, fresh, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) || fresh {
		t.Fatalf("empty cache: want ErrNoCachedPlate and not fresh, got fresh=%v, %v", fresh, err)
	}

	// Fresh cache is served and reported fresh.
	c.regCache.Store(key, cachedReg{reg: "ABC123", at: time.Now()})
	if got, _, fresh, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); err != nil || got != "ABC123" || !fresh {
		t.Fatalf("fresh cache: got %q fresh=%v, %v", got, fresh, err)
	}

	// A stale value is still served (revalidation happens in the background),
	// reported non-fresh so the UI can offer a follow-up fetch.
	c.regCache.Store(key, cachedReg{reg: "ABC123", at: time.Now().Add(-time.Hour)})
	if got, age, fresh, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); err != nil || got != "ABC123" || fresh || age < time.Hour {
		t.Fatalf("stale cache: got %q fresh=%v age=%v, %v", got, fresh, age, err)
	}
}

// C9: a tenant permit can change hands — a household permit is visible to two
// tenant logins, and "stop managing" plus "manage" from the other account is the
// ordinary way that happens. A plate cached under the previous holder must never
// be served to the new one, and stopping must clear the entry.
func TestRegCacheIsOwnerScopedAndForgettable(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := NewClient(nil, st, nil, nil) // unlinked: a background refresh cannot supply an answer
	ctx := context.Background()
	p := model.Permit{CouncilPermitID: "14576"}
	const first, second = "first@example.com", "second@example.com"

	c.regCache.Store(regKey{first, p.CouncilPermitID}, cachedReg{reg: "OLD111", at: time.Now()})

	// The new holder of the same tenant permit gets a cache MISS, not the previous
	// household's plate.
	if got, _, fresh, err := c.CurrentVehicleCached(ctx, second, p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) || got != "" || fresh {
		t.Fatalf("second owner read the first owner's cached plate: %q fresh=%v, %v", got, fresh, err)
	}
	// The original owner still sees their own.
	if got, _, _, err := c.CurrentVehicleCached(ctx, first, p, 5*time.Minute); err != nil || got != "OLD111" {
		t.Fatalf("first owner lost their own entry: %q, %v", got, err)
	}

	// Stopping management drops it, and only theirs.
	c.regCache.Store(regKey{second, p.CouncilPermitID}, cachedReg{reg: "NEW222", at: time.Now()})
	c.ForgetPermit(first, p.CouncilPermitID)
	if _, _, _, err := c.CurrentVehicleCached(ctx, first, p, 5*time.Minute); !errors.Is(err, ErrNoCachedPlate) {
		t.Fatalf("ForgetPermit left the entry behind: %v", err)
	}
	if got, _, _, err := c.CurrentVehicleCached(ctx, second, p, 5*time.Minute); err != nil || got != "NEW222" {
		t.Fatalf("ForgetPermit evicted another owner's entry: %q, %v", got, err)
	}
}

// TestCooldownBackoff confirms a penalised owner enters cooldown and that a
// success clears it.
func TestCooldownBackoff(t *testing.T) {
	c := NewClient(nil, nil, nil, nil)
	const owner = "a@b.com"
	if _, blocked := c.cooldownFor(owner); blocked {
		t.Fatal("owner should start un-penalised")
	}
	c.penalize(owner, 0)
	if _, blocked := c.cooldownFor(owner); !blocked {
		t.Fatal("owner should be in cooldown after a penalty")
	}
	c.clearPenalty(owner)
	if _, blocked := c.cooldownFor(owner); blocked {
		t.Fatal("cooldown should clear after success")
	}
}

// TestRefreshFailingForTracksTheStreakNotTheAge: the dashboard's couldn't-confirm
// clock seeds from THIS, so its semantics carry real weight. A cache entry that is
// merely old (nobody looked lately) must report zero — seeding from raw age made
// every cold daily visit declare "couldn't check" instantly, with no polls, while
// a perfectly healthy refresh was landing in the background (shipped and caught
// 2026-08-10). Only consecutive refresh FAILURES start the clock, a success or
// ForgetPermit clears it, and repeats keep the streak's original start.
func TestRefreshFailingForTracksTheStreakNotTheAge(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := NewClient(nil, st, nil, nil) // no session: any background refresh fails fast
	ctx := context.Background()
	p := model.Permit{CouncilPermitID: "14576"}
	const owner = "o@example.com"
	key := regKey{owner, p.CouncilPermitID}

	// An old-but-healthy cache entry alone is NOT a failure streak.
	c.regCache.Store(key, cachedReg{reg: "ABC123", at: time.Now().Add(-20 * time.Hour)})
	if d := c.RefreshFailingFor(owner, p); d != 0 {
		t.Fatalf("an aged cache with no failed refresh reported a %v streak; want 0", d)
	}

	// A stale read kicks a background refresh, which fails (no session) and must
	// start the streak. Poll: the refresh runs on its own goroutine.
	if _, _, _, err := c.CurrentVehicleCached(ctx, owner, p, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.RefreshFailingFor(owner, p) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a failed background refresh never started the failure streak")
		}
		time.Sleep(10 * time.Millisecond)
	}
	first, ok := c.regFail.Load(key)
	if !ok {
		t.Fatal("streak start missing after a failure")
	}

	// A second failure keeps the ORIGINAL start (the streak measures the outage,
	// not the latest attempt).
	c.regFail.LoadOrStore(key, time.Now()) // what refreshCurrentVehicle does on repeat
	if again, _ := c.regFail.Load(key); again != first {
		t.Fatal("a repeat failure moved the streak's start; the clock would reset every attempt")
	}

	// Success clears it (simulate the success path's bookkeeping)...
	c.regFail.Delete(key)
	if d := c.RefreshFailingFor(owner, p); d != 0 {
		t.Fatalf("streak survived a success: %v", d)
	}
	// ...and so does ForgetPermit.
	c.regFail.Store(key, time.Now().Add(-time.Hour))
	c.ForgetPermit(owner, p.CouncilPermitID)
	if d := c.RefreshFailingFor(owner, p); d != 0 {
		t.Fatalf("streak survived ForgetPermit: %v", d)
	}
}

// TestNoteExpiredReportsOnlyTaggedExpiries: the read-path expiry hook (wired to
// the scheduler's reconnect queue) must fire for a generation-tagged session
// expiry and stay silent otherwise — an untagged expiry cannot be safely bound
// to a session, and a non-expiry error is not recovery's business. This hook is
// what stops a dashboard-discovered death waiting ~9h for the next keep-warm
// pass (observed live 2026-08-11).
func TestNoteExpiredReportsOnlyTaggedExpiries(t *testing.T) {
	c := NewClient(nil, nil, nil, nil)
	var got []int64
	c.OnSessionExpired = func(owner, tenantID string, gen int64) {
		if owner != "o@example.com" {
			t.Fatalf("hook got owner %q", owner)
		}
		got = append(got, gen)
	}
	c.noteExpired("o@example.com", withSessionGen(ErrSessionExpired, 42)) // tagged → fires
	c.noteExpired("o@example.com", ErrSessionExpired)                     // untagged → silent
	c.noteExpired("o@example.com", ErrCouncilBusy)                        // not an expiry → silent
	if len(got) != 1 || got[0] != 42 {
		t.Fatalf("hook calls = %v, want exactly [42]", got)
	}
	// A nil hook must be safe: the client is usable without a scheduler.
	c.OnSessionExpired = nil
	c.noteExpired("o@example.com", withSessionGen(ErrSessionExpired, 7))
}
