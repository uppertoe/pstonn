package parking

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// These tests drive the GENERIC client through the provider contract with a
// provider that is not Orikan: the in-memory fake, and a scripted stub. They lock
// the behaviour every backend inherits — session sealing and persistence,
// rotation write-back, capability gating, backoff and breaker feeding, expiry
// tagging — independently of any portal's protocol.

// stubProvider scripts each operation so the generic layer's reactions can be
// observed one at a time.
type stubProvider struct {
	caps      provider.Capabilities
	loginErr  error
	refresh   func(s *provider.Session) error
	current   func(s *provider.Session) (provider.Vehicle, error)
	set       func(s *provider.Session, reg string) error
	calls     []string
	sessionIn []string // the session material each call received
}

func (p *stubProvider) ID() string                          { return "stub" }
func (p *stubProvider) Capabilities() provider.Capabilities { return p.caps }
func (p *stubProvider) Login(ctx context.Context, c provider.Credentials) (provider.Session, error) {
	p.calls = append(p.calls, "login:"+c.Username)
	if p.loginErr != nil {
		return nil, p.loginErr
	}
	return provider.Session(`{"u":"` + c.Username + `","n":0}`), nil
}
func (p *stubProvider) Refresh(ctx context.Context, s *provider.Session) error {
	p.calls = append(p.calls, "refresh")
	p.sessionIn = append(p.sessionIn, string(*s))
	if p.refresh != nil {
		return p.refresh(s)
	}
	return nil
}
func (p *stubProvider) ListPermits(ctx context.Context, s *provider.Session) ([]provider.Permit, int, error) {
	p.calls = append(p.calls, "list")
	return []provider.Permit{{CouncilPermitID: "1", PermitType: "Visitor Permit", CanChangeVehicle: true}}, 2, nil // deliberately partial
}
func (p *stubProvider) CurrentVehicle(ctx context.Context, s *provider.Session, r provider.PermitRef) (provider.Vehicle, error) {
	p.calls = append(p.calls, "current:"+r.ID)
	p.sessionIn = append(p.sessionIn, string(*s))
	if p.current != nil {
		return p.current(s)
	}
	return provider.Vehicle{Registration: "AAA111"}, nil
}
func (p *stubProvider) SetVehicle(ctx context.Context, s *provider.Session, r provider.PermitRef, v provider.Vehicle) error {
	call := "set:" + v.Registration
	if v.Region != "" {
		call += "@" + v.Region
	}
	p.calls = append(p.calls, call)
	if p.set != nil {
		return p.set(s, v.Registration)
	}
	return nil
}
func (p *stubProvider) ClearVehicle(ctx context.Context, s *provider.Session, r provider.PermitRef) error {
	p.calls = append(p.calls, "clear")
	return nil
}

func stubClient(t *testing.T, p provider.Provider) (*Client, *store.Store, *secretbox.Box) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(p, st, box, nil), st, box
}

func TestLinkSealsProviderSessionAndPinsUsername(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
	c, st, box := stubClient(t, p)

	if err := c.Link(ctx, "o@example.com", "o@example.com", "pw", true, true, 0); err != nil {
		t.Fatal(err)
	}
	cs, err := st.GetTenantSession(ctx, "o@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Stored material is the provider's blob, prefixed and sealed under the owner.
	plain, _, err := box.OpenCtx(secretbox.TenantCookie("o@example.com"), cs.Cookie)
	if err != nil {
		t.Fatalf("session not sealed under the owner's context: %v", err)
	}
	if !strings.HasPrefix(plain, sessionPrefix) || !strings.Contains(plain, `"u":"o@example.com"`) {
		t.Fatalf("stored session = %q, want the prefixed provider blob", plain)
	}
	if cs.Password == "" {
		t.Fatal("opted-in password was not saved")
	}
	if cs.TenantEmail != "o@example.com" {
		t.Fatalf("council username not recorded: %q", cs.TenantEmail)
	}
	if !c.Linked(ctx, "o@example.com") {
		t.Fatal("Linked = false after a successful link")
	}
	// Reconnect signs in again with the SAVED password and the recorded username.
	if err := c.Reconnect(ctx, "o@example.com"); err != nil {
		t.Fatalf("Reconnect = %v", err)
	}
	if got := p.calls[len(p.calls)-1]; got != "login:o@example.com" {
		t.Fatalf("reconnect used %q", got)
	}
}

func TestLoginRejectedStoresNothing(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}, loginErr: provider.ErrLoginRejected}
	c, st, _ := stubClient(t, p)
	if err := c.Link(ctx, "o@example.com", "o@example.com", "bad", true, true, 0); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("Link = %v, want ErrLoginRejected", err)
	}
	if _, err := st.GetTenantSession(ctx, "o@example.com"); err == nil {
		t.Fatal("a rejected login stored a session (and the password with it)")
	}
}

// A provider that rotates session material mid-call must have the rotated value
// persisted, and the NEXT call must receive it — that is the whole contract of
// passing the session by pointer.
func TestRotatedSessionIsPersistedAndReused(t *testing.T) {
	ctx := context.Background()
	n := 0
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password", SupportsRefresh: true}}
	p.current = func(s *provider.Session) (provider.Vehicle, error) {
		n++
		*s = provider.Session(`{"u":"o@example.com","n":` + string(rune('0'+n)) + `}`)
		return provider.Vehicle{Registration: "AAA111"}, nil
	}
	c, st, _ := stubClient(t, p)
	if err := c.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0); err != nil {
		t.Fatal(err)
	}
	before, _ := st.GetTenantSession(ctx, "o@example.com")
	perm := model.Permit{CouncilPermitID: "1"}
	if _, err := c.CurrentVehicle(ctx, "o@example.com", perm); err != nil {
		t.Fatal(err)
	}
	after, _ := st.GetTenantSession(ctx, "o@example.com")
	if after.Cookie == before.Cookie {
		t.Fatal("rotated session material was not persisted")
	}
	if after.Generation <= before.Generation {
		t.Fatal("persisting rotated material must bump the session generation (the reconnect queue's CAS token)")
	}
	if _, err := c.CurrentVehicle(ctx, "o@example.com", perm); err != nil {
		t.Fatal(err)
	}
	if got := p.sessionIn[len(p.sessionIn)-1]; !strings.Contains(got, `"n":1`) {
		t.Fatalf("second call received %q, want the material rotated by the first", got)
	}
}

// Refresh persists even when nothing rotated: the write is keep-warm's freshness
// clock (updated_at), and without it every pass would renew again immediately.
func TestRefreshAlwaysBumpsFreshness(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password", SupportsRefresh: true}}
	c, st, _ := stubClient(t, p)
	if err := c.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0); err != nil {
		t.Fatal(err)
	}
	before, _ := st.GetTenantSession(ctx, "o@example.com")
	time.Sleep(1100 * time.Millisecond) // updated_at has second resolution
	if err := c.Refresh(ctx, "o@example.com"); err != nil {
		t.Fatal(err)
	}
	after, _ := st.GetTenantSession(ctx, "o@example.com")
	if !after.UpdatedAt.After(before.UpdatedAt) {
		t.Fatalf("Refresh did not bump updated_at (%s → %s)", before.UpdatedAt, after.UpdatedAt)
	}
	// And a provider with nothing to keep warm is a no-op that still succeeds.
	p2 := &stubProvider{caps: provider.Capabilities{LoginKind: "password", SupportsRefresh: false}}
	c2, _, _ := stubClient(t, p2)
	_ = c2.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0)
	if err := c2.Refresh(ctx, "o@example.com"); err != nil {
		t.Fatalf("Refresh on a no-refresh provider = %v, want nil", err)
	}
	for _, call := range p2.calls {
		if call == "refresh" {
			t.Fatal("Refresh was forwarded to a provider that does not support it")
		}
	}
}

func TestCapabilityGating(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "device", CanClearVehicle: false}}
	c, _, _ := stubClient(t, p)
	if err := c.Link(ctx, "o@example.com", "o@example.com", "pw", true, true, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.ClearVehicle(ctx, "o@example.com", model.Permit{CouncilPermitID: "1"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ClearVehicle on a provider that cannot = %v, want ErrUnsupported", err)
	}
	if err := c.Reconnect(ctx, "o@example.com"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Reconnect on a non-password provider = %v, want ErrUnsupported", err)
	}
}

// The partial-list contract crosses the seam intact: a provider reporting fewer
// rows than its total yields complete=false and is noted for the status page.
func TestPartialListCrossesTheSeam(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
	c, _, _ := stubClient(t, p)
	_ = c.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0)
	ps, complete, err := c.ListPermitsComplete(ctx, "o@example.com")
	if err != nil || complete || len(ps) != 1 {
		t.Fatalf("got %d permits complete=%v err=%v; want 1, false, nil", len(ps), complete, err)
	}
	if s := c.Stats(); s.TruncatedGridGot != 1 || s.TruncatedGridWant != 2 {
		t.Fatalf("truncation not surfaced: %+v", s)
	}
}

// Push-back reported by ANY provider feeds the owner's backoff and the diagnostics,
// and an expiry is tagged with the generation it failed at.
func TestProviderOutcomesFeedBackoffAndTagging(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
	busy := &provider.Unavailable{RetryAfter: 30 * time.Second, Status: 429, Surface: provider.SurfaceAPI, Ref: "ref-1"}
	p.current = func(s *provider.Session) (provider.Vehicle, error) { return provider.Vehicle{}, busy }
	c, st, _ := stubClient(t, p)
	_ = c.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0)
	perm := model.Permit{CouncilPermitID: "1"}

	if _, err := c.CurrentVehicle(ctx, "o@example.com", perm); !errors.Is(err, ErrCouncilBusy) {
		t.Fatalf("err = %v, want ErrCouncilBusy", err)
	}
	if d, blocked := c.cooldownFor("o@example.com"); !blocked || d > 30*time.Second {
		t.Fatalf("cooldown = %v/%v, want Retry-After honoured", d, blocked)
	}
	if s := c.Stats(); s.LastPushbackRef != "ref-1" || s.LastPushbackStatus != 429 || s.Pushback != 1 {
		t.Fatalf("pushback diagnostics not recorded: %+v", s)
	}
	// While cooling down the provider is not even called.
	calls := len(p.calls)
	if _, err := c.CurrentVehicle(ctx, "o@example.com", perm); !errors.Is(err, ErrCouncilBusy) || len(p.calls) != calls {
		t.Fatalf("cooldown did not short-circuit (err=%v, calls %d→%d)", err, calls, len(p.calls))
	}
	c.clearPenalty("o@example.com")

	p.current = func(s *provider.Session) (provider.Vehicle, error) {
		return provider.Vehicle{}, provider.ErrSessionExpired
	}
	cs, _ := st.GetTenantSession(ctx, "o@example.com")
	_, err := c.CurrentVehicle(ctx, "o@example.com", perm)
	if gen, ok := SessionGenOf(err); !ok || gen != cs.Generation {
		t.Fatalf("expiry not tagged with the failing generation: %v (gen %d, want %d)", err, gen, cs.Generation)
	}
}

// The fake provider end to end through the generic client: link, list, a write
// that lands immediately, a plate read, and a clear.
func TestFakeProviderEndToEnd(t *testing.T) {
	ctx := context.Background()
	f := fake.New()
	f.ApplyDelay = 0
	c, _, _ := stubClient(t, f)
	const owner = "sandbox@example.com"
	if err := c.Link(ctx, owner, owner, "anything", false, true, 0); err != nil {
		t.Fatal(err)
	}
	ps, complete, err := c.ListPermitsComplete(ctx, owner)
	if err != nil || !complete || len(ps) != 2 {
		t.Fatalf("list: %d complete=%v err=%v", len(ps), complete, err)
	}
	perm := model.Permit{CouncilPermitID: ps[0].CouncilPermitID}
	if err := c.SetVehicle(ctx, owner, perm, "NEW123", ""); err != nil {
		t.Fatalf("SetVehicle = %v", err)
	}
	if reg, err := c.CurrentVehicle(ctx, owner, perm); err != nil || reg != "NEW123" {
		t.Fatalf("CurrentVehicle = %q, %v", reg, err)
	}
	if reg, _, fresh, err := c.CurrentVehicleCached(ctx, owner, perm, time.Minute); err != nil || reg != "NEW123" || !fresh {
		t.Fatalf("cache after a confirmed write = %q fresh=%v err=%v", reg, fresh, err)
	}
	if err := c.ClearVehicle(ctx, owner, perm); err != nil {
		t.Fatalf("ClearVehicle = %v", err)
	}
	if reg, err := c.CurrentVehicle(ctx, owner, perm); err != nil || reg != "" {
		t.Fatalf("after clear = %q, %v", reg, err)
	}
	// A delayed fake reports transient until the change lands — the pipeline the
	// sandbox exists to exercise.
	f.ApplyDelay = 50 * time.Millisecond
	err = c.SetVehicle(ctx, owner, perm, "LATER1", "")
	if kind, _ := FailureOf(err); err == nil || kind != FailTransient {
		t.Fatalf("delayed write = %v (kind %v), want a transient", err, kind)
	}
	time.Sleep(100 * time.Millisecond)
	if err := c.SetVehicle(ctx, owner, perm, "LATER1", ""); err != nil {
		t.Fatalf("after landing, SetVehicle = %v, want nil", err)
	}
}

// An operation that rotates the session and THEN fails must not persist the
// rotation: persisting bumps the generation, and the expiry it reports would be
// tagged with the generation it started from — which the scheduler's
// generation-checked retire/reconnect could no longer match, leaving a dead
// session in place. Error paths write nothing; the tag matches the row.
func TestFailedOperationDoesNotPersistRotation(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
	p.current = func(s *provider.Session) (provider.Vehicle, error) {
		*s = provider.Session(`{"u":"o@example.com","n":9}`)  // a token minted mid-op…
		return provider.Vehicle{}, provider.ErrSessionExpired // …then the session died
	}
	c, st, _ := stubClient(t, p)
	_ = c.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0)
	before, _ := st.GetTenantSession(ctx, "o@example.com")
	_, err := c.CurrentVehicle(ctx, "o@example.com", model.Permit{CouncilPermitID: "1"})
	after, _ := st.GetTenantSession(ctx, "o@example.com")
	if after.Cookie != before.Cookie || after.Generation != before.Generation {
		t.Fatal("a failed operation persisted rotated material (and bumped the generation)")
	}
	if gen, ok := SessionGenOf(err); !ok || gen != before.Generation {
		t.Fatalf("expiry tagged with %d (ok=%v), want the row's generation %d", gen, ok, before.Generation)
	}
}

// A re-link that lands while an operation is in flight wins: the operation's
// rotated material is dropped (superseded), the call still succeeds, and the
// next call runs on the re-linked session.
func TestRotationDuringRelinkKeepsTheNewerSession(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
	c, st, _ := stubClient(t, p)
	_ = c.Link(ctx, "o@example.com", "o@example.com", "pw", false, true, 0)
	relinked := false
	p.current = func(s *provider.Session) (provider.Vehicle, error) {
		*s = provider.Session(`{"u":"o@example.com","n":5}`)
		if !relinked {
			relinked = true
			// The user re-links mid-operation (the store has no owner lock).
			if err := c.Link(ctx, "o@example.com", "o@example.com", "pw2", false, true, 0); err != nil {
				t.Fatal(err)
			}
		}
		return provider.Vehicle{Registration: "AAA111"}, nil
	}
	perm := model.Permit{CouncilPermitID: "1"}
	if _, err := c.CurrentVehicle(ctx, "o@example.com", perm); err != nil {
		t.Fatalf("superseded write must not fail the operation: %v", err)
	}
	after, _ := st.GetTenantSession(ctx, "o@example.com")
	if _, err := c.CurrentVehicle(ctx, "o@example.com", perm); err != nil {
		t.Fatal(err)
	}
	if got := p.sessionIn[len(p.sessionIn)-1]; !strings.Contains(got, `"n":0`) {
		t.Fatalf("next call ran on %q, want the re-linked session (n:0), not the superseded rotation", got)
	}
	if again, _ := st.GetTenantSession(ctx, "o@example.com"); again.Generation != after.Generation+0 && again.Cookie == "" {
		t.Fatal("re-linked session lost")
	}
}

// Pre-provider rows: a provider that cannot import them reads as an expiry
// tagged with the row's generation (retire + re-link), without ever being
// called; an import that fails for another reason is NOT reported as an expiry.
func TestLegacyRowsAcrossProviders(t *testing.T) {
	ctx := context.Background()
	seed := func(t *testing.T, st *store.Store, box *secretbox.Box) store.TenantSession {
		sealed, _ := box.Seal("Permits.IDM.Identity=abc") // un-prefixed: the old shape
		if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: "old@example.com", Cookie: sealed}); err != nil {
			t.Fatal(err)
		}
		cs, _ := st.GetTenantSession(ctx, "old@example.com")
		return cs
	}
	t.Run("no importer", func(t *testing.T) {
		p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
		c, st, box := stubClient(t, p)
		cs := seed(t, st, box)
		_, err := c.CurrentVehicle(ctx, "old@example.com", model.Permit{CouncilPermitID: "1"})
		if gen, ok := SessionGenOf(err); !ok || gen != cs.Generation || !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("err = %v (gen %d ok=%v), want a tagged expiry at gen %d", err, gen, ok, cs.Generation)
		}
		if len(p.calls) != 0 {
			t.Fatalf("provider was called with material it cannot read: %v", p.calls)
		}
	})
	t.Run("importer fails", func(t *testing.T) {
		p := &importFailProvider{stubProvider{caps: provider.Capabilities{LoginKind: "password"}}}
		c, st, box := stubClient(t, p)
		seed(t, st, box)
		_, err := c.CurrentVehicle(ctx, "old@example.com", model.Permit{CouncilPermitID: "1"})
		if err == nil || errors.Is(err, ErrSessionExpired) {
			t.Fatalf("an import failure must surface as itself, got %v", err)
		}
	})
}

type importFailProvider struct{ stubProvider }

func (p *importFailProvider) ImportLegacy(cookie, token string, exp time.Time) (provider.Session, error) {
	return nil, errors.New("import: unreadable")
}

// Reconnect signs in as the recorded tenant username, falling back to the
// owner's email for rows that predate the column (every pre-branch row).
func TestReconnectUsernameFallback(t *testing.T) {
	ctx := context.Background()
	p := &stubProvider{caps: provider.Capabilities{LoginKind: "password"}}
	c, st, box := stubClient(t, p)
	pw, _ := box.SealCtx(secretbox.TenantPassword("o@example.com"), "pw")
	sess, _ := c.sealSession("o@example.com", provider.Session(`{"u":"x"}`))
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: "o@example.com", Cookie: sess, Password: pw}); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconnect(ctx, "o@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := p.calls[len(p.calls)-1]; got != "login:o@example.com" {
		t.Fatalf("reconnect used %q, want the owner as username", got)
	}
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: "o@example.com", TenantEmail: "other@example.com", Cookie: sess, Password: pw}); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconnect(ctx, "o@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := p.calls[len(p.calls)-1]; got != "login:other@example.com" {
		t.Fatalf("reconnect used %q, want the recorded council username", got)
	}
}
