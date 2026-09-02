package scheduler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/store"
)

// Every per-tenant decision the scheduler makes must be about the PERMIT's or
// SESSION's tenant, never the fleet or the account's current selection: council
// permit ids overlap between portals, breakers open per portal, and providers
// differ in whether their sessions need keeping warm at all.

// TestCheckDriftIgnoresSameIdAtAnotherTenant: an account linked in two areas holds
// a permit with the same council id at each portal. A drift read of one portal
// must not judge the other portal's permit against this portal's grid row — the
// post-meta re-read used to be unfiltered, so the other permit's plate was
// "corrected" to what a different council reported.
func TestCheckDriftIgnoresSameIdAtAnotherTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner, shared = "twoareas@example.com", "shared-1"
	if err := st.SetAccountTenant(ctx, owner, "alpha"); err != nil {
		t.Fatal(err)
	}
	alphaID, _ := seedActivePermit(t, st, owner, shared, "ROSTER1", "ALPHA1")
	if err := st.SetAccountTenant(ctx, owner, "beta"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: owner, TenantID: "beta", Cookie: "sealed-b"}); err != nil {
		t.Fatal(err)
	}
	betaID, err := st.UpsertPermit(ctx, owner, shared, "14", "Beta permit")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPermitActive(ctx, betaID, "BETA1"); err != nil {
		t.Fatal(err)
	}
	if alphaID == betaID {
		t.Fatal("fixture: the two tenants' permits must be distinct rows")
	}
	fc := &fakeTenant{}
	fc.setCurrent(shared, "ALPHA1") // alpha's portal agrees with alpha's record
	s := New(st, fc, time.UTC, Options{Notifier: &fakeNotifier{on: true}})

	if err := s.checkDrift(ctx, owner, "alpha"); err != nil {
		t.Fatalf("checkDrift: %v", err)
	}
	if p, _ := st.GetPermit(ctx, betaID); p.ActiveRegistration != "BETA1" {
		t.Fatalf("beta's permit was rewritten to %q from alpha's grid row", p.ActiveRegistration)
	}
	if p, _ := st.GetPermit(ctx, alphaID); p.ActiveRegistration != "ALPHA1" {
		t.Fatalf("alpha's permit = %q, want ALPHA1 (no drift)", p.ActiveRegistration)
	}
	logs, _ := st.ListApplyLogFor(ctx, owner, 10)
	for _, r := range logs {
		if r.Source == "external" {
			t.Fatalf("a false external-change row was written: %+v", r)
		}
	}
}

// TestKeepWarmSkipsSessionWithNoPermitAtItsTenant: a session is warmed to act on
// a permit at ITS portal. An account linked in two areas but managing a permit in
// only one used to have both sessions warmed (the permit check was account-wide).
func TestKeepWarmSkipsSessionWithNoPermitAtItsTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "onehome@example.com"
	seedSession(t, st, owner) // a permit at the default tenant
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: owner, TenantID: "othertown", Cookie: "sealed-2"}); err != nil {
		t.Fatal(err)
	}
	fc := &fakeTenant{}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(ctx)
	if len(fc.refreshedTenants) != 1 || fc.refreshedTenants[0] != owner+"|" {
		t.Fatalf("refreshed = %v, want only the session with a permit at its tenant", fc.refreshedTenants)
	}
}

// TestKeepWarmHonoursProviderCapabilities: a provider whose sessions do not lapse
// (NeedsKeepWarm=false) is never refreshed — but its drift read still runs, since
// the session is alive. The scheduler used to warm every tenant on the global
// interval regardless of what the provider declared.
func TestKeepWarmHonoursProviderCapabilities(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "durable@example.com"
	if err := st.SetAccountTenant(ctx, owner, "durable"); err != nil {
		t.Fatal(err)
	}
	seedSession(t, st, owner)
	fc := &fakeTenant{caps: map[string]provider.Capabilities{
		"durable": {SupportsRefresh: true, NeedsKeepWarm: false, LoginKind: "password"},
	}}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, DriftInterval: time.Nanosecond})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(ctx)
	s.keepWarm(ctx)
	if len(fc.refreshed) != 0 {
		t.Fatalf("a durable-session provider was refreshed %d times; keep-warm should not touch it", len(fc.refreshed))
	}
	// The drift interval is always-due here, so each pass reads once: the session
	// counts as alive without a refresh, and drift keeps its own cadence.
	if n := fc.listCallCount(); n != 2 {
		t.Fatalf("drift reads = %d, want 2 (one per pass; the session is alive without a refresh)", n)
	}
}

// TestWarmThresholdBoundedByDeclaredIdleWindow: the clamp anchors on the tenant's
// idle window — the provider's declaration, the global option, or the tighter of
// the two — so a portal with a shorter window than the operator's single-tenant
// estimate is never warmed too late.
func TestWarmThresholdBoundedByDeclaredIdleWindow(t *testing.T) {
	const margin = time.Hour
	s := New(newStore(t), &fakeTenant{}, time.UTC, Options{WarmInterval: 12 * time.Hour, IdleWindow: 10 * time.Hour, WarmSafetyMargin: margin, JitterFrac: 0.2})
	cases := []struct {
		name          string
		declared      time.Duration
		global        time.Duration
		wantWindow    time.Duration
		wantThreshold time.Duration // upper bound on the threshold
	}{
		{"declared tighter than global", 4 * time.Hour, 10 * time.Hour, 4 * time.Hour, 3 * time.Hour},
		{"global tighter than declared", 12 * time.Hour, 10 * time.Hour, 10 * time.Hour, 9 * time.Hour},
		{"declared only", 4 * time.Hour, 0, 4 * time.Hour, 3 * time.Hour},
		{"global only (provider declares none)", 0, 10 * time.Hour, 10 * time.Hour, 9 * time.Hour},
		{"neither: clamp disabled", 0, 0, 0, 12 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s.idleWindow = c.global
			w := s.idleWindowFor(provider.Capabilities{NeedsKeepWarm: true, IdleWindow: c.declared})
			if w != c.wantWindow {
				t.Fatalf("idleWindowFor = %v, want %v", w, c.wantWindow)
			}
			if got := s.warmThresholdFor("o@example.com", time.Unix(1_700_000_000, 0), w); got > c.wantThreshold {
				t.Fatalf("threshold %v exceeds %v", got, c.wantThreshold)
			}
		})
	}
}

// TestBlockedIsAskedPerPermitTenant: a confirmed block at ONE portal must not
// escalate the busy warning for a permit at another, nor suspend its drift read.
func TestBlockedIsAskedPerPermitTenant(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "elsewhere@example.com"
	pid, _ := seedActivePermit(t, st, owner, "blk-2", "ROSTER1", "OLD999")
	p, _ := st.GetPermit(ctx, pid)
	fc := &fakeTenant{setErr: parking.ErrCouncilBusy, blocked: true, blockedIn: "othertown"} // othertown is blocked; this permit is not there
	fn := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn, SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, DriftInterval: time.Nanosecond})
	for i := 0; i < blockNotifyThreshold; i++ {
		s.reconcileAll(ctx)
	}
	time.Sleep(40 * time.Millisecond)
	asked := fc.blockedAskedSnap()
	if len(asked) == 0 || asked[len(asked)-1] != p.TenantID {
		t.Fatalf("Blocked was asked about %v, want the permit's tenant %q", asked, p.TenantID)
	}
	for _, o := range fn.outcomeSnap() {
		if o.Urgent {
			t.Fatalf("another portal's block escalated this permit's warning: %+v", o)
		}
	}
	// Drift for this tenant proceeds despite the other portal's block.
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(ctx)
	if n := fc.listCallCount(); n != 1 {
		t.Fatalf("drift reads = %d, want 1: another portal's block must not suspend this tenant's drift", n)
	}
}

// TestUnavailableTenantIsSurfacedOnce: a permit whose tenant this process is not
// serving cannot be applied here, ever, and the household must hear it — once —
// rather than the permit sitting silently unapplied. A genuinely unlinked
// account (the dashboard prompts) stays quiet, as before.
func TestUnavailableTenantIsSurfacedOnce(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "disabled@example.com"
	pid, _ := seedActivePermit(t, st, owner, "off-1", "ROSTER1", "OLD999")
	fc := &fakeTenant{setErr: fmt.Errorf("%w: %q", parking.ErrTenantUnavailable, "gone")}
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: fn})

	s.reconcileAll(ctx)
	s.KickPermit(pid) // clear the deferral so a second pass genuinely re-attempts
	s.reconcileAll(ctx)
	time.Sleep(40 * time.Millisecond)
	applied := fn.appliedSnap()
	if len(applied) != 1 || applied[0].ok {
		t.Fatalf("notifications = %+v, want exactly one failure", applied)
	}
	if out := fn.outcomeSnap()[0]; out.Transient || out.CurrentReg != "OLD999" {
		t.Fatalf("the notice must be final and name the plate still on the permit: %+v", out)
	}
	logs, _ := st.ListApplyLogFor(ctx, owner, 10)
	if len(logs) != 1 || logs[0].Status != "error" {
		t.Fatalf("activity rows = %+v, want one error row", logs)
	}
	if hasAdmin(fn, "multiple users") {
		t.Fatal("a routing failure is not a council outage; it must not feed the systemic alarm")
	}

	// Control: plain not-linked stays silent.
	st2 := newStore(t)
	seedActivePermit(t, st2, owner, "off-2", "ROSTER1", "OLD999")
	fn2 := &fakeNotifier{on: true, admin: true}
	s2 := New(st2, &fakeTenant{setErr: parking.ErrNotLinked}, time.UTC, Options{Notifier: fn2})
	s2.reconcileAll(ctx)
	time.Sleep(20 * time.Millisecond)
	if logs, _ := st2.ListApplyLogFor(ctx, owner, 10); len(logs) != 0 || len(fn2.appliedSnap()) != 0 {
		t.Fatalf("not-linked should stay quiet: rows=%d notices=%d", len(logs), len(fn2.appliedSnap()))
	}
}

// TestKickOwnerInClearsOnlyThatTenantsBackoffs: a re-link with one council
// plausibly fixes the permits THERE. The other council's parked refusal is
// still a refusal — clearing it re-runs a write that portal already said no to.
func TestKickOwnerInClearsOnlyThatTenantsBackoffs(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "twoareas-kick@example.com"
	if err := st.SetAccountTenant(ctx, owner, "alpha"); err != nil {
		t.Fatal(err)
	}
	alphaID, _ := seedActivePermit(t, st, owner, "kick-a", "ROSTER1", "ALPHA1")
	if err := st.SetAccountTenant(ctx, owner, "beta"); err != nil {
		t.Fatal(err)
	}
	betaID, err := st.UpsertPermit(ctx, owner, "kick-b", "14", "Beta permit")
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, &fakeTenant{}, time.UTC, Options{})
	s.parkRetry(alphaID, "ROSTER1")
	s.parkRetry(betaID, "ROSTER1")

	s.KickOwnerIn(ctx, owner, "alpha")
	if s.retryDeferred(alphaID, time.Now()) {
		t.Fatal("a re-link at alpha should clear alpha's backoff")
	}
	if !s.retryDeferred(betaID, time.Now()) {
		t.Fatal("a re-link at alpha cleared beta's parked refusal")
	}
	// The owner-wide kick still clears everything.
	s.KickOwner(ctx, owner)
	if s.retryDeferred(betaID, time.Now()) {
		t.Fatal("KickOwner must clear every tenant's backoffs")
	}
}
