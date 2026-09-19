package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// An "empty" roster day is a scheduled state like any plate: the loop clears
// the permit for it (one tenant write, recorded as no rego), the household is
// told the permit now has no rego, and a permit already empty is left alone.
// Where the council cannot leave a permit empty the day is skipped with a log
// line rather than an error the household hears about.
func TestReconcileEmptyDayClearsThePermit(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "empty@example.com"
	seedSession(t, st, owner)
	pid, _ := st.UpsertPermit(ctx, owner, "vpp-empty", "14", "Home")
	if err := st.SetPermitActive(ctx, pid, "ABC123"); err != nil {
		t.Fatal(err)
	}
	today := time.Now().In(time.UTC).Weekday()
	if err := st.SetEmptyRule(ctx, owner, pid, 0, today); err != nil {
		t.Fatal(err)
	}
	fc := &fakeTenant{}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, Notifier: nf})
	s.reconcileAll(ctx)

	fc.mu.Lock()
	regs := append([]string(nil), fc.setRegs...)
	fc.mu.Unlock()
	if len(regs) != 1 || regs[0] != "" {
		t.Fatalf("tenant writes = %q, want one clear", regs)
	}
	if p, _ := st.GetPermit(ctx, pid); p.ActiveRegistration != "" {
		t.Fatalf("permit still records %q", p.ActiveRegistration)
	}
	time.Sleep(20 * time.Millisecond) // the notice is delivered off the pass
	outs := nf.outcomeSnap()
	if len(outs) != 1 || !outs[0].OK || !outs[0].Empty || outs[0].Reg != "" || outs[0].Source != "roster" {
		t.Fatalf("outcomes = %+v, want one successful empty roster outcome", outs)
	}
	// Already empty: nothing to write.
	s.reconcileAll(ctx)
	fc.mu.Lock()
	n := len(fc.setRegs)
	fc.mu.Unlock()
	if n != 1 {
		t.Fatalf("a second pass wrote again (%d writes)", n)
	}

	// A council that cannot clear: the plate stays, no write, no notice.
	pid2, _ := st.UpsertPermit(ctx, owner, "vpp-noclear", "14", "Beach")
	if err := st.SetPermitActive(ctx, pid2, "XYZ789"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEmptyRule(ctx, owner, pid2, 0, today); err != nil {
		t.Fatal(err)
	}
	fc.caps = map[string]provider.Capabilities{st.DefaultTenant: {NeedsKeepWarm: true, SupportsRefresh: true, LoginKind: "password"}}
	s.reconcileAll(ctx)
	fc.mu.Lock()
	n = len(fc.setRegs)
	fc.mu.Unlock()
	if n != 1 {
		t.Fatalf("a permit whose council cannot clear was written to (%d writes)", n)
	}
	if p, _ := st.GetPermit(ctx, pid2); p.ActiveRegistration != "XYZ789" {
		t.Fatalf("no-clear permit now records %q", p.ActiveRegistration)
	}
	if outs := nf.outcomeSnap(); len(outs) != 1 {
		t.Fatalf("outcomes after the no-clear pass = %+v", outs)
	}
}
