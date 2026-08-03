package scheduler

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// fakeCouncil records calls and returns configured errors, standing in for the
// real HTTP client.
type fakeCouncil struct {
	refreshed            []string
	refreshErr           error
	reconnected          []string
	reconnectErr         error // defaults to ErrNoSavedPassword via reconnectSet
	reconnectSet         bool
	reconnectHadDeadline bool // recoverOrRetire must pass a bounded context
	permits              []parking.PermitInfo
	permitsErr           error
	setErr               error
	setDelay             time.Duration // how long a council write takes, to widen races
	panicOn              string        // council_permit_id whose SetVehicle should panic (per-unit-recovery test)
	onListPermits        func()        // runs INSIDE ListPermits, to simulate an apply landing mid-read

	// mu guards the SetVehicle bookkeeping: the apply-exclusion test drives writes
	// from a handler-style goroutine and the reconcile loop at the same time.
	mu       sync.Mutex
	setCalls []string        // council_permit_id per SetVehicle call
	setRegs  []string        // registration per SetVehicle call, in order
	inFlight map[string]bool // council permit ids with a write in flight right now
	overlaps int             // times two writes to the SAME permit were in flight together

	// current is what the council REPORTS is on each permit, keyed by council permit
	// id, and currentErr is a read failure. This used to be hardcoded empty, which
	// meant checkDrift — the whole external-change detection path — was never once
	// executed by a test.
	current    map[string]string
	currentErr error

	blocked   bool // fleet breaker "open" for the escalated busy-warning tests
	listCalls int  // ListPermits (owner-grid) calls, to prove drift is decoupled from warm
}

// setCurrent makes the council report reg on a permit, as if someone had changed it
// in the portal directly.
//
// It updates BOTH views the real council exposes: the per-permit managedVehicle
// read (current) and the owner-level Index/grid row (permits). A 2026-07-31 live
// capture confirmed the two agree, and drift detection now reads the grid, so a
// fake that populated only one of them would no longer model the council at all.
// Use setGridRego to drive them apart deliberately.
func (f *fakeCouncil) setCurrent(councilPermitID, reg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current == nil {
		f.current = map[string]string{}
	}
	f.current[councilPermitID] = reg
	f.upsertGridLocked(councilPermitID, func(pi *parking.PermitInfo) { pi.CurrentRego = reg })
}

// setGridRego changes ONLY the grid's view of the plate, leaving managedVehicle's
// alone — the disagreement drift's empty-plate corroboration exists to survive.
func (f *fakeCouncil) setGridRego(councilPermitID, reg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upsertGridLocked(councilPermitID, func(pi *parking.PermitInfo) { pi.CurrentRego = reg })
}

// setCouncilEndDate makes the council report an expiry for the permit. The council
// is the authority on expiry, and checkDrift writes what it reports straight into
// the permit row, so a test that wants an expired permit must expire it HERE.
func (f *fakeCouncil) setCouncilEndDate(councilPermitID string, end time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upsertGridLocked(councilPermitID, func(pi *parking.PermitInfo) { pi.EndDate = end })
}

// upsertGridLocked finds or appends the grid row for a permit and applies mutate.
// Callers hold f.mu. New rows default to a granted permit expiring well in the
// future, so merely reporting a plate never silently retires the fixture.
func (f *fakeCouncil) upsertGridLocked(councilPermitID string, mutate func(*parking.PermitInfo)) {
	for i := range f.permits {
		if f.permits[i].CouncilPermitID == councilPermitID {
			mutate(&f.permits[i])
			return
		}
	}
	pi := parking.PermitInfo{
		CouncilPermitID:  councilPermitID,
		PermitTypeID:     "14",
		PermitNumber:     "VPP" + councilPermitID,
		PermitType:       "(A) 1st Visitor Permit",
		Status:           "Granted",
		EndDate:          time.Now().AddDate(1, 0, 0),
		CanChangeVehicle: true,
	}
	mutate(&pi)
	f.permits = append(f.permits, pi)
}

func (f *fakeCouncil) SetVehicle(_ context.Context, _ string, p model.Permit, reg string) error {
	if p.CouncilPermitID == f.panicOn {
		panic("fakeCouncil: forced panic for " + p.CouncilPermitID)
	}
	f.mu.Lock()
	f.setCalls = append(f.setCalls, p.CouncilPermitID)
	f.setRegs = append(f.setRegs, reg)
	if f.inFlight == nil {
		f.inFlight = map[string]bool{}
	}
	if f.inFlight[p.CouncilPermitID] {
		f.overlaps++
	}
	f.inFlight[p.CouncilPermitID] = true
	delay, err := f.setDelay, f.setErr
	f.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay) // hold the "connection" open so an overlap is observable
	}

	f.mu.Lock()
	delete(f.inFlight, p.CouncilPermitID)
	f.mu.Unlock()
	return err
}

func (f *fakeCouncil) callSnap() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.setCalls...)
}

// lastReg is the registration the council was last asked to hold.
func (f *fakeCouncil) lastReg() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.setRegs) == 0 {
		return ""
	}
	return f.setRegs[len(f.setRegs)-1]
}

func (f *fakeCouncil) overlapCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.overlaps
}
func (f *fakeCouncil) CurrentVehicle(_ context.Context, _ string, p model.Permit) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.currentErr != nil {
		return "", f.currentErr
	}
	return f.current[p.CouncilPermitID], nil
}
func (f *fakeCouncil) Refresh(_ context.Context, owner string) error {
	f.refreshed = append(f.refreshed, owner)
	return f.refreshErr
}
func (f *fakeCouncil) Reconnect(ctx context.Context, owner string) error {
	f.reconnected = append(f.reconnected, owner)
	_, f.reconnectHadDeadline = ctx.Deadline() // recoverOrRetire must bound this
	if !f.reconnectSet {
		return parking.ErrNoSavedPassword // no saved password by default
	}
	return f.reconnectErr
}
func (f *fakeCouncil) ListPermits(_ context.Context, owner string) ([]parking.PermitInfo, error) {
	if f.onListPermits != nil {
		f.onListPermits()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++ // the owner-grid read; drift/expiry uses it, so counting it counts drift
	return append([]parking.PermitInfo(nil), f.permits...), f.permitsErr
}

func (f *fakeCouncil) listCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

// blocked simulates the fleet circuit breaker being open (a confirmed shared-edge
// block), which escalates the user-facing busy warning.
func (f *fakeCouncil) Blocked() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.blocked
}

type sentMail struct {
	to, url  string
	deadline time.Time
}

type appliedNote struct {
	owner, reg string
	ok         bool
}

type fakeNotifier struct {
	on         bool
	admin      bool
	deliverSet bool // when true, NotifyApply returns deliver; else it returns 1
	deliver    int  // delivered-channel count to report (0 = user not reached)

	mu            sync.Mutex // guards the slices: notifications fire from goroutines
	sent          []sentMail
	applied       []appliedNote
	outcomes      []notify.ApplyOutcome // full outcomes, for asserting message content
	adminNotes    []string
	adminErr      error // when set, NotifyAdmin records the attempt but returns this
	relinks       []string
	displaced     []string // guest emails told their car came off the permit
	expiries      []string // "owner:permitLabel" per expiry warning sent
	expiryDeliver int      // channels to report delivered (0 => 1)
}

func (f *fakeNotifier) Enabled() bool         { return f.on }
func (f *fakeNotifier) AdminConfigured() bool { return f.admin }
func (f *fakeNotifier) SendRenewalReminder(ctx context.Context, to string, deadline time.Time, url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMail{to, url, deadline})
	return nil
}

func (f *fakeNotifier) NotifyApply(_ context.Context, o notify.ApplyOutcome) (int, error) {
	f.mu.Lock()
	f.applied = append(f.applied, appliedNote{o.Owner, o.Reg, o.OK})
	f.outcomes = append(f.outcomes, o)
	f.mu.Unlock()
	if f.deliverSet {
		return f.deliver, nil
	}
	return 1, nil // default: delivered on one channel
}

func (f *fakeNotifier) NotifyRelinkRequired(_ context.Context, owner string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relinks = append(f.relinks, owner)
	return 1
}

func (f *fakeNotifier) NotifyPermitExpiry(_ context.Context, owner, permitLabel string, expiry time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expiries = append(f.expiries, owner+":"+permitLabel)
	if f.expiryDeliver == 0 {
		return 1
	}
	return f.expiryDeliver
}

func (f *fakeNotifier) NotifyAdmin(_ context.Context, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adminNotes = append(f.adminNotes, subject) // records the ATTEMPT, success or not
	return f.adminErr
}

func (f *fakeNotifier) setAdminErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adminErr = err
}

func (f *fakeNotifier) NotifyDriverDisplaced(_ context.Context, owner, to, permitLabel, oldReg, newReg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.displaced = append(f.displaced, to)
	return nil
}

// snapshot accessors: copy the slices under lock so tests read them safely while
// background notification goroutines may still be running.
func (f *fakeNotifier) appliedSnap() []appliedNote {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]appliedNote(nil), f.applied...)
}
func (f *fakeNotifier) sentSnap() []sentMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentMail(nil), f.sent...)
}
func (f *fakeNotifier) adminSnap() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.adminNotes...)
}
func (f *fakeNotifier) relinkSnap() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.relinks...)
}
func (f *fakeNotifier) outcomeSnap() []notify.ApplyOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notify.ApplyOutcome(nil), f.outcomes...)
}

// seedSchedule gives an owner something for the scheduler to act on, so their
// session is eligible for keep-warm renewal.
func seedSchedule(t *testing.T, s *store.Store, owner string) {
	t.Helper()
	ctx := context.Background()
	veh, err := s.CreateVehicle(ctx, owner, "REG123", "car")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := s.UpsertPermit(ctx, owner, "perm-"+owner, "14", "P")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRule(ctx, pid, time.Monday, veh); err != nil {
		t.Fatal(err)
	}
}

func TestDecideWarm(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	const maxAge = 90 * 24 * time.Hour
	const warm = 45 * time.Minute
	cases := []struct {
		name                        string
		lastActive, linked, updated time.Time
		want                        warmAction
	}{
		// Renew/skip is decided by cookie staleness, independent of the idle clock.
		{"fresh cookie, active", now.Add(-24 * time.Hour), now.Add(-24 * time.Hour), now.Add(-10 * time.Minute), warmSkip},
		{"stale cookie, active", now.Add(-24 * time.Hour), now.Add(-24 * time.Hour), now.Add(-46 * time.Minute), warmRenew},
		{"exactly warm boundary", now.Add(-24 * time.Hour), now.Add(-24 * time.Hour), now.Add(-warm), warmRenew},

		// The bound is IDLENESS, not age. A household that linked a year ago but was
		// here yesterday keeps its session...
		{"linked long ago but recently active", now.Add(-24 * time.Hour), now.Add(-400 * 24 * time.Hour), now.Add(-46 * time.Minute), warmRenew},
		// ...and one that linked recently but has not been seen for the whole bound
		// is retired, which the old link-time clock would have missed entirely.
		{"linked recently but idle past bound", now.Add(-91 * 24 * time.Hour), now.Add(-2 * 24 * time.Hour), now.Add(-1 * time.Minute), warmRetire},
		{"exactly at the idle bound", now.Add(-maxAge), now.Add(-maxAge), now.Add(-1 * time.Minute), warmRetire},

		// Sessions predating the idle clock fall back to the link time, so upgrading
		// does not retire anyone early or keep a stale session forever.
		{"no idle clock, link in bound", time.Time{}, now.Add(-24 * time.Hour), now.Add(-46 * time.Minute), warmRenew},
		{"no idle clock, link past bound", time.Time{}, now.Add(-91 * 24 * time.Hour), now.Add(-1 * time.Minute), warmRetire},
		{"no clock at all", time.Time{}, time.Time{}, now.Add(-1 * time.Minute), warmRetire},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decideWarm(now, c.lastActive, c.linked, c.updated, maxAge, warm); got != c.want {
				t.Fatalf("decideWarm = %v, want %v", got, c.want)
			}
		})
	}
}

// TestWarmThresholdFor: the per-session renew threshold is deterministic (stable
// within a warm cycle so the fast recovery tick can't bias renewals to the low
// end of the jitter band), stays inside warmInterval×(1±jitterFrac), and varies
// by owner so touches desync.
func TestWarmThresholdFor(t *testing.T) {
	const warm = 105 * time.Minute
	s := New(nil, nil, time.UTC, Options{WarmInterval: warm, JitterFrac: 0.2})
	up := time.Date(2026, 7, 26, 9, 0, 0, 0, time.UTC)

	// Deterministic: same (owner, updatedAt) → identical threshold across calls.
	a1 := s.warmThresholdFor("a@example.com", up)
	a2 := s.warmThresholdFor("a@example.com", up)
	if a1 != a2 {
		t.Fatalf("threshold not deterministic: %v vs %v", a1, a2)
	}
	// Within the ±20% band.
	lo, hi := time.Duration(float64(warm)*0.8), time.Duration(float64(warm)*1.2)
	if a1 < lo || a1 > hi {
		t.Fatalf("threshold %v outside [%v,%v]", a1, lo, hi)
	}
	// A different owner (very likely) lands on a different phase.
	if b := s.warmThresholdFor("b@example.com", up); b == a1 {
		t.Fatalf("distinct owners share a threshold (%v); desync lost", a1)
	}
	// A new cycle (updatedAt slid) re-derives the offset.
	if c := s.warmThresholdFor("a@example.com", up.Add(time.Hour)); c == a1 {
		t.Fatalf("threshold did not re-derive across cycles")
	}
	// jitterFrac 0 → exactly warmInterval (no jitter). Built directly: New() clamps
	// a non-positive JitterFrac up to its 0.2 default.
	s0 := &Scheduler{warmInterval: warm, jitterFrac: 0}
	if got := s0.warmThresholdFor("a@example.com", up); got != warm {
		t.Fatalf("jitterFrac 0: got %v, want %v", got, warm)
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedSession(t *testing.T, s *store.Store, owner string) {
	t.Helper()
	// SaveCouncilSession stamps linked_at = now, so these sessions start in-bound.
	if err := s.SaveCouncilSession(context.Background(), store.CouncilSession{Owner: owner, Cookie: "seed"}); err != nil {
		t.Fatal(err)
	}
}

// TestKeepWarmRetiresPastBound: a zero max-age makes every session instantly
// past-bound, so keep-warm unlinks it (and never calls Refresh).
func TestKeepWarmRetiresPastBound(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "gone@example.com")
	fc := &fakeCouncil{}
	// maxAge tiny → past bound immediately; warmInterval irrelevant.
	s := New(st, fc, time.UTC, Options{SessionMaxAge: time.Nanosecond, WarmInterval: time.Hour})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())

	if len(fc.refreshed) != 0 {
		t.Fatalf("retired session should not be refreshed, got %v", fc.refreshed)
	}
	if _, err := st.GetCouncilSession(context.Background(), "gone@example.com"); err != store.ErrNotFound {
		t.Fatalf("session should be retired, got err=%v", err)
	}
}

// TestKeepWarmRenewsStale: an in-bound session past the warm interval is renewed
// and kept.
func TestKeepWarmRenewsStale(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "active@example.com")
	seedSchedule(t, st, "active@example.com")
	fc := &fakeCouncil{}
	// Large maxAge (in bound), tiny warmInterval (stale after a moment).
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())

	if len(fc.refreshed) != 1 || fc.refreshed[0] != "active@example.com" {
		t.Fatalf("expected one refresh of active@example.com, got %v", fc.refreshed)
	}
	if _, err := st.GetCouncilSession(context.Background(), "active@example.com"); err != nil {
		t.Fatalf("renewed session should still exist: %v", err)
	}
}

// TestKeepWarmUnlinksOnExpiry: when Refresh reports the cookie is dead, keep-warm
// retires the session so the dashboard can prompt a re-link.
func TestKeepWarmUnlinksOnExpiry(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "expired@example.com")
	seedSchedule(t, st, "expired@example.com")
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())
	// keep-warm enqueues the reconnect; the worker drains it. Drive that step directly.
	s.drainOneReconnect(context.Background()) // the reconnect worker drains the queued item

	if len(fc.refreshed) != 1 {
		t.Fatalf("expected one refresh attempt, got %v", fc.refreshed)
	}
	if _, err := st.GetCouncilSession(context.Background(), "expired@example.com"); err != store.ErrNotFound {
		t.Fatalf("expired session should be unlinked, got err=%v", err)
	}
}

// TestPermitExpiryReminder: keep-warm syncs the permit's expiry from the council,
// warns the account once when it's within the lead window, doesn't warn again for
// the same date, and re-arms when a renewal moves the date.
func TestPermitExpiryReminder(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	owner := "expiry@example.com"
	seedSession(t, st, owner)
	seedSchedule(t, st, owner) // creates permit "perm-<owner>"
	cpid := "perm-" + owner

	soon := time.Now().Add(5 * 24 * time.Hour)
	fc := &fakeCouncil{permits: []parking.PermitInfo{{CouncilPermitID: cpid, Status: "Granted", EndDate: soon}}}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond,
		DriftInterval: time.Nanosecond, ExpiryLead: 14 * 24 * time.Hour, Notifier: nf})

	time.Sleep(2 * time.Millisecond)
	s.keepWarm(ctx)
	if got := len(nf.expiries); got != 1 {
		t.Fatalf("expected one expiry warning, got %d (%v)", got, nf.expiries)
	}
	// Expiry + status were written back to the permit.
	if p, _ := st.PermitByCouncilID(ctx, cpid); p.Status != "Granted" || p.EndDate.IsZero() {
		t.Fatalf("permit meta not persisted: status=%q end=%v", p.Status, p.EndDate)
	}
	// A second pass must NOT re-warn for the same expiry date.
	s.keepWarm(ctx)
	if got := len(nf.expiries); got != 1 {
		t.Fatalf("expiry warning should be sent once per date, got %d", got)
	}
	// A renewal (new, far-off date) clears the flag; it's outside the lead so no
	// new warning, but the flag being re-armed is what we assert via the date write.
	fc.permits = []parking.PermitInfo{{CouncilPermitID: cpid, Status: "Granted", EndDate: time.Now().Add(60 * 24 * time.Hour)}}
	s.keepWarm(ctx)
	if got := len(nf.expiries); got != 1 {
		t.Fatalf("far-off renewal should not warn, got %d", got)
	}
	if p, _ := st.PermitByCouncilID(ctx, cpid); p.ExpiryReminded {
		t.Fatal("renewal to a new date should clear the reminded flag")
	}
}

// TestReconcileSkipsInactivePermits: an expired permit is not written to (no
// doomed council calls, no failure noise), while an active one still is.
func TestReconcileSkipsInactivePermits(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	owner := "r@example.com"
	seedSession(t, st, owner)
	veh, err := st.CreateVehicle(ctx, owner, "AAA111", "Car")
	if err != nil {
		t.Fatal(err)
	}
	today := time.Now().In(time.UTC).Weekday()
	future := time.Now().Add(30 * 24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	act, _ := st.UpsertPermit(ctx, owner, "active-1", "14", "Active")
	if err := st.SetRule(ctx, act, today, veh); err != nil {
		t.Fatal(err)
	}
	_ = st.UpdatePermitMeta(ctx, owner, "active-1", "Granted", "VPP1", "1st Visitor Permit", future)

	exp, _ := st.UpsertPermit(ctx, owner, "expired-1", "14", "Expired")
	if err := st.SetRule(ctx, exp, today, veh); err != nil {
		t.Fatal(err)
	}
	_ = st.UpdatePermitMeta(ctx, owner, "expired-1", "Granted", "VPP2", "1st Visitor Permit", past)

	fc := &fakeCouncil{}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour})
	s.reconcileAll(ctx)

	if calls := fc.callSnap(); len(calls) != 1 || calls[0] != "active-1" {
		t.Fatalf("SetVehicle calls = %v, want [active-1] only (expired skipped)", calls)
	}
}

// TestReconnectTransientPreservesSession: a TRANSIENT reconnect failure (busy /
// network) must NOT delete the session or its saved password — a later pass retries.
func TestReconnectTransientPreservesSession(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "blip@example.com")
	seedSchedule(t, st, "blip@example.com")
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired, reconnectSet: true,
		reconnectErr: errors.New("council busy 503")} // transient
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: nf})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())

	if _, err := st.GetCouncilSession(context.Background(), "blip@example.com"); err != nil {
		t.Fatalf("transient reconnect failure must keep the session, got err=%v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if got := nf.relinkSnap(); len(got) != 0 {
		t.Fatalf("transient failure should not alert re-link yet, got %v", got)
	}
}

// TestReconnectRejectedRetires: a saved password that's genuinely rejected retires
// the session and prompts a manual re-link (no pointless retrying).
func TestReconnectRejectedRetires(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "badpw@example.com")
	seedSchedule(t, st, "badpw@example.com")
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired, reconnectSet: true,
		reconnectErr: parking.ErrLoginRejected}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: nf})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())
	s.drainOneReconnect(context.Background()) // drain the queued reconnect

	if _, err := st.GetCouncilSession(context.Background(), "badpw@example.com"); err != store.ErrNotFound {
		t.Fatalf("rejected password should retire the session, got err=%v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if got := nf.relinkSnap(); len(got) != 1 {
		t.Fatalf("rejected reconnect should alert re-link once, got %v", got)
	}
}

// TestKeepWarmAutoReconnects: when the session expires but the user saved their
// password, the scheduler reconnects silently instead of unlinking + alerting.
func TestKeepWarmAutoReconnects(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "saved@example.com")
	seedSchedule(t, st, "saved@example.com")
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired, reconnectSet: true} // reconnectErr nil = success
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: nf})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())
	s.drainOneReconnect(context.Background()) // drain the queued reconnect

	if len(fc.reconnected) != 1 {
		t.Fatalf("expected one reconnect attempt, got %v", fc.reconnected)
	}
	if !fc.reconnectHadDeadline {
		t.Fatal("reconnect must run under a bounded context so a slow login can't stall the loop")
	}
	if _, err := st.GetCouncilSession(context.Background(), "saved@example.com"); err != nil {
		t.Fatalf("auto-reconnected session should be kept, got err=%v", err)
	}
	time.Sleep(2 * time.Millisecond) // let any (unexpected) alert goroutine run
	if got := nf.relinkSnap(); len(got) != 0 {
		t.Fatalf("auto-reconnect should not alert re-link, got %v", got)
	}
}

func rejectedErr() error {
	return &parking.CouncilError{Kind: parking.FailRejected, Op: "change the vehicle on your permit", Err: errors.New("no")}
}
func transientErr() error {
	return &parking.CouncilError{Kind: parking.FailTransient, Op: "change the vehicle on your permit", Err: errors.New("timeout")}
}

// TestFailureNotifyDedupAndSuccess: a repeated identical REJECTION (alarms at
// once) is logged and notified once; a later success fires a new notification.
func TestFailureNotifyDedupAndSuccess(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "u@example.com", "14576", "14", "1st Visitor Permit")
	p := model.Permit{ID: pid, Owner: "u@example.com", CouncilPermitID: "14576", Label: "1st Visitor Permit", ActiveRegistration: "OLD111"}
	fn := &fakeNotifier{on: true}
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})

	// Ticks are a minute apart in production; sleep so async delivery lands first.
	s.handleApplyFailure(ctx, p, "AVS619", "", "override", rejectedErr(), nil)
	time.Sleep(60 * time.Millisecond)
	s.handleApplyFailure(ctx, p, "AVS619", "", "override", rejectedErr(), nil) // identical → suppressed
	time.Sleep(60 * time.Millisecond)
	// Success (as the reconcile success branch would do).
	s.clearFailStreak(ctx, p.ID)
	s.logApply(ctx, p.ID, "AVS619", "override", "success", "")
	s.notifyUser(ctx, p, notify.ApplyOutcome{Owner: p.Owner, PermitLabel: permitLabel(p), Reg: "AVS619", OK: true}, "success|AVS619")
	time.Sleep(60 * time.Millisecond)

	if logs, _ := st.ListApplyLogFor(ctx, "u@example.com", 10); len(logs) != 2 {
		t.Fatalf("apply_log rows = %d, want 2 (dup suppressed)", len(logs))
	}
	applied := fn.appliedSnap()
	if len(applied) != 2 {
		t.Fatalf("notifications = %d, want 2", len(applied))
	}
	if applied[0].ok || !applied[1].ok {
		t.Fatalf("expected [fail, success], got %+v", applied)
	}
	// Message suitability: the failure names the consequence (still shows OLD111)
	// and is marked non-transient (a rejection needs the user to act).
	fail := fn.outcomeSnap()[0]
	if fail.CurrentReg != "OLD111" || fail.Transient || fail.Reason == "" || fail.Action == "" {
		t.Fatalf("rejection message not suitable: %+v", fail)
	}
}

// TestTransientFailureGracePeriod: a transient blip does NOT alarm the user until
// it has persisted (failNotifyThreshold ticks), though it is logged immediately.
func TestTransientFailureGracePeriod(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "u@example.com", "14576", "14", "Permit")
	p := model.Permit{ID: pid, Owner: "u@example.com", CouncilPermitID: "14576", Label: "Permit", ActiveRegistration: "OLD111"}
	fn := &fakeNotifier{on: true}
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})

	for i := 0; i < failNotifyThreshold-1; i++ {
		s.handleApplyFailure(ctx, p, "AVS619", "", "override", transientErr(), nil)
		time.Sleep(30 * time.Millisecond)
	}
	if n := len(fn.appliedSnap()); n != 0 {
		t.Fatalf("transient blip alarmed the user too early: %d notifications", n)
	}
	if logs, _ := st.ListApplyLogFor(ctx, "u@example.com", 10); len(logs) == 0 {
		t.Fatal("transient failure should still be recorded in the activity log")
	}
	// The threshold-th consecutive failure now alarms.
	s.handleApplyFailure(ctx, p, "AVS619", "", "override", transientErr(), nil)
	time.Sleep(60 * time.Millisecond)
	out := fn.outcomeSnap()
	if len(out) != 1 || out[0].OK || !out[0].Transient {
		t.Fatalf("expected one transient failure notification, got %+v", out)
	}
	// A success resets the streak so the next blip gets a fresh grace period.
	s.clearFailStreak(ctx, p.ID)
	s.handleApplyFailure(ctx, p, "AVS619", "", "override", transientErr(), nil)
	time.Sleep(30 * time.Millisecond)
	if n := len(fn.appliedSnap()); n != 1 {
		t.Fatalf("streak not reset after success; got %d notifications", n)
	}
}

// TestSystemicDetection: many users failing in one pass alerts the operator.
func TestSystemicDetection(t *testing.T) {
	st := newStore(t)
	fn := &fakeNotifier{on: true, admin: true}
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})
	stats := &passStats{
		failOwners:       map[string]bool{"a@x": true, "b@x": true, "c@x": true},
		unexpectedOwners: map[string]bool{},
	}
	s.detectSystemic(context.Background(), stats, 5)
	time.Sleep(60 * time.Millisecond)
	found := false
	for _, subj := range fn.adminSnap() {
		if strings.Contains(subj, "failing for multiple users") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a systemic admin alert, got %v", fn.adminSnap())
	}
}

// TestFailureEscalatesWhenUserNotReached: when the user's channels all fail, the
// outcome is NOT marked delivered (so it retries), and the operator is alerted
// once. This is the anti-fine guarantee.
func TestFailureEscalatesWhenUserNotReached(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "u@example.com", "14576", "14", "Permit")
	p := model.Permit{ID: pid, Owner: "u@example.com", CouncilPermitID: "14576", Label: "Permit"}
	fn := &fakeNotifier{on: true, admin: true, deliverSet: true, deliver: 0} // user not reached
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})

	// A rejection alarms on the first tick.
	s.handleApplyFailure(ctx, p, "AVS619", "", "override", rejectedErr(), nil)
	time.Sleep(60 * time.Millisecond)
	if n := len(fn.adminSnap()); n != 1 {
		t.Fatalf("admin escalations = %d, want 1 (user not reached)", n)
	}
	// Not marked delivered → an identical repeat is RE-attempted, not suppressed.
	s.handleApplyFailure(ctx, p, "AVS619", "", "override", rejectedErr(), nil)
	time.Sleep(60 * time.Millisecond)
	if n := len(fn.appliedSnap()); n != 2 {
		t.Fatalf("undelivered failure must be retried; NotifyApply calls = %d, want 2", n)
	}
	// Admin alerted once per distinct outcome, not on every retry.
	if n := len(fn.adminSnap()); n != 1 {
		t.Fatalf("admin alerted %d times, want 1 for the same outcome", n)
	}
}

// TestSessionExpiryNotifiesRelink: a session that expires during keep-warm
// proactively tells the user to re-link (not just a log line).
func TestSessionExpiryNotifiesRelink(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "expired@example.com")
	seedSchedule(t, st, "expired@example.com")
	fn := &fakeNotifier{on: true, admin: true}
	fc := &fakeCouncil{refreshErr: parking.ErrSessionExpired}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond, Notifier: fn})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())
	s.drainOneReconnect(context.Background()) // the reconnect worker drains the queued item
	time.Sleep(60 * time.Millisecond)         // async re-link notify
	if rl := fn.relinkSnap(); len(rl) != 1 || rl[0] != "expired@example.com" {
		t.Fatalf("expected one re-link notification to the user, got %v", rl)
	}
}

// TestKeepWarmSkipsNoSchedule: a linked user with no rules/overrides isn't warmed
// (their dashboard use would renew it), keeping council traffic proportional to
// actual schedules.
func TestKeepWarmSkipsNoSchedule(t *testing.T) {
	st := newStore(t)
	seedSession(t, st, "idle@example.com") // linked, but no schedule seeded
	fc := &fakeCouncil{}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(context.Background())

	if len(fc.refreshed) != 0 {
		t.Fatalf("session with no schedule should not be warmed, got %v", fc.refreshed)
	}
	if _, err := st.GetCouncilSession(context.Background(), "idle@example.com"); err != nil {
		t.Fatalf("idle session should be left intact: %v", err)
	}
}

// TestKeepWarmSendsReminder: a session inside the reminder window emails the
// confirm link exactly once, stores the token, and a click extends the deadline.
func TestKeepWarmSendsReminder(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedSession(t, st, "soon@example.com")
	fn := &fakeNotifier{on: true}
	// Window = [deadline-lead, deadline); with maxAge==lead==10s and a just-linked
	// session, "now" is inside the window (few ms in), well before the deadline.
	s := New(st, &fakeCouncil{}, time.UTC, Options{
		SessionMaxAge: 10 * time.Second, WarmInterval: time.Hour,
		ReminderLead: 10 * time.Second, PublicBaseURL: "https://pstonn.example", Notifier: fn,
	})
	s.keepWarm(ctx)

	sent := fn.sentSnap()
	if len(sent) != 1 {
		t.Fatalf("expected exactly one reminder, got %d", len(sent))
	}
	if sent[0].to != "soon@example.com" || !strings.Contains(sent[0].url, "/council/confirm?token=") {
		t.Fatalf("bad reminder: %+v", sent[0])
	}
	cs, _ := st.GetCouncilSession(ctx, "soon@example.com")
	if cs.ReminderSent.IsZero() || cs.ConfirmToken == "" {
		t.Fatalf("reminder state not persisted: %+v", cs)
	}
	// A second pass must not re-send.
	s.keepWarm(ctx)
	if n := len(fn.sentSnap()); n != 1 {
		t.Fatalf("reminder re-sent: %d", n)
	}
	// Clicking the link clears the reminder cycle (deadline-extension precision is
	// verified in the store test with a backdated link time). The token comes from
	// the EMAIL, not from the row: the column stores only its hash, so a link cannot
	// be reconstructed from a database read.
	_, token, _ := strings.Cut(sent[0].url, "token=")
	if token == "" {
		t.Fatalf("no token in the reminder link: %q", sent[0].url)
	}
	if token == cs.ConfirmToken {
		t.Fatal("the emailed token equals the stored column, so it is stored in plaintext")
	}
	owner, err := st.ConfirmSession(ctx, token, 0)
	if err != nil || owner != "soon@example.com" {
		t.Fatalf("ConfirmSession = %q, %v", owner, err)
	}
	cs2, _ := st.GetCouncilSession(ctx, "soon@example.com")
	if !cs2.ReminderSent.IsZero() || cs2.ConfirmToken != "" {
		t.Fatalf("confirm did not reset the cycle: %+v", cs2)
	}
}

func TestDisplaced(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	s := New(st, &fakeCouncil{}, time.UTC, Options{})
	const owner = "owner@example.com"
	p := model.Permit{ID: 1, Owner: owner}
	now := time.Now()
	end := now.Add(2 * time.Hour)
	veh := map[ownerVehicle]model.VehicleInfo{
		{owner, 5}: {Registration: "MUM123", Label: "Mum's car", Email: "nanny@example.com"},
	}

	guestOvr := []model.Override{
		{ID: 1, PermitID: 1, Registration: "GUEST99", StartsAt: now.Add(-time.Hour), EndsAt: &end, CreatedBy: "dad@example.com", CreatedAt: now.Add(-time.Hour)},
	}
	// The removed plate was the guest's live activation → that guest is notified.
	if got := s.displaced(ctx, p, guestOvr, veh, "GUEST99", "", now); got.Contact != "dad@example.com" {
		t.Fatalf("displaced = %+v, want contact dad@example.com", got)
	}
	// The same guest displacing their own booking (another car, same person) → quiet.
	if got := s.displaced(ctx, p, guestOvr, veh, "GUEST99", "dad@example.com", now); got != (model.DisplacedBooking{}) {
		t.Fatalf("self-displacement should be quiet, got %+v", got)
	}
	// A plate not set by any active override → nobody.
	if got := s.displaced(ctx, p, guestOvr, veh, "SOMETHINGELSE", "", now); got != (model.DisplacedBooking{}) {
		t.Fatalf("no match should be empty, got %+v", got)
	}
	// The account owner's own ad-hoc booking is not a displaced third party.
	ownOvr := []model.Override{
		{ID: 2, PermitID: 1, Registration: "OWN123", StartsAt: now.Add(-time.Hour), EndsAt: &end, CreatedBy: owner, CreatedAt: now},
	}
	if got := s.displaced(ctx, p, ownOvr, veh, "OWN123", "", now); got != (model.DisplacedBooking{}) {
		t.Fatalf("member's own booking should not notify, got %+v", got)
	}
	// A member's booking of a saved car with an attached driver email → the
	// driver (borrowed-car case) is warned, not the member.
	memberSavedOvr := []model.Override{
		{ID: 3, PermitID: 1, VehicleID: 5, StartsAt: now.Add(-time.Hour), EndsAt: &end, CreatedBy: owner, CreatedAt: now},
	}
	if got := s.displaced(ctx, p, memberSavedOvr, veh, "MUM123", "", now); got.Contact != "nanny@example.com" {
		t.Fatalf("displaced = %+v, want contact nanny@example.com", got)
	}
	// An expired guest override is not "active", so no notification.
	expired := []model.Override{
		{ID: 4, PermitID: 1, Registration: "GUEST99", StartsAt: now.Add(-3 * time.Hour), EndsAt: ptr(now.Add(-time.Hour)), CreatedBy: "dad@example.com", CreatedAt: now.Add(-3 * time.Hour)},
	}
	if got := s.displaced(ctx, p, expired, veh, "GUEST99", "", now); got != (model.DisplacedBooking{}) {
		t.Fatalf("expired override should not notify, got %+v", got)
	}
	// An unreachable displaced booking (a QR visitor's ad-hoc plate) reports the
	// displaced plate with no contact, so the account notice can say "tell them".
	qrOvr := []model.Override{
		{ID: 5, PermitID: 1, Registration: "VIS777", StartsAt: now.Add(-time.Hour), EndsAt: &end, CreatedBy: "visitor (printed QR)", CreatedAt: now},
	}
	if got := s.displaced(ctx, p, qrOvr, veh, "VIS777", "", now); got.Reg != "VIS777" || got.Contact != "" {
		t.Fatalf("displaced = %+v, want reg VIS777 with no contact", got)
	}
}

func ptr(t time.Time) *time.Time { return &t }

// TestDetectSystemicOwnerCounting locks in the fix that the "everything is
// blocked" alert compares owner-counts to owner-counts. The failN/busyN sets are
// owner-keyed, so comparing them to a permit count (the old bug) made the
// equality unsatisfiable whenever any owner held more than one permit, hiding a
// fully-blocked small fleet.
func TestDetectSystemicOwnerCounting(t *testing.T) {
	ctx := context.Background()
	nf := &fakeNotifier{on: true, admin: true}
	s := &Scheduler{notifier: nf, lastAlert: make(map[string]time.Time)}

	// Two owners (each may hold several permits), ALL council-busy. totalOwners=2.
	stats := &passStats{
		failOwners:       map[string]bool{},
		unexpectedOwners: map[string]bool{},
		busyOwners:       map[string]bool{"a@x.co": true, "b@x.co": true},
	}
	s.detectSystemic(ctx, stats, 2)
	// systemAlert delivers on a goroutine; give it a moment to land.
	var got []string
	for i := 0; i < 50; i++ {
		if got = nf.adminSnap(); len(got) > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if len(got) != 1 || !strings.Contains(got[0], "rate-limiting") {
		t.Fatalf("all-owners-busy should raise the council-busy alert, got %v", got)
	}

	// A single owner busy on their own permits is NOT a fleet-wide event.
	nf2 := &fakeNotifier{on: true, admin: true}
	s2 := &Scheduler{notifier: nf2, lastAlert: make(map[string]time.Time)}
	solo := &passStats{
		failOwners:       map[string]bool{},
		unexpectedOwners: map[string]bool{},
		busyOwners:       map[string]bool{"a@x.co": true},
	}
	s2.detectSystemic(ctx, solo, 1)
	if got := nf2.adminSnap(); len(got) != 0 {
		t.Fatalf("a single busy owner should not self-alert, got %v", got)
	}
}

// A persistently failing permit must not hit the council every tick: after each
// failure the next attempt is deferred exponentially, success clears the
// deferral, and a user action (Kick) clears all deferrals immediately.
func TestRetryBackoff(t *testing.T) {
	s := New(nil, nil, time.UTC, Options{JitterFrac: 0.0001})
	now := time.Now()

	s.deferRetry(7, 1) // ~2 min
	if !s.retryDeferred(7, now) {
		t.Fatal("permit should be deferred right after a failure")
	}
	if s.retryDeferred(7, now.Add(3*time.Minute)) {
		t.Fatal("a streak-1 deferral should be about 2 minutes")
	}

	s.deferRetry(7, 10) // capped at 30 min
	if s.retryDeferred(7, now.Add(31*time.Minute)) {
		t.Fatal("deferral must be capped at 30 minutes")
	}
	if !s.retryDeferred(7, now.Add(20*time.Minute)) {
		t.Fatal("a long streak should defer well past 20 minutes")
	}

	s.clearRetry(7)
	if s.retryDeferred(7, now) {
		t.Fatal("success must clear the deferral")
	}

	// Kick asks for an immediate pass but must NOT clear failure backoffs. It used
	// to clear every permit's, and it is reachable from unauthenticated guest
	// activations — so one actor could hold the whole fleet at the 1-minute
	// reconcile rate instead of its 2–30 minute backoff, which is the exact
	// hammering nextTry exists to prevent.
	s.deferRetry(7, 5)
	s.deferRetry(8, 5)
	s.Kick()
	if !s.retryDeferred(7, now) || !s.retryDeferred(8, now) {
		t.Fatal("Kick must NOT clear failure backoffs (it is reachable unauthenticated)")
	}

	// KickPermit clears exactly the permit the user acted on, and nothing else.
	s.KickPermit(7)
	if s.retryDeferred(7, now) {
		t.Fatal("KickPermit must clear that permit's deferral: the user may have just fixed the cause")
	}
	if !s.retryDeferred(8, now) {
		t.Fatal("KickPermit must not clear another permit's deferral")
	}
}

// TestCouncilBusyTellsTheUserEventually: a council block used to be completely
// silent to the user — no activity row, no notification, however long a permit
// sat un-updatable. A brief block should still stay quiet (it self-heals), but a
// sustained one has to reach the person whose permit is wrong.
func TestCouncilBusyTellsTheUserEventually(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "busy@example.com"
	seedSession(t, st, owner)
	veh, err := st.CreateVehicle(ctx, owner, "AAA111", "Car")
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := st.UpsertPermit(ctx, owner, "busy-1", "14", "Busy permit")
	if err := st.SetRule(ctx, pid, time.Now().In(time.UTC).Weekday(), veh); err != nil {
		t.Fatal(err)
	}
	// The permit currently shows something else, so there is a real change pending.
	if err := st.SetPermitActive(ctx, pid, "OLD999"); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCouncil{setErr: parking.ErrCouncilBusy}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{SessionMaxAge: 90 * 24 * time.Hour, Notifier: nf})

	// A few blocked ticks: the user is not bothered yet...
	for i := 0; i < 3; i++ {
		s.reconcileAll(ctx)
	}
	if n := len(nf.appliedSnap()); n != 0 {
		t.Fatalf("a brief council block notified the user %d time(s); it should stay quiet", n)
	}
	// ...but it IS already visible in the activity log, so someone looking can see
	// why their permit hasn't changed.
	logs, err := st.ListApplyLogFor(ctx, owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || logs[0].Status != "error" {
		t.Fatalf("a blocked apply should be recorded in the activity log, got %+v", logs)
	}

	// Sustained: now they hear about it.
	for i := 0; i < busyNotifyThreshold; i++ {
		s.reconcileAll(ctx)
	}
	applied := nf.appliedSnap()
	if len(applied) == 0 {
		t.Fatal("a sustained council block never reached the user")
	}
	out := nf.outcomeSnap()[0]
	if out.OK || !out.Transient {
		t.Fatalf("a block should read as a transient failure, got OK=%v Transient=%v", out.OK, out.Transient)
	}
	if out.CurrentReg != "OLD999" {
		t.Fatalf("the notice should say what is still on the permit, got %q", out.CurrentReg)
	}

	// A success clears the streak, so a later block starts counting from scratch
	// rather than notifying immediately.
	fc.setErr = nil
	s.reconcileAll(ctx)
	time.Sleep(20 * time.Millisecond) // notifications fire from goroutines
	failuresBefore := countFailures(nf.outcomeSnap())

	fc.setErr = parking.ErrCouncilBusy
	if err := st.SetPermitActive(ctx, pid, "OLD999"); err != nil {
		t.Fatal(err)
	}
	s.reconcileAll(ctx)
	time.Sleep(20 * time.Millisecond)
	if got := countFailures(nf.outcomeSnap()); got != failuresBefore {
		t.Fatalf("after a success, one fresh blocked tick notified again (%d -> %d)", failuresBefore, got)
	}
}

// countFailures counts failure notifications among recorded outcomes.
func countFailures(os []notify.ApplyOutcome) int {
	n := 0
	for _, o := range os {
		if !o.OK {
			n++
		}
	}
	return n
}

// seedActivePermit gives an owner one permit rostered to one car for TODAY, with
// the council currently holding something else — so a reconcile pass has a real
// change to make. Returns the permit id and the rostered plate.
func seedActivePermit(t *testing.T, st *store.Store, owner, councilID, reg, active string) (int64, string) {
	t.Helper()
	ctx := context.Background()
	seedSession(t, st, owner)
	veh, err := st.CreateVehicle(ctx, owner, reg, "Rostered car")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := st.UpsertPermit(ctx, owner, councilID, "14", "Permit")
	if err != nil {
		t.Fatal(err)
	}
	// The scheduler resolves the roster from time.Now() in its own location (UTC in
	// these tests), so the rule has to be for today's UTC weekday.
	if err := st.SetRule(ctx, pid, time.Now().In(time.UTC).Weekday(), veh); err != nil {
		t.Fatal(err)
	}
	if err := st.SetPermitActive(ctx, pid, active); err != nil {
		t.Fatal(err)
	}
	return pid, reg
}

// TestApplyExclusion (F3, I8) is the anti-lost-update test. A guest tapping a car
// runs the same three steps the reconcile loop does — claim, council write, record
// the plate — and if the two interleave the council can end up holding one plate
// while the database records another. Every later tick then compares its target
// against that wrong belief, concludes there is nothing to do, and leaves a car
// uncovered until the next drift check ~105 minutes later.
//
// Two invariants: no two writes to one permit are ever in flight together, and
// when the dust settles the stored belief IS the plate the council was last given.
// Run under -race, which also covers the shared scheduler state both sides touch.
func TestApplyExclusion(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "race@example.com"
	pid, _ := seedActivePermit(t, st, owner, "race-1", "ROSTER1", "OLD999")

	fc := &fakeCouncil{setDelay: time.Millisecond}
	s := New(st, fc, time.UTC, Options{})
	handlerPermit := model.Permit{ID: pid, Owner: owner, CouncilPermitID: "race-1"}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // the handler side (guestActivate / guestRevert / decideRequest)
		defer wg.Done()
		for i := 0; i < 40; i++ {
			reg := fmt.Sprintf("GUEST%02d", i)
			release, ok := s.AcquireApply(ctx, pid)
			if !ok {
				release()
				return
			}
			if err := fc.SetVehicle(ctx, owner, handlerPermit, reg); err == nil {
				if err := st.SetPermitActive(ctx, pid, reg); err != nil {
					t.Errorf("record applied plate: %v", err)
				}
			}
			release()
		}
	}()
	go func() { // the reconcile loop
		defer wg.Done()
		for i := 0; i < 40; i++ {
			s.reconcileAll(ctx)
		}
	}()
	wg.Wait()

	if n := fc.overlapCount(); n != 0 {
		t.Fatalf("%d council write(s) overlapped on one permit: the handler and the reconcile loop are not serialised", n)
	}
	p, err := st.GetPermit(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if last := fc.lastReg(); !model.SamePlate(p.ActiveRegistration, last) {
		t.Fatalf("the council was last given %q but the permit records %q — a car is uncovered and no tick will notice", last, p.ActiveRegistration)
	}
}

// TestReconcileSkipsPermitWithApplyInFlight: the reconcile loop must not WAIT on a
// handler's claim, because `want` was computed before that handler's decision — it
// would apply a stale target, which is the clobber the claim exists to prevent. It
// skips the permit (and does not count as a council hit), and the next tick heals.
func TestReconcileSkipsPermitWithApplyInFlight(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "held@example.com"
	pid, _ := seedActivePermit(t, st, owner, "held-1", "ROSTER1", "OLD999")

	fc := &fakeCouncil{}
	s := New(st, fc, time.UTC, Options{})

	release, ok := s.AcquireApply(ctx, pid)
	if !ok {
		t.Fatal("AcquireApply on a free permit must succeed")
	}
	s.reconcileAll(ctx)
	if calls := fc.callSnap(); len(calls) != 0 {
		t.Fatalf("reconcile wrote to the council while a handler held the permit: %v", calls)
	}
	release()

	s.reconcileAll(ctx)
	if calls := fc.callSnap(); len(calls) != 1 {
		t.Fatalf("the next tick must heal the skipped permit; SetVehicle calls = %v", calls)
	}
}

// TestCaseVariantPlateIsNotAChange (F5, I8): the portal echoes plates back in
// whatever case they were entered with, and a case-only difference must not look
// like a change. It used to drive a real council write, a "your permit was updated"
// notification and a displaced-driver email for a no-op.
func TestCaseVariantPlateIsNotAChange(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "case@example.com"
	pid, reg := seedActivePermit(t, st, owner, "case-1", "ABC123", "abc123")

	fc := &fakeCouncil{}
	nf := &fakeNotifier{on: true, admin: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})
	s.reconcileAll(ctx)
	time.Sleep(20 * time.Millisecond) // notifications fire from goroutines

	if calls := fc.callSnap(); len(calls) != 0 {
		t.Fatalf("a case variant of %s drove a real council write: %v", reg, calls)
	}
	if applied := nf.appliedSnap(); len(applied) != 0 {
		t.Fatalf("a case variant notified the household of a change that changed nothing: %+v", applied)
	}
	if logs, err := st.ListApplyLogFor(ctx, owner, 10); err != nil || len(logs) != 0 {
		t.Fatalf("a case variant wrote an activity row (%d rows, err=%v)", len(logs), err)
	}
	// Spacing is the same class of difference, and the council echoes that back too.
	if err := st.SetPermitActive(ctx, pid, "abc 123"); err != nil {
		t.Fatal(err)
	}
	s.reconcileAll(ctx)
	if calls := fc.callSnap(); len(calls) != 0 {
		t.Fatalf("a spacing variant of %s drove a real council write: %v", reg, calls)
	}
}

// TestFailStreakClearsWithoutATarget (F4, I8): a busy/failing episode that ends by
// the target becoming UNRESOLVABLE (the rostered car was deleted, which cascades
// its rules away) has still ended. The old gate only cleared the streak when a
// target resolved, so the counter stayed inflated permanently — and a single
// transient blip weeks later landed straight on the notify threshold and took the
// maximum 30-minute backoff on the first failure of a fresh episode.
func TestFailStreakClearsWithoutATarget(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "streak@example.com"
	pid, _ := seedActivePermit(t, st, owner, "streak-1", "ROSTER1", "OLD999")

	fc := &fakeCouncil{setErr: parking.ErrCouncilBusy}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})

	// Build a real episode: several consecutive blocked ticks.
	for i := 0; i < 4; i++ {
		s.reconcileAll(ctx)
	}
	p, err := st.GetPermit(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.FailStreak == 0 {
		t.Fatal("blocked ticks should have built a fail streak")
	}

	// The episode ends the other way: the car is deleted, so there is no target at
	// all (weekly_rule cascades with the vehicle).
	vehicles, err := st.ListVehiclesFor(ctx, owner)
	if err != nil || len(vehicles) != 1 {
		t.Fatalf("expected one saved vehicle, got %d (err=%v)", len(vehicles), err)
	}
	if err := st.DeleteVehicle(ctx, owner, vehicles[0].ID); err != nil {
		t.Fatal(err)
	}
	fc.setErr = nil
	s.reconcileAll(ctx)

	p, err = st.GetPermit(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.FailStreak != 0 {
		t.Fatalf("fail streak = %d, want 0: a settled permit with no target still ends the episode", p.FailStreak)
	}
	if s.retryDeferred(pid, time.Now()) {
		t.Fatal("a settled permit must not stay inside its stretched retry window")
	}
}

// TestUnresolvableTargetIsReported (F8): a schedule that points at a car we cannot
// turn into a plate used to be a fully silent no-op — no log, no activity row, no
// notification — while the permit kept whatever plate it had. It must be reported,
// and reported ONCE: the condition does not clear itself, so a per-tick alert would
// be one people learn to ignore.
func TestUnresolvableTargetIsReported(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	const owner = "gap@example.com"
	seedSession(t, st, owner)
	pid, err := st.UpsertPermit(ctx, owner, "gap-1", "14", "Permit")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPermitActive(ctx, pid, "STALE11"); err != nil {
		t.Fatal(err)
	}
	// A booking on this permit that points at ANOTHER owner's vehicle: reconcile
	// resolves vehicles per-owner precisely so a foreign id can never yield a plate,
	// which is exactly the state this reports.
	foreign, err := st.CreateVehicle(ctx, "someone@else.example", "BBB222", "Their car")
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(6 * time.Hour)
	if _, err := st.CreateOverride(ctx, pid, foreign, time.Now().Add(-time.Hour), &end, "someone@else.example"); err != nil {
		t.Fatal(err)
	}

	fc := &fakeCouncil{}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, time.UTC, Options{Notifier: nf})
	s.reconcileAll(ctx)
	time.Sleep(40 * time.Millisecond)

	if calls := fc.callSnap(); len(calls) != 0 {
		t.Fatalf("an unresolvable target must not reach the council: %v", calls)
	}
	logs, err := st.ListApplyLogFor(ctx, owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Status != "error" || logs[0].Registration != "STALE11" {
		t.Fatalf("expected one error row naming the plate still on the permit, got %+v", logs)
	}
	out := nf.outcomeSnap()
	if len(out) != 1 || out[0].OK || out[0].CurrentReg != "STALE11" || out[0].Action == "" {
		t.Fatalf("expected one actionable notice naming what is still on the permit, got %+v", out)
	}
	// Every later tick in the same state stays silent.
	for i := 0; i < 3; i++ {
		s.reconcileAll(ctx)
	}
	time.Sleep(40 * time.Millisecond)
	if logs, _ := st.ListApplyLogFor(ctx, owner, 10); len(logs) != 1 {
		t.Fatalf("the notice repeated: %d activity rows", len(logs))
	}
	if n := len(nf.outcomeSnap()); n != 1 {
		t.Fatalf("the notice repeated: %d notifications", n)
	}
}

// TestExpiryWarningRunsToTheEndOfTheLastDay (F7): EndDate is a zoneless council
// date parsed as UTC midnight and is the INCLUSIVE last valid day, so comparing
// `now` against the bare instant closed the warning window at ~10-11am local on the
// permit's final valid day — while the permit was still live and still needed its
// plate kept right. A notifier that was down through the lead window would then
// never warn at all.
func TestExpiryWarningRunsToTheEndOfTheLastDay(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	const owner = "lastday@example.com"
	seedSession(t, st, owner)
	seedSchedule(t, st, owner)
	cpid := "perm-" + owner

	// The permit's last valid day is TODAY in Melbourne, as the council reports it:
	// a zoneless date, i.e. UTC midnight — which is 10am local. "A permit whose last
	// valid day is today still gets its warning" must hold at every hour of the day;
	// the old bare-instant comparison broke it from 10am local onward, so this test
	// discriminates in the afternoon and evening and asserts the invariant always.
	today := time.Now().In(loc)
	endDate := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)

	fc := &fakeCouncil{permits: []parking.PermitInfo{{CouncilPermitID: cpid, Status: "Granted", EndDate: endDate}}}
	nf := &fakeNotifier{on: true}
	s := New(st, fc, loc, Options{SessionMaxAge: 90 * 24 * time.Hour, WarmInterval: time.Nanosecond,
		DriftInterval: time.Nanosecond, ExpiryLead: 14 * 24 * time.Hour, Notifier: nf})
	time.Sleep(2 * time.Millisecond)
	s.keepWarm(ctx)

	if len(nf.expiries) != 1 {
		t.Fatalf("a permit still valid until midnight tonight got %d expiry warnings, want 1", len(nf.expiries))
	}
}
