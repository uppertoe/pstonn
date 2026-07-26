package scheduler

import (
	"context"
	"errors"
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
	refreshed    []string
	refreshErr   error
	reconnected  []string
	reconnectErr error // defaults to ErrNoSavedPassword via reconnectSet
	reconnectSet bool
	permits      []parking.PermitInfo
	permitsErr   error
	setCalls     []string // council_permit_id per SetVehicle call
	setErr       error
}

func (f *fakeCouncil) SetVehicle(_ context.Context, _ string, p model.Permit, _ string) error {
	f.setCalls = append(f.setCalls, p.CouncilPermitID)
	return f.setErr
}
func (f *fakeCouncil) CurrentVehicle(context.Context, string, model.Permit) (string, error) {
	return "", nil
}
func (f *fakeCouncil) Refresh(_ context.Context, owner string) error {
	f.refreshed = append(f.refreshed, owner)
	return f.refreshErr
}
func (f *fakeCouncil) Reconnect(_ context.Context, owner string) error {
	f.reconnected = append(f.reconnected, owner)
	if !f.reconnectSet {
		return parking.ErrNoSavedPassword // no saved password by default
	}
	return f.reconnectErr
}
func (f *fakeCouncil) ListPermits(_ context.Context, owner string) ([]parking.PermitInfo, error) {
	return f.permits, f.permitsErr
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
	relinks       []string
	displaced     []string // guest emails told their car came off the permit
	expiries      []string // "owner:permitLabel" per expiry warning sent
	expiryDeliver int      // channels to report delivered (0 => 1)
}

func (f *fakeNotifier) Enabled() bool         { return f.on }
func (f *fakeNotifier) AdminConfigured() bool { return f.admin }
func (f *fakeNotifier) SendRenewalReminder(to string, deadline time.Time, url string) error {
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
	f.adminNotes = append(f.adminNotes, subject)
	return nil
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
		name            string
		linked, updated time.Time
		want            warmAction
	}{
		{"fresh, in bound", now.Add(-24 * time.Hour), now.Add(-10 * time.Minute), warmSkip},
		{"stale, in bound", now.Add(-24 * time.Hour), now.Add(-46 * time.Minute), warmRenew},
		{"exactly warm boundary", now.Add(-24 * time.Hour), now.Add(-warm), warmRenew},
		{"past re-link bound", now.Add(-91 * 24 * time.Hour), now.Add(-1 * time.Minute), warmRetire},
		{"exactly at bound", now.Add(-maxAge), now.Add(-1 * time.Minute), warmRetire},
		{"unknown link time", time.Time{}, now.Add(-1 * time.Minute), warmRetire},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decideWarm(now, c.linked, c.updated, maxAge, warm); got != c.want {
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
		ExpiryLead: 14 * 24 * time.Hour, Notifier: nf})

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

	if len(fc.setCalls) != 1 || fc.setCalls[0] != "active-1" {
		t.Fatalf("SetVehicle calls = %v, want [active-1] only (expired skipped)", fc.setCalls)
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

	if len(fc.reconnected) != 1 {
		t.Fatalf("expected one reconnect attempt, got %v", fc.reconnected)
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
	time.Sleep(60 * time.Millisecond) // async re-link notify
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

	if sent := fn.sentSnap(); len(sent) != 1 {
		t.Fatalf("expected exactly one reminder, got %d", len(sent))
	} else if sent[0].to != "soon@example.com" || !strings.Contains(sent[0].url, "/council/confirm?token=") {
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
	// verified in the store test with a backdated link time).
	owner, err := st.ConfirmSession(ctx, cs.ConfirmToken)
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

	s.deferRetry(7, 5)
	s.Kick()
	if s.retryDeferred(7, now) {
		t.Fatal("Kick must clear deferrals: the user may have just fixed the cause")
	}
}
