package scheduler

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// fakeCouncil records calls and returns configured errors, standing in for the
// real HTTP client.
type fakeCouncil struct {
	refreshed  []string
	refreshErr error
}

func (f *fakeCouncil) SetVehicle(context.Context, string, model.Permit, string) error { return nil }
func (f *fakeCouncil) Refresh(_ context.Context, owner string) error {
	f.refreshed = append(f.refreshed, owner)
	return f.refreshErr
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

	mu         sync.Mutex // guards the slices: notifications fire from goroutines
	sent       []sentMail
	applied    []appliedNote
	adminNotes []string
	relinks    []string
}

func (f *fakeNotifier) Enabled() bool         { return f.on }
func (f *fakeNotifier) AdminConfigured() bool { return f.admin }
func (f *fakeNotifier) SendRenewalReminder(to string, deadline time.Time, url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMail{to, url, deadline})
	return nil
}

func (f *fakeNotifier) NotifyApply(_ context.Context, owner, label, reg, source string, ok bool, detail string) (int, error) {
	f.mu.Lock()
	f.applied = append(f.applied, appliedNote{owner, reg, ok})
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

func (f *fakeNotifier) NotifyAdmin(_ context.Context, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adminNotes = append(f.adminNotes, subject)
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

// TestRecordApplyDedup: a repeated identical outcome (e.g. a failure recurring
// every tick) is logged and notified once, but a genuinely new outcome fires.
func TestRecordApplyDedup(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "u@example.com", "14576", "14", "1st Visitor Permit")
	p := model.Permit{ID: pid, Owner: "u@example.com", CouncilPermitID: "14576", Label: "1st Visitor Permit"}
	fn := &fakeNotifier{on: true}
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})

	// The notification dedup key is written after async delivery; production ticks
	// are a minute apart, so allow each delivery to land before the next outcome
	// (a sleep between calls emulates that cadence).
	s.recordApply(ctx, p, "AVS619", "override", "error", "boom")
	time.Sleep(60 * time.Millisecond)
	s.recordApply(ctx, p, "AVS619", "override", "error", "boom") // identical → suppressed
	time.Sleep(60 * time.Millisecond)
	s.recordApply(ctx, p, "AVS619", "override", "success", "") // new outcome → fires
	time.Sleep(60 * time.Millisecond)

	logs, _ := st.ListApplyLogFor(ctx, "u@example.com", 10)
	if len(logs) != 2 {
		t.Fatalf("apply_log rows = %d, want 2 (dup suppressed)", len(logs))
	}
	applied := fn.appliedSnap()
	if len(applied) != 2 {
		t.Fatalf("notifications = %d, want 2", len(applied))
	}
	if applied[0].ok || !applied[1].ok {
		t.Fatalf("expected [fail, success], got %+v", applied)
	}
}

// TestRecordApplyEscalatesWhenUserNotReached: when the user's channels all fail,
// the outcome is NOT marked delivered (so it retries), and the operator is
// alerted once. This is the anti-fine guarantee.
func TestRecordApplyEscalatesWhenUserNotReached(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	pid, _ := st.UpsertPermit(ctx, "u@example.com", "14576", "14", "Permit")
	p := model.Permit{ID: pid, Owner: "u@example.com", CouncilPermitID: "14576", Label: "Permit"}
	fn := &fakeNotifier{on: true, admin: true, deliverSet: true, deliver: 0} // user not reached
	s := New(st, &fakeCouncil{}, time.UTC, Options{Notifier: fn})

	s.recordApply(ctx, p, "AVS619", "override", "error", "boom")
	time.Sleep(60 * time.Millisecond)
	if n := len(fn.adminSnap()); n != 1 {
		t.Fatalf("admin escalations = %d, want 1 (user not reached)", n)
	}
	// Not marked delivered → an identical repeat is RE-attempted, not suppressed.
	s.recordApply(ctx, p, "AVS619", "override", "error", "boom")
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
