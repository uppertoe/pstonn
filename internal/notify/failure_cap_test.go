package notify

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestFailureNoticesAreCappedPerRecipient: the scheduler dedups an outcome per
// permit but remembers only the last delivered key, so an outage whose outcome
// ping-pongs between families could email on every capped retry. A council
// outage must never become a stream of mail: a person gets at most three soft
// failure notices a day across every permit, urgent ones have their own small
// budget so they cannot be crowded out, and successes are never throttled.
func TestFailureNoticesAreCappedPerRecipient(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "primary@example.com"
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	sent := 0
	m.SetSendHook(func(_, _, _ string, _ mailer.Options) error { sent++; return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	fail := func(i int, urgent bool) ApplyOutcome {
		// Distinct keys and permits: every one is a legitimately new outcome to the
		// scheduler, which is exactly the shape the cap exists for.
		return ApplyOutcome{Owner: owner, PermitID: int64(i), PermitLabel: fmt.Sprintf("VPP%d", i), Reg: "ABC123",
			OK: false, CurrentReg: "OLD1", Reason: "r", Action: "a", Transient: true, Urgent: urgent,
			Key: fmt.Sprintf("error|ABC123|day|%d", i)}
	}
	for i := 0; i < 6; i++ {
		if n, err := svc.NotifyApply(ctx, fail(i, false)); n != 1 || err != nil {
			t.Fatalf("soft failure %d = (%d, %v); a throttled notice must still count as delivered so the scheduler stops retrying it", i, n, err)
		}
	}
	if sent != 3 {
		t.Fatalf("soft failure emails = %d, want 3 (the daily cap)", sent)
	}
	// Urgent notices ride their own budget.
	for i := 10; i < 13; i++ {
		if n, err := svc.NotifyApply(ctx, fail(i, true)); n != 1 || err != nil {
			t.Fatalf("urgent failure %d = (%d, %v)", i, n, err)
		}
	}
	if sent != 5 {
		t.Fatalf("emails after three urgent notices = %d, want 5 (two urgent allowed)", sent)
	}
	// A success is never throttled: it is the news the person is waiting for.
	ok := ApplyOutcome{Owner: owner, PermitID: 99, PermitLabel: "VPP", Reg: "ABC123", OK: true, Key: "success|ABC123"}
	if n, err := svc.NotifyApply(ctx, ok); n != 1 || err != nil {
		t.Fatalf("success = (%d, %v)", n, err)
	}
	if sent != 6 {
		t.Fatalf("emails after a success = %d, want 6", sent)
	}
}

// TestDeferredFailureNoticesDoNotSpendTheCap: the cap is checked after the
// quiet-hours deferral, so a notice that goes to the outbox (where it is deduped)
// costs nothing. An overnight outage re-attempting every half hour used to burn
// the whole day's allowance on notices that never went anywhere, so the first
// daytime failure was already throttled.
func TestDeferredFailureNoticesDoNotSpendTheCap(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "primary@example.com"
	// A quiet window that covers "now" in the service's zone (UTC below).
	h := time.Now().UTC().Hour()
	quiet := store.NotifyPref{Owner: owner, EmailEnabled: true, QuietFrom: (h + 23) % 24, QuietUntil: (h + 2) % 24}
	if err := st.SetNotifyPref(ctx, quiet); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	sent := 0
	m.SetSendHook(func(_, _, _ string, _ mailer.Options) error { sent++; return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	fail := func(i int) ApplyOutcome {
		return ApplyOutcome{Owner: owner, PermitID: int64(i), PermitLabel: fmt.Sprintf("VPP%d", i), Reg: "ABC123",
			OK: false, CurrentReg: "OLD1", Reason: "r", Action: "a", Transient: true, Key: fmt.Sprintf("error|ABC123|day|%d", i)}
	}
	// Six overnight attempts: all deferred to the outbox, none sent, none throttled.
	for i := 0; i < 6; i++ {
		if n, err := svc.NotifyApply(ctx, fail(i)); n != 1 || err != nil {
			t.Fatalf("deferred failure %d = (%d, %v), want (1, nil)", i, n, err)
		}
	}
	if sent != 0 {
		t.Fatalf("emails during quiet hours = %d, want 0", sent)
	}
	// Morning: quiet hours off. The day's budget is still whole.
	quiet.QuietFrom, quiet.QuietUntil = 0, 0
	if err := st.SetNotifyPref(ctx, quiet); err != nil {
		t.Fatal(err)
	}
	for i := 10; i < 14; i++ {
		if n, err := svc.NotifyApply(ctx, fail(i)); n != 1 || err != nil {
			t.Fatalf("daytime failure %d = (%d, %v)", i, n, err)
		}
	}
	if sent != 3 {
		t.Fatalf("daytime failure emails = %d, want 3: the deferred ones must not have spent the cap", sent)
	}
}

// TestResolvingSuccessReachesFailuresOnlyMembers: a member on "only tell me about
// problems" heard the problem, so they hear that it is over — a success flagged
// as resolving a failure episode is not muted for them; an ordinary roster
// success still is.
func TestResolvingSuccessReachesFailuresOnlyMembers(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "primary@example.com"
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, FailuresOnly: true}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	sent := 0
	m.SetSendHook(func(_, _, _ string, _ mailer.Options) error { sent++; return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	plain := ApplyOutcome{Owner: owner, PermitID: 1, PermitLabel: "VPP", Reg: "ABC123", Source: "roster", OK: true, Key: "success|A>B"}
	if n, err := svc.NotifyApply(ctx, plain); n != -1 || err != nil {
		t.Fatalf("plain roster success to a failures-only member = (%d, %v), want (-1, nil): muted", n, err)
	}
	resolving := plain
	resolving.ResolvesFailure = true
	resolving.Key = "success|A>B|resolved"
	if n, err := svc.NotifyApply(ctx, resolving); n != 1 || err != nil {
		t.Fatalf("resolving success = (%d, %v), want (1, nil)", n, err)
	}
	if sent != 1 {
		t.Fatalf("emails = %d, want exactly the resolving one", sent)
	}
}

// TestDriftNoticeIsSoft: the "changed at the council directly" notice honours
// quiet hours and skips members who only hear about problems, and a removal is
// worded as a removal.
func TestDriftNoticeIsSoft(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner, quietMember, problemsOnly = "primary@example.com", "quiet@example.com", "problems@example.com"
	for _, m := range []string{quietMember, problemsOnly} {
		if err := st.AddMember(ctx, owner, m); err != nil {
			t.Fatal(err)
		}
	}
	h := time.Now().UTC().Hour()
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: quietMember, EmailEnabled: true, QuietFrom: (h + 23) % 24, QuietUntil: (h + 2) % 24}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: problemsOnly, EmailEnabled: true, FailuresOnly: true}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)
	if err := svc.NotifyDriftChanged(ctx, owner, "", "Visitor Permit", "ABC123"); err != nil {
		t.Fatal(err)
	}
	rows, err := st.DueOutbox(ctx, time.Now().Add(48*time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	var to []string
	for _, r := range rows {
		to = append(to, r.Recipients...)
		if !strings.Contains(r.Body, "changed to ABC123 at the council directly") || !strings.Contains(r.Body, "p.stonn didn't make this change") {
			t.Fatalf("unexpected body: %q", r.Body)
		}
	}
	sort.Strings(to)
	if want := []string{owner, quietMember}; !reflect.DeepEqual(to, want) {
		t.Fatalf("recipients = %v, want %v (problems-only member skipped)", to, want)
	}
	// Only the owner's row is due now; the quiet-hours member's waits for the window.
	dueNow, err := st.DueOutbox(ctx, time.Now(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(dueNow) != 1 || dueNow[0].Recipients[0] != owner {
		t.Fatalf("rows due now = %d, want just the owner's (the quiet-hours member's is held)", len(dueNow))
	}
	// A removal is worded as a removal.
	if err := svc.NotifyDriftChanged(ctx, owner, "", "Visitor Permit", ""); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.DueOutbox(ctx, time.Now().Add(48*time.Hour), 50)
	found := false
	for _, r := range rows {
		if strings.Contains(r.Body, "was removed at the council directly") {
			found = true
		}
	}
	if !found {
		t.Fatalf("removal wording not queued")
	}
}

// TestDriverFailedNoticeCopy: the driver's notice names the cause the way the
// household's does, and is capped per recipient.
func TestDriverFailedNoticeCopy(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)
	if err := svc.NotifyDriverFailed(ctx, "o@example.com", "", "nanny@example.com", "AAA111", "#123456", true); err != nil {
		t.Fatal(err)
	}
	if err := svc.NotifyDriverFailed(ctx, "o@example.com", "", "nanny@example.com", "BBB222", "#123456", false); err != nil {
		t.Fatal(err)
	}
	rows, err := st.DueOutbox(ctx, time.Now().Add(time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("queued = %d, want 2", len(rows))
	}
	bodies := rows[0].Body + "\n" + rows[1].Body
	for _, want := range []string{"Your car AAA111 couldn't be put on the", "the council's system is down right now", "Your car BBB222 couldn't be put on the", "p.stonn couldn't update the permit", "It may not be covered right now"} {
		if !strings.Contains(bodies, want) {
			t.Fatalf("driver notice missing %q in:\n%s", want, bodies)
		}
	}
	// Third of the day is throttled (cap is 2).
	if err := svc.NotifyDriverFailed(ctx, "o@example.com", "", "nanny@example.com", "CCC333", "", false); err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.DueOutbox(ctx, time.Now().Add(time.Hour), 50); len(rows) != 2 {
		t.Fatalf("queued after the cap = %d, want still 2", len(rows))
	}
}
