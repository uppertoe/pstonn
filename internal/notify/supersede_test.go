package notify

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestUrgentInlineSupersedesHeldSoftNotice: a soft "still updating" failure notice
// held for quiet hours must be cancelled when the act-now escalation for the SAME
// permit + plate + member is sent inline — otherwise the household gets the urgent
// notice now AND the reassuring one hours later, in confusing reverse order.
//
// It drives the REAL deferred path to queue the soft notice, so heldApplyTwins and
// enqueueSplit's per-channel key scheme cannot silently drift apart.
func TestUrgentInlineSupersedesHeldSoftNotice(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const owner = "owner@example.com"
	// A quiet-hours window that certainly covers "now" (starts this hour, spans two),
	// so a soft failure notice defers into the outbox instead of sending inline.
	h := time.Now().In(time.UTC).Hour()
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, QuietFrom: h, QuietUntil: (h + 2) % 24}); err != nil {
		t.Fatal(err)
	}

	var sent int
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	m.SetSendHook(func(to, subject, body string, o mailer.Options) error { sent++; return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("k"), nil)

	base := ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "WANT1", CurrentReg: "OLD1", OK: false, Reason: "r", Action: "a"}

	// 1. Soft (transient, not urgent) → held for quiet hours, nothing sent.
	soft := base
	soft.Transient = true
	soft.Key = "busy|WANT1|day"
	if _, err := svc.NotifyApply(ctx, soft); err != nil {
		t.Fatal(err)
	}
	if due, _ := st.DueOutbox(ctx, time.Now().Add(24*time.Hour), 10); len(due) != 1 {
		t.Fatalf("soft notice should be one held row, got %d", len(due))
	}
	if sent != 0 {
		t.Fatalf("soft notice must not send inline during quiet hours; sent=%d", sent)
	}

	// 2. The urgent escalation for the same permit+plate → sent inline once, and the
	//    held soft twin must be superseded so nothing arrives later.
	urg := base
	urg.Transient = true
	urg.Urgent = true
	urg.Key = "busy-blocked|WANT1|day"
	if _, err := svc.NotifyApply(ctx, urg); err != nil {
		t.Fatal(err)
	}
	if sent != 1 {
		t.Fatalf("urgent escalation should send inline exactly once; sent=%d", sent)
	}
	if due, _ := st.DueOutbox(ctx, time.Now().Add(24*time.Hour), 10); len(due) != 0 {
		t.Fatalf("held soft notice was not superseded by the urgent escalation: %d rows remain", len(due))
	}
}

// TestThrottledUrgentStillSupersedesHeldSoft: the supersede must run even when the
// urgent escalation is dropped by the per-recipient daily cap. Otherwise a member
// who has hit their urgent budget keeps the held soft twin, which then delivers the
// reassuring notice after the (earlier) urgents — the reverse-order double again.
func TestThrottledUrgentStillSupersedesHeldSoft(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const owner = "owner@example.com"
	h := time.Now().In(time.UTC).Hour()
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, QuietFrom: h, QuietUntil: (h + 2) % 24}); err != nil {
		t.Fatal(err)
	}

	var sent int
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	m.SetSendHook(func(to, subject, body string, o mailer.Options) error { sent++; return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("k"), nil)

	// Exhaust this member's per-recipient urgent cap with escalations for OTHER
	// permits (distinct keys, so they never touch THIS permit's held soft twin).
	for i := 0; i < 2; i++ {
		o := ApplyOutcome{Owner: owner, PermitLabel: fmt.Sprintf("OTHER%d", i), Reg: "ZZ", OK: false, Transient: true, Urgent: true, Reason: "r", Action: "a"}
		if _, err := svc.NotifyApply(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	// Hold a soft notice for THIS permit.
	soft := ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "WANT1", OK: false, Transient: true, Reason: "r", Action: "a", Key: "busy|WANT1|day"}
	if _, err := svc.NotifyApply(ctx, soft); err != nil {
		t.Fatal(err)
	}
	if due, _ := st.DueOutbox(ctx, time.Now().Add(24*time.Hour), 10); len(due) != 1 {
		t.Fatalf("held soft not queued: %d", len(due))
	}
	sentBefore := sent

	// The urgent escalation for THIS permit is now past the cap → throttled (not
	// sent), but it must STILL supersede the held soft twin.
	urg := soft
	urg.Urgent = true
	urg.Key = "busy-blocked|WANT1|day"
	if _, err := svc.NotifyApply(ctx, urg); err != nil {
		t.Fatal(err)
	}
	if sent != sentBefore {
		t.Fatalf("urgent should have been throttled by the cap, but sent %d->%d", sentBefore, sent)
	}
	if due, _ := st.DueOutbox(ctx, time.Now().Add(24*time.Hour), 10); len(due) != 0 {
		t.Fatalf("a throttled urgent did not supersede the held soft twin: %d rows remain", len(due))
	}
}
