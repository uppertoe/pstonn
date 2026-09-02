package notify

import (
	"context"
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
