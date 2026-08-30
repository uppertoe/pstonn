package notify

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// rejectingMailer stands in for an SMTP server whose rejection echoes the
// recipient back, the way a real "user unknown" does. The mailer wraps that
// reply verbatim, so the address rides inside the error itself.
func rejectingMailer(t *testing.T) *mailer.Mailer {
	t.Helper()
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	m.SetSendHook(func(to, subject, body string, o mailer.Options) error {
		return fmt.Errorf("%w: 550 5.1.1 <%s>: Recipient address rejected: User unknown (%s)",
			mailer.ErrBadAddress, to, strings.ToUpper(to))
	})
	return m
}

// TestApplyErrorsRedactRecipients: the joined error NotifyApply returns is %v'd
// into the scheduler log, and it used to carry the member's address twice — once
// in our own "email <addr>:" prefix and once inside the server's reply. Neither
// copy may survive.
func TestApplyErrorsRedactRecipients(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner, member = "household@example.com", "member1@example.com"
	if err := st.AddMember(ctx, owner, member); err != nil {
		t.Fatal(err)
	}
	// Quiet hours off so both sends are inline, not queued.
	for _, e := range []string{owner, member} {
		if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: e, EmailEnabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(st, rejectingMailer(t), "", "", "", "", "", time.UTC, nil, nil)

	n, err := svc.NotifyApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "ABC123", OK: true, Source: "roster"})
	if n != 0 || err == nil {
		t.Fatalf("NotifyApply = %d, %v; want nobody reached and an error", n, err)
	}
	for _, addr := range []string{owner, member, strings.ToUpper(owner)} {
		if strings.Contains(err.Error(), addr) {
			t.Fatalf("NotifyApply's error names %s in full: %q", addr, err)
		}
	}
	if !strings.Contains(err.Error(), "h***@example.com") || !strings.Contains(err.Error(), "User unknown") {
		t.Fatalf("error should keep the redacted address and the server's diagnostic: %q", err)
	}

	// SendTest and NotifyDisconnected build the same kind of string.
	if err := svc.SendTest(ctx, owner); err == nil || strings.Contains(err.Error(), owner) {
		t.Fatalf("SendTest error = %v; must not name the address", err)
	}
	if err := svc.NotifyDisconnected(ctx, owner); err == nil || strings.Contains(err.Error(), owner) {
		t.Fatalf("NotifyDisconnected error = %v; must not name the address", err)
	}
}

// TestDeliverRedactsServerEcho: deliver's joined error becomes last_error, the
// dead-letter log line and the operator alert — three copies that outlive the
// notification — so the address the server echoed must be scrubbed from it.
func TestDeliverRedactsServerEcho(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc := New(st, rejectingMailer(t), "", "", "", "", "", time.UTC, nil, nil)
	const addr = "guest.one@example.com"
	lastErr, permanent := svc.deliver(ctx, store.OutboxItem{ID: 1, Recipients: []string{addr}, Subject: "S", Body: "B"})
	if lastErr == "" || !permanent {
		t.Fatalf("deliver = %q, permanent=%v; want a permanent failure", lastErr, permanent)
	}
	if strings.Contains(strings.ToLower(lastErr), addr) {
		t.Fatalf("last_error carries the recipient in full: %q", lastErr)
	}
	if !strings.Contains(lastErr, "g***@example.com") {
		t.Fatalf("last_error should still identify the mailbox in redacted form: %q", lastErr)
	}
	// The server's reply itself stays useful to the operator.
	if !errors.Is(mailer.ErrBadAddress, mailer.ErrPermanent) || !strings.Contains(lastErr, "550") {
		t.Fatalf("diagnostic lost: %q", lastErr)
	}
}

// TestQueuedCriticalMailSurvivesUnsubscribe is the outbox half of
// TestCriticalMailSurvivesUnsubscribe. A permit-expiry warning HELD for quiet
// hours used to be delivered by the routine sender, so the same message reached
// an unsubscribed member at 9pm and was silently dropped at 11pm. The row now
// carries its tier, and deliver honours it.
func TestQueuedCriticalMailSurvivesUnsubscribe(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "muted@example.com"
	if err := st.SuppressAddress(ctx, owner, store.SuppressUnsubscribed, "one-click"); err != nil {
		t.Fatal(err)
	}
	// Quiet hours cover the whole day, so the expiry warning is queued, not sent.
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, QuietFrom: 0, QuietUntil: 23}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	m.SetSendHook(func(to, subject, body string, o mailer.Options) error { sent = append(sent, to); return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, nil, nil)

	if n := svc.NotifyPermitExpiry(ctx, owner, "", "Visitor", time.Now().Add(14*24*time.Hour)); n != 1 {
		t.Fatalf("NotifyPermitExpiry queued for %d members, want 1", n)
	}
	if len(sent) != 0 {
		t.Fatalf("expiry warning was sent inline (%v); quiet hours should have queued it", sent)
	}
	due, err := st.DueOutbox(ctx, time.Now().Add(48*time.Hour), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %v, %v; want the one queued row", due, err)
	}
	if !due[0].Critical {
		t.Fatal("the queued expiry warning lost its safety tier on the way into the outbox")
	}
	if lastErr, _ := svc.deliver(ctx, due[0]); lastErr != "" {
		t.Fatalf("deliver: %s", lastErr)
	}
	if len(sent) != 1 || sent[0] != owner {
		t.Fatalf("critical queued mail to an unsubscribed member was not delivered: sent=%v", sent)
	}

	// A routine queued row to the same address is still muted.
	sent = nil
	if err := svc.enqueue(ctx, outMessage{Account: owner, Recipients: []string{owner}, Subject: "routine", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	due, _ = st.DueOutbox(ctx, time.Now(), 10)
	for _, it := range due {
		svc.deliver(ctx, it)
	}
	if len(sent) != 0 {
		t.Fatalf("routine queued mail reached an unsubscribed address: %v", sent)
	}

	// A guest-activation failure that needs action rides the same tier.
	if err := svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "Visitor", Reg: "ABC123", OK: false, Reason: "The council rejected the plate."}); err != nil {
		t.Fatal(err)
	}
	due, _ = st.DueOutbox(ctx, time.Now(), 10)
	var critical bool
	for _, it := range due {
		if it.Subject != "routine" {
			critical = critical || it.Critical
		}
	}
	if !critical {
		t.Fatal("an action-needed apply failure queued by EnqueueApply is not marked critical")
	}
}
