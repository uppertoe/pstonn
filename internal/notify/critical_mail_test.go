package notify

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestCriticalMailSurvivesUnsubscribe: a self-service unsubscribe (which a mail
// scanner can trigger via the RFC 8058 one-click POST without the user knowing)
// used to silence EVERY notification, including "act now or someone gets a
// fine". Critical mail must pass the unsubscribe suppression; a bounce or a
// complaint must still block everything — those addresses are dead or asked the
// provider to stop, and mailing them damages the domain for every user.
func TestCriticalMailSurvivesUnsubscribe(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// A configured-but-unreachable mailer: the suppression gate runs before the
	// dial, so ErrSuppressed vs any-other-error is exactly the decision under test.
	m := mailer.New(config.SMTPConfig{Host: "smtp.invalid", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"))

	const addr = "muted@example.com"
	if err := st.SuppressAddress(ctx, addr, store.SuppressUnsubscribed, "one-click"); err != nil {
		t.Fatal(err)
	}

	if err := svc.sendEmail(ctx, addr, "routine", "body", reasonAccount); !errors.Is(err, ErrSuppressed) {
		t.Fatalf("routine mail to an unsubscribed address must be suppressed, got %v", err)
	}
	if err := svc.sendEmailCritical(ctx, addr, "critical", "body", reasonAccount); errors.Is(err, ErrSuppressed) {
		t.Fatal("critical mail must pass a self-service unsubscribe, but was suppressed")
	}

	// A later bounce upgrades the row (strongest reason wins) and blocks even
	// critical mail: the mailbox is dead, and sending anyway only burns reputation.
	if err := st.SuppressAddress(ctx, addr, store.SuppressBounce, "550 no such user"); err != nil {
		t.Fatal(err)
	}
	if err := svc.sendEmailCritical(ctx, addr, "critical", "body", reasonAccount); !errors.Is(err, ErrSuppressed) {
		t.Fatalf("critical mail to a BOUNCED address must stay suppressed, got %v", err)
	}

	const complainer = "spam-report@example.com"
	if err := st.SuppressAddress(ctx, complainer, store.SuppressComplaint, "abuse"); err != nil {
		t.Fatal(err)
	}
	if err := svc.sendEmailCritical(ctx, complainer, "critical", "body", reasonAccount); !errors.Is(err, ErrSuppressed) {
		t.Fatalf("critical mail to a COMPLAINED address must stay suppressed, got %v", err)
	}
}
