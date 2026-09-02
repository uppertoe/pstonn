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

// TestPartialDeliveryRetrySkipsReachedMembers: when NotifyApply reaches one
// member and not another, the scheduler leaves its durable key unwritten and
// retries the whole outcome next pass — the missed member may be the one who
// parks the car. But the retry used to go to EVERYONE again, so the member who
// was reached got the same notice on every attempt until the other's mail came
// good. With the caller's outcome Key set, a reached member is remembered and
// the retry goes only to the rest; once all are reached the call reports a
// clean delivery so the scheduler can record it.
func TestPartialDeliveryRetrySkipsReachedMembers(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const primary, secondary = "primary@example.com", "member1@example.com"
	if err := st.AddMember(ctx, primary, secondary); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{primary, secondary} {
		if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: m, EmailEnabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	sent := map[string]int{}
	failSecondary := true
	m.SetSendHook(func(to, _, _ string, _ mailer.Options) error {
		if to == secondary && failSecondary {
			return errors.New("dial tcp: connection refused")
		}
		sent[to]++
		return nil
	})
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)
	o := ApplyOutcome{Owner: primary, PermitLabel: "VPP1", Reg: "ABC123", OK: false, CurrentReg: "OLD1", Reason: "r", Action: "a", Key: "error|ABC123|r|2026-09-02"}

	// First attempt: the primary is reached, the secondary is not.
	if n, err := svc.NotifyApply(ctx, o); n != 1 || err == nil {
		t.Fatalf("first attempt = (%d, %v), want a partial delivery (1, error)", n, err)
	}
	// Retry, still failing for the secondary: the primary must NOT be mailed again.
	if n, err := svc.NotifyApply(ctx, o); n != 1 || err == nil {
		t.Fatalf("second attempt = (%d, %v), want still partial", n, err)
	}
	if sent[primary] != 1 {
		t.Fatalf("the reached member was mailed %d times across the retry, want 1", sent[primary])
	}
	// The secondary's mail comes good: only they are sent to, and the outcome now
	// reports everyone reached with no error, so the scheduler records it.
	failSecondary = false
	if n, err := svc.NotifyApply(ctx, o); n != 2 || err != nil {
		t.Fatalf("third attempt = (%d, %v), want (2, nil): both reached, one of them remembered", n, err)
	}
	if sent[primary] != 1 || sent[secondary] != 1 {
		t.Fatalf("sends = primary %d, secondary %d; want exactly one each", sent[primary], sent[secondary])
	}

	// A DIFFERENT outcome key about the same plate (the urgent escalation of a
	// soft notice) is a new message, not a retry: the primary hears it.
	o.Key = "busy-blocked|ABC123|2026-09-02"
	if n, err := svc.NotifyApply(ctx, o); n != 2 || err != nil {
		t.Fatalf("new key = (%d, %v), want (2, nil)", n, err)
	}
	if sent[primary] != 2 {
		t.Fatalf("a distinct outcome key was deduped against the earlier one: primary sends = %d, want 2", sent[primary])
	}
	// And with no Key there is no memory — the one-shot callers' behaviour.
	o.Key = ""
	_, _ = svc.NotifyApply(ctx, o)
	_, _ = svc.NotifyApply(ctx, o)
	if sent[primary] != 4 {
		t.Fatalf("keyless outcomes must not be deduped: primary sends = %d, want 4", sent[primary])
	}
}

// TestReachedMemoryIsPerPermitAndForgottenOnceComplete: the reached-member memory
// exists to finish a PARTIAL delivery. Once everyone is reached it must be
// forgotten, so a later outcome that legitimately carries the same key (the
// roster re-applying A>B after the resident reverted the plate at the portal)
// is delivered again rather than swallowed. And it is scoped to a permit: two
// permits on one account can share an outcome key (a tenant-wide "council
// unavailable") and each is its own notice.
func TestReachedMemoryIsPerPermitAndForgottenOnceComplete(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const primary = "primary@example.com"
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: primary, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	sent := 0
	m.SetSendHook(func(_, _, _ string, _ mailer.Options) error { sent++; return nil })
	svc := New(st, m, "", "", "", "", "", time.UTC, []byte("test-unsub-key"), nil)

	o := ApplyOutcome{Owner: primary, PermitID: 1, PermitLabel: "VPP1", Reg: "ABC123", OK: true, Key: "success|OLD1>ABC123"}
	if n, err := svc.NotifyApply(ctx, o); n != 1 || err != nil {
		t.Fatalf("first delivery = (%d, %v), want (1, nil)", n, err)
	}
	// The same outcome recurs as a genuinely new event (the drift revert case).
	if n, err := svc.NotifyApply(ctx, o); n != 1 || err != nil {
		t.Fatalf("repeat after a complete delivery = (%d, %v), want (1, nil)", n, err)
	}
	if sent != 2 {
		t.Fatalf("sends after a completed delivery and a genuine repeat = %d, want 2", sent)
	}
	// A second permit with the identical key is its own notice.
	o2 := o
	o2.PermitID = 2
	o2.PermitLabel = "VPP2"
	if n, err := svc.NotifyApply(ctx, o2); n != 1 || err != nil {
		t.Fatalf("other permit = (%d, %v), want (1, nil)", n, err)
	}
	if sent != 3 {
		t.Fatalf("sends = %d, want 3: a different permit must not be deduped against the first", sent)
	}
}
