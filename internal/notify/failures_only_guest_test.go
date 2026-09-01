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

// FailuresOnly ("only tell me about problems") mutes the household's OWN
// schedule running — the roster and their one-off bookings — but must NOT mute a
// change made by someone else: a guest link or an approved door-QR request is a
// third party touching the permit, which the household should still hear about.
func TestFailuresOnlyMutesScheduleNotGuest(t *testing.T) {
	ctx := context.Background()
	m := mailer.New(config.SMTPConfig{Host: "smtp.test", Port: 587, From: "p.stonn <no-reply@stonn.org>"})
	const owner = "owner@example.com"

	newSvc := func(t *testing.T) (*Service, *store.Store) {
		st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true, FailuresOnly: true}); err != nil {
			t.Fatal(err)
		}
		return New(st, m, "", "", "", "", "", time.UTC, []byte("k"), nil), st
	}

	due := func(st *store.Store) int {
		rows, err := st.DueOutbox(ctx, time.Now().UTC().Add(time.Hour), 10)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}

	for _, src := range []string{"roster", "override"} {
		svc, st := newSvc(t)
		if err := svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "ABC123", Source: src, OK: true}); err != nil {
			t.Fatal(err)
		}
		if n := due(st); n != 0 {
			t.Fatalf("source %q: failures-only should mute the schedule, got %d queued", src, n)
		}
	}
	for _, src := range []string{"guest", "doorqr"} {
		svc, st := newSvc(t)
		if err := svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, PermitLabel: "VPP1", Reg: "GST123", Source: src, OK: true}); err != nil {
			t.Fatal(err)
		}
		if n := due(st); n != 1 {
			t.Fatalf("source %q: a third-party change must notify even with failures-only, got %d queued", src, n)
		}
	}
}
