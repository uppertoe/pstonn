package notify

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// TestMessagesNameThePermitsTenant: a message about one permit or one session
// resolves THAT tenant (the council named, the portal linked), never the
// account's current selection; account-level mail (an invite, a nudge) resolves
// the account's current tenant ("" — the resolver decides).
func TestMessagesNameThePermitsTenant(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "two@example.com"
	if err := st.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	var asked []string
	svc := New(st, mailer.New(config.SMTPConfig{}), "", "", "https://p.example", "", "", time.UTC, nil, nil)
	svc.TenantFor = func(_ context.Context, o, tenantID string) *tenant.Tenant {
		asked = append(asked, tenantID)
		return nil
	}
	// Permit-scoped: the outcome carries the permit's tenant.
	_, _ = svc.NotifyApply(ctx, ApplyOutcome{Owner: owner, TenantID: "othertown", PermitLabel: "VPP1", Reg: "ABC123", OK: true})
	_ = svc.EnqueueApply(ctx, ApplyOutcome{Owner: owner, TenantID: "othertown", PermitLabel: "VPP1", Reg: "ABC123", OK: false})
	svc.NotifyPermitExpiry(ctx, owner, "othertown", "VPP1", time.Now().Add(14*24*time.Hour))
	// Session-scoped: the session's tenant.
	svc.NotifyRelinkRequired(ctx, owner, "othertown")
	svc.NotifyReconnectStalled(ctx, owner, "othertown")
	for i, got := range asked {
		if got != "othertown" {
			t.Errorf("call %d resolved tenant %q, want the permit's/session's \"othertown\"", i, got)
		}
	}
	if len(asked) < 5 {
		t.Fatalf("only %d tenant resolutions for 5 permit/session messages", len(asked))
	}
	// Account-level: no tenant named; the resolver falls back to the account.
	asked = nil
	_ = svc.SendInvite(ctx, "friend@example.com", owner)
	_ = svc.SendOnboardNudge(ctx, owner)
	for i, got := range asked {
		if got != "" {
			t.Errorf("account-level call %d named tenant %q", i, got)
		}
	}
}

// TestTenantOfFallsBackSafely: an unknown id (a tenant removed from the
// registry) and a nil resolver both land on the default tenant rather than
// panicking mid-send.
func TestTenantOfFallsBackSafely(t *testing.T) {
	svc := &Service{TenantFor: func(context.Context, string, string) *tenant.Tenant { return nil }}
	if c := svc.tenantOf(context.Background(), "x@example.com", "gone"); c.Name != tenant.Default().Name {
		t.Fatalf("unknown tenant resolved to %q", c.Name)
	}
	if c := (&Service{}).tenantOf(context.Background(), "x@example.com", "anything"); c.Links.Portal == "" {
		t.Fatal("nil resolver gave no portal link")
	}
}
