package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// TestFailedLinkKeepsTheCurrentTenant: "connect another area" with a rejected
// password must not move the account's current tenant to the area it never
// linked — the dashboard would then show onboarding for it while the real area is
// linked and running. The choice is recorded only once the login succeeds.
func TestFailedLinkKeepsTheCurrentTenant(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "lf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	box, _ := secretbox.New(bytes.Repeat([]byte{3}, 32))
	regPath := filepath.Join(t.TempDir(), "councils.json")
	if err := os.WriteFile(regPath, []byte(`{"tenants":[
	  {"id":"stonnington","name":"City of Stonnington","short":"Stonnington","connector":"fake","model":"swap","timezone":"Australia/Melbourne","policy":{"visitor_word":"visitor","resident_word":"resident"},"enabled":true},
	  {"id":"othertown","name":"Othertown Council","short":"Othertown","connector":"fake","model":"swap","timezone":"Australia/Perth","policy":{"visitor_word":"visitor"},"enabled":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := tenant.Load(config.CouncilConfig{}, regPath)
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultTenant = reg.Default.ID
	clients := map[string]*parking.Client{}
	for _, c := range reg.Enabled() {
		f := fake.New()
		f.ApplyDelay = 0
		f.RejectPassword = "wrong"
		clients[c.ID] = parking.NewClientFor(c.ID, f, st, box, nil)
	}
	mux := tenant.NewMux(st, clients)
	s := &Server{
		cfg:   &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store: st, box: box, terms: loadTerms(""), tenant: mux, registry: reg,
		sched: scheduler.New(st, mux, time.UTC, scheduler.Options{}),
	}
	ctx := context.Background()
	const user = "home@example.com"
	if err := st.RecordConsent(ctx, user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	// Linked and current in stonnington.
	if rr := s.doReq(http.MethodPost, "/tenant/link", user, "https://app.example.com", url.Values{"portal_password": {"ok"}, "tenant_id": {"stonnington"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("link: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if id, _ := st.TenantIDFor(ctx, user); id != "stonnington" {
		t.Fatalf("current after link = %q", id)
	}
	// A rejected attempt at othertown leaves the account where it was.
	if rr := s.doReq(http.MethodPost, "/tenant/link", user, "https://app.example.com", url.Values{"portal_password": {"wrong"}, "tenant_id": {"othertown"}}); rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == "/schedule?linked=1" {
		t.Fatalf("rejected password reported as linked")
	}
	if id, _ := st.TenantIDFor(ctx, user); id != "stonnington" {
		t.Fatalf("current tenant moved to %q on a FAILED link", id)
	}
	if sessions, _ := st.ListTenantSessionsFor(ctx, user); len(sessions) != 1 || sessions[0].TenantID != "stonnington" {
		t.Fatalf("sessions after failed link = %+v", sessions)
	}
	// A successful one does switch.
	if rr := s.doReq(http.MethodPost, "/tenant/link", user, "https://app.example.com", url.Values{"portal_password": {"ok"}, "tenant_id": {"othertown"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("second link: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if id, _ := st.TenantIDFor(ctx, user); id != "othertown" {
		t.Fatalf("current after a successful second link = %q", id)
	}
}
