package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// These tests pin the registration STATE on every guest-authorised tenant write.
// Activation carried it; the door-QR approval and the revert dropped it, so an
// interstate visitor's plate went on under the tenant's home state — a plate the
// portal would happily accept and the ranger would happily fine. All three now
// go through applyGuestPlate; the assertions here are on what the PROVIDER was
// handed, which is the only place the state actually matters.

// recordingProvider is the fake portal plus a log of every SetVehicle it was
// asked for. The fake itself keeps only the plate, so the state has to be
// captured at the provider boundary.
type recordingProvider struct {
	*fake.Provider
	mu   sync.Mutex
	sets []provider.Vehicle
}

func (p *recordingProvider) SetVehicle(ctx context.Context, s *provider.Session, ref provider.PermitRef, v provider.Vehicle) error {
	p.mu.Lock()
	p.sets = append(p.sets, v)
	p.mu.Unlock()
	return p.Provider.SetVehicle(ctx, s, ref, v)
}

// last returns the most recent write, resetting the log so each step asserts
// only its own.
func (p *recordingProvider) last(t *testing.T) provider.Vehicle {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sets) == 0 {
		t.Fatal("no SetVehicle reached the provider")
	}
	v := p.sets[len(p.sets)-1]
	p.sets = nil
	return v
}

// newApplyRig is newTenantRig with the recording provider: the real generic
// client, the real mux and an (unstarted) scheduler, so AcquireApply and the
// authorisation re-check are on the path exactly as in production.
func newApplyRig(t *testing.T) (*Server, *recordingProvider) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "apply.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secretbox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	f := fake.New()
	f.ApplyDelay = 0 // a write lands immediately, so SetVehicle confirms synchronously
	rp := &recordingProvider{Provider: f}
	reg, err := tenant.Load(config.CouncilConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	st.DefaultTenant = reg.Default.ID
	client := parking.NewClientFor(reg.Default.ID, rp, st, box, nil)
	mux := tenant.NewMux(st, map[string]*parking.Client{reg.Default.ID: client})
	s := &Server{
		cfg:      &config.Config{DisplayLocation: time.UTC, PublicBaseURL: "https://p.example"},
		store:    st,
		box:      box,
		terms:    loadTerms(""),
		tenant:   mux,
		registry: reg,
		sched:    scheduler.New(st, mux, time.UTC, scheduler.Options{}),
	}
	return s, rp
}

func TestGuestApplyCarriesRegistrationState(t *testing.T) {
	s, rp := newApplyRig(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "lily@example.com"
	if err := s.tenant.Link(ctx, owner, "", owner, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
	// The fake portal's canned permit 90001 already shows SBX1AB; mirror that as
	// our stored belief so the activation captures it as the revert baseline.
	pid, err := s.store.UpsertPermit(ctx, owner, "90001", "14", "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetPermitActive(ctx, pid, "SBX1AB"); err != nil {
		t.Fatal(err)
	}
	// The pre-existing plate is also one of the owner's saved cars, registered
	// interstate — the only evidence of its state a revert can consult.
	if _, err := s.store.CreateVehicle(ctx, owner, "SBX1AB", "Dad", "QLD"); err != nil {
		t.Fatal(err)
	}
	nswVan, err := s.store.CreateVehicle(ctx, owner, "NSW123", "Van", "NSW")
	if err != nil {
		t.Fatal(err)
	}
	const raw = "nanny-token-for-state-test-0001"
	if _, err := s.store.CreateGuestGrant(ctx, owner, owner, pid, "Nanny", false, []int64{nswVan},
		[]store.GuestRecipient{{Email: "nanny@example.com", TokenHash: hashGuestToken(raw)}}); err != nil {
		t.Fatal(err)
	}

	t.Run("activation applies the saved car under its own state", func(t *testing.T) {
		w := s.postGuest("/g/"+raw, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(nswVan)}})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "NSW123 is now on the permit") {
			t.Fatalf("activation = %d %s", w.Code, excerpt(w.Body.String()))
		}
		if got := rp.last(t); got.Registration != "NSW123" || got.Region != "NSW" {
			t.Fatalf("provider was handed %+v, want NSW123/NSW", got)
		}
	})

	t.Run("revert restores the baseline under the saved car's state", func(t *testing.T) {
		w := s.postGuest("/g/"+raw+"/revert", "203.0.113.5", "", url.Values{})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "SBX1AB is back on the permit") {
			t.Fatalf("revert = %d %s", w.Code, excerpt(w.Body.String()))
		}
		if got := rp.last(t); got.Registration != "SBX1AB" || got.Region != "QLD" {
			t.Fatalf("provider was handed %+v, want SBX1AB/QLD (the revert used to send \"\")", got)
		}
	})

	t.Run("door-QR approval applies the state the visitor chose", func(t *testing.T) {
		const door = "door-token-for-state-test-00001"
		grantID, err := s.store.CreatePrintedGrant(ctx, owner, owner, pid, hashGuestToken(door), "sealed")
		if err != nil {
			t.Fatal(err)
		}
		w := s.postGuest("/g/"+door, "203.0.113.6", "", url.Values{"plate": {"act 999"}, "plate_state": {"act"}})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "ACT999") {
			t.Fatalf("door request = %d %s", w.Code, excerpt(w.Body.String()))
		}
		pending, err := s.store.ListPendingRequests(ctx, owner)
		if err != nil || len(pending) != 1 || pending[0].GrantID != grantID {
			t.Fatalf("pending = %+v (%v)", pending, err)
		}
		// The state survives the row: normalised to the tenant's code, not the
		// visitor's casing.
		if pending[0].Plate != "ACT999" || pending[0].State != "ACT" {
			t.Fatalf("request row = %q/%q, want ACT999/ACT", pending[0].Plate, pending[0].State)
		}
		out := s.runDecideRequest(httptest.NewRequest("POST", "/guests/requests/x/approve", nil), owner, owner, pending[0].ID, true)
		if out.kind != decideApplied {
			t.Fatalf("approve = kind %d (err %v), want decideApplied", out.kind, out.err)
		}
		if got := rp.last(t); got.Registration != "ACT999" || got.Region != "ACT" {
			t.Fatalf("provider was handed %+v, want ACT999/ACT (the approval used to send \"\")", got)
		}
		// And the override the scheduler would replay agrees with it.
		ovs, err := s.store.ListOverrides(ctx, pid, time.Now())
		if err != nil || len(ovs) == 0 {
			t.Fatalf("overrides after approval: %v %v", ovs, err)
		}
		if o := ovs[len(ovs)-1]; o.Registration != "ACT999" || o.State != "ACT" {
			t.Fatalf("override = %q/%q, want ACT999/ACT", o.Registration, o.State)
		}
	})

	t.Run("an unknown state collapses to the home state, never reaches the portal", func(t *testing.T) {
		const door2 = "door-token-for-state-test-00002"
		if _, err := s.store.CreatePrintedGrant(ctx, owner, owner, pid, hashGuestToken(door2), "sealed2"); err != nil {
			t.Fatal(err)
		}
		s.postGuest("/g/"+door2, "203.0.113.7", "", url.Values{"plate": {"ZZZ111"}, "plate_state": {"MARS"}})
		pending, err := s.store.ListPendingRequests(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range pending {
			if p.Plate == "ZZZ111" && p.State != "" {
				t.Fatalf("an invalid state was stored on the request: %q", p.State)
			}
		}
	})
}

// TestGuestRequestStateSurvivesOlderSchema: a database created before
// guest_request.state existed upgrades on first touch (the column is added from
// guests.go, not the shared migration list), so a door-QR flow on an existing
// deployment never fails with "no such column".
func TestGuestRequestStateColumnIsAddedLazily(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "u@example.com"
	pid, grantID, _ := seedDoorQR(t, s, owner, "Lazy")
	id, _, created, err := s.store.CreateGuestRequest(ctx, grantID, pid, owner, "VIC111", "VIC", "n1")
	if err != nil || !created {
		t.Fatalf("create: %v created=%v", err, created)
	}
	req, err := s.store.GuestRequestByID(ctx, id)
	if err != nil || req.State != "VIC" {
		t.Fatalf("read back = %+v (%v), want State VIC", req, err)
	}
}
