package fake

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

func login(t *testing.T, f *Provider) *provider.Session {
	t.Helper()
	s, err := f.Login(context.Background(), provider.Credentials{Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func waitFor(t *testing.T, f *Provider, id, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur, ok := f.Current(id); ok && cur == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	cur, _ := f.Current(id)
	t.Fatalf("permit %s shows %q, want %q", id, cur, want)
}

func TestNewSeedsPlatesAndValidCapabilities(t *testing.T) {
	f := New()
	if cur, ok := f.Current("90001"); !ok || cur == "" {
		t.Fatalf("canned permit should be seeded with a plate, got %q/%v", cur, ok)
	}
	if err := f.Capabilities().Validate(); err != nil {
		t.Fatal(err)
	}
	if f.ID() != ID || ID != "fake" {
		t.Fatalf("ID() = %q", f.ID())
	}
}

func TestLoginKnobs(t *testing.T) {
	ctx := context.Background()
	f := New()
	f.RejectPassword = "wrong"
	if _, err := f.Login(ctx, provider.Credentials{Username: "u", Password: "wrong"}); !errors.Is(err, provider.ErrLoginRejected) {
		t.Fatalf("RejectPassword: got %v, want ErrLoginRejected", err)
	}
	if _, err := f.Login(ctx, provider.Credentials{Username: "u", Password: "anything"}); err != nil {
		t.Fatalf("any other password signs in: %v", err)
	}
	boom := errors.New("boom")
	f.LoginErr = boom
	if _, err := f.Login(ctx, provider.Credentials{Username: "u", Password: "anything"}); !errors.Is(err, boom) {
		t.Fatalf("LoginErr: got %v", err)
	}
}

// ApplyDelay 0 lands the write inside the call; >0 reports transient until the
// fake portal's own record shows the plate.
func TestSetVehicleLandsImmediatelyWithZeroDelay(t *testing.T) {
	f := New()
	f.ApplyDelay = 0
	s := login(t, f)
	ref := provider.PermitRef{ID: "90001"}
	if err := f.SetVehicle(context.Background(), s, ref, provider.Vehicle{Registration: "NEW111"}); err != nil {
		t.Fatal(err)
	}
	v, err := f.CurrentVehicle(context.Background(), s, ref)
	if err != nil || v.Registration != "NEW111" {
		t.Fatalf("read back %+v, %v", v, err)
	}
}

func TestSetVehiclePendingThenLanded(t *testing.T) {
	f := New()
	f.ApplyDelay = 20 * time.Millisecond
	s := login(t, f)
	ref := provider.PermitRef{ID: "90001"}
	err := f.SetVehicle(context.Background(), s, ref, provider.Vehicle{Registration: "NEW111"})
	if err == nil {
		t.Fatal("a delayed write must report pending, not success")
	}
	if kind, op := provider.FailureOf(err); kind != provider.FailTransient || op != provider.OpSetVehicle {
		t.Fatalf("classified %v/%v, want FailTransient/%v", kind, op, provider.OpSetVehicle)
	}
	if cur, _ := f.Current("90001"); cur == "NEW111" {
		t.Fatal("the plate landed before the delay elapsed")
	}
	waitFor(t, f, "90001", "NEW111")
	// Once landed, the same request is confirmed by the portal's own record.
	if err := f.SetVehicle(context.Background(), s, ref, provider.Vehicle{Registration: "NEW111"}); err != nil {
		t.Fatalf("re-sending a landed plate should succeed, got %v", err)
	}
}

// Idempotency ignores plate formatting: the plate already on the permit,
// however it is spelled, is success with nothing scheduled.
func TestSetVehicleSamePlateIsIdempotent(t *testing.T) {
	f := New()
	f.ApplyDelay = time.Hour // would never land if scheduled
	s := login(t, f)
	f.SetNow("90001", "ABC123")
	if err := f.SetVehicle(context.Background(), s, provider.PermitRef{ID: "90001"}, provider.Vehicle{Registration: "abc 123"}); err != nil {
		t.Fatalf("same plate, different spelling: %v", err)
	}
	if cur, _ := f.Current("90001"); cur != "ABC123" {
		t.Fatalf("an idempotent write must not touch the record, now %q", cur)
	}
}

func TestClearVehiclePendingThenLandedAndIdempotent(t *testing.T) {
	f := New()
	f.ApplyDelay = 20 * time.Millisecond
	s := login(t, f)
	ref := provider.PermitRef{ID: "90002"}
	err := f.ClearVehicle(context.Background(), s, ref)
	if kind, op := provider.FailureOf(err); err == nil || kind != provider.FailTransient || op != provider.OpClearVehicle {
		t.Fatalf("got %v (%v/%v), want transient clear", err, kind, op)
	}
	waitFor(t, f, "90002", "")
	if err := f.ClearVehicle(context.Background(), s, ref); err != nil {
		t.Fatalf("clearing an empty permit is success, got %v", err)
	}
	f.ApplyDelay = 0
	f.SetNow("90002", "XYZ789")
	if err := f.ClearVehicle(context.Background(), s, ref); err != nil {
		t.Fatal(err)
	}
	if cur, _ := f.Current("90002"); cur != "" {
		t.Fatalf("zero-delay clear did not land, shows %q", cur)
	}
}

// An unknown permit has no reading: transient, so callers keep their stored belief.
func TestCurrentVehicleUnknownPermitIsTransient(t *testing.T) {
	f := New()
	_, err := f.CurrentVehicle(context.Background(), login(t, f), provider.PermitRef{ID: "nope"})
	if kind, op := provider.FailureOf(err); err == nil || kind != provider.FailTransient || op != provider.OpReadVehicle {
		t.Fatalf("got %v (%v/%v)", err, kind, op)
	}
}

func TestListPermitsKnobs(t *testing.T) {
	ctx := context.Background()
	f := New()
	s := login(t, f)
	ps, total, err := f.ListPermits(ctx, s)
	if err != nil || len(ps) != 2 || total != 2 {
		t.Fatalf("canned list: %d/%d, %v", len(ps), total, err)
	}
	if ps[0].CurrentRego == "" || ps[0].CouncilPermitID != "90001" {
		t.Fatalf("first permit %+v", ps[0])
	}
	f.Extra = []provider.Permit{{CouncilPermitID: "90003", PermitNumber: "VPP-3"}}
	f.Partial = true
	ps, total, err = f.ListPermits(ctx, s)
	if err != nil || len(ps) != 3 || total != len(ps)+1 {
		t.Fatalf("Extra+Partial: %d/%d, %v (want 3/4)", len(ps), total, err)
	}
	boom := errors.New("boom")
	f.ListErr = boom
	if _, _, err := f.ListPermits(ctx, s); !errors.Is(err, boom) {
		t.Fatalf("ListErr: got %v", err)
	}
}

func TestCapabilityOverrides(t *testing.T) {
	f := New()
	caps := f.Capabilities()
	if !caps.CanClearVehicle || len(caps.Regions) == 0 || caps.Regions[0].Code != "VIC" {
		t.Fatalf("defaults: %+v", caps)
	}
	f.NoClear = true
	f.Regions = []provider.Region{{Code: "NZ", Label: "New Zealand"}}
	caps = f.Capabilities()
	if caps.CanClearVehicle {
		t.Fatal("NoClear must turn CanClearVehicle off")
	}
	if len(caps.Regions) != 1 || caps.Regions[0].Code != "NZ" {
		t.Fatalf("Regions override not honoured: %+v", caps.Regions)
	}
	if err := caps.Validate(); err != nil {
		t.Fatalf("overridden capabilities should still validate: %v", err)
	}
}
