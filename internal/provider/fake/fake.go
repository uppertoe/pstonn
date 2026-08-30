// Package fake is an in-memory provider for local development, demos and tests
// (COUNCIL_SANDBOX=1): any credentials sign in, ListPermits returns two canned
// visitor permits, and SetVehicle "lands" a few seconds later — returning
// transient until the fake portal's own record shows the plate — so the whole
// pending → settled pipeline (scheduler retries, read-back confirmation, guest
// page polling) runs exactly as it does against a real portal.
//
// It is also the second, genuinely different implementation of the provider
// contract: no HTTP, no sessions to keep warm, and it is what the core's tests
// run against. Never enable in production.
package fake

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider"
)

// ID is the connector name a tenant descriptor refers to.
const ID = "fake"

// DefaultApplyDelay is how long a plate change takes to "land" — long enough to
// see the applying state, short enough to feel live.
const DefaultApplyDelay = 6 * time.Second

// Provider is the fake portal. One instance is one portal: every account sees
// the same permits, so plates are keyed by permit only (as a real portal's are).
type Provider struct {
	mu     sync.Mutex
	plates map[string]string // permit id → plate the fake portal currently shows
	// ApplyDelay is how long a write takes to land; 0 lands immediately (tests).
	ApplyDelay time.Duration
	// RejectPassword, when non-empty, is the one password that is refused — so a
	// wrong-password path can be exercised. Every other password signs in.
	RejectPassword string
	// Scripting hooks for tests: LoginErr fails every login with the given error;
	// ListErr fails ListPermits; Extra permits are appended to the canned two;
	// Partial makes ListPermits claim one more permit than it returns.
	LoginErr error
	ListErr  error
	Extra    []provider.Permit
	Partial  bool
	// Regions, when set, replaces the canned Australian state set — so a test can
	// give two fake tenants different jurisdictions and prove routing by tenant.
	Regions []provider.Region
}

// New builds a fake portal seeded with a plate on each canned permit, like a real
// granted permit that always has SOME vehicle on it (without a reading the card's
// plate poll would pin on until a change landed).
func New() *Provider {
	return &Provider{plates: map[string]string{"90001": "SBX1AB", "90002": "SBX2CD"}, ApplyDelay: DefaultApplyDelay}
}

func (f *Provider) ID() string { return ID }

// fakeRegions mirrors an Australian council's state set (home VIC first), so a
// COUNCIL_SANDBOX run exercises the registration-state chooser exactly as the real
// Orikan connector would rather than hiding it.
var fakeRegions = []provider.Region{
	{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}, {Code: "ACT", Label: "ACT"},
	{Code: "QLD", Label: "QLD"}, {Code: "SA", Label: "SA"}, {Code: "WA", Label: "WA"},
	{Code: "TAS", Label: "TAS"}, {Code: "NT", Label: "NT"},
}

func (f *Provider) Capabilities() provider.Capabilities {
	regions := fakeRegions
	if f.Regions != nil {
		regions = f.Regions
	}
	return provider.Capabilities{CanClearVehicle: true, SupportsRefresh: true, NeedsKeepWarm: false, SupportsExpiry: true, LoginKind: "password", Regions: regions}
}

type session struct {
	User string `json:"user"`
}

func (f *Provider) Login(ctx context.Context, creds provider.Credentials) (provider.Session, error) {
	if f.LoginErr != nil {
		return nil, f.LoginErr
	}
	if f.RejectPassword != "" && creds.Password == f.RejectPassword {
		return nil, provider.ErrLoginRejected
	}
	return json.Marshal(session{User: creds.Username})
}

// Refresh: fake sessions never lapse.
func (f *Provider) Refresh(ctx context.Context, s *provider.Session) error { return nil }

// Current returns the plate the fake portal shows for a permit.
func (f *Provider) Current(id string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reg, ok := f.plates[id]
	return reg, ok
}

// SetNow puts a plate on a permit immediately (tests seeding state).
func (f *Provider) SetNow(id, reg string) {
	f.mu.Lock()
	f.plates[id] = reg
	f.mu.Unlock()
}

func (f *Provider) applyLater(id, reg string) {
	if f.ApplyDelay <= 0 {
		f.SetNow(id, reg)
		return
	}
	time.AfterFunc(f.ApplyDelay, func() { f.SetNow(id, reg) })
}

func (f *Provider) ListPermits(ctx context.Context, s *provider.Session) ([]provider.Permit, int, error) {
	if f.ListErr != nil {
		return nil, 0, f.ListErr
	}
	// Two permits, matching households that hold a 1st and a 2nd visitor permit —
	// the account shape the multi-permit UI needs a sandbox for.
	now := time.Now()
	reg1, _ := f.Current("90001")
	reg2, _ := f.Current("90002")
	ps := []provider.Permit{{
		CouncilPermitID: "90001", PermitTypeID: "14", PermitNumber: "VPP-SANDBOX", PermitType: "(A) 1st Visitor Permit",
		Status: "Granted", CurrentRego: reg1, StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 6, 0), CanChangeVehicle: true,
	}, {
		CouncilPermitID: "90002", PermitTypeID: "15", PermitNumber: "VPP-SANDBOX-2", PermitType: "(A) 2nd Visitor Permit",
		Status: "Granted", CurrentRego: reg2, StartDate: now.AddDate(0, -1, 0), EndDate: now.AddDate(0, 6, 0), CanChangeVehicle: true,
	}}
	ps = append(ps, f.Extra...)
	total := len(ps)
	if f.Partial {
		total++
	}
	return ps, total, nil
}

func (f *Provider) CurrentVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) (provider.Vehicle, error) {
	if reg, ok := f.Current(p.ID); ok {
		return provider.Vehicle{Registration: reg}, nil
	}
	// No reading yet: transient, so callers fall back to their stored belief
	// instead of treating "unknown" as an empty permit.
	return provider.Vehicle{}, provider.Fail(provider.FailTransient, provider.OpReadVehicle, errors.New("fake: no reading for this permit yet"))
}

func (f *Provider) SetVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef, v provider.Vehicle) error {
	registration := v.Registration
	if cur, ok := f.Current(p.ID); ok && model.SamePlate(cur, registration) {
		return nil // the fake portal's own record confirms the plate
	}
	f.applyLater(p.ID, registration)
	if f.ApplyDelay <= 0 {
		return nil
	}
	return provider.Fail(provider.FailTransient, provider.OpSetVehicle, errors.New("fake: the change lands in a few seconds"))
}

func (f *Provider) ClearVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) error {
	if cur, ok := f.Current(p.ID); ok && cur == "" {
		return nil
	}
	f.applyLater(p.ID, "")
	if f.ApplyDelay <= 0 {
		return nil
	}
	return provider.Fail(provider.FailTransient, provider.OpClearVehicle, errors.New("fake: the change lands in a few seconds"))
}
