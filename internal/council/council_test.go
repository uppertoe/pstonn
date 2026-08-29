package council

import (
	"testing"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/parking"
)

func TestStonningtonPolicy(t *testing.T) {
	pol := Stonnington().Policy
	cases := []struct {
		typ               string
		visitor, resident bool
	}{
		{"(A) 1st Visitor Permit", true, false},
		{"(A) 2nd Resident Permit", false, true},
		{"Residential Tradesperson Permit", false, false}, // whole-word: not a resident permit
		{"Special Occasion Permit", false, false},
	}
	for _, c := range cases {
		if got := pol.IsVisitor(c.typ); got != c.visitor {
			t.Errorf("IsVisitor(%q) = %v, want %v", c.typ, got, c.visitor)
		}
		if got := pol.IsResident(c.typ); got != c.resident {
			t.Errorf("IsResident(%q) = %v, want %v", c.typ, got, c.resident)
		}
	}
	if pol.DefaultVehicleState != "1" {
		t.Errorf("DefaultVehicleState = %q, want VIC (1)", pol.DefaultVehicleState)
	}
	// Under fallback a changeable resident permit is still never schedulable.
	res := parking.PermitInfo{PermitType: "(A) 1st Resident Permit", CanChangeVehicle: true}
	if pol.Schedulable(res, true) {
		t.Error("resident permit offered under fallback")
	}
}

// An uncompiled policy (as a future file loader would produce) behaves like the
// compiled one.
func TestPolicyUncompiled(t *testing.T) {
	pol := PermitPolicy{VisitorWord: "visitor", ResidentWord: "resident"}
	if !pol.IsResident("(A) 1st Resident Permit") || pol.IsResident("Residential Tradesperson Permit") {
		t.Error("uncompiled resident match differs from compiled")
	}
	if (PermitPolicy{}).IsResident("Resident Permit") {
		t.Error("empty policy must match nothing")
	}
}

func TestFromConfig(t *testing.T) {
	cfg := config.CouncilConfig{Issuer: "https://x/idm", APIBase: "https://x/ssp-svc", ClientID: "c", Scopes: []string{"openid"}}
	c := FromConfig(cfg)
	if c.ID != "stonnington" || c.Connector != "orikan-ssp" || c.Endpoints.Issuer != "https://x/idm" {
		t.Errorf("unexpected descriptor: %+v", c)
	}
	cfg.Sandbox = true
	if FromConfig(cfg).Connector != "fake" {
		t.Error("sandbox should select the fake connector")
	}
}
