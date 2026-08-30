package tenant

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
	if pol.HomeState != "VIC" {
		t.Errorf("HomeState = %q, want VIC", pol.HomeState)
	}
	// Under fallback a changeable resident permit is still never schedulable.
	res := parking.PermitInfo{PermitType: "(A) 1st Resident Permit", CanChangeVehicle: true}
	if pol.Schedulable(res, true) {
		t.Error("resident permit offered under fallback")
	}
	// Stonnington is the swap model; nothing in this refactor may change that.
	if m := Stonnington().Model; m != ModelSwap {
		t.Errorf("Stonnington model = %q, want swap", m)
	}
}

// TestModelAxis locks the open-set predicates the scheduler and validator branch
// on: which models are recognised, and which drive the plate-write path.
func TestModelAxis(t *testing.T) {
	for _, m := range []Model{ModelSwap, ModelReplate, ModelCoupon, ModelPaper} {
		if !m.Known() {
			t.Errorf("%q should be a known model", m)
		}
	}
	if Model("teleport").Known() {
		t.Error("an unknown model reported known")
	}
	// Plate() gates SetVehicle: swap and replate write a plate, coupon and paper
	// must not reach that path.
	if !ModelSwap.Plate() || !ModelReplate.Plate() {
		t.Error("swap and replate must be plate models")
	}
	if ModelCoupon.Plate() || ModelPaper.Plate() {
		t.Error("coupon and paper must not be plate models")
	}
}

// TestScheduleResidentPolicy is the re-plate generalisation: the same resident
// permit that Stonnington must never schedule is schedulable for a council whose
// policy opts in (Brimbank, Glen Eira's 3.3.1), with no visitor permit required.
func TestScheduleResidentPolicy(t *testing.T) {
	res := parking.PermitInfo{PermitType: "(A) 1st Resident Permit", CanChangeVehicle: true}
	swap := PermitPolicy{VisitorWord: "visitor", ResidentWord: "resident"}
	if swap.Schedulable(res, true) {
		t.Error("swap policy scheduled a resident permit")
	}
	replate := PermitPolicy{ResidentWord: "resident", ScheduleResident: true}
	if !replate.Schedulable(res, false) {
		t.Error("replate policy did not schedule its resident permit (even without fallback)")
	}
	// Opting resident permits in does not drag in unrelated changeable types: they
	// still need the name match or fallback.
	other := parking.PermitInfo{PermitType: "Loading Zone Permit", CanChangeVehicle: true}
	if replate.Schedulable(other, false) {
		t.Error("replate scheduled an unrelated type with no fallback")
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
