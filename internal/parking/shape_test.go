package parking

import (
	"context"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/model"
)

// emptyIsCredible must require every corroborating field to be EXPLICITLY present.
// A shape change that drops permitVehicleCount (or the permitVehicles array) while
// keeping permitNumber must NOT read as a credible empty permit.
func TestEmptyIsCredibleRequiresExplicitFields(t *testing.T) {
	zero := 0
	one := 1
	cases := []struct {
		name string
		mv   managedVehicleResp
		want bool
	}{
		{"count 0 and explicit empty array", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &zero, PermitVehicles: []permitVehicle{}}, true},
		{"count field absent", managedVehicleResp{PermitNumber: "VPP1", PermitVehicles: []permitVehicle{}}, false},
		{"permitVehicles key absent", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &zero}, false},
		{"permitNumber absent", managedVehicleResp{PermitVehicleCount: &zero, PermitVehicles: []permitVehicle{}}, false},
		{"count present but non-zero", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &one, PermitVehicles: []permitVehicle{}}, false},
	}
	for _, c := range cases {
		if got := c.mv.emptyIsCredible(); got != c.want {
			t.Errorf("%s: emptyIsCredible = %v, want %v", c.name, got, c.want)
		}
	}
}

// End to end through the real client: a response that dropped permitVehicleCount is
// an unexpected shape, NOT an empty permit — so CurrentVehicle errors rather than
// reporting a false clearing. An explicit count:0 + [] is a believed empty permit.
func TestCurrentVehicleRejectsMissingCount(t *testing.T) {
	const owner = "shape@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	f.apiBody.Store(`{"permitNumber":"VPP1"}`) // count and vehicles both absent
	if _, err := c.CurrentVehicle(context.Background(), owner, p); err == nil {
		t.Fatal("a response missing permitVehicleCount must not read as an empty permit")
	}

	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":0,"permitVehicles":[]}`)
	reg, err := c.CurrentVehicle(context.Background(), owner, p)
	if err != nil || reg != "" {
		t.Fatalf("an explicit empty permit should read as no vehicle, got reg=%q err=%v", reg, err)
	}
}

// The visitor-permit model is one managed vehicle. More than one is an unexpected
// shape: reading (or editing) only [0] could act on the wrong record, so refuse.
func TestCurrentVehicleRejectsMultipleVehicles(t *testing.T) {
	const owner = "multi@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":2,"permitVehicles":[` +
		`{"PKPermitVehicleDetailID":1,"RegistrationNumber":"AAA111","FKVehicleStateID":"1"},` +
		`{"PKPermitVehicleDetailID":2,"RegistrationNumber":"BBB222","FKVehicleStateID":"1"}]}`)
	_, err := c.CurrentVehicle(context.Background(), owner, p)
	if err == nil || !strings.Contains(err.Error(), "exactly one managed vehicle") {
		t.Fatalf("two managed vehicles should be refused as unexpected, got %v", err)
	}
}

// A plate read that was already in flight when the permit was FORGOTTEN must not
// resurrect the cache entry: storeRegIfCurrent drops a write whose generation is
// stale.
func TestForgetPermitInvalidatesInFlightRefresh(t *testing.T) {
	c := &Client{}
	key := regKey{"owner@example.com", "p1"}

	gen := c.regGeneration(key)             // captured "before the read"
	c.ForgetPermit(key.owner, key.permitID) // permit removed while the read runs
	c.storeRegIfCurrent(key, gen, "STALE1") // the read completes and tries to store

	if _, ok := c.regCache.Load(key); ok {
		t.Fatal("a forgotten permit's cache entry was resurrected by an in-flight refresh")
	}

	// A fresh read (generation captured after the forget) stores normally.
	gen2 := c.regGeneration(key)
	c.storeRegIfCurrent(key, gen2, "FRESH1")
	if v, ok := c.regCache.Load(key); !ok || v.(cachedReg).reg != "FRESH1" {
		t.Fatalf("a current-generation write should store, got %v (ok=%v)", v, ok)
	}
}
