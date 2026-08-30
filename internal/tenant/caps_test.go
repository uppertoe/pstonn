package tenant

import (
	"context"
	"testing"
)

// TestMuxCapabilitiesFollowThePermitsTenant: capability lookups name the
// permit's tenant, not the account's current selection, and an unserved tenant
// reports nothing supported (so nothing is offered).
func TestMuxCapabilitiesFollowThePermitsTenant(t *testing.T) {
	ctx := context.Background()
	m, st, fakes := muxRig(t, "stonnington", "othertown")
	fakes["othertown"].NoClear = true
	const owner = "two@example.com"
	if err := st.SetAccountTenant(ctx, owner, "stonnington"); err != nil {
		t.Fatal(err)
	}
	if !m.Capabilities(ctx, owner, "stonnington").CanClearVehicle {
		t.Fatal("stonnington should clear")
	}
	if m.Capabilities(ctx, owner, "othertown").CanClearVehicle {
		t.Fatal("othertown declared it cannot clear; the permit's tenant must win over the current selection")
	}
	if !m.Capabilities(ctx, owner, "").CanClearVehicle {
		t.Fatal(`"" should resolve the owner's current tenant (stonnington)`)
	}
	if c := m.Capabilities(ctx, owner, "gone"); c.CanClearVehicle || c.SupportsExpiry || len(c.Regions) != 0 {
		t.Fatalf("an unserved tenant should support nothing, got %+v", c)
	}
}
