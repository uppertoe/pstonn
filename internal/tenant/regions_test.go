package tenant

import (
	"context"
	"testing"

	"github.com/uppertoe/pstonn/internal/provider"
)

// TestMuxRegionsFollowThePermitsTenant: a vehicle's state chooser and its
// validation are per TENANT, and a permit-scoped page asks for its permit's
// tenant — not the account's current selection, which differs for a second-home
// account. Account-wide ("" tenant) is the union, current tenant first.
func TestMuxRegionsFollowThePermitsTenant(t *testing.T) {
	ctx := context.Background()
	m, st, fakes := muxRig(t, "stonnington", "othertown")
	fakes["stonnington"].Regions = []provider.Region{{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}}
	fakes["othertown"].Regions = []provider.Region{{Code: "WA", Label: "WA"}, {Code: "NSW", Label: "NSW"}}
	const owner = "two@example.com"
	if err := st.SetAccountTenant(ctx, owner, "stonnington"); err != nil {
		t.Fatal(err)
	}
	codes := func(rs []provider.Region) string {
		s := ""
		for _, r := range rs {
			s += r.Code + ","
		}
		return s
	}
	// A permit in othertown validates against othertown's set even though the
	// account currently sits in stonnington.
	if got := codes(m.Regions(ctx, owner, "othertown")); got != "WA,NSW," {
		t.Fatalf("othertown regions = %q", got)
	}
	if !m.RegionValid(ctx, owner, "othertown", "WA") || m.RegionValid(ctx, owner, "othertown", "VIC") {
		t.Fatal("RegionValid did not follow the named tenant")
	}
	if !m.RegionValid(ctx, owner, "stonnington", "VIC") || m.RegionValid(ctx, owner, "stonnington", "WA") {
		t.Fatal("RegionValid did not follow the named tenant")
	}
	// "" (the home state) is always valid; an unserved tenant offers nothing.
	if !m.RegionValid(ctx, owner, "othertown", "") || m.Regions(ctx, owner, "gone") != nil {
		t.Fatal("home-state / unknown-tenant rules")
	}
	// Account-wide: the union, the current tenant's first, no duplicates.
	if got := codes(m.Regions(ctx, owner, "")); got != "VIC,NSW,WA," {
		t.Fatalf("union = %q", got)
	}
	if !m.RegionValid(ctx, owner, "", "WA") || m.RegionValid(ctx, owner, "", "QLD") {
		t.Fatal("account-wide validation is not the union")
	}
	if err := st.SetAccountTenant(ctx, owner, "othertown"); err != nil {
		t.Fatal(err)
	}
	if got := codes(m.Regions(ctx, owner, "")); got != "WA,NSW,VIC," {
		t.Fatalf("union after a switch = %q (current tenant should lead)", got)
	}
}
