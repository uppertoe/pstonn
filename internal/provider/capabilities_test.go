package provider

import (
	"testing"
	"time"
)

// TestCapabilitiesValidate pins the coherence rules a connector's declaration
// must meet before the core will drive it.
func TestCapabilitiesValidate(t *testing.T) {
	ok := Capabilities{LoginKind: "password", SupportsRefresh: true, NeedsKeepWarm: true, IdleWindow: time.Hour,
		Regions: []Region{{Code: "VIC", Label: "VIC"}, {Code: "NSW", Label: "NSW"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("coherent set rejected: %v", err)
	}
	if err := (Capabilities{LoginKind: "password"}).Validate(); err != nil {
		t.Fatalf("minimal set rejected: %v", err)
	}
	bad := map[string]Capabilities{
		"no login kind":         {},
		"keep-warm, no refresh": {LoginKind: "password", NeedsKeepWarm: true, IdleWindow: time.Hour},
		"keep-warm, no window":  {LoginKind: "password", NeedsKeepWarm: true, SupportsRefresh: true},
		"region without code":   {LoginKind: "password", Regions: []Region{{Label: "x"}}},
		"region without label":  {LoginKind: "password", Regions: []Region{{Code: "X"}}},
		"duplicate region code": {LoginKind: "password", Regions: []Region{{Code: "X", Label: "x"}, {Code: "X", Label: "y"}}},
	}
	for name, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
