package main

import (
	"testing"
	"time"
)

// councilOpDrain ties the rollover spread window to the governor rate, so raising
// COUNCIL_GOV_RATE for a larger fleet shrinks the window with no separate tuning.
// The model is a conservative 4 requests/operation; raising the rate shortens the
// drain proportionally.
func TestCouncilOpDrain(t *testing.T) {
	cases := []struct {
		ratePerMin int
		want       time.Duration
	}{
		{60, 4 * time.Second},  // default: 4 reqs/op ÷ 1 req/s
		{120, 2 * time.Second}, // 2x rate -> half the drain
		{240, 1 * time.Second},
		{0, 4 * time.Second},  // unset -> mirrors the governor's built-in default
		{-5, 4 * time.Second}, // nonsensical -> same fallback
	}
	for _, c := range cases {
		if got := councilOpDrain(c.ratePerMin); got != c.want {
			t.Errorf("councilOpDrain(%d) = %s, want %s", c.ratePerMin, got, c.want)
		}
	}
}
