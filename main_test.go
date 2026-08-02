package main

import (
	"testing"
	"time"
)

// councilOpDrain is what ties the rollover spread window to the governor rate, so
// raising COUNCIL_GOV_RATE for a larger fleet shrinks the window with no separate
// tuning. At the default 60/min it must equal the old hard-coded 3s (so convergence
// is unchanged on deploy); raising the rate must shorten it proportionally.
func TestCouncilOpDrain(t *testing.T) {
	cases := []struct {
		ratePerMin int
		want       time.Duration
	}{
		{60, 3 * time.Second},          // default: identical to the retired rateDelay
		{120, 1500 * time.Millisecond}, // 2x rate -> half the drain
		{240, 750 * time.Millisecond},
		{0, 3 * time.Second},  // unset -> mirrors the governor's built-in default
		{-5, 3 * time.Second}, // nonsensical -> same fallback
	}
	for _, c := range cases {
		if got := councilOpDrain(c.ratePerMin); got != c.want {
			t.Errorf("councilOpDrain(%d) = %s, want %s", c.ratePerMin, got, c.want)
		}
	}
}
