package main

import (
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
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

// TestBuildSecretBoxDevSignals: a missing DATA_ENCRYPTION_KEY is fatal in
// production but fine in local/dev, and BOTH local signals count — not just
// DEV_IDENTITY_EMAIL. Sandbox fakes the council, so the cipher protects only
// fake secrets; treating only DEV_IDENTITY_EMAIL as dev left a catch-22 where a
// signed-out sandbox preview demanded a key the sandbox tripwire then forbade.
func TestBuildSecretBoxDevSignals(t *testing.T) {
	newCfg := func() *config.Config { return &config.Config{} }

	// No key, no dev signal → production → fatal.
	if _, err := buildSecretBox(newCfg()); err == nil {
		t.Fatal("no key and no dev signal should be fatal (production)")
	}
	// DEV_IDENTITY_EMAIL alone → ephemeral key OK.
	c := newCfg()
	c.DevIdentityEmail = "you@example.com"
	if _, err := buildSecretBox(c); err != nil {
		t.Fatalf("DEV_IDENTITY_EMAIL should allow an ephemeral key: %v", err)
	}
	// COUNCIL_SANDBOX alone (no DEV_IDENTITY_EMAIL) → ephemeral key OK. This is
	// the case the catch-22 blocked.
	c = newCfg()
	c.Council.Sandbox = true
	if _, err := buildSecretBox(c); err != nil {
		t.Fatalf("COUNCIL_SANDBOX should allow an ephemeral key without DEV_IDENTITY_EMAIL: %v", err)
	}
	// A real 32-byte key is always used, dev signals or not.
	c = newCfg()
	c.DataEncryptionKey = make([]byte, 32)
	if _, err := buildSecretBox(c); err != nil {
		t.Fatalf("a valid key should always build: %v", err)
	}
}
