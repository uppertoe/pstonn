package config

import (
	"strings"
	"testing"
	"time"
)

// TestDevIdentityProductionGuard locks in the refusal to start with
// DEV_IDENTITY_EMAIL set alongside a production signal (a real encryption key or
// a configured OIDC login) — that combination would silently bypass
// authentication (every request becomes an admin).
func TestDevIdentityProductionGuard(t *testing.T) {
	const key64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("dev email with encryption key is refused", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		t.Setenv("DATA_ENCRYPTION_KEY", key64)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "DATA_ENCRYPTION_KEY") {
			t.Fatalf("want a DATA_ENCRYPTION_KEY guard error, got %v", err)
		}
	})

	t.Run("dev email with OIDC is refused", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		t.Setenv("APP_OIDC_ISSUER", "https://id.example.com")
		t.Setenv("SESSION_SECRET", "a-sufficiently-long-session-secret")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "APP_OIDC_ISSUER") {
			t.Fatalf("want an APP_OIDC_ISSUER guard error, got %v", err)
		}
	})

	t.Run("dev email alone is allowed (local dev)", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		if _, err := Load(); err != nil {
			t.Fatalf("dev email alone should load, got %v", err)
		}
	})

	t.Run("production config without dev email is allowed", func(t *testing.T) {
		t.Setenv("DATA_ENCRYPTION_KEY", key64)
		if _, err := Load(); err != nil {
			t.Fatalf("prod config should load, got %v", err)
		}
	})
}

// COUNCIL_SANDBOX fakes the council end to end; like DEV_IDENTITY_EMAIL it must
// refuse to coexist with production signals so it can never silently ship.
func TestSandboxProductionGuard(t *testing.T) {
	const key64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("sandbox with encryption key is refused", func(t *testing.T) {
		t.Setenv("COUNCIL_SANDBOX", "1")
		t.Setenv("DATA_ENCRYPTION_KEY", key64)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "COUNCIL_SANDBOX") {
			t.Fatalf("want a COUNCIL_SANDBOX guard error, got %v", err)
		}
	})

	t.Run("sandbox with OIDC is refused", func(t *testing.T) {
		t.Setenv("COUNCIL_SANDBOX", "true")
		t.Setenv("APP_OIDC_ISSUER", "https://id.example.com")
		t.Setenv("SESSION_SECRET", "a-sufficiently-long-session-secret")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "COUNCIL_SANDBOX") {
			t.Fatalf("want a COUNCIL_SANDBOX guard error, got %v", err)
		}
	})

	t.Run("sandbox alone is allowed (local dev)", func(t *testing.T) {
		t.Setenv("COUNCIL_SANDBOX", "1")
		if _, err := Load(); err != nil {
			t.Fatalf("sandbox alone should load, got %v", err)
		}
	})
}

// A set-but-invalid tuning value must fail startup, not silently run with the
// default (COUNCIL_WARM_INTERVAL=75 missing its unit is the canonical typo).
func TestInvalidEnvValuesFailFast(t *testing.T) {
	t.Run("bad duration", func(t *testing.T) {
		t.Setenv("COUNCIL_WARM_INTERVAL", "75")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "COUNCIL_WARM_INTERVAL") {
			t.Fatalf("want a COUNCIL_WARM_INTERVAL error, got %v", err)
		}
	})
	t.Run("bad int", func(t *testing.T) {
		t.Setenv("COUNCIL_SESSION_MAX_AGE_DAYS", "ninety")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "COUNCIL_SESSION_MAX_AGE_DAYS") {
			t.Fatalf("want a COUNCIL_SESSION_MAX_AGE_DAYS error, got %v", err)
		}
	})
	t.Run("valid values load", func(t *testing.T) {
		t.Setenv("COUNCIL_WARM_INTERVAL", "45m")
		t.Setenv("COUNCIL_SESSION_MAX_AGE_DAYS", "30")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("valid values should load, got %v", err)
		}
		if cfg.Council.WarmInterval != 45*time.Minute || cfg.Council.SessionMaxAge != 30*24*time.Hour {
			t.Fatalf("values not applied: %+v", cfg.Council)
		}
	})
}

// TestSharesParentDomain covers the multi-label public suffix case: without it,
// any two .com.au domains look "aligned" and the DMARC mismatch warning never
// fires for the most likely Australian misconfiguration.
func TestSharesParentDomain(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"stonn.org", "stonn.org", true},
		{"p.stonn.org", "stonn.org", true},
		{"mail.stonn.org", "p.stonn.org", true},
		{"stonn.org", "other.net", false},
		// The bug: both reduce to "com.au" under a last-two-labels comparison.
		{"p.stonn.com.au", "some-relay.com.au", false},
		{"p.stonn.com.au", "stonn.com.au", true},
		{"mail.example.co.uk", "example.co.uk", true},
		{"example.co.uk", "other.co.uk", false},
		{"localhost", "localhost", true},
	}
	for _, c := range cases {
		if got := sharesParentDomain(c.a, c.b); got != c.want {
			t.Errorf("sharesParentDomain(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
