package config

import (
	"strings"
	"testing"
	"time"
)

// TestDevIdentityProductionGuard locks in the refusal to start with
// DEV_IDENTITY_EMAIL set alongside anything that means "real deployment" — an
// at-rest key, a configured OIDC login, DOMAIN, or a public base URL. That
// combination silently bypasses authentication (every request becomes an admin),
// so each signal is asserted separately: they are not redundant, and a deployment
// only has to present one of them.
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

	// The guard that A4 added. In the recommended posture APP_OIDC_ISSUER is unset
	// and users sign in through the forward-auth layer, so DATA_ENCRYPTION_KEY was
	// the ONLY thing standing between "operator comments out the key to debug" and
	// an app that hands ["user","admin"] to every caller. DOMAIN and a public
	// PUBLIC_BASE_URL exist only on a real deployment, so they must refuse too.
	t.Run("dev email with DOMAIN is refused", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		t.Setenv("DOMAIN", "example.com")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "DOMAIN") {
			t.Fatalf("want a DOMAIN guard error, got %v", err)
		}
	})

	t.Run("dev email with a public PUBLIC_BASE_URL is refused", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		t.Setenv("PUBLIC_BASE_URL", "https://p.example.com")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "PUBLIC_BASE_URL") {
			t.Fatalf("want a PUBLIC_BASE_URL guard error, got %v", err)
		}
	})

	t.Run("dev email alone is allowed (local dev)", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		if _, err := Load(); err != nil {
			t.Fatalf("dev email alone should load, got %v", err)
		}
	})

	// A loopback base is how a local run makes guest-pass links resolve while
	// clicking through the flow, so it must not be read as a production signal —
	// otherwise the guard trains developers to work around it.
	t.Run("dev email with a loopback PUBLIC_BASE_URL is allowed", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		for _, base := range []string{"http://127.0.0.1:8099", "http://localhost:8099", "http://[::1]:8099"} {
			t.Setenv("PUBLIC_BASE_URL", base)
			if _, err := Load(); err != nil {
				t.Fatalf("local base %q should load, got %v", base, err)
			}
		}
	})

	t.Run("production config without dev email is allowed", func(t *testing.T) {
		t.Setenv("DATA_ENCRYPTION_KEY", key64)
		t.Setenv("DOMAIN", "example.com")
		if _, err := Load(); err != nil {
			t.Fatalf("prod config should load, got %v", err)
		}
	})
}

// TestPublicBaseURL covers A5. The base is concatenated with a path to build the
// re-authorise confirm link, the guest-pass links and the door QR, so a missing or
// non-absolute value does not fail — it silently mints links that cannot be
// clicked, and the confirm link exists precisely to stop a session lapsing.
func TestPublicBaseURL(t *testing.T) {
	t.Run("missing on a real deployment is fatal", func(t *testing.T) {
		t.Setenv("DATA_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "PUBLIC_BASE_URL") {
			t.Fatalf("want a PUBLIC_BASE_URL error, got %v", err)
		}
	})

	t.Run("missing on a local run is fine", func(t *testing.T) {
		t.Setenv("DEV_IDENTITY_EMAIL", "dev@example.com")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("local run should load without a base, got %v", err)
		}
		if cfg.PublicBaseURL != "" {
			t.Fatalf("expected an empty base, got %q", cfg.PublicBaseURL)
		}
	})

	t.Run("derived from DOMAIN", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PublicBaseURL != "https://p.example.com" {
			t.Fatalf("PublicBaseURL = %q", cfg.PublicBaseURL)
		}
	})

	t.Run("non-absolute values are refused", func(t *testing.T) {
		for _, bad := range []string{"p.example.com", "/p", "example.com/app", "ftp://p.example.com", "https://"} {
			t.Setenv("PUBLIC_BASE_URL", bad)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "PUBLIC_BASE_URL") {
				t.Fatalf("PUBLIC_BASE_URL=%q should be refused, got %v", bad, err)
			}
		}
	})

	t.Run("a trailing slash is trimmed, not rejected", func(t *testing.T) {
		t.Setenv("PUBLIC_BASE_URL", "https://p.example.com/")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PublicBaseURL != "https://p.example.com" {
			t.Fatalf("PublicBaseURL = %q", cfg.PublicBaseURL)
		}
	})
}

// TestStatusTokenRequiresRosterKey covers A3. /status carries every consented
// account's email and private push topic; with no ROSTER_KEY the endpoint used to
// ship all of it in plaintext on every watchdog poll, and ?roster=0 could not stop
// it. The transitional allowance is gone, so the pair is now mandatory.
func TestStatusTokenRequiresRosterKey(t *testing.T) {
	const key64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const token = "a-long-enough-status-token-value"

	t.Run("status token without a roster key is refused", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("STATUS_TOKEN", token)
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "ROSTER_KEY") {
			t.Fatalf("want a ROSTER_KEY error, got %v", err)
		}
	})

	t.Run("both set is allowed", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("STATUS_TOKEN", token)
		t.Setenv("ROSTER_KEY", key64)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("token + key should load, got %v", err)
		}
		if len(cfg.RosterKey) != 32 {
			t.Fatalf("RosterKey = %d bytes", len(cfg.RosterKey))
		}
	})

	t.Run("neither set is allowed (endpoint disabled)", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		if _, err := Load(); err != nil {
			t.Fatalf("no status endpoint should load, got %v", err)
		}
	})
}

// TestStartupErrorsKeepSecretsOut covers A9: a startup error is written to the
// container log and shipped wherever those go, so it must not carry fragments of
// the secret it is complaining about — not the offending character, not its index,
// not the length that was accepted.
func TestStartupErrorsKeepSecretsOut(t *testing.T) {
	t.Run("hex key errors name neither the byte nor the length", func(t *testing.T) {
		for _, bad := range []string{
			"0123456789abcdefZZ23456789abcdef0123456789abcdef0123456789abcdef", // invalid character
			"0123456789abcdef", // too short
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefab", // too long
		} {
			for _, name := range []string{"DATA_ENCRYPTION_KEY", "ROSTER_KEY"} {
				t.Setenv("DOMAIN", "example.com")
				t.Setenv("DATA_ENCRYPTION_KEY", "")
				t.Setenv("ROSTER_KEY", "")
				t.Setenv(name, bad)
				_, err := Load()
				if err == nil {
					t.Fatalf("%s=%q should be refused", name, bad)
				}
				msg := err.Error()
				if !strings.Contains(msg, name) {
					t.Fatalf("error should name %s: %s", name, msg)
				}
				// "invalid byte: U+005A 'Z'", an index, or the decoded length would
				// each be a fragment of a live key in the log.
				for _, leak := range []string{"invalid byte", "U+", "got ", "hex string"} {
					if strings.Contains(msg, leak) {
						t.Fatalf("error leaks key detail (%q): %s", leak, msg)
					}
				}
			}
		}
	})

	t.Run("a short status token error does not report its length", func(t *testing.T) {
		t.Setenv("DOMAIN", "example.com")
		t.Setenv("STATUS_TOKEN", "short")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "STATUS_TOKEN") {
			t.Fatalf("want a STATUS_TOKEN error, got %v", err)
		}
		if strings.Contains(err.Error(), "5") {
			t.Fatalf("error reports the rejected token length: %v", err)
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
		t.Setenv("DOMAIN", "example.com")
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
