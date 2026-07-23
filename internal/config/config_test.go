package config

import (
	"strings"
	"testing"
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
