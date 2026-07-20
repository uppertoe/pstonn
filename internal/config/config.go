// Package config loads runtime configuration from environment variables.
//
// The design mirrors the vps-scaffold-auth conventions: internal HTTP port
// :8080, a SQLite file on a mounted data volume, and an at-rest encryption key
// used to seal sensitive material (here, the council session cookie). Users log
// in via OIDC (AppOIDC); if that is disabled the app falls back to the
// platform's forward_auth Remote-* headers, or DevIdentityEmail for local runs.
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	ListenAddr string // LISTEN_ADDR, default ":8080"
	SQLitePath string // SQLITE_PATH, default "/data/pstonn.db"
	Domain     string // DOMAIN, e.g. "example.com" (used to build the OAuth redirect URI)

	// DataEncryptionKey seals the council session cookie at rest (AES-256-GCM).
	// 32 bytes, provided as 64 hex chars via DATA_ENCRYPTION_KEY.
	DataEncryptionKey []byte

	// DisplayLocation is the timezone rosters are interpreted in. Parking is a
	// local-time concern ("swap the plate on Monday morning"), so we schedule in
	// the council's wall-clock time, not UTC. DISPLAY_TIMEZONE, default
	// "Australia/Melbourne".
	DisplayLocation *time.Location

	// Council OIDC / API settings. Defaults target City of Stonnington ePermits.
	Council CouncilConfig

	// DevIdentityEmail, when set (DEV_IDENTITY_EMAIL), supplies an identity for
	// local/standalone runs where no real login is wired up. It MUST be empty in
	// production.
	DevIdentityEmail string

	// SessionSecret signs the app's stateless session cookie (HMAC-SHA256).
	// Required whenever app-login (AppOIDC) is enabled. SESSION_SECRET.
	SessionSecret []byte

	// CookieSecure controls the Secure flag on the session cookie. Default true;
	// set COOKIE_SECURE=false only for local http development.
	CookieSecure bool

	// AppOIDC configures the app's own user login as an OIDC relying party
	// (the OIDC provider). When Issuer is empty, OIDC login is disabled and the app falls
	// back to forward_auth Remote-* headers (or DevIdentityEmail locally).
	AppOIDC AppOIDCConfig

	// AuthLogoutURL is the forward-auth provider's sign-out URL (vps-scaffold-auth),
	// used when the app's own OIDC is disabled. AUTH_LOGOUT_URL.
	AuthLogoutURL string

	// TermsPath optionally points at a markdown terms file to use instead of the
	// built-in one (TERMS_PATH), so terms can be edited without recompiling.
	TermsPath string

	// PublicBaseURL is the app's externally-reachable base (no trailing slash),
	// used to build absolute links in emails (the renewal-confirm link). Derived
	// from DOMAIN as https://p.<DOMAIN> when PUBLIC_BASE_URL is unset.
	PublicBaseURL string

	// SMTP configures outbound email (renewal reminders). Disabled when unset.
	SMTP SMTPConfig

	// Ntfy configures push notifications via a self-hosted ntfy server (a separate
	// container). Disabled when BaseURL is unset.
	Ntfy NtfyConfig

	// ContactTo is the operator address the public contact form delivers to
	// (CONTACT_TO). It is never shown to users. The form is enabled only when this
	// is set and outbound email (SMTP) is configured.
	ContactTo string

	// Admin alerting: where systemic-failure alerts go (API-shape change, a
	// notification that could not be delivered to a user, keep-warm collapse,
	// scheduler panic/stall, DB errors). Both are tried so one being down (which
	// may be the failure) doesn't blind the operator. Either or both may be empty.
	AdminEmail     string // ADMIN_EMAIL (durable; needs SMTP configured)
	AdminNtfyTopic string // ADMIN_NTFY_TOPIC (instant push; needs NTFY_BASE_URL configured)

	// StatusToken gates the machine-readable /status endpoint the external outage
	// watchdog polls (bearer token). Empty disables the endpoint. STATUS_TOKEN.
	StatusToken string
}

// ContactEnabled reports whether the public contact form should be offered: a
// destination address plus a working outbound mailer.
func (c *Config) ContactEnabled() bool { return c.ContactTo != "" && c.SMTP.Enabled() }

// NtfyConfig points at a self-hosted ntfy server for push notifications.
type NtfyConfig struct {
	BaseURL string // NTFY_BASE_URL, e.g. http://ntfy:80 (internal) or https://ntfy.example
	Token   string // NTFY_TOKEN, optional bearer token if the server requires auth
}

// Enabled reports whether ntfy push is configured.
func (n NtfyConfig) Enabled() bool { return n.BaseURL != "" }

// SMTPConfig configures the outbound mailer. Email is disabled unless both Host
// and From are set (mirrors the OIDC-optional pattern).
type SMTPConfig struct {
	Host     string // SMTP_HOST
	Port     int    // SMTP_PORT, default 587 (STARTTLS submission)
	Username string // SMTP_USERNAME
	Password string // SMTP_PASSWORD
	From     string // SMTP_FROM, e.g. "pstonn <no-reply@example.com>"
}

// Enabled reports whether outbound email is configured.
func (s SMTPConfig) Enabled() bool { return s.Host != "" && s.From != "" }

// AppOIDCConfig configures the app's user-facing login (relying party).
type AppOIDCConfig struct {
	Issuer       string   // APP_OIDC_ISSUER, e.g. https://auth.example.com
	ClientID     string   // APP_OIDC_CLIENT_ID
	ClientSecret string   // APP_OIDC_CLIENT_SECRET (confidential client)
	RedirectURI  string   // APP_OIDC_REDIRECT_URI (must be registered in the OIDC provider)
	Scopes       []string // APP_OIDC_SCOPES, default "openid profile email groups"
	AdminGroups  []string // APP_ADMIN_GROUPS, comma-separated groups granted admin
}

// Enabled reports whether OIDC app-login is configured.
func (a AppOIDCConfig) Enabled() bool { return a.Issuer != "" }

// CouncilConfig describes how to talk to the council's IdentityServer + API.
type CouncilConfig struct {
	Issuer      string   // COUNCIL_ISSUER, the OIDC issuer (…/idm)
	ClientID    string   // COUNCIL_CLIENT_ID, the public SPA client we reuse
	RedirectURI string   // COUNCIL_REDIRECT_URI, the client's REGISTERED redirect (the council SPA's own /ssp/callback); we intercept the code from the 302 rather than receiving it here
	Scopes      []string // COUNCIL_SCOPES, space-separated (NO offline_access, the client rejects it)
	APIBase     string   // COUNCIL_API_BASE, base URL for /ssp-svc/api calls

	// SessionMaxAge bounds how long a linked council session is kept alive by
	// keep-warm renewal before the user must re-authorise (re-link). It is the
	// safety limit so a departed user's plate is not changed forever: measured
	// from the last interactive link, after which we stop renewing, let the
	// session lapse, and the dashboard prompts a re-link (which resets the clock).
	// COUNCIL_SESSION_MAX_AGE_DAYS, default 90.
	SessionMaxAge time.Duration

	// WarmInterval is how stale a still-valid session may get before keep-warm
	// silent-renews it (sliding the council cookie so an idle, set-and-forget
	// user's session does not lapse). COUNCIL_WARM_INTERVAL, default 1h15m: half
	// the measured proven-safe idle window of ~2h32m (session dies by ~3h48m),
	// so there is a comfortable margin.
	WarmInterval time.Duration

	// ReminderLead is how far before the SessionMaxAge deadline to email the user
	// a "confirm you're still using this" link. COUNCIL_REMINDER_LEAD_DAYS,
	// default 7.
	ReminderLead time.Duration
}

// Load reads and validates configuration from the environment.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:       env("LISTEN_ADDR", ":8080"),
		SQLitePath:       env("SQLITE_PATH", "/data/pstonn.db"),
		Domain:           os.Getenv("DOMAIN"),
		DevIdentityEmail: strings.ToLower(strings.TrimSpace(os.Getenv("DEV_IDENTITY_EMAIL"))),
		CookieSecure:     env("COOKIE_SECURE", "true") != "false",
		Council: CouncilConfig{
			Issuer:        env("COUNCIL_ISSUER", "https://parkingpermits.stonnington.vic.gov.au/idm"),
			ClientID:      env("COUNCIL_CLIENT_ID", "ePermits.ssp.web"),
			RedirectURI:   env("COUNCIL_REDIRECT_URI", "https://parkingpermits.stonnington.vic.gov.au/ssp/callback"),
			Scopes:        strings.Fields(env("COUNCIL_SCOPES", "openid profile ePermits.ssp.api.all")),
			APIBase:       env("COUNCIL_API_BASE", "https://parkingpermits.stonnington.vic.gov.au/ssp-svc"),
			SessionMaxAge: time.Duration(envInt("COUNCIL_SESSION_MAX_AGE_DAYS", 90)) * 24 * time.Hour,
			WarmInterval:  envDuration("COUNCIL_WARM_INTERVAL", 75*time.Minute),
			ReminderLead:  time.Duration(envInt("COUNCIL_REMINDER_LEAD_DAYS", 7)) * 24 * time.Hour,
		},
		AuthLogoutURL: strings.TrimSpace(os.Getenv("AUTH_LOGOUT_URL")),
		TermsPath:     strings.TrimSpace(os.Getenv("TERMS_PATH")),
		PublicBaseURL: strings.TrimRight(os.Getenv("PUBLIC_BASE_URL"), "/"),
		SMTP: SMTPConfig{
			Host:     os.Getenv("SMTP_HOST"),
			Port:     envInt("SMTP_PORT", 587),
			Username: os.Getenv("SMTP_USERNAME"),
			Password: os.Getenv("SMTP_PASSWORD"),
			From:     strings.TrimSpace(os.Getenv("SMTP_FROM")),
		},
		Ntfy: NtfyConfig{
			BaseURL: strings.TrimRight(os.Getenv("NTFY_BASE_URL"), "/"),
			Token:   strings.TrimSpace(os.Getenv("NTFY_TOKEN")),
		},
		ContactTo:      strings.TrimSpace(os.Getenv("CONTACT_TO")),
		AdminEmail:     strings.TrimSpace(os.Getenv("ADMIN_EMAIL")),
		AdminNtfyTopic: strings.TrimSpace(os.Getenv("ADMIN_NTFY_TOPIC")),
		StatusToken:    strings.TrimSpace(os.Getenv("STATUS_TOKEN")),
		AppOIDC: AppOIDCConfig{
			Issuer:       strings.TrimRight(os.Getenv("APP_OIDC_ISSUER"), "/"),
			ClientID:     os.Getenv("APP_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("APP_OIDC_CLIENT_SECRET"),
			RedirectURI:  os.Getenv("APP_OIDC_REDIRECT_URI"),
			Scopes:       strings.Fields(env("APP_OIDC_SCOPES", "openid profile email groups")),
			AdminGroups:  splitCSV(env("APP_ADMIN_GROUPS", "")),
		},
	}

	if raw := strings.TrimSpace(os.Getenv("SESSION_SECRET")); raw != "" {
		cfg.SessionSecret = []byte(raw)
	}

	tzName := env("DISPLAY_TIMEZONE", "Australia/Melbourne")
	loc, err := time.LoadLocation(tzName)
	if err != nil {
		return nil, fmt.Errorf("DISPLAY_TIMEZONE %q: %w", tzName, err)
	}
	cfg.DisplayLocation = loc

	if raw := strings.TrimSpace(os.Getenv("DATA_ENCRYPTION_KEY")); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("DATA_ENCRYPTION_KEY: not valid hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("DATA_ENCRYPTION_KEY: need 32 bytes (64 hex chars), got %d", len(key))
		}
		cfg.DataEncryptionKey = key
	}

	// Derive redirect URIs from DOMAIN if not set explicitly. Each must be
	// registered against its respective identity provider.
	base := ""
	if cfg.Domain != "" {
		base = "https://p." + cfg.Domain
	}
	// Council.RedirectURI is the SPA client's own registered callback (defaulted
	// above); we never receive a redirect there, so it is not derived from base.
	if cfg.AppOIDC.RedirectURI == "" && base != "" {
		cfg.AppOIDC.RedirectURI = base + "/auth/callback"
	}
	if cfg.PublicBaseURL == "" && base != "" {
		cfg.PublicBaseURL = base
	}

	if cfg.AppOIDC.Enabled() && len(cfg.SessionSecret) < 16 {
		return nil, fmt.Errorf("SESSION_SECRET must be set (>=16 bytes) when APP_OIDC_ISSUER is configured")
	}

	return cfg, nil
}

func splitCSV(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envInt reads a non-negative integer env var, falling back to def when unset or
// unparseable.
func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// envDuration reads a Go duration env var (e.g. "45m"), falling back to def.
func envDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
