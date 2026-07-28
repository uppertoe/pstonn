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
	"net/mail"
	"net/url"
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

	// MaxAccounts caps how many accounts may hold a linked council session
	// (MAX_ACCOUNTS, 0 = unlimited). Existing users are never affected; a new user
	// who would exceed it is told the service is full rather than silently getting
	// a degraded experience.
	//
	// This exists because convergence latency, not council capacity, is the limit:
	// reconcile applies changes one permit at a time with a few seconds between
	// them, and rosters roll at a common wall-clock boundary, so past roughly fifty
	// households the last one's midnight change lands minutes late.
	MaxAccounts int

	// RosterKey seals the user roster in the /status payload (32 bytes, 64 hex, via
	// ROSTER_KEY). The outage watchdog holds the same key and decrypts it.
	//
	// Without this the roster — every consented account's email plus their push
	// topic — travels and sits in the response in the clear, so one leaked
	// STATUS_TOKEN yields the entire user list and a live read capability on
	// everyone's notifications. With it, a leaked token yields ciphertext.
	// Empty keeps the old plaintext behaviour (so the app can be deployed before
	// the watchdog is updated), with a startup warning.
	RosterKey []byte

	// SESTopicARN is the SNS topic that carries this domain's SES bounce and
	// complaint events. Set it to enable POST /hooks/ses, which records dead
	// addresses so the app stops mailing them. Empty disables the endpoint
	// entirely (no route, 404), so a deployment that hasn't wired SES up is not
	// exposing an unused public handler. SES_SNS_TOPIC_ARN.
	SESTopicARN string
}

// SESHookEnabled reports whether the SES bounce/complaint webhook is configured.
func (c *Config) SESHookEnabled() bool { return c.SESTopicARN != "" }

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
	From     string // SMTP_FROM, e.g. "p.stonn <notifications@example.com>" (shown as the sender)
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

	// SessionMaxAge bounds how long an account may sit IDLE before the user must
	// re-authorise (re-link). It is the safety limit so a departed household's
	// plate is not changed forever: measured from the last time anyone on the
	// account used the app (see store.TouchAccountActive) or clicked the confirm
	// email, after which we stop renewing, let the session lapse, and the dashboard
	// prompts a re-link. Deliberately NOT measured from the original link: this is
	// set-and-forget software, so a household using it every week would otherwise
	// be retired on schedule while one that moved away a year ago looked identical
	// to one that linked yesterday. COUNCIL_SESSION_MAX_AGE_DAYS, default 90.
	SessionMaxAge time.Duration

	// WarmInterval is how stale a still-valid session may get before keep-warm
	// silent-renews it (sliding the council cookie so an idle, set-and-forget
	// user's session does not lapse). COUNCIL_WARM_INTERVAL, default 1h45m ≈ 0.7×
	// the measured proven-safe idle window of ~2h32m (session dies by ~3h48m).
	// The 0.7 ratio (vs a more cautious 0.5) trades ~30% fewer council touches for
	// less headroom; the keep-warm loop compensates by retrying a failed or
	// pushback-deferred renew every few minutes rather than once per interval, so
	// the narrower margin to the ~3h48m cliff is never exposed to a single missed
	// pass. See scheduler.warmLoop.
	WarmInterval time.Duration

	// ReminderLead is how far before the SessionMaxAge deadline to email the user
	// a "confirm you're still using this" link. COUNCIL_REMINDER_LEAD_DAYS,
	// default 7.
	ReminderLead time.Duration

	// ExpiryLead is how far before a permit's own expiry date to warn the account
	// so they can renew it with the council. COUNCIL_EXPIRY_LEAD_DAYS, default 14.
	ExpiryLead time.Duration
	// Sandbox (COUNCIL_SANDBOX=1) fakes the council in memory for local
	// development: any login links, and plate changes land after a short delay so
	// the pending → settled UX runs end to end. Never set in production.
	Sandbox bool
}

// Load reads and validates configuration from the environment.
func Load() (*Config, error) {
	// Set-but-invalid numeric/duration values are an error, not a silent
	// fallback: these tune session-survival behavior (warm interval, max age),
	// where running with an unintended default misbehaves subtly. The closures
	// shadow the lenient package helpers and collect the first parse error.
	var envErr error
	envInt := func(key string, def int) int {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			if envErr == nil {
				envErr = fmt.Errorf("%s: need a non-negative integer, got %q", key, v)
			}
			return def
		}
		return n
	}
	envDuration := func(key string, def time.Duration) time.Duration {
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			if envErr == nil {
				envErr = fmt.Errorf("%s: need a positive Go duration (e.g. \"75m\"), got %q", key, v)
			}
			return def
		}
		return d
	}
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
			WarmInterval:  envDuration("COUNCIL_WARM_INTERVAL", 105*time.Minute),
			Sandbox:       env("COUNCIL_SANDBOX", "") == "1" || env("COUNCIL_SANDBOX", "") == "true",
			ReminderLead:  time.Duration(envInt("COUNCIL_REMINDER_LEAD_DAYS", 7)) * 24 * time.Hour,
			ExpiryLead:    time.Duration(envInt("COUNCIL_EXPIRY_LEAD_DAYS", 14)) * 24 * time.Hour,
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
		MaxAccounts:    envInt("MAX_ACCOUNTS", 0),
		SESTopicARN:    strings.TrimSpace(os.Getenv("SES_SNS_TOPIC_ARN")),
		AppOIDC: AppOIDCConfig{
			Issuer:       strings.TrimRight(os.Getenv("APP_OIDC_ISSUER"), "/"),
			ClientID:     os.Getenv("APP_OIDC_CLIENT_ID"),
			ClientSecret: os.Getenv("APP_OIDC_CLIENT_SECRET"),
			RedirectURI:  os.Getenv("APP_OIDC_REDIRECT_URI"),
			Scopes:       strings.Fields(env("APP_OIDC_SCOPES", "openid profile email groups")),
			AdminGroups:  splitCSV(env("APP_ADMIN_GROUPS", "")),
		},
	}

	if envErr != nil {
		return nil, envErr
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

	if raw := strings.TrimSpace(os.Getenv("ROSTER_KEY")); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("ROSTER_KEY: not valid hex: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("ROSTER_KEY: need 32 bytes (64 hex chars), got %d", len(key))
		}
		cfg.RosterKey = key
	}

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

	// DEV_IDENTITY_EMAIL authenticates every request as that user with the admin
	// group and puts the at-rest cipher into ephemeral-key mode — a full auth
	// bypass if it ever ships in production. Refuse to start when it is set
	// alongside any production signal (a real encryption key or a configured OIDC
	// login), so it can never silently coexist with a real deployment.
	if cfg.DevIdentityEmail != "" {
		if len(cfg.DataEncryptionKey) == 32 {
			return nil, fmt.Errorf("DEV_IDENTITY_EMAIL must not be set together with DATA_ENCRYPTION_KEY: it bypasses authentication (every request becomes an admin). Unset it for production")
		}
		if cfg.AppOIDC.Enabled() {
			return nil, fmt.Errorf("DEV_IDENTITY_EMAIL must not be set together with APP_OIDC_ISSUER: it bypasses the OIDC login (every request becomes an admin). Unset it for production")
		}
	}

	// COUNCIL_SANDBOX fakes the council in memory: logins "link" and plate
	// changes "land" without anything reaching Stonnington. If it leaked into a
	// production deployment users would see confirmations for changes that never
	// happened, so refuse to start when it coexists with any production signal
	// (same shape as the DEV_IDENTITY_EMAIL guard above).
	if cfg.Council.Sandbox {
		if len(cfg.DataEncryptionKey) == 32 {
			return nil, fmt.Errorf("COUNCIL_SANDBOX must not be set together with DATA_ENCRYPTION_KEY: it fakes the council, so no plate change would reach Stonnington. Unset it for production")
		}
		if cfg.AppOIDC.Enabled() {
			return nil, fmt.Errorf("COUNCIL_SANDBOX must not be set together with APP_OIDC_ISSUER: it fakes the council, so no plate change would reach Stonnington. Unset it for production")
		}
	}

	// Address and token sanity. These are all operator-supplied and every one of
	// them fails SILENTLY when mistyped: a bad SMTP_FROM makes every send bounce
	// somewhere nobody reads, a bad ADMIN_EMAIL means systemic alerts vanish, and a
	// short STATUS_TOKEN weakens the only gate on the outage endpoint. Refusing to
	// start is much kinder than discovering it during an incident.
	if cfg.SMTP.Enabled() {
		if _, err := mail.ParseAddress(cfg.SMTP.From); err != nil {
			return nil, fmt.Errorf("SMTP_FROM (%q) is not a valid email address: %w", cfg.SMTP.From, err)
		}
	}
	for name, addr := range map[string]string{"ADMIN_EMAIL": cfg.AdminEmail, "CONTACT_TO": cfg.ContactTo} {
		if addr == "" {
			continue
		}
		if _, err := mail.ParseAddress(addr); err != nil {
			return nil, fmt.Errorf("%s (%q) is not a valid email address: %w", name, addr, err)
		}
	}
	// A guessable status token would expose the user roster; the endpoint has no
	// attempt throttle, so length is the defence.
	if cfg.StatusToken != "" && len(cfg.StatusToken) < 24 {
		return nil, fmt.Errorf("STATUS_TOKEN is too short (%d chars): use at least 24 random characters, e.g. openssl rand -hex 24", len(cfg.StatusToken))
	}

	return cfg, nil
}

// MailDomainMismatch reports the sending domain and the app's own domain when
// they differ, so main can warn. Mail whose From domain is unrelated to the links
// inside it is the exact shape receivers score as phishing, and DMARC alignment
// is judged on that domain — but plenty of legitimate setups relay through a
// subdomain, so this is a warning, never a refusal to start.
func (c *Config) MailDomainMismatch() (fromDomain, appDomain string, mismatch bool) {
	if !c.SMTP.Enabled() || c.PublicBaseURL == "" {
		return "", "", false
	}
	addr, err := mail.ParseAddress(c.SMTP.From)
	if err != nil {
		return "", "", false
	}
	at := strings.LastIndex(addr.Address, "@")
	if at < 0 {
		return "", "", false
	}
	fromDomain = strings.ToLower(addr.Address[at+1:])
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || u.Hostname() == "" {
		return "", "", false
	}
	appDomain = strings.ToLower(u.Hostname())
	// Compare registrable-ish suffixes: p.stonn.org sending as no-reply@stonn.org
	// is aligned in every way that matters, so only flag genuinely unrelated ones.
	return fromDomain, appDomain, !sharesParentDomain(fromDomain, appDomain)
}

// sharesParentDomain reports whether two hosts share a registrable parent
// (example.org vs mail.example.org → true; example.org vs other.net → false).
//
// Comparing the last two labels alone is wrong under a multi-label public suffix:
// p.stonn.com.au and some-relay.com.au both reduce to "com.au" and would look
// aligned when they are unrelated domains with unrelated DMARC policies. That is
// the likely shape for an Australian deployment, i.e. exactly the case this
// warning exists for, so take one label more whenever the last two are a known
// multi-label suffix.
func sharesParentDomain(a, b string) bool {
	return registrable(a) == registrable(b)
}

// multiLabelSuffixes are public suffixes that are themselves two labels, so the
// registrable domain under them needs three. Not exhaustive (the full Public
// Suffix List is thousands of entries and not worth vendoring for a startup
// warning) — it covers the ones this app plausibly meets.
var multiLabelSuffixes = map[string]bool{
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true,
	"co.uk": true, "org.uk": true, "me.uk": true, "ac.uk": true, "gov.uk": true,
	"co.nz": true, "net.nz": true, "org.nz": true,
	"com.sg": true, "com.hk": true, "co.jp": true, "co.za": true, "com.br": true,
}

// registrable returns the registrable domain: the public suffix plus one label.
func registrable(host string) string {
	parts := strings.Split(strings.Trim(strings.ToLower(host), "."), ".")
	if len(parts) < 2 {
		return strings.Join(parts, ".")
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if multiLabelSuffixes[last2] && len(parts) >= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
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
