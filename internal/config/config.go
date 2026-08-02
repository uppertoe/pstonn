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
	"net"
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
	// them, and rosters roll at a common wall-clock boundary, so the last household's
	// midnight change lands late in proportion to the fleet.
	//
	// That latency is no longer an implicit cliff to be guessed at. The rollover
	// window (RolloverWindow) makes it deliberate and bounded, and startup logs the
	// actual convergence bound for the permits on file — so the question "is this
	// many accounts still acceptable?" is now answered by that number rather than by
	// this cap. Raising MaxAccounts is safe as long as the logged bound stays inside
	// what a roster can tolerate; it is the bound, not the account count, to watch.
	MaxAccounts int

	// RosterKey seals the user roster in the /status payload (32 bytes, 64 hex, via
	// ROSTER_KEY). The outage watchdog holds the same key and decrypts it.
	//
	// Without this the roster — every consented account's email plus their push
	// topic — travels and sits in the response in the clear, so one leaked
	// STATUS_TOKEN yields the entire user list and a live read capability on
	// everyone's notifications. With it, a leaked token yields ciphertext.
	//
	// It is therefore REQUIRED whenever StatusToken is set (Load refuses to start
	// otherwise). There used to be a transitional allowance, warning at startup and
	// serving plaintext, so the app could be deployed before the watchdog learned
	// the sealed shape; that rollout is finished, and an allowance nobody needs is
	// just a way for a plaintext roster to come back unnoticed.
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
	// silent-renews it (sliding the council cookie so an idle, set-and-forget user's
	// session does not lapse). COUNCIL_WARM_INTERVAL, default 1h45m. Fewer touches
	// means a longer interval, and the scheduler makes that safe rather than
	// dangerous: the effective threshold is jittered only DOWNWARD and hard-clamped
	// to IdleWindow-WarmSafetyMargin, so it can be raised toward the idle window
	// without ever letting a session lapse before its first renew, and the keep-warm
	// loop retries a failed or pushback-deferred renew every few minutes (not once
	// per interval) so the remaining margin is never spent on a single missed pass.
	// See scheduler.warmThresholdFor and scheduler.warmLoop. Raise it once the clean
	// idle-timeout measurement brackets the real window.
	WarmInterval time.Duration

	// IdleWindow is the ESTIMATED council session idle timeout. It is the anchor for
	// two things: the warm-margin metrics on /status (how close sessions are to
	// lapsing, so the watchdog can alert before a council outage near the cliff
	// creates a reconnect backlog), AND the keep-warm safety clamp — the scheduler
	// never lets a session's warm threshold sit within WarmSafetyMargin of this, so
	// COUNCIL_WARM_INTERVAL can be raised toward the window without risking a lapse
	// before the first renew attempt. COUNCIL_IDLE_WINDOW, default 10h — the Duende
	// IdentityServer default CookieLifetime, consistent with a live probe that
	// survived a 7h+ gap; set it to the measured value once the clean run brackets it.
	IdleWindow time.Duration

	// WarmSafetyMargin is the minimum gap the scheduler guarantees between a
	// session's warm threshold and IdleWindow: the effective threshold is capped at
	// IdleWindow - WarmSafetyMargin however high WarmInterval is set. This is the
	// runway the fast recovery tick (every ~3 min) has to retry a failed renew before
	// the cookie would actually lapse, so it must comfortably exceed a few ticks.
	// COUNCIL_WARM_SAFETY_MARGIN, default 1h (≈20 recovery attempts at a 10h window).
	WarmSafetyMargin time.Duration

	// ExpiryWarningMargin is the danger zone for the /status near_expiry metric: a
	// maintained session whose estimated margin (IdleWindow - age) falls below this
	// is counted, so the watchdog can alert on a forming backlog. Kept SEPARATE from
	// WarmInterval — coupling them meant a longer warm interval would flag healthy
	// sessions hours before their renew was even due. COUNCIL_EXPIRY_WARNING_MARGIN,
	// default 2h (should stay above WarmSafetyMargin so the alert precedes the clamp).
	ExpiryWarningMargin time.Duration

	// DriftInterval is how often the owner-grid drift/expiry read runs, on its own
	// per-owner cadence decoupled from keep-warm. COUNCIL_DRIFT_INTERVAL, default 6h.
	// It used to piggyback on every keep-warm (~105 min), doubling the auth-warm
	// traffic for a check that catches a rare event (an external portal edit); the
	// per-minute reconcile still enforces the desired plate regardless. 0 disables
	// drift reads entirely.
	DriftInterval time.Duration

	// Governor limits: the transport-level CEILING on outbound council traffic and
	// the SINGLE throughput authority (there is no separate per-operation pacing —
	// requests that would exceed these simply wait). All 500 households share one
	// egress IP, so this bounds what that IP presents to Azure Front Door. The
	// defaults are ~6x the steady-state floor: a generous ceiling, not a target. The
	// rollover spread window derives from GovRatePerMin too (see scheduler), so
	// raising the rate for a larger fleet is a single knob — no other retuning.
	//   COUNCIL_GOV_RATE          total requests/min across all surfaces (default 60)
	//   COUNCIL_GOV_BURST         total burst allowance                  (default 10)
	//   COUNCIL_GOV_LOGIN_RATE    credential-login surface requests/min  (default 12)
	//   COUNCIL_GOV_LOGIN_BURST   login burst (one full login ≈ 6 reqs)  (default 6)
	//   COUNCIL_GOV_CONCURRENCY   max simultaneous council requests       (default 4)
	GovRatePerMin      int
	GovBurst           int
	GovLoginRatePerMin int
	GovLoginBurst      int
	GovConcurrency     int

	// RolloverWindow staggers SCHEDULED plate changes across a window opening at
	// the schedule boundary, capped at this value. COUNCIL_ROLLOVER_WINDOW, default
	// 60m. The window SCALES with the fleet (see scheduler.effectiveSpread), so this
	// is a ceiling on how stale a permit may get, not a fixed delay: a handful of
	// permits spread over seconds, a large fleet up to this cap.
	//
	// Rosters are written in human hours, so households share a handful of
	// boundaries and overwhelmingly midnight; applied the moment they fall due,
	// every household's change leaves this one IP back to back. Spreading them is
	// the cheapest way to stop the largest burst we produce looking like abuse.
	//
	// The price is precision: between the boundary and its slot a permit still
	// shows the previous day's plate. That is acceptable for a roster whose car
	// arrives hours later and NOT acceptable for a change someone is waiting on, so
	// only clock-driven changes are spread (model.Resolution.Scheduled) — a booking
	// or guest activation still applies on the next tick.
	//
	// Below the serial drain implied by the governor rate (permits × per-operation
	// drain) the window buys nothing, because that drain is already the constraint;
	// startup logs the resulting convergence bound and says so. 0 disables spreading
	// entirely.
	RolloverWindow time.Duration

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
			Issuer:              env("COUNCIL_ISSUER", "https://parkingpermits.stonnington.vic.gov.au/idm"),
			ClientID:            env("COUNCIL_CLIENT_ID", "ePermits.ssp.web"),
			RedirectURI:         env("COUNCIL_REDIRECT_URI", "https://parkingpermits.stonnington.vic.gov.au/ssp/callback"),
			Scopes:              strings.Fields(env("COUNCIL_SCOPES", "openid profile ePermits.ssp.api.all")),
			APIBase:             env("COUNCIL_API_BASE", "https://parkingpermits.stonnington.vic.gov.au/ssp-svc"),
			SessionMaxAge:       time.Duration(envInt("COUNCIL_SESSION_MAX_AGE_DAYS", 90)) * 24 * time.Hour,
			WarmInterval:        envDuration("COUNCIL_WARM_INTERVAL", 105*time.Minute),
			RolloverWindow:      envDuration("COUNCIL_ROLLOVER_WINDOW", 60*time.Minute),
			DriftInterval:       envDuration("COUNCIL_DRIFT_INTERVAL", 6*time.Hour),
			IdleWindow:          envDuration("COUNCIL_IDLE_WINDOW", 10*time.Hour),
			WarmSafetyMargin:    envDuration("COUNCIL_WARM_SAFETY_MARGIN", time.Hour),
			ExpiryWarningMargin: envDuration("COUNCIL_EXPIRY_WARNING_MARGIN", 2*time.Hour),
			GovRatePerMin:       envInt("COUNCIL_GOV_RATE", 60),
			GovBurst:            envInt("COUNCIL_GOV_BURST", 10),
			GovLoginRatePerMin:  envInt("COUNCIL_GOV_LOGIN_RATE", 12),
			GovLoginBurst:       envInt("COUNCIL_GOV_LOGIN_BURST", 6),
			GovConcurrency:      envInt("COUNCIL_GOV_CONCURRENCY", 4),
			Sandbox:             env("COUNCIL_SANDBOX", "") == "1" || env("COUNCIL_SANDBOX", "") == "true",
			ReminderLead:        time.Duration(envInt("COUNCIL_REMINDER_LEAD_DAYS", 7)) * 24 * time.Hour,
			ExpiryLead:          time.Duration(envInt("COUNCIL_EXPIRY_LEAD_DAYS", 14)) * 24 * time.Hour,
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
		key, err := hexKey("ROSTER_KEY", raw)
		if err != nil {
			return nil, err
		}
		cfg.RosterKey = key
	}

	if raw := strings.TrimSpace(os.Getenv("DATA_ENCRYPTION_KEY")); raw != "" {
		key, err := hexKey("DATA_ENCRYPTION_KEY", raw)
		if err != nil {
			return nil, err
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

	// PUBLIC_BASE_URL is how every link the app mints leaves the machine: the
	// re-authorise confirm link in the reminder email, the guest-pass links, the
	// door-QR URL. It is concatenated with a path, so a value that is not an
	// absolute http(s) URL with a host does not fail — it produces a link that is
	// merely wrong. A relative href in an email is not a link at all, and the
	// reminder email exists precisely to stop a session lapsing, so the failure
	// mode is the one thing the feature is for.
	if cfg.PublicBaseURL != "" {
		u, err := url.Parse(cfg.PublicBaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("PUBLIC_BASE_URL (%q, or the value derived from DOMAIN) must be an absolute http(s) URL with a host, e.g. https://p.example.com", cfg.PublicBaseURL)
		}
	}

	// Local runs are the one posture where an empty base is tolerable: every link
	// is then a same-origin relative path, which a browser resolves correctly, and
	// no mail goes anywhere real. Any other deployment must have one, and must find
	// out now rather than in the mail nobody could click — the alternative, erroring
	// only when a link is minted, surfaces weeks later inside a scheduler pass whose
	// failure is invisible to the person it concerns.
	localOnly := cfg.DevIdentityEmail != "" || cfg.Council.Sandbox
	if cfg.PublicBaseURL == "" && !localOnly {
		return nil, fmt.Errorf("PUBLIC_BASE_URL must be set (or DOMAIN, from which https://p.<DOMAIN> is derived): the confirm, guest-pass and door-QR links are absolute URLs, and without a base they are relative and unusable in email")
	}

	// DEV_IDENTITY_EMAIL authenticates every request as that user with the admin
	// group and puts the at-rest cipher into ephemeral-key mode — a full auth
	// bypass if it ever ships in production. Refuse to start when it is set
	// alongside anything that means "real deployment", so it can never silently
	// coexist with one.
	if cfg.DevIdentityEmail != "" {
		if sig := productionSignal(cfg); sig != "" {
			return nil, fmt.Errorf("DEV_IDENTITY_EMAIL must not be set together with %s: it bypasses authentication (every request becomes an admin, with the group list [\"user\",\"admin\"]). Unset it for production", sig)
		}
	}

	// COUNCIL_SANDBOX fakes the council in memory: logins "link" and plate
	// changes "land" without anything reaching Stonnington. If it leaked into a
	// production deployment users would see confirmations for changes that never
	// happened, so refuse to start on the same signals as above.
	if cfg.Council.Sandbox {
		if sig := productionSignal(cfg); sig != "" {
			return nil, fmt.Errorf("COUNCIL_SANDBOX must not be set together with %s: it fakes the council, so no plate change would reach Stonnington. Unset it for production", sig)
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
	// A guessable status token would expose the user roster. The endpoint does
	// throttle attempts per client IP, so this floor is not the only defence — but
	// the throttle is per-IP and the roster is worth a distributed guess, so keep
	// both. The error deliberately does not report the length that was rejected:
	// startup errors are logged, and the length of a live bearer token is not
	// something to write down.
	if cfg.StatusToken != "" && len(cfg.StatusToken) < 24 {
		return nil, fmt.Errorf("STATUS_TOKEN is too short: use at least 24 random characters, e.g. openssl rand -hex 24")
	}
	// The roster is the sensitive half of /status, and the watchdog needs it only
	// during an outage. Serving it unsealed puts every consented account's email
	// and private push topic behind a single bearer token, so a leak of that token
	// is a leak of the user list plus a live read on everyone's notifications.
	// Sealing it is not optional any more: the staged rollout that once allowed a
	// plaintext roster is done, and the app must not be able to fall back to it.
	if cfg.StatusToken != "" && len(cfg.RosterKey) != 32 {
		return nil, fmt.Errorf("ROSTER_KEY must be set (64 hex chars) whenever STATUS_TOKEN is: /status carries every consented account's email and push topic, and it is only ever served encrypted. Set the same key in the outage watchdog and have it request GET /status?roster=1")
	}

	// Cross-field session-lifetime invariant. The keep-warm safety clamp caps a
	// session's warm threshold at IdleWindow-WarmSafetyMargin, and ONLY when that
	// ceiling is positive; if WarmSafetyMargin >= IdleWindow the clamp silently
	// disables itself and a warm interval near or above the idle window could let a
	// set-and-forget user's session lapse before its first renewal. Refuse to start in
	// that state rather than silently stop managing a permit.
	if wc := cfg.Council; wc.IdleWindow > 0 && wc.WarmSafetyMargin >= wc.IdleWindow {
		return nil, fmt.Errorf("COUNCIL_WARM_SAFETY_MARGIN (%s) must be less than COUNCIL_IDLE_WINDOW (%s): otherwise the keep-warm safety clamp is disabled and a session could lapse before its first renewal", wc.WarmSafetyMargin, wc.IdleWindow)
	}

	return cfg, nil
}

// CouncilWarnings returns non-fatal configuration concerns for the operator log:
// field relationships that are legal but most likely a mistake. Fatal invariants are
// enforced in Load; these are surfaced (main logs them at startup) rather than
// blocking, so an unusual-but-deliberate setup can still run.
func (c CouncilConfig) CouncilWarnings() []string {
	var w []string
	if c.ExpiryWarningMargin > 0 && c.WarmSafetyMargin > 0 && c.ExpiryWarningMargin <= c.WarmSafetyMargin {
		w = append(w, fmt.Sprintf("COUNCIL_EXPIRY_WARNING_MARGIN (%s) is not above COUNCIL_WARM_SAFETY_MARGIN (%s): the near-expiry alert will not precede the warm clamp floor, so a forming reconnect backlog may go unwarned", c.ExpiryWarningMargin, c.WarmSafetyMargin))
	}
	if c.ReminderLead > 0 && c.SessionMaxAge > 0 && c.ReminderLead >= c.SessionMaxAge {
		w = append(w, fmt.Sprintf("COUNCIL_REMINDER_LEAD (%s) is not less than the session max age (%s): the re-authorise reminder would never be sent before the session is retired", c.ReminderLead, c.SessionMaxAge))
	}
	if c.GovBurst > 0 && c.GovBurst < 4 {
		w = append(w, fmt.Sprintf("COUNCIL_GOV_BURST (%d) is below one ordinary operation's ~4 requests: routine plate changes may self-throttle", c.GovBurst))
	}
	if c.GovLoginBurst > 0 && c.GovLoginBurst < 6 {
		w = append(w, fmt.Sprintf("COUNCIL_GOV_LOGIN_BURST (%d) is below one login flow's ~6 requests: logins may self-throttle", c.GovLoginBurst))
	}
	return w
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

// productionSignal names the first setting present that can only mean "this is a
// real deployment", or "" when nothing does. The two local-only escape hatches
// (DEV_IDENTITY_EMAIL, COUNCIL_SANDBOX) refuse to start beside any of them.
//
// The list is deliberately longer than the two secrets it started as. Those two
// looked like a belt-and-braces pair but were complementary only by luck: the
// recommended posture leaves APP_OIDC_ISSUER unset and signs users in through the
// forward-auth layer, so DATA_ENCRYPTION_KEY was the *sole* backstop, and an
// operator debugging a production incident by commenting out the key and setting
// the dev email would have got a fully open app — every request an admin, right
// after Caddy had correctly stripped the identity headers. DOMAIN and a
// non-loopback PUBLIC_BASE_URL cannot be explained away: they exist only because
// someone is serving this to the internet, and no local run needs them.
func productionSignal(cfg *Config) string {
	switch {
	case len(cfg.DataEncryptionKey) == 32:
		return "DATA_ENCRYPTION_KEY"
	case cfg.AppOIDC.Enabled():
		return "APP_OIDC_ISSUER"
	case cfg.Domain != "":
		return "DOMAIN"
	case cfg.PublicBaseURL != "" && !loopbackBase(cfg.PublicBaseURL):
		return "PUBLIC_BASE_URL"
	}
	return ""
}

// loopbackBase reports whether a base URL addresses this machine. Local
// development legitimately sets PUBLIC_BASE_URL to a 127.0.0.1 or localhost
// origin so guest-pass links resolve while clicking through the flow, so that
// spelling must not be read as a production signal — but a public host must.
func loopbackBase(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// hexKey decodes a 32-byte at-rest key supplied as 64 hex characters.
//
// The error deliberately says nothing about the value. encoding/hex reports the
// offending character and its index ("invalid byte: U+0058 'X' at 17"), and
// reporting the decoded length tells a reader how much of the key was accepted —
// so a wrapped error puts fragments of a live secret into the startup log, the
// container log, and whatever ships those off-host. The operator does not need
// them: there is exactly one correct shape, and it is stated.
func hexKey(name, raw string) ([]byte, error) {
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be exactly 32 bytes as 64 hex characters (generate with: openssl rand -hex 32)", name)
	}
	return key, nil
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
