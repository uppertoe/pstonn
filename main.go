// Command pstonn schedules which vehicle registration is allocated to a City of
// Stonnington visitor parking permit. It runs an always-on desired-state loop
// plus a small web UI, and drives the council API from a stored, encrypted
// council session cookie. User login is via forward_auth headers (or its own
// OIDC relying party).
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	// Embed the IANA timezone database so DISPLAY_TIMEZONE (time.LoadLocation)
	// works on the distroless/static image, which ships no /usr/share/zoneinfo.
	_ "time/tzdata"

	"flag"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/server"
	"github.com/uppertoe/pstonn/internal/session"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/webauth"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit")
	flag.Parse()
	if *healthcheck {
		os.Exit(runHealthcheck())
	}
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	box, err := buildSecretBox(cfg)
	if err != nil {
		return fmt.Errorf("secretbox: %w", err)
	}

	st, err := store.OpenSQLite(cfg.SQLitePath)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	// One-time: lock in existing vehicles' current colours so later additions
	// don't re-shuffle them (safe/idempotent after the first run).
	if err := st.BackfillVehicleColors(context.Background()); err != nil {
		log.Printf("startup: backfill vehicle colours: %v", err)
	}

	var sessions *session.Manager
	if len(cfg.SessionSecret) > 0 {
		sessions = session.New(cfg.SessionSecret, cfg.CookieSecure)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	auth, err := webauth.New(ctx, cfg, st, sessions)
	if err != nil {
		return fmt.Errorf("oidc login: %w", err)
	}
	if auth == nil {
		log.Print("APP_OIDC_ISSUER not set: OIDC login disabled; relying on forward_auth headers or DEV_IDENTITY_EMAIL")
	}

	council := parking.New(cfg, st, box)
	if cfg.Council.Sandbox {
		log.Print("WARNING: COUNCIL_SANDBOX is on — the council is FAKED in memory (dev/demo only; nothing reaches the real portal)")
	}
	mail := mailer.New(cfg.SMTP)
	notifier := notify.New(st, mail, cfg.Ntfy.BaseURL, cfg.Ntfy.Token, cfg.PublicBaseURL, cfg.AdminEmail, cfg.AdminNtfyTopic, cfg.DisplayLocation)
	log.Printf("notifications: email=%v ntfy=%v contact-form=%v admin-alerts=%v", mail.Enabled(), cfg.Ntfy.Enabled(), cfg.ContactEnabled(), notifier.AdminConfigured())
	if !notifier.AdminConfigured() {
		log.Print("WARNING: no admin alert channel configured (set ADMIN_EMAIL and/or ADMIN_NTFY_TOPIC); systemic failures will only be logged")
	}
	sched := scheduler.New(st, council, cfg.DisplayLocation, scheduler.Options{
		SessionMaxAge: cfg.Council.SessionMaxAge,
		WarmInterval:  cfg.Council.WarmInterval,
		ReminderLead:  cfg.Council.ReminderLead,
		ExpiryLead:    cfg.Council.ExpiryLead,
		PublicBaseURL: cfg.PublicBaseURL,
		Notifier:      notifier,
		RateDelay:     3 * time.Second,
	})
	srv := server.New(cfg, st, sessions, auth, council, sched, notifier, mail, box)

	go sched.Run(ctx)
	go notifier.RunOutbox(ctx) // drain the durable notification queue with retry/backoff

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (timezone: %s, oidc login: %v)", cfg.ListenAddr, cfg.DisplayLocation, auth != nil)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Print("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}

// buildSecretBox builds the at-rest cipher from DATA_ENCRYPTION_KEY.
//
// A dedicated key is REQUIRED in production. Without one we would otherwise fall
// back to an ephemeral key that changes every restart, silently making every
// stored council session undecryptable (users appear linked but nothing applies).
// So a missing key is fatal unless the app is in local/dev mode
// (DEV_IDENTITY_EMAIL set), where an ephemeral key is acceptable for iteration.
// We deliberately do NOT derive the key from SESSION_SECRET: coupling the two
// means rotating the cookie-signing secret would brick every stored session.
func buildSecretBox(cfg *config.Config) (*secretbox.Box, error) {
	if len(cfg.DataEncryptionKey) == 32 {
		return secretbox.New(cfg.DataEncryptionKey)
	}
	if cfg.DevIdentityEmail == "" {
		return nil, errors.New("DATA_ENCRYPTION_KEY is required in production: set it to 64 hex chars (openssl rand -hex 32). " +
			"Without it, stored council sessions cannot survive a restart.")
	}
	log.Print("WARNING: DATA_ENCRYPTION_KEY not set; using an ephemeral key (DEV_IDENTITY_EMAIL is set, so local/dev mode). " +
		"Stored council sessions will not survive a restart.")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return secretbox.New(key)
}

func runHealthcheck() int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	url := "http://127.0.0.1" + addr + "/healthz"
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
