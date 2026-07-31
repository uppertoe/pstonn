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
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
		// Seed the revocation generations so cookies issued before someone lost access
		// (or had their account deleted) are refused across a restart too. Only people
		// who have actually had something revoked have a row, so this is tiny.
		if epochs, err := st.AllSessionEpochs(context.Background()); err != nil {
			// Failing open here would silently un-revoke every past revocation, so refuse
			// to start rather than serve sessions we cannot vouch for.
			return fmt.Errorf("load session epochs: %w", err)
		} else {
			sessions.SetEpochs(epochs)
		}
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
	// Unsubscribe links are signed with a key derived from the at-rest key, so no
	// per-recipient row is needed to offer an opt-out to people with no account.
	unsubKey := notify.DeriveUnsubKey(cfg.DataEncryptionKey)
	notifier := notify.New(st, mail, cfg.Ntfy.BaseURL, cfg.Ntfy.Token, cfg.PublicBaseURL, cfg.AdminEmail, cfg.AdminNtfyTopic, cfg.DisplayLocation, unsubKey)
	log.Printf("notifications: email=%v ntfy=%v contact-form=%v admin-alerts=%v", mail.Enabled(), cfg.Ntfy.Enabled(), cfg.ContactEnabled(), notifier.AdminConfigured())
	if !notifier.AdminConfigured() {
		log.Print("WARNING: no admin alert channel configured (set ADMIN_EMAIL and/or ADMIN_NTFY_TOPIC); systemic failures will only be logged")
	}
	if from, app, mismatch := cfg.MailDomainMismatch(); mismatch {
		log.Printf("WARNING: mail is sent from %q but the app is served at %q. Receivers judge DMARC alignment on the From domain, "+
			"and mail whose sender is unrelated to the links inside it is scored as phishing. Prefer a From on %s, and publish SPF/DKIM/DMARC for the sending domain.", from, app, app)
	}
	if !cfg.SESHookEnabled() && mail.Enabled() {
		log.Print("NOTE: SES_SNS_TOPIC_ARN not set, so bounce/complaint feedback is not wired up. " +
			"Hard SMTP rejections are still learned at send time, but provider-reported bounces are not. See deploy/aws-ses-hook-setup.py")
	}
	sched := scheduler.New(st, council, cfg.DisplayLocation, scheduler.Options{
		SessionMaxAge: cfg.Council.SessionMaxAge,
		WarmInterval:  cfg.Council.WarmInterval,
		ReminderLead:  cfg.Council.ReminderLead,
		ExpiryLead:    cfg.Council.ExpiryLead,
		PublicBaseURL: cfg.PublicBaseURL,
		Notifier:      notifier,
		RateDelay:     3 * time.Second,
		// A daily consistent snapshot next to the live DB: the restic files-only
		// backup of the volume can catch the live db + WAL mid-write, but this
		// file is always a coherent database to restore from.
		SnapshotPath: filepath.Join(filepath.Dir(cfg.SQLitePath), "backup-snapshot.db"),
	})
	srv := server.New(cfg, st, sessions, auth, council, sched, notifier, mail, box)

	// Track the worker loops so shutdown can join them: st.Close() runs on
	// return from this function, and closing the store under a loop that is
	// mid-DB-call (or mid-council-write) could truncate an in-flight apply.
	loopsDone := make(chan struct{}, 2)
	go func() { sched.Run(ctx); loopsDone <- struct{}{} }()
	go func() { notifier.RunOutbox(ctx); loopsDone <- struct{}{} }() // drain the durable notification queue with retry/backoff

	// Hourly council-traffic summary so the operator can see how often the app
	// actually touches the portal (renews, applies, background plate refreshes —
	// page renders never call the council synchronously). Quiet hours log nothing.
	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		var pl, pa, pi, po uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				l, a, api, o := council.Traffic()
				if d := (l - pl) + (a - pa) + (api - pi) + (o - po); d > 0 {
					log.Printf("council traffic: %d requests last hour (login=%d auth=%d api=%d other=%d); since start: login=%d auth=%d api=%d other=%d",
						d, l-pl, a-pa, api-pi, o-po, l, a, api, o)
				}
				pl, pa, pi, po = l, a, api, o
			}
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Default is 1 MB of headers; nothing here needs more than a few KB, and
		// the public endpoints are reachable by anyone holding a printed poster.
		MaxHeaderBytes: 32 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s (timezone: %s, oidc login: %v)", cfg.ListenAddr, cfg.DisplayLocation, auth != nil)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// joinLoops waits for the worker loops to return so the deferred st.Close() does
	// not land under an in-flight DB call or a half-applied council write. It takes
	// its OWN deadline rather than sharing the HTTP drain's: a slow drain used to
	// consume nearly all of a single budget and leave the loops a fraction of a
	// second, which tripped the "did not stop in time" path during entirely normal
	// shutdowns. A reconcile pass legitimately sleeps seconds between permits.
	joinLoops := func() {
		joinCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for i := 0; i < cap(loopsDone); i++ {
			select {
			case <-loopsDone:
			case <-joinCtx.Done():
				log.Print("shutdown: worker loops did not stop in time; closing the store anyway")
				return
			}
		}
	}

	select {
	case err := <-errCh:
		// The listener failed (a port clash after a config edit is the usual cause).
		// This path used to return immediately, running the deferred st.Close() while
		// the startup reconcile could still be mid-council-write. Stop the loops first,
		// then let the deferred close run.
		stop()
		joinLoops()
		return err
	case <-ctx.Done():
		log.Print("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		joinLoops()
		return err
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
	// Extract just the port: LISTEN_ADDR may include a host (e.g. 0.0.0.0:8080),
	// and naive concatenation would build a garbage URL — a healthcheck that can
	// never pass means a permanent container restart loop.
	port := "8080"
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		port = p
	}
	url := "http://127.0.0.1:" + port + "/healthz"
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
