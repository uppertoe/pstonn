# p.stonn

Visitor parking permit scheduler for the City of Stonnington ePermits system.

A shared visitor permit only holds one number plate at a time. Instead of logging
into the council portal and re-typing a plate every time a different car needs it,
you set a weekly roster (which registration is on the permit each day) plus any
one-off overrides, and p.stonn applies the change for you and tells you when it
has done so.

## How it works

**App sign-in** goes through the platform's forward-auth layer (vps-scaffold-auth).
A user signs in with a one-time code sent to their email address, so every account
is tied to a verified address on any domain. The app reads the `Remote-User`,
`Remote-Email` and `Remote-Groups` headers that the auth layer sets after a
successful login. There is no password to store and no separate account to create.
See `internal/server` and `internal/config`.

**Linking a council account** is a headless login against the council's Duende
IdentityServer. The council issues no refresh tokens, so the durable secret is the
IdentityServer session cookie. p.stonn encrypts that cookie at rest with
AES-256-GCM (a 32-byte `DATA_ENCRYPTION_KEY`) and never stores the council
password. Access tokens are short-lived and minted on demand by a silent renew
(a `prompt=none` authorize against the live session). The council username is
pinned to the user's own verified email, so a user can only link their own
account. See `internal/parking`.

**Keeping the session alive.** The council session lapses if left idle. A
keep-warm loop silently renews idle-but-valid sessions before they expire, on a
measured interval well under the idle window, with jitter and rate limiting, and
it skips users who have nothing scheduled. Each linked session is kept warm for at
most 90 days from the last interactive link; a one-click confirm email goes out
before that deadline, and if a user stops confirming, renewal stops. See
`internal/scheduler`.

**Scheduling** is a reconcile loop. Every minute, and immediately after any edit,
it works out the target plate for each permit from its roster and active
overrides, and if that differs from the plate currently on the permit it applies
the change and records it. The loop is stateless across restarts, so a missed
tick corrects itself on the next run.

**Notifications.** A missed change can mean a fine, so users are told about every
plate change and every failure. Each user picks their channels in Settings: email
(any SMTP provider) and ntfy push (a private auto-generated topic). At least one
channel must stay enabled. Delivery is tracked: an undelivered notification is
retried on the next tick (it never becomes the dedup key), and if a user can't be
reached the operator is alerted. A lapsed council session proactively prompts the
user to re-link rather than failing silently. Account disconnection always emails
the verified address. See `internal/notify` and `internal/mailer`.

**Admin alerts.** Systemic failures the operator must know about (a council
API-shape change, a notification that couldn't be delivered, keep-warm collapse,
a scheduler panic or stall, DB errors) are sent to `ADMIN_EMAIL` and/or
`ADMIN_NTFY_TOPIC`, both tried so one being down doesn't blind you. The scheduler
loops recover from panics and a watchdog alerts if reconcile stalls.

**Acting like a normal browser.** Council traffic presents a real Chrome
User-Agent and browser headers (never Go's default), spaces and jitters its
requests, serialises per-user session renews, and backs off with a cooldown when
the portal (Akamai) pushes back (429/403/503), so a soft block isn't hammered
into a hard one. The TLS fingerprint is still Go's; see `internal/parking/browser.go`.

**Terms.** Sign-up records which version of the terms a user agreed to. The terms
live in markdown (`internal/server/terms.md`, overridable at `TERMS_PATH`); their
sha256 hash is stored with each consent in an append-only audit table. Editing the
terms or bumping the version re-prompts everyone. A user who declines the new
terms has their council account disconnected, not just logged out, and is
notified.

**Contact.** An optional public contact form (`/contact`) lets people reach the
operator without exposing an address. It posts to the server, which relays the
message over the same SMTP as notifications to `CONTACT_TO` (a private address,
never shown), with the sender's address as `Reply-To` if they give one. The form
is rate-limited per IP and carries a honeypot, and it only appears when
`CONTACT_TO` and SMTP are both set. See `internal/server/contact.go`.

**Storage** is SQLite (`modernc.org/sqlite`, pure Go, no cgo, WAL) on a `/data`
volume. **UI** is server-rendered `html/template` with htmx and Alpine.js: a
public landing page, about page and contact form, an onboarding flow, and the app
itself (schedule roster, vehicles, activity log, settings).

## Run locally

```bash
# No auth layer needed locally: use the dev identity escape hatch.
# COUNCIL_SANDBOX=1 fakes the council in memory (any login links; plate changes
# land after ~6s) so the full apply pipeline works without council credentials.
COUNCIL_SANDBOX=1 DEV_IDENTITY_EMAIL=you@example.com \
  DATA_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  COOKIE_SECURE=false LISTEN_ADDR=127.0.0.1:8099 SQLITE_PATH=./local.db \
  go run .
# open http://127.0.0.1:8099
go test ./...
```

## CI and image publishing

`.github/workflows/ci.yml` runs `go vet`, `go test -race`, a `CGO_ENABLED=0`
build, a gofmt check and `govulncheck` on every push and pull request. On pushes
to `main` and on version tags it builds a multi-arch image (amd64 and arm64),
loads it locally and smoke-tests that it boots and serves `/healthz` before
pushing to `ghcr.io/uppertoe/pstonn`. A weekly scheduled run rebuilds so
base-image security fixes are picked up. All action versions are pinned by commit
SHA.

## Deploy into the vps-scaffold platform

1. Push the image (CI does this) and confirm `ghcr.io/uppertoe/pstonn` is in the
   server repo's `renovate.json5` first-party list.
2. Copy `deploy/` into the server repo as `apps/pstonn/` (`docker-compose.yml`,
   `.env.example`, `pstonn.caddy`). Copy `deploy/backup-service.env.example` to
   `backup/services/pstonn.env`.
3. Add `- apps/pstonn/docker-compose.yml` to the root `docker-compose.yml`
   `include:` list, run `bash scaffold/docker/render-caddy-routes.sh`, and commit
   `.generated/`.
4. Create `apps/pstonn/.env` (mode 600) from the example and set
   `DATA_ENCRYPTION_KEY` (required: the app refuses to start in production
   without it), the SMTP and ntfy settings, `ADMIN_EMAIL` / `ADMIN_NTFY_TOPIC`
   for operator alerts, `CONTACT_TO` if you want the contact form, and any
   council overrides. Pin the image by `@sha256` (the CI image-pins job enforces
   this).
5. Add DNS for `p.<domain>` and deploy.

Config reference: [`deploy/.env.example`](deploy/.env.example).
