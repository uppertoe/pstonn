# p.stonn

**[p.stonn.org](https://p.stonn.org)** — a free scheduler for City of Stonnington
visitor parking permits.

## The problem

A Stonnington visitor permit covers **one number plate at a time**. If different
cars use it on different days — a nanny on weekdays, grandparents on the weekend,
a friend staying over — someone has to log into the council portal and re-type
the plate at every changeover. Forget once and the person parked outside cops a
fine.

## What p.stonn does

You tell it which car should be on the permit and when; it makes the change in
the council's own system for you and confirms when it's done.

- **Weekly roster** — which registration is on the permit each day of the week.
- **One-off bookings** — override the roster for a visit, an overnight stay, a
  holiday.
- **Guest links** — send a visitor a private link so they can put their own car
  on the permit when they arrive, without an account. There's also a printable
  door QR: a visitor scans it and *requests* a plate, and nothing changes until
  you approve it from your phone.
- **Notifications** — every plate change and every failure is reported to you by
  email and/or push, so a missed change never silently costs someone a fine. The
  app confirms changes against the council's own record before claiming success.
- **Shared access** — household members can manage the same schedule.

It's free, has no ads, collects nothing it doesn't need, and doesn't sell
anything. It exists because re-typing number plates into a council portal is a
problem worth solving once, properly, for everyone. Use the hosted site at
[p.stonn.org](https://p.stonn.org) or self-host it (below).

**Is this official?** No. p.stonn is an independent community tool and is not
affiliated with or endorsed by the City of Stonnington. It automates exactly the
actions you could do yourself in the council portal, on your own account, at
your instruction — nothing more.

**Is my council password safe?** The app signs in once to obtain the council's
session cookie and then **discards your password**. The cookie (and everything
else sensitive) is encrypted at rest with AES-256-GCM. If you opt in to
auto-reconnect, the password is stored encrypted the same way — and you can
withdraw that at any time in Settings. Sessions are only kept alive for 90 days
from your last sign-in; after that you're asked to confirm you still want the
service before it continues.

## How it works

*This section is the technical detail for developers and the curious — if you
just want to use the site, the summary above is all you need.*

**App sign-in** goes through a forward-auth layer (or the app's own OIDC): a
one-time code sent to your email, so every account is tied to a verified
address. There is no app password to store. See `internal/server` and
`internal/config`.

**Linking a council account** is a headless login against the council's Duende
IdentityServer. The council issues no refresh tokens, so the durable secret is
the IdentityServer session cookie, sealed at rest. Access tokens are short-lived
and minted on demand by a silent renew (`prompt=none`). The council username is
pinned to your own verified email, so you can only ever link your own account.
See `internal/parking`.

**Keeping the session alive.** A keep-warm loop silently renews idle-but-valid
sessions before they lapse, on a measured interval well inside the observed idle
window, with jitter and rate limiting. Each linked session is kept warm for at
most 90 days from the last interactive link; a one-click confirm email goes out
before the deadline, and if you stop confirming, renewal stops. See
`internal/scheduler`.

**Scheduling** is a reconcile loop: every minute (and immediately after any
edit) it computes the target plate for each permit from the roster and active
overrides, applies any difference, and records it. Success is only reported
after the council's own record confirms the change. Stateless across restarts;
a missed tick heals on the next one.

**Notifications** are per-user (email via any SMTP provider, push via a private
ntfy topic) with quiet hours, durable retry through an outbox, and operator
escalation when a user can't be reached. A lapsed council session proactively
prompts a re-link rather than failing silently.

**Undeliverable email** is learned, not ignored. A hard SMTP rejection (5xx) at
send time is classified as permanent, so the outbox stops retrying it instead of
hammering a dead mailbox; on AWS SES, bounce and complaint events also arrive
asynchronously at `/hooks/ses` (SNS-signature verified, topic-pinned) and land on
a suppression list consulted before every send. The account holder sees
"email bounced" next to that guest instead of a link that silently never arrived,
and the operator sees the whole list on `/admin`. Set up with
[`deploy/aws-ses-hook-setup.py`](deploy/aws-ses-hook-setup.py); without it the
app still classifies rejections at send time.

**Light on the council's systems.** The app talks to the council portal
sparingly and politely: it only makes a change when something actually needs to
change, spaces its requests out, and if the portal is slow or busy it waits and
tries again later rather than retrying in a tight loop. The load one household
puts on the portal is about the same as that household logging in and updating
the permit themselves.

**Terms and consent.** Sign-up records which version of the terms each user
accepted (by content hash, append-only). Editing the terms re-prompts everyone;
declining disconnects the council account rather than just logging out.

**Storage** is SQLite (`modernc.org/sqlite`, pure Go, WAL) on a `/data` volume,
with a daily consistent snapshot for file-level backups. **UI** is
server-rendered `html/template` with htmx and Alpine.js.

## Run locally

```bash
# No auth layer needed locally: use the dev identity escape hatch.
# COUNCIL_SANDBOX=1 fakes the council in memory (any login links; plate changes
# land after ~6s) so the full apply pipeline works without council credentials.
COUNCIL_SANDBOX=1 DEV_IDENTITY_EMAIL=you@example.com \
  COOKIE_SECURE=false LISTEN_ADDR=127.0.0.1:8099 SQLITE_PATH=./local.db \
  go run .
# open http://127.0.0.1:8099
go test ./...
```

Both escape hatches refuse to start alongside production settings, so neither
can leak into a real deployment.

## Deploy (self-hosting)

The app is a single static binary in a distroless image:
`ghcr.io/uppertoe/pstonn` (amd64 + arm64). It expects to sit behind a reverse
proxy that terminates TLS and provides login — either a forward-auth layer
setting `Remote-User`/`Remote-Email`/`Remote-Groups` headers, or configure the
app's own OIDC client (`APP_OIDC_*`).

The `deploy/` directory contains a complete example for the
[vps-scaffold](deploy/docker-compose.yml) platform:

1. Copy `deploy/` into your server repo as `apps/pstonn/`
   (`docker-compose.yml`, `.env.example`, `pstonn.caddy`), and
   `deploy/backup-service.env.example` to `backup/services/pstonn.env` if you
   use the scaffold's restic runner.
2. Add `- apps/pstonn/docker-compose.yml` to the root compose `include:` list
   and re-render the Caddy routes.
3. Create `apps/pstonn/.env` (mode 600) from the example. `DATA_ENCRYPTION_KEY`
   is **required** — the app refuses to start in production without it. Set the
   SMTP and ntfy settings, `ADMIN_EMAIL` / `ADMIN_NTFY_TOPIC` for operator
   alerts, and `CONTACT_TO` if you want the public contact form.
4. Add DNS for `p.<domain>` and deploy. Pin the image by `@sha256` digest.
5. On SES, wire up bounce/complaint feedback so the app stops emailing dead
   addresses (see above): `python3 deploy/aws-ses-hook-setup.py --domain
   <sending-domain> --app-url https://p.<domain>`. Run it twice — the first pass
   prints `SES_SNS_TOPIC_ARN` for the `.env`, the second creates the subscription
   the running app confirms. It is additive: an existing SES bounce→Lambda alert
   keeps working alongside it.

On any other Docker host the same image works with any proxy: the compose
fragment shows the hardening flags (read-only FS, no capabilities, non-root)
and the healthcheck (`/app -healthcheck`). Full config reference:
[`deploy/.env.example`](deploy/.env.example).

## CI

`.github/workflows/ci.yml` runs `go vet`, `go test -race`, a `CGO_ENABLED=0`
build, gofmt and `govulncheck` on every push and PR. On pushes to `main` it
builds the multi-arch image, boots it and checks `/healthz` **before** pushing
to GHCR. A weekly rebuild picks up base-image security fixes. All actions and
base images are pinned by digest.

## Status

Running in production for a small number of Stonnington households. Not
affiliated with the City of Stonnington; use at your own risk — the app can
only ever do what your own council login can do, but it is your council login.
Questions or problems: use the [contact form](https://p.stonn.org/contact) or
open an issue.

**If you're from the City of Stonnington** and have questions or concerns
about this service, please get in touch the same way — happy to talk. The app
acts only with each resident's own login, at their request, on their own
permit, and is rate-limited to stay well below what a person clicking through
ePermits would generate. If the council ever offers permit scheduling
natively, or an official way for residents to delegate access, this app will
adopt it or retire.

## License

[MIT](LICENSE).
