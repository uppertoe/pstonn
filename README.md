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
- **Notifications** — the app tries to tell you by email and/or push whenever it
  changes your permit, or can't. Brief hiccups it expects to resolve are retried
  before you're bothered, and delivery is never guaranteed, so treat notifications
  as a convenience rather than a guarantee — you remain responsible for your
  permit. Success is only reported after the council's own record confirms the
  change.
- **Shared access** — household members can manage the same schedule.

It's free, has no ads, collects nothing it doesn't need, and doesn't sell
anything. It exists because re-typing number plates into a council portal is a
problem worth solving once, properly, for everyone. Use the hosted site at
[p.stonn.org](https://p.stonn.org) or self-host it (below).

**Is this official?** No. p.stonn is an independent community tool and is not
affiliated with or endorsed by the City of Stonnington. It only ever acts on your
own council account, doing things you could do yourself in the portal: it changes
which of your vehicles is on your own visitor permit. Two things worth knowing
because they aren't literally "only when you ask": it holds a continuously-renewed
session so it can act on your schedule while you're not there, and if you create a
guest link, the person holding it can change your permit at a time of their
choosing.

**Is my council password safe?** The app signs in to the council with your
password to obtain a session cookie. **By default it also keeps the password**,
encrypted, so it can sign back in on its own when the council ends the session —
untick "Save my password" when you link, or turn it off later in Settings, and
the password is erased and never stored again. Either way the session cookie is
encrypted at rest with AES-256-GCM.

**What else is encrypted?** Your council session cookie, its access token, and
(if you saved it) your council password. The rest of your data — number plates,
your schedule, permit details, email addresses, the activity log — is stored
unencrypted in the app's SQLite database on the server. Anyone with the server or
its database can read it. See [/security](https://p.stonn.org/security) for what that
means and what is stored.

**How long does a link last?** As long as the account is in use. The connection
stops after **90 days with nobody using it** — opening the app resets that clock,
and it counts anyone you share the account with, not just you. If a household does
go quiet, the app emails a one-click link about a week before the deadline;
clicking it (or simply signing in) resets the clock. Ignore it and the session
lapses, the app stops managing the permit, and you re-link in the app. The point
is to stop holding a council session for someone who has moved away or stopped
using the service.

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
sessions before they lapse, on a measured interval inside the observed idle window
(~0.7x), with jitter and per-account spacing. The re-authorise bound is measured
against ACCOUNT IDLENESS — the last authenticated visit by any member (throttled
to one write per person per hour), plus a click on the confirm email — not against
the age of the link, because the bound exists to stop holding a session for a
household that has left. The confirm email goes out ~7 days before the deadline;
ignore it and renewal stops, the session lapses, and the user is told to re-link.
See `internal/scheduler` (`decideWarm`).

**Scheduling** is a reconcile loop: every minute (and immediately after any
edit) it computes the target plate for each permit from the roster and active
overrides, applies any difference, and records it. Success is only reported
after the council's own record confirms the change. Stateless across restarts;
a missed tick heals on the next one.

**Notifications** are per-user (email via any SMTP provider, push via a private
ntfy topic) with quiet hours, durable retry through an outbox, and operator
escalation when a user can't be reached. A lapsed council session proactively
prompts a re-link rather than failing silently. The outbox is **at-least-once**:
a send and the write that records it are two steps, so a crash or a refused
write between them can deliver the same message twice (a duplicate confirmation,
never a missed one). The drain parks a row whose bookkeeping write fails rather
than re-sending it every tick, which bounds the duplicates to one per incident.

**Undeliverable email** is learned, not ignored. A hard SMTP rejection (5xx) at
send time is classified as permanent, so the outbox stops retrying it instead of
hammering a dead mailbox; on AWS SES, bounce and complaint events also arrive
asynchronously at `/hooks/ses` (SNS-signature verified, topic-pinned) and land on
a suppression list consulted before every send. The account holder sees
"email bounced" next to that guest instead of a link that silently never arrived,
and the operator sees the whole list on `/admin`. Set up with
[`deploy/aws-ses-hook-setup.py`](deploy/aws-ses-hook-setup.py); without it the
app still classifies rejections at send time.

**Light on the council's systems.** The app only makes a change when something
actually needs to change, spaces and jitters its requests, and backs off (per
account, exponentially) when the portal pushes back. In practice one household's
schedule costs the portal roughly 50–70 requests a day — comparable to a resident
who logs in and edits their permit daily, though it continues on days they would
not have logged in at all, because keeping the session alive is most of that
traffic.

To reach the portal at all it replays the ePermits web app's own login form and
sends browser request headers, because the portal's protection layer refuses
non-browser clients. That is stated plainly here rather than buried: it is the
part of this project most worth a conversation with the council, and if there were
a supported way in — an API, or an official delegated-access mechanism — this app
would use it instead.

**Terms and consent.** Sign-up records which version of the terms each user
accepted (by content hash, append-only). Editing the terms re-prompts everyone;
declining disconnects the council account rather than just logging out.

**Storage** is SQLite (`modernc.org/sqlite`, pure Go, WAL) on a `/data` volume,
with a daily consistent snapshot for file-level backups. **UI** is
server-rendered `html/template` with htmx and Alpine.js.

**Retention** is enforced in code, on the housekeeping pass: activity and change
logs 90 days; a door-QR request 7 days from the scan, whatever its outcome (and
its poll secret dropped once settled); a revoked guest link's recipient address
30 days; sent and undeliverable notifications stripped of their content (and
their dedup key stored only as a digest) when they settle and purged after 24h;
referral invitations 90 days; bounce/unsubscribe suppressions 2 years,
complaints kept. Container logs need a size cap too — stock Docker keeps json-file logs forever,
while a journald host usually caps them already; see the note in
`deploy/docker-compose.yml`. Backup retention comes from the
platform's restic runner (see `deploy/backup-service.env.example`); whatever it
is set to is the real upper bound on how long deleted data stays recoverable, and
/security states that bound to users.

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

Both escape hatches refuse to start alongside any setting that means "real
deployment" — `DATA_ENCRYPTION_KEY`, `APP_OIDC_ISSUER`, `DOMAIN`, or a
non-loopback `PUBLIC_BASE_URL`. Be clear about what that is and isn't: it is a
tripwire on the settings a deployment happens to carry, not a proof of
environment. `DEV_IDENTITY_EMAIL` authenticates **every** request as that
address with the admin group, so on a host where none of those are set — a
staging box, a VM someone left reachable — setting it is still a wide-open app.
Treat it as a local-only tool and not as something the config will save you
from.

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
   is **required** — the app refuses to start in production without it. An
   absolute public base is required too: set `DOMAIN` (the root `.env` normally
   supplies it, and `https://p.<DOMAIN>` is derived from it) or
   `PUBLIC_BASE_URL` directly, because every link the app mails — the
   re-authorise confirm link, guest passes, the door QR — is absolute. Set the
   SMTP and ntfy settings, `ADMIN_EMAIL` / `ADMIN_NTFY_TOPIC` for operator
   alerts, and `CONTACT_TO` if you want the public contact form. If you run the
   outage watchdog, `STATUS_TOKEN` and `ROSTER_KEY` go together — the app will
   not start with one and not the other.
4. Add DNS for `p.<domain>` and deploy, **DNS-only** (no CDN proxy in front of
   Caddy: it replaces every client address with an edge address, which silently
   disables all per-IP rate limiting). Pin the image by `@sha256` digest.
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
base images are pinned by digest. To run the same fast checks locally before
every push, enable the bundled hook once per clone: `git config core.hooksPath .githooks`.

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
