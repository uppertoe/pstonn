# Council connections: making p.stonn multi-council

Status: **planned, phase 0 in progress** (2026-08-29). No second council is being
added yet — the goal of the current work is to decouple the app from the City of
Stonnington so that adding one later is configuration plus a capture, not a rewrite.

## Why

The portal p.stonn drives is Orikan's off-the-shelf *ePermits* product, not something
Stonnington built. A dozen other councils run the same `/ssp` + `/idm` + `/ssp-svc`
stack (Yarra Ranges, Bayside, Hume, Brimbank, Blue Mountains, Burwood, Ryde, Town of
Victoria Park, Brisbane, ANU). Whether their scheme has a shared visitor permit with a
holder-editable plate is council configuration, not platform — so some of them are
one config entry away from working.

## Where the coupling is today

The domain model (vehicles, rosters, one-offs, guests, apply-log, notifications) is
already council-agnostic: keyed on `owner` / `permit_id`. The coupling sits in five
places:

| Layer | Coupling | Where |
|---|---|---|
| Protocol | Duende endpoint layout, ASP.NET login-form replay, `/ssp-svc` paths, `manageVehicle` JSON shape, VIC vehicle-state id `"1"` hardcoded, cookie name | `internal/parking/{parking,auth,browser}.go` |
| Wiring | One `parking.New`, passed to the scheduler by interface but to the server as the concrete `*parking.Client` | `main.go`, `internal/server/server.go` |
| Schema | `council_session` has no council column; `permit.council_permit_id` is globally `UNIQUE` (two councils' `PKPermitID` spaces would collide); `breaker_state` is a single row | `internal/store/migrate.go` |
| Policy | `isVisitorPermit` / `isResidentPermit` / the rename fallback — a Stonnington permit-type judgement living in the server | `internal/server/permits.go` |
| Copy | ~200 "Stonnington / ePermits / City of" strings across onboarding, landing, SEO + guides, emails, terms, settings, share and guest pages | templates, `seo.go`, `notify.go`, `terms.md` |

Also: `DisplayLocation` is one process-wide timezone — fine for Victorian councils,
wrong the moment a WA or QLD council is added.

## Design

### Two concepts, not one

- **Connector** — a protocol driver: how to log in, keep a session alive, list
  permits, read and write the plate. Today there is exactly one, `orikan-ssp`
  (authorization code + PKCE, `/ssp-svc`). Orikan tenants on older builds use an
  implicit flow (`ePermits80`, `id_token token`) and would be a second connector; a
  non-Orikan council would be a third.
- **Council** — a tenant descriptor: id, names, connector and its parameters, permit
  policy, links, copy, timezone, operational limits, enabled flag and capacity.
  Stonnington, Bayside, Hume… are the same connector with different parameters.

```go
// internal/council
type Council struct {
    ID        string   // "stonnington" — stable; appears in URLs and the database
    Name      string   // "City of Stonnington"
    Short     string   // "Stonnington"
    Connector string   // "orikan-ssp" | "fake"
    Endpoints Endpoints // Issuer, APIBase, ClientID, RedirectURI, Scopes
    Timezone  string   // "Australia/Melbourne"
    Policy    PermitPolicy // schedulable-type matcher, resident-type matcher, default vehicle state id
    Links     Links    // Portal, Register, Reset, ApplyVisitor
    Copy      Copy     // Suburbs, Phone, per-council notes (message keys, see i18n)
    Limits    Limits   // governor rates, login sub-limit, concurrency, idle window, warm interval
    Enabled   bool
    Capacity  int
}
```

Definitions live in an embedded `councils.yaml`, overridable at runtime by
`COUNCILS_PATH` (the `TERMS_PATH` pattern). The existing `COUNCIL_*` environment
variables remain as overrides applied to the `stonnington` entry, so the current
deployment config keeps working unchanged.

### The provider contract (implemented)

The seam is **session-keyed and stateless**, not owner-keyed: a backend owns one
portal's protocol and nothing else.

```go
// internal/provider
type Provider interface {
    ID() string
    Capabilities() Capabilities
    Login(ctx, creds Credentials) (Session, error)          // Link and Reconnect are the same call
    Refresh(ctx, s *Session) error                          // may rotate in place; persisted if changed
    ListPermits(ctx, s *Session) (permits []Permit, total int, err error) // len<total = partial
    CurrentVehicle(ctx, s *Session, p PermitRef) (Vehicle, error)
    SetVehicle(ctx, s *Session, p PermitRef, registration string) error
    ClearVehicle(ctx, s *Session, p PermitRef) error
}
```

- `Session` is an **opaque provider blob** the generic client seals and persists
  without interpreting (Orikan: cookie + cached token + expiry; another backend: a
  refresh token). It is stored in the existing `cookie_sealed` column behind a
  `pstonn-session:` prefix; a value without the prefix is the pre-provider shape and
  is imported once through the provider's `ImportLegacy` hook — no migration, no
  re-link.
- **Errors are typed, never worded.** Providers return the shared sentinels
  (`ErrSessionExpired`, `ErrLoginRejected`, `ErrUnavailable{RetryAfter,Status,
  Surface,Ref}`, `ErrPermitInactive`, `ErrUnsupported`, …) and a classified
  `Error{Kind, Op, Detail}` where `Op` is an identifier (`OpSetVehicle`) and `Detail`
  is council-supplied text. Wording lives in the core (today `scheduler.opWording`;
  it moves into the message catalog with the copy pass).
- `Capabilities{CanClearVehicle, SupportsRefresh, NeedsKeepWarm, IdleWindow,
  SupportsExpiry, LoginKind}` lets the core adapt (hide the clear button, skip
  keep-warm, refuse a password reconnect on a device-flow provider) instead of
  assuming.
- Requests are tagged with a `Surface` (login / auth / api) on the context; the
  generic `Transport` governs and counts by surface, so the login sub-limit and
  the traffic summary are provider-agnostic.

Layout: `internal/provider` (contract + vocabulary), `internal/provider/orikan`
(the Orikan ePermits protocol: Duende flow, form replay, browser identity,
add/edit/delete shapes, paging, diagnostics), `internal/provider/fake` (the
sandbox — the second, genuinely different implementation, and what the core's
tests run against), `internal/parking` (the generic per-owner client: sealing and
persistence, per-owner serialisation, plate cache, backoff, fleet breaker,
governed transport, expiry tagging). `server.Council` / `scheduler.Council` are
unchanged: the generic client still satisfies them, and a `Mux` over several
clients will too.

### Per-council operational state

Edge blocks (Azure Front Door / Akamai) are per host, so the breaker, governor,
login-flow serialiser and traffic counters are **per council**. They already live on
`Client`, so one instance per council gives this for free. One **global concurrency
cap** is added across councils because the egress IP is shared. `breaker_state` gains
a `council_id` key.

### Schema

- `account.council_id` — chosen at sign-up, before any link exists.
- `council_session.council_id` — PK stays `owner`: **one council per account**.
  A household is in one council; switching means disconnect and re-onboard.
- `permit.council_id`, `UNIQUE(council_id, council_permit_id)`; `PermitByCouncilID`,
  `UpsertPermit` and `ForgetPermit` take the council.
- `breaker_state` keyed by `council_id`.
- Additive `ALTER` + backfill of every existing row to `'stonnington'`, in the style
  of the `linked_at` migration.

### Sign-up

Onboarding gains a step 0: a council picker (cards; enabled councils only; capacity
shown per council; "not listed? tell us" → the contact form, which doubles as demand
signal). Everything downstream reads `.Council` from the account. The rule that the
council username is pinned to the verified email stays — it is per tenant and still
correct.

### Permit policy

`isVisitorPermit` / `isResidentPermit` / `visitorNameFallback` move behind
`council.Policy.Schedulable(PermitInfo)`. The name matching is confirmed for
Stonnington only (see the permit-type catalog note). The vehicle-state default comes
from the policy (VIC=1, ACT=2, NSW=3, WA=4, TAS=5, QLD=6, SA=7, NT=8).

### Copy

Templates and emails receive `.Council`. Council-specific material on the landing page
(suburbs, apply links, the "For the City of Stonnington" section, the guides) moves to
`/councils/<id>`; the landing becomes "works with: …". `terms.md` clause 1 becomes
generic ("your council's permit portal"). Editing `terms.md` changes its hash, so every
user re-accepts terms — time it with a release note.

## i18n

Decision: **do not translate now, but route every string touched by the copy pass
through one mechanism so translating later is a catalog, not another sweep.** The
council pass and an i18n pass touch the same ~200 strings; doing the plumbing once is
the whole point of combining them.

Shape:

- `internal/i18n`: embedded message catalogs, one file per locale
  (`en-AU.toml` first; keys are stable identifiers like `onboarding.link.intro`, values
  are Go `text/template` fragments so they can carry `{{.Council.Name}}`).
  Stdlib only — `encoding/json` or a small TOML reader; no `golang.org/x/text`
  dependency unless plural/gender rules become necessary.
- Template func `T "key" .` (and `Tf` with args); the same catalog serves the mailer
  and `notify` so emails are translated with the pages.
- Locale resolution: account preference → `Accept-Language` → `en-AU`.
  Persisted as `account.locale`. `<html lang>` follows it.
- Council copy fields are **message keys**, not literal strings, so a council's
  suburb list or notes translate like any other message.
- Dates already go through `localTime`; it takes the locale (and, per council, the
  timezone) rather than the current hard-coded en-AU format.
- **Terms stay English-governed.** A translated `terms.md` is a courtesy rendering;
  consent is recorded against the English hash. Do not translate terms until that
  legal position is written down in the terms themselves.
- Guides and SEO pages are locale-specific *content*, not messages: they get
  `hreflang` and a per-locale file only when a translation actually exists.

What this is not: a commitment to ship a second language. The plumbing costs little
when done alongside the council pass; a real translation is its own project (and the
translation itself must be reviewed by a speaker, never shipped machine-generated for
copy that mentions fines).

## Phases

**Phase 0 — seams, zero behaviour change.** Ships on its own; every existing test
must pass with byte-identical rendered output.

0. ✅ **Golden harness** (the guardrail for everything below). 164 golden files:
   `internal/server/testdata/golden/{pages,fragments,http}` (every page state and
   htmx fragment at a pinned clock; every public GET through the real handler with
   the CSP nonce masked), `internal/notify/testdata/golden` (every email/push/outbox
   row the service composes, signed-link tokens masked) and
   `internal/mailer/testdata/golden` (the HTML wrapper with the brand footer).
   Regenerate with `go test ./internal/<pkg> -run Golden -update`, **only in a commit
   that touches nothing else**, so the golden diff is the review of a copy change.
   The set is locked both ways: a case without a golden and a golden without a case
   both fail.

1. ✅ Server takes a `server.Council` interface, not `*parking.Client`
   (`scheduler.Council` already existed). Interfaces are defined by their consumers,
   Go-style; `PermitInfo`, the error sentinels and `FailureKind` stay in `parking`
   for now — moving them buys nothing until a second connector exists.
2. ✅ `internal/council` with the descriptor (`FromConfig`) and a single Stonnington
   entry built from today's `cfg.Council`; `main.go` builds it and passes it to the
   server. The vehicle-state id is set on the client from the descriptor rather than
   hard-coded.
3. ✅ Permit policy behind `council.PermitPolicy`; the server's helpers delegate.
4. ✅ Provider contract extracted (see above): `internal/provider`, the Orikan
   provider, the `fake` provider replacing the in-client sandbox branches, and the
   generic client rewritten over the contract. The parking suite ports across
   (protocol tests moved to `orikan`; integration tests run the generic client over
   the Orikan provider at an httptest portal), plus new seam tests driving the
   generic client with a scripted stub and the fake.
5. `internal/i18n` scaffold + `T`; templates, `seo.go`, `notify.go`, `mailer` read
   `.Council` and the catalog. Output for Stonnington stays identical.

**Phase 1 — registry + schema.**

6. `councils.yaml`, loader, env-override merge, `COUNCILS_PATH`.
7. Migrations: `council_id` on account / session / permit / breaker; backfill.
8. `Mux`; `main.go` builds one client per enabled council; global concurrency cap;
   `OnSessionExpired` wired per client.
9. Admin `/status` groups sessions, stats and breaker per council; watchdog alerts
   name the council.

**Phase 2 — product surface.**

10. Council picker at sign-up; per-council capacity; "request my council".
11. Landing, guides, emails and terms re-cut for multi-council; `/councils/<id>`.
12. `account.locale` + locale resolution; `<html lang>`; `localTime` per locale.

**Phase 3 — prove it with a second tenant** (not started; needs a go decision).

13. One Orikan council on the modern code + PKCE flow. Expected to be config-only —
    this is the real test of the model.
14. Only when a council needs a different auth flow: split `Client` into an auth
    strategy (`login → session`, `renew(session) → token`) and an API shape. Not built
    speculatively.

## Adding a council — checklist

Every council needs a live capture before it is enabled:

- OIDC client id and flow from `/ssp/assets/app-config.json` (code+PKCE or implicit?).
- `/ssp-svc` grid and `managedVehicle` shapes against the parameterised
  `shape_test` / `capture_test` fixtures.
- A shared, holder-editable visitor permit type exists
  (`PermitTypeAllowsVehicleChangeByHolder`) and how it is named.
- Vehicle-state id for the council's state.
- A test account; `live_test` read → write → read-back, permit restored.
- Login POST from the VPS IP works (edge behaviour is per host).
- Timezone; copy and links; `/councils/<id>` page explaining the traffic to that
  council's operator (the honest-UA principle in `browser.go`).
- `enabled: true` with a small capacity.

## Open decisions

1. **Brand.** "p.stonn" = *parking Stonnington*. Keep it and position as "started in
   Stonnington" until a second council is real.
2. **One council per account** (chosen). Many-per-account complicates every
   owner-keyed table for a case that barely exists.
3. Egress reputation is the scale ceiling and it is per host, so a second council
   roughly doubles headroom rather than sharing it.
4. Phase 3 step 13 is the go/no-go: if the second tenant is not config-only, the
   connector split moves up.
