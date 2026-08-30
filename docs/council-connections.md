# Council connections: making p.stonn multi-council

Status: **phases 0–2 merged to `main` and deployed to production** (2026-08-30,
deliberately; implemented on branch `council-decoupling` 2026-08-29). No second
council is enabled — the goal of this work was to decouple
the app from the City of Stonnington so that adding one is a registry entry plus a
live capture, not a rewrite. Every golden (page, fragment, HTTP response, email) is
byte-identical to the pre-refactor output; the suite passes.

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
  policy, links, copy, timezone, operational limits and enabled flag.
  Stonnington, Bayside, Hume… are the same connector with different parameters.

```go
// internal/tenant
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
}
```

Definitions live in an embedded `councils.yaml`, overridable at runtime by
`TENANTS_PATH` (the `TERMS_PATH` pattern). The existing `COUNCIL_*` environment
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

### Naming

"Council" is fine as default *copy*; the technical surface says **tenant**: routes
(`/tenant/link`, `/tenant/select`, `/tenant/unlink`, `/tenant/forget-password`,
`/tenant/confirm`), form fields (`tenant_id`, `portal_password`), the registry
(`internal/tenant/tenants.json`, `TENANTS_PATH`), package/type names
(`tenant.Tenant`, `tenant.Registry`, `tenant.Mux`, `store.TenantSession`, `TenantID`).
Deliberately kept: database column names (`council_session`, `council_id`,
`council_permit_id` — a rename is a migration for no functional gain), the
`COUNCIL_*` environment variables and `config.CouncilConfig` (the deployment
contract), the sealing-context strings (`council-cookie:` etc. — changing them
would make existing ciphertexts unreadable), `CouncilPermitID` (it is the
council's own id for the permit), the `/status` JSON key `council` (the watchdog
reads it; rename together with the watchdog), and `/council/confirm` as an alias
for links in emails already sent.

An entry in the registry is a **tenant** (the technical word: an ePermits tenant
is exactly what it is; a council, a university, a precinct). The user-facing
generic word is a catalog term — **"area"** by default ("Switch to…", "Connect
another area") — so it changes per deployment or locale without code. Internal
identifiers stay `council`/`council_id`.

### Schema (as built)

- `account_flags.council_id` — the account's **current tenant**: the sign-up
  choice, later the menu's switcher. A selection, not a binding.
- `council_session` keyed by **`(owner, council_id)`**: one session per tenant an
  account is linked to. An account may hold several (a second home); each has
  its own cookie, saved password, re-authorise clock and reconnect state.
- `permit.council_id`, `UNIQUE(council_id, council_permit_id)`; `PermitByCouncilID`,
  `UpsertPermit` and `ForgetPermit` take the council.
- `breaker_state` keyed by `council_id`.
- Additive `ALTER` + backfill of every existing row to `'stonnington'`, in the style
  of the `linked_at` migration.

### Sign-up and switching

With one enabled tenant nothing is asked. With several, the link form asks which
(the sign-up choice), the user menu shows the current area and offers "Switch
to…" (linked) or "Connect…" (not yet) for the others, Settings shows a card per
connection, and permit cards carry a tenant label once an account's permits span
tenants. Link, pick-a-permit and add-a-permit act in the current tenant; every
permit-level operation follows the permit's own tenant, and a client never acts on
another tenant's session or permit. The rule that the council username is pinned
to the verified email stays — it is per tenant and still correct.

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

## What was built (branch `council-decoupling`)

| Layer | Now |
|---|---|
| Contract | `internal/provider`: `Provider` (session-keyed, stateless), `Capabilities`, typed errors (`Error{Kind, Op, Detail}`, `Unavailable{RetryAfter…}`, sentinels), request `Surface` tagging |
| Backends | `internal/provider/orikan` (the ePermits protocol, with its form/shape/identity tests and the env-gated live tools); `internal/provider/fake` (the sandbox, a real second implementation) |
| Generic client | `internal/parking`: sealed opaque session blob (legacy rows import once), per-owner serialisation, plate cache, backoff, per-council breaker, governed surface-counted transport, a fleet-wide `ConcurrencyLimit`, expiry tagging; `NewClientFor(councilID, …)` |
| Registry | `internal/tenant`: embedded `tenants.json` (single source of truth; `TENANTS_PATH` override; `COUNCIL_*` still overrides Stonnington; `COUNCIL_SANDBOX` narrows to one fake); validated on load; per-council permit policy, links, copy, terms, timezone |
| Routing | `council.Mux` implements `server.Council` and `scheduler.Council`: choice → linked session → process default |
| Schema | `council_session` keyed by `(owner, council_id)`; `council_id` on `permit` (`UNIQUE(council_id, council_permit_id)`) and `account_flags` (the current tenant); `breaker_state` per council; all via column-aware rebuilds, backfilled to `stonnington`, tested from the pre-change schema |
| Product | one account, several tenants: sessions per (account, tenant), a switcher in the user menu, per-tenant Settings cards and unlink/forget-password, tenant labels on permit cards; timezone follows the permit; `/status` per-council breakdown |
| Copy | `internal/i18n` catalogs (en-AU) + council terminology; messages are **prose with named slots** (`{{slot "reset"}}Reset it at the council{{endslot}}`) and the call site supplies the markup (`(slots "reset" (link .Council.Links.ResetPassword …))`) — templates own every anchor, attribute and emphasis, a lint keeps markup and entities out of the catalog; templates, SEO, FAQ, guides, manifest and mail speak through `.Council`; guard tests keep council literals out of code and keys in sync |
| Tests | provider contract; generic client over a scripted stub and the fake; Orikan protocol; HTTP tests of link/picker/add/clear on the real client + fake provider, incl. a two-council run; migration; registry; mux; shared limit; goldens |

## Review pass (2026-08-29)

Security, correctness and test-gap reviews of the branch found and fixed:
a failed operation persisting rotated session material (bumping the generation
so the scheduler's generation-checked recovery read an expiry as "superseded"
and left dead sessions in place — keep-warm was the common path); no guard
against session material or permits stamped for one council reaching another
council's client (an unlink → re-link elsewhere would have scheduled the old
permits at the new portal); `ErrCouncilUnavailable` not reading as not-linked;
`http://` endpoints accepted for a real connector. Also: the per-owner council
lookup is memoised; the failure-notice day key follows the owner's timezone;
the unscoped `PermitByCouncilID` is gone. Known, accepted differences from the
old client: the plate cache stores the plate the app wrote rather than the
council's own string for it (comparisons use `SamePlate`); breaker/cooldown
success is counted per whole operation rather than per 2xx.

## Second review pass (2026-08-30) — the tenant guarantees

A correctness/security pass on the connector/model shape, aimed at making
"a new tenant with passing tests works" true rather than hoped. What changed:

- **Messages name the permit's tenant.** `notify.TenantFor(ctx, owner, tenantID)`;
  `ApplyOutcome.TenantID`; every permit- or session-scoped notification passes the
  permit's/session's tenant. Account-level mail (invite, nudges, referral) passes
  `""` and gets the account's current tenant. A second-home account no longer gets
  Stonnington's name and portal in an email about its Banyule permit.
- **Regions follow the permit.** `Tenant.Regions(ctx, owner, tenantID)` /
  `RegionValid(ctx, owner, tenantID, code)`; the guest and booking pages pass the
  permit's tenant; the account-wide vehicles page passes `""` = the union over the
  served tenants, current first.
- **The seam enforces the contract.** `connectors.Build` refuses a non-plate model,
  a connector it does not know, a portal connector without endpoints, and a
  provider whose `Capabilities().Validate()` fails (keep-warm without refresh, no
  idle window, malformed regions). `main` builds EVERY registry entry at startup,
  enabled or not, so a bad descriptor fails the deploy, not the day it is enabled.
- **Registry validation.** Unknown JSON keys are refused (`DisallowUnknownFields`);
  `replate` cannot be enabled until the scheduler has a home-vehicle restore path;
  any endpoint given must be https whatever the connector; `tenant.Connectors()`
  is the registry's list and the connectors tests hold it equal to `Build`'s cases.
- **Store.** `UpdateTenantToken` is tenant-scoped; the current-tenant wrappers
  `ClearTenantPassword`/`DeleteTenantSession` are gone (`…In`, and
  `DeleteAllTenantSessions` for consent withdrawal, say what they do);
  `TenantIDFor`'s memo is epoch-checked so a read racing a write cannot pin a
  stale tenant; `store.LegacyTenantID` names the backfill target and the registry
  test checks it is still described.
- **Link.** The account's current tenant is switched only after the login
  succeeds, so a failed "connect another area" leaves the dashboard alone.
- `orikanv7.New(cfg, tr)` takes the governed transport like `orikan.New`, so the
  capture work cannot bypass the governor; its capabilities are now coherent.

Tests that pin all of this: `connectors/registry_test.go` (every embedded tenant
builds; names agree; undrivable pairings refused), `tenant/guard_test.go`
(unknown fields, replate, copies), `tenant/regions_test.go`,
`notify/tenant_routing_test.go`, `server/tenant_link_failure_test.go`,
`store/tenant_memo_test.go`, `provider/capabilities_test.go`.

**Adding a tenant, mechanically:** a `tenants.json` entry (validated on load and
built by the connectors test); if its portal is new, a package under
`internal/provider/`, a case in `connectors.Build`, and its name in
`tenant.knownConnectors` — the tests fail until all three agree.

## UI that depends on the portal — the three mechanisms (2026-08-30)

An integration that needs the UI to differ is one of three things, each with its
own mechanism; pick by kind, never by council name (the literal-lint enforces it):

1. **Words, links, facts** → registry `terms`, the catalog, `links`, `copy`. No code.
2. **Same model, different portal capabilities** → `provider.Capabilities`,
   declared by the connector and consumed by the page through `capsView`
   (`internal/server/views.go`): `buildPermitView` resolves the PERMIT's tenant's
   capabilities via `Tenant.Capabilities(ctx, owner, tenantID)` and the card
   branches on `.Caps` / the derived fields only — `CanClear` (button hidden AND
   `clearPermit` refuses), `Regions` (chooser), `Expiry` (labels left unknown).
   Adding a capability = a field on `Capabilities` (+ a `Validate()` rule if it
   has one), a `capsView` field, a template branch, and a fake-provider toggle so
   it is tested as a matrix (`TestPortalThatCannotClearOverHTTP` is the pattern).
   A portal that needs extra vehicle attributes (make/model/colour — Banyule's
   `GetJsonMakes/Models/Colours` hints at it) is the same mechanism one size up:
   a `VehicleFields` capability the provider names, rendered generically by the
   vehicle form, stored in one JSON column.
3. **A different model** (coupon, replate) → a different page and planner
   selected by `Model` at the handler, sharing the shell, vehicles, guests and
   notifications. Not `{{if eq .Model …}}` sprinkled through the schedule page.
   Built when a tenant exists to drive it; `Model.Plate()` keeps it unreachable
   until then.

## Remaining (not done in this branch)

- **Landing / public pages per council.** Public pages render for the registry
  default; `/councils/<id>` pages and a multi-council landing are not built. The
  "For the City of X" section, guides and FAQ already parameterise.
- **Per-account locale.** The catalog is locale-ready (`Bundles.For`, `LocaleTag()`
  hook on page data) but nothing sets a locale yet; only en-AU exists. Dates still
  format en-AU in `localTime`.
- **Remaining generic sentences** stay literal in templates and Go; the harness
  makes extracting them safe, one golden-neutral commit at a time.
- **`terms.md`** still names the City of Stonnington: changing it re-prompts every
  user for consent and is a wording change — needs the operator's approval first.
- **Watchdog/operator alerts** don't name the council yet (the `/status` breakdown does).
- **Second council** — phase 3: a live capture per the checklist below, then a
  registry entry. If it is not config-only, split the auth strategy inside the
  Orikan provider then.

## Backlog

- **Forward-auth proxy identity** (security review item): the app trusts `Remote-*`
  headers from any private/link-local peer. It should identify the actual reverse
  proxy (a pinned peer address, or a shared secret header from Caddy) rather than
  the address class.
- Council-aware operator alerts; per-council capacity (there is none — the
  descriptor field was dropped rather than left loaded-but-unenforced; `MAX_ACCOUNTS`
  caps the deployment).

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
- `enabled: true`.

## Open decisions

1. **Brand.** "p.stonn" = *parking Stonnington*. Keep it and position as "started in
   Stonnington" until a second council is real.
2. **Several tenants per account** (chosen 2026-08-29, superseding one-per-account):
   a resident with homes in two councils cannot use two accounts, since each
   sign-in is an email address. Sessions are per (account, tenant).
3. Egress reputation is the scale ceiling and it is per host, so a second council
   roughly doubles headroom rather than sharing it.
4. Phase 3 step 13 is the go/no-go: if the second tenant is not config-only, the
   connector split moves up.
