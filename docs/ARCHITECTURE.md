# p.stonn architecture

A map of how the pieces fit and — more importantly — the **load-bearing invariants**
that are otherwise recorded only in inline comments. This file is a guide, not the
source of truth: where it names a constant or a rule, the cited code is authoritative,
and several invariants below are pinned by a named guard test so this document and the
code cannot drift apart silently.

## What it is

A single Go binary. An always-on **desired-state loop** decides which vehicle
registration should be on each council visitor-parking permit and drives the council
portal to make it so; a small web UI lets households manage permits, schedules,
vehicles and guest passes. User identity comes from a forward-auth gateway (or the
app's own OIDC relying party); the council session is a stored, encrypted cookie.

## Package layering

Dependencies point downward only — there are no cycles (a cycle would not compile).

```
main                        composition root: builds everything, wires the loops
  └── server                HTTP routes, rendering, guest surfaces  (depends on ~everything)
        ├── scheduler        the desired-state loop + keep-warm/drift/reconnect/notify
        ├── notify           email/push, the durable outbox, message composition
        ├── tenant           registry + mux: routes each account to its council
        ├── parking          the GOVERNED client: transport, rate governor, fleet breaker,
        │                    per-owner backoff, session sealing/persistence
        ├── provider         the council-backend CONTRACT (interface + error taxonomy)
        │     └── orikan / orikanv7 / fake   concrete connectors
        ├── store            SQLite persistence + migrations
        ├── webauth/session/identity   the app's own login + identity middleware
        └── config, model, secretbox, redact, i18n, mailer   leaves
```

Two deliberate boundaries worth preserving:

- **`provider` speaks no words.** A connector returns a typed `FailureKind`/`Op` and
  an optional tenant-supplied `Detail`; the UI/notify layer chooses the wording. That
  is what lets a second council be a real test of the architecture, not a fork. Council
  neutrality is enforced structurally by `TestNoTenantLiteralsOutsideTheRegistry`.
- **`scheduler` is config-free.** It takes a plain `Options` struct, never imports
  `config`. (That is why the keep-warm default is duplicated rather than shared — see
  below.)

## The desired-state loop

`scheduler.Scheduler.Run` ticks every **1 minute** (`interval`). Each pass resolves
every permit's target plate from its roster + one-off overrides and, if the council
shows something else, applies the change through the tenant mux. Page renders never
call the council synchronously; only the loop, keep-warm, drift and reconnect do.

Supporting workers in the same package: **keep-warm** (silent-renews sessions before
they idle out), **drift** (notices a plate changed directly in the council portal),
**reconnect** (owner-deduplicated recovery of a dead session), and **housekeeping**
(retention purges + a daily consistent DB snapshot).

## Invariant: keep-warm vs the idle window

The council session idle-timeout is estimated (`IdleWindow`, default **10h**). Keep-warm
renews when a session is older than `WarmInterval` (default **105m**), but the effective
threshold is **jittered only downward** and **hard-clamped to `IdleWindow −
WarmSafetyMargin`** (margin default **1h**), and a failed/deferred renew retries every
few minutes rather than once per interval. So `WarmInterval` can be raised toward the
window to cut council traffic without ever risking a lapse before the first renew.
See `scheduler.warmThresholdFor`, `config.CouncilConfig` (the field docs carry the math).

`DefaultWarmInterval` exists in **both** `config` and `scheduler` (the config value
feeds load-time validation; the scheduler keeps a construction fallback because it is
config-free). They are pinned equal by **`TestWarmDefaultsAgree`** — change one and CI
fails until the other matches.

## Invariant: rollover spread

When many permits share a boundary (midnight, overwhelmingly), applying them all at
once would spike council traffic. `RolloverWindow` spreads the burst — but only if it
is *wider* than the serial drain the governor imposes (`OpDrain`, itself derived from
the governor rate so a larger fleet needs no separate tuning). `main` logs at startup
whether the window is actually smoothing anything. See `Scheduler.RolloverBound`.

## Invariant: the failure-notification episode model

The single most bug-prone area; treat it as a contract.

- **`scheduler.notifyFailure` is the ONE place that decides whether a household hears
  about a failure.** No other path builds a notification key. It records, per permit,
  an *episode*: the target plate it last told them about and whether the urgent tier
  went out. Rule: **one soft notice per episode per target plate, one urgent escalation
  per episode, never a downgrade.** The failure *cause text* is content, never a trigger
  (a flapping error description must not re-alarm). Episodes are rows in `permit_notify`.
- **`escalateFailure` is the single streak gate** in front of it: it bumps the
  consecutive-fail streak and only calls `notifyFailure` once a per-cause threshold is
  met (`failNotifyThreshold`=3, `busyNotifyThreshold`=15, `blockNotifyThreshold`=4,
  `sessionNotifyThreshold`=4). A new failing branch must go through it, so it cannot
  forget the gate.
- **`legacyFailureTold`** adopts pre-episode notification keys of every old format, so
  shipping the episode model re-told nobody.
- Deliberately **outside** the episode model: `reportTenantUnavailable` (a permanent
  condition, so it calls `notifyFailure` directly with no streak), and `settle`
  (episode close-out) + `reportUnresolvable` (a schedule-config problem that attempts
  nothing at the council) which use `notifyUser` with their own day-keyed dedup.

Pinned by `episode_test.go`, `failure_flood_test.go`, `failure_cap_test.go`,
`partial_retry_test.go`, whose assertions are the executable form of this contract.

## Invariant: the two circuit breakers

An auth-only council outage and an edge (WAF/rate-limit) block are different failures
with different owners, kept strictly separate:

- **Auth circuit** (`orikan.authCircuit`, per tenant) gates only the *authorize* surface
  that mints tokens. It opens after `authTripThreshold`=3 consecutive **origin** failures
  (transport error / 5xx) and admits one escalating-backoff probe (1m → ×2 → 15m cap).
  An op holding a valid cached token never touches it, so applies keep working in an
  auth-only outage.
- **Fleet breaker** (`parking`) opens on edge **push-back** (429/403/503/WAF) seen across
  *distinct owners* — a systemic block, not one household's problem.

The separation rests on one rule: **only a real edge response is modelled as
`*provider.Unavailable`**; the auth-backoff error wraps the `ErrUnavailable` *sentinel*
but is not that *struct*, so it never feeds the fleet breaker. All three consumers of a
failure (auth circuit, per-owner backoff, `/status` health) read one classifier,
**`provider.Classify(err) → Signal`**, so a new failure mode is reasoned about once.
Pinned by `TestClassifySignals` (including the sentinel-is-not-struct row).

## Invariant: dev vs production startup

`config.productionSignal` names the first setting that can only mean a real deployment —
`DATA_ENCRYPTION_KEY`, `APP_OIDC_ISSUER`, `DOMAIN`, or a non-loopback `PUBLIC_BASE_URL`.
The two local-only escape hatches (`DEV_IDENTITY_EMAIL`, `COUNCIL_SANDBOX`) **refuse to
start beside any of them**, so an operator cannot accidentally turn a real deployment
into a fully-open, every-request-is-admin app by commenting out the key. A missing
`DATA_ENCRYPTION_KEY` is fatal in production (stored council sessions could not survive
a restart) but falls back to an ephemeral key in dev. See `buildSecretBox` in `main`.

## Invariant: the shared SQLite connection

The store runs on effectively one connection, shared between the HTTP handlers and the
reconcile loop. So unbounded anonymous work does not merely slow pages — it **starves
the loop, and a permit that stops updating is a parking fine.** Consequences you must
respect:

- Every public route is bounded (per-IP throttles + a global guest concurrency cap);
  the public guest surface sheds with 503 rather than queueing on the connection.
- Capacity-and-consume decisions are single guarded `INSERT … WHERE (SELECT COUNT…) < ?`
  statements, and multi-statement invariants use an explicit transaction, so a race
  between the loop and a handler cannot double-fill or corrupt.

## Invariant: mutation routes are guarded

Every route registers through `server.handle(mux, pattern, guardKind, h)`, which records
the guard on `s.routes`. **`TestMutatingRoutesAreGuarded`** derives the rule: every
state-changing route is behind `withConsent` (auth + CSRF + terms) — the safe default —
unless it is an enumerated consent-exempt user action or a token/signature-authenticated
public one. A mutating route added with the wrong guard fails CI rather than shipping
ungated.

## Data retention

The housekeeping sweep's retention windows are named constants gathered in
`scheduler/housekeeping.go` (decided guest requests 7d — visitor plates are PII; revoked
recipient addresses 30d; bounce/unsubscribe suppressions 2y; the PII-bearing logs 90d).
They are code constants, not env knobs, on purpose: they encode a privacy commitment
that should change by review, not by a deploy-time override.

## Where to look

| Concern | Package / file |
|---|---|
| Composition, worker wiring, shutdown | `main.go` |
| Routes + guards | `internal/server/server.go` (`Handler`, `handle`) |
| The desired-state decision | `internal/scheduler/reconcile.go` |
| Failure notices | `internal/scheduler/notify.go`, `internal/notify/notify.go` |
| Council contract + error taxonomy | `internal/provider/provider.go` |
| The live Orikan connector | `internal/provider/orikan/` |
| Governor, breaker, session sealing | `internal/parking/` |
| Multi-council registry/mux | `internal/tenant/`, `docs/council-connections.md` |
| Schema + migrations | `internal/store/migrate.go` |
| Tunables + startup validation | `internal/config/config.go` |
