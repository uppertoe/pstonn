# Adversarial review — 2026-07-30

Findings from a full adversarial review of logic, state handling, and implementation
security. Each item has a stable ID so commits and tests can cite it.

**Status: all 77 addressed.** B3 is now complete too: sliding renewal, a 7-day absolute
cap, and genuine revocation via a per-person session epoch (`session_epoch`), bumped
wherever authority is withdrawn — account deletion, losing shared access, leaving an
account, declining the terms.

Three further items were found *while* fixing, and were also completed rather than left
implicit: deleting a vehicle now names the roster days it empties (it cascades them away
silently otherwise); a booking that runs to the end of a day is described by the day it
completes rather than as "12:00am" the day after; and `deploy/aws-ses-hook-setup.py` sets
the SNS topic's SignatureVersion to 2. The webhook still accepts SigV1 until it has seen
a genuine v2 message, so the v1 branch can be deleted once the updated script has been
run against the live topic — that is the one piece of this work that needs an action
outside the repository.

Severity is impact-weighted, not likelihood-weighted: an item marked HIGH may need an
operator mistake or a third-party flaw to trigger, but the consequence if triggered is
severe. The `Trigger` column says what it takes.

Verified clean and deliberately NOT listed as findings: SQL injection (all dynamic SQL
interpolates compile-time constants only), XSS (no `template.HTML`/`JS`/`HTMLAttr` uses,
no Alpine expression interpolates user data, no `x-html`), open redirect (all 27
`http.Redirect` sites take literals), cross-account IDOR (every user-reachable by-ID
query is owner-scoped at the SQL layer), SNS signature verification, and the
forward-auth header-stripping boundary as currently deployed.

---

## A. Deployment & configuration

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| A1 | CRITICAL (availability) | documented rebuild procedure | `deploy/pstonn.caddy:27-46` | Ships the `forward_auth` + `handle_response { redir }` construct that returns `200`/empty for signed-in `GET /`. Production already fixed this (`markbot-server/apps/pstonn/pstonn.caddy` uses `@hassession` + `redir`) but the fix was never back-ported, and `README.md:181` says to copy `deploy/` over the working config. The template comment also documents the broken shape as correct. | done |
| A2 | HIGH | operator publishes the port directly | `internal/identity/identity.go:57-65`, `internal/server/server.go:250` | `Remote-Email`/`Remote-Groups` are trusted from **any** peer with no `RemoteAddr` check. Port-published + `APP_OIDC_ISSUER` unset (the recommended posture) means any caller becomes any user or an admin. App starts with no warning. `contact.go:179` already has the right check (`fromProxy`) for the far less dangerous XFF path. | done |
| A3 | MEDIUM | partial rollout | `internal/server/admin.go:205` | `wantRoster := ... \|\| len(s.cfg.RosterKey) == 0` — with no roster key every health poll ships every account's email + private ntfy topic in plaintext, and `?roster=0` cannot suppress it. Startup warning only. | done |
| A4 | MEDIUM | operator debugging in prod | `internal/config/config.go:354-361, 368-375` | The `DEV_IDENTITY_EMAIL` guards key off `DataEncryptionKey` length or `AppOIDC.Enabled()`. In the recommended posture OIDC is unset, so the key is the sole backstop — complementary by luck. Commenting out the key while setting the dev email yields `["user","admin"]` on every request, after Caddy correctly stripped the headers. `README.md:167` overstates the protection. | done |
| A5 | MEDIUM | `DOMAIN` + `PUBLIC_BASE_URL` both empty | `internal/config/config.go:265,341-343` → `internal/scheduler/scheduler.go:945` | `PublicBaseURL` is never validated and degrades silently to `""`, making the 90-day re-authorise confirm link relative and unclickable — so sessions lapse, which is the exact failure the email exists to prevent. | done |
| A6 | MEDIUM | second process on the volume | `internal/store/migrate.go:400-421` | No schema-version table and no migration lock. `rebuildOverrideTable` does `PRAGMA foreign_keys=OFF` + `DROP`/`RENAME` guarded only by a `columnExists` probe — a read-then-write with no lock. | done |
| A7 | MEDIUM (operational) | CF proxy re-enabled | `internal/server/contact.go:160-174` | `clientIP` is correct for DNS-only Caddy, but nothing detects the 2026-07-28 Cloudflare regression returning. No startup assertion, no `/status` field echoing the observed client IP, no warning in the Caddy template. A bug that shipped once has zero detection. | done |
| A8 | LOW | CI artifact inspection | `.dockerignore` | Excludes `deploy`, `*.db`, `data`, `.git` but not a root `.env` (which `.gitignore:3` anticipates). `Dockerfile:14 COPY . .` pulls it into the build stage. Cannot reach the published image. | done |
| A9 | LOW | — | `internal/config/config.go:311,322,398`; `internal/server/admin.go:194` | Startup errors name the offending hex byte + index and print key/token lengths. `ConstantTimeCompare` leaks token length; a bare `Authorization: <token>` without `Bearer ` is also accepted (laxer than documented). `config.go:395` comment claims the status endpoint has no throttle — it does; the stale comment invites removing the length floor. | done |

## B. Authentication core

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| B1 | HIGH | OIDC mode only | `internal/webauth/webauth.go:64-91,101` | `Login` sets no cookie, so nothing binds the OAuth `state` to the browser that began the flow; `Callback` validates it purely by DB lookup. An attacker can force a victim's browser to complete the attacker's login — and the next thing the app asks a signed-in user for is their council password. | done |
| B2 | MEDIUM | anonymous flood | `internal/server/server.go:147` | `/auth/login` has no rate limiter and no concurrency cap, and each hit runs an unindexed `DELETE FROM oauth_state WHERE created_at < ?` plus an INSERT on the single shared SQLite connection. Every other public route self-throttles (`confirmLimit`, `statusLimit`); this is the outlier, and it contradicts the `guestSlots` reasoning. | done |
| B3 | MEDIUM | admin demotion / account deletion | `internal/session/session.go:33-64` | The signed cookie carries `Groups` with a fixed 12h TTL and no server-side store, so revoking admin or deleting an account leaves the old cookie fully valid — including `admin` — for up to 12h. No sliding renewal either, so active users are cut off abruptly. | done |
| B4 | LOW | — | `internal/server/contact.go:31-41` | `sameOrigin` compares host only, ignoring scheme, so an `http://` Origin matches an `https://` host. | done |
| B5 | LOW | — | `internal/server/middleware.go:123-127` | `touchActivity` runs **before** the CSRF check, so a rejected cross-origin request still resets the account idle clock. | done |

## C. Council client & credentials

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| C1 | HIGH | council-side HTML injection or open redirect | `internal/parking/auth.go:224,231,361-370` | `resolveAction` returns `base.ResolveReference(ref)` unchanged, so an absolute `action="https://attacker/"` in scraped login HTML becomes the POST target for `fields["Password"]`. No host allowlist anywhere, and the login client uses Go's default redirect policy so the base URL may already be off-host. Exfiltrates plaintext council passwords server-side; the user sees an ordinary failure. | done |
| C2 | MEDIUM | portal returns 200 + login page | `internal/parking/auth.go:65-78` | Only a 302/303 with `error=` or no `code` yields `ErrSessionExpired`. An HTML login page, JS-redirect, or 200 interstitial classifies as transient, so `recoverOrRetire` never fires: the session is never retired, no re-link prompt shows, and the user is told "trouble reaching the council" forever while the permit holds the wrong plate. | done |
| C3 | MEDIUM | portal API shape change | `internal/parking/parking.go:500-503` | `len(mv.PermitVehicles) == 0 → "", nil` makes "response not understood" indistinguishable from "no vehicle". The scheduler then writes an empty active registration and logs "changed directly at the council portal" — a false claim about the user's council account. | done |
| C4 | MEDIUM | cosmetic portal HTML change | `internal/parking/auth.go:228,231-232,330-357` | Attribute regexes match double-quoted values only; the antiforgery token is checked for presence but not non-emptiness; credential field names are hardcoded. A quoting-style change makes every login fail as `ErrLoginRejected`, which tells users their password is wrong, burns their throttle, and makes `recoverOrRetire` delete every saved session — a mass unlink blamed on users. | done |
| C5 | MEDIUM | any DB-write primitive | `internal/secretbox/secretbox.go:44,59` | No associated data, and one key seals the council cookie, access token, **council password**, and guest tokens. `viewDoorQR` (`internal/server/guest.go:1799`) opens `token_sealed` and renders the plaintext into a link and on-screen QR, so any blob moved into that column becomes a plaintext oracle. Defence-in-depth today (no write primitive exists). Fix must open legacy no-AAD ciphertexts and re-seal. | done |
| C6 | LOW-MED | failed login leaves a sibling cookie | `internal/parking/auth.go:274` | `strings.Contains(cookie, "Permits.IDM.Identity")` matches prefixed siblings (`.External`, `.Nonce`, `.Antiforgery`), so a failed login can report success, seal a useless cookie and store the password. Needs exact cookie-name parsing. | done |
| C7 | MEDIUM | hostile/broken portal | `internal/parking/auth.go:145` | Up to 1 MiB of portal-controlled body is embedded in an error string that reaches `log.Printf` — log injection via newlines plus 1 MiB log records per attempt. | done |
| C8 | LOW | hostile/broken portal | `internal/parking/parking.go:484,690` | `json.NewDecoder(resp.Body).Decode` with no `io.LimitReader` on attacker-sized arrays; unbounded `io.Copy(io.Discard, ...)` at `auth.go:57,262`, `parking.go:617`. Adjacent code already limits correctly, so these are omissions. | done |
| C9 | LOW | permit changes hands | `internal/parking/parking.go:526-534,584,640` | `regCache` is keyed on council permit ID with no owner and is never evicted; `internal/server/permits.go:234` deletes a permit without touching it. A re-added permit serves the previous owner's cached plate to the new one. | done |
| C10 | LOW | read-only DB leak | `internal/store/council.go:110-138` | The confirm token is stored plaintext while everything else in the row is sealed; it also rides in a GET query string, so it lands in proxy access logs. Store a hash. | done |
| C11 | LOW | — | `internal/server/templates/onboarding.html:23` | "Save my password" is pre-ticked on a first link, so retaining a third-party credential is the default outcome. Should be opt-in. | done |

## D. Multi-tenancy & authorization

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| D1 | HIGH | any signed-in user | `internal/server/account.go:194-259`, `internal/store/accounts.go:367-380` | `addMember` writes the `account_member` row immediately; the email is explicitly "not a login code" and there is no accept endpoint. `IsPrimary`/`HasOwnData` both pass for anyone not yet linked, so an arbitrary address can be claimed. The victim then sees the attacker's household, cannot link their own council account (403), and every vehicle/booking they create is written under the attacker's owner. Needs a real pending-invite + acceptance flow. | done |
| D2 | MEDIUM | any signed-in user | `internal/server/account.go:210-231` | The three rejection branches are distinguishable and run before the cap check, making `addMember` a zero-write oracle for "does this address use p.stonn, and is their permit set up". `removeMember:274` explicitly avoids implying knowledge of an address; this does the opposite. | done |
| D3 | LOW | household member | `internal/server/schedule.go:510-536`, `internal/store/schedule.go:249-254` | `{oid}` is owner-scoped but not bound to `{id}`, so a member can delete a booking on permit B via permit A's URL while the response re-renders A — an invisible deletion. Intra-account only. | done |
| D4 | LOW | household member | `internal/server/schedule.go:529-534` | `DeleteOverride` returns nil regardless of `RowsAffected`, so a no-op delete still writes an audit row and kicks the scheduler — replayable to flood the activity log past its display limit. `deleteGuestGrant` and `revokeDoorQR` avoid exactly this. | done |
| D5 | LOW | user deletes account | `internal/store/accounts.go:99-102` | `DELETE FROM account_log WHERE actor = ? OR target = ?` exact-matches a single-recipient `ActionGuestCreate` target, deleting a row from **another** household's audit trail. `redactLogTargets` exists for this reason but only sees the multi-recipient rows the delete missed. | done |
| D6 | LOW | OIDC mode | `internal/webauth/webauth.go:138,186-194` vs `internal/identity/identity.go:58` | OIDC lowercases ASCII-only with no `TrimSpace`; forward-auth does `ToLower(TrimSpace(...))`, as do all invite/recipient paths. A claim with whitespace or a non-ASCII uppercase silently voids a share. Not an impersonation path (one mode is active per deployment). | done |
| D7 | INFO | DB blip | `internal/server/middleware.go:99-107` | On a `MemberAccount` failure a **secondary's** writes silently re-scope to their own email, creating a phantom account. Not escalation (`isPrimary` stays false), but the comment claims "this can never read anyone else's data" without noting the write-scope shift. | done |

## E. Guest-pass surface

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| E1 | MEDIUM | anyone scanning a poster, or a visitor typing `ABC-123` | `internal/server/guest.go:1661-1668` | The invalid-plate branch builds `guestActView` inline with `PermitLabel: permitLabel(permit)`, bypassing the `RequestOnly` redaction at `guest.go:379-381` that exists because a wall-mounted QR would otherwise leak "typically an address or apartment number". Fires accidentally, not just adversarially. | done |
| E2 | MEDIUM | one anonymous scanner | `internal/store/guests.go:485-518`, `internal/notify/notify.go:739-763` | Five distinct plates fill `maxPendingGuestRequests`, and `ExpireGuestRequests` only clears rows >1h old on a 15-min tick, so one phone can kill a door QR for 60-75 min repeatedly. The nudge deliberately bypasses quiet hours at `high` priority, fans out to every member, and dedups on the plate — so ~120 3am pushes/hour/member, and denying frees slots faster. | done |
| E3 | MEDIUM | guest link holder | `internal/server/guest.go:512-560` → `internal/notify/notify.go:484-519` | `EnqueueApply`'s dedup key includes the plate and there is no per-account cap on the apply path (unlike invites at 1/day and guest links at 5/day), so cycling plates generates an email + push per attempt, plus one override row each. | done |
| E4 | LOW | household member | `internal/server/guest.go:1454-1466`, `internal/store/guests.go:818-830` | `RevokeGuestToken` lacks the `request_only = 0 AND on_screen = 0` filter that `ResetGuestToken` has, so a printed grant can be killed through the token route — which logs an empty target and sends **no** notification, unlike `revokeDoorQR`. | done |
| E5 | LOW | crafted POST | `internal/store/guests.go:143-174`, `internal/server/guest.go:1222` | `UpdateGuestGrant` omits the `on_screen`/`request_only` guard, so household cars can be attached to the public poster grant, and `guest-body` renders `Cars` without gating on `RequestOnly`. Not reachable via the UI; activation stays safe. | done |
| E6 | LOW | any consented user | `internal/server/guest.go:1075-1087,1516-1534`, `internal/store/guests.go:179-206` | No recipient cap: a 64 KB body allows ~4000 addresses, each a live token. `AddGuestTokens` loops **outside a transaction**, two statements each, monopolising the single DB connection and stalling the scheduler. `label` is likewise uncapped. | done |
| E7 | LOW | abusing guest | `internal/store/guests.go:818-843,458-468`, `internal/server/guest.go:665` | Revocation is not retroactive: no revoke/delete/kill-switch path touches the `override` table, so a guest's plate stays on the permit until end of tomorrow. UI copy ("can no longer use your permit", "will not work") reads as retroactive. Approved door-QR overrides use `guest_token_id = 0` so no sweep can even target them. | done |
| E8 | LOW | two visitors, same plate | `internal/store/guests.go:500-513` | Dedup returns the existing row's nonce, so visitor B receives visitor A's request id + poll nonce and can read A's status. | done |

## F. Scheduler & state machine

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| F1 | HIGH | disk full during VACUUM | `internal/store/store.go:82-86` | `os.Remove(path)` then `VACUUM INTO` — the last coherent snapshot is destroyed before the new one is written, and the retry repeats remove-then-fail, so no restorable backup exists for the whole outage. Also a daily window where a file-level backup can capture a half-written file. Needs temp + fsync + rename. | done |
| F2 | MEDIUM | port clash; slow HTTP drain | `main.go:171-197` | On a `ListenAndServe` error the function returns immediately, running the deferred `st.Close()` **without joining `loopsDone`** — the store can close under an in-flight council write. The SIGTERM path joins but reuses the same 10s `shutdownCtx` already spent by `httpServer.Shutdown`, so a 9s drain trips "did not stop in time" during normal operation. | done |
| F3 | MEDIUM | guest tap during a roster-boundary apply | `internal/server/guest.go:604-616` vs `internal/scheduler/scheduler.go:1128,1151-1154` | Handler and reconcile loop both call `SetVehicle` with no mutual exclusion. The council can end up holding the roster plate while the DB records the guest's, after which `want == p.ActiveRegistration` and every tick concludes "nothing to do". Correction waits on `checkDrift` — up to ~105 min. | done |
| F4 | MEDIUM | busy episode then vehicle deletion | `internal/scheduler/scheduler.go:1140-1144,1185-1213` | The `want != "" && p.FailStreak != 0` gate means a busy episode ended by the target becoming unresolvable never clears the streak — permanently. Weeks later a single transient blip lands at the notify threshold instantly and takes the maximum 30-min backoff on its first failure. | done |
| F5 | LOW | portal echoes a case variant | `internal/scheduler/scheduler.go:804,1128`, `internal/server/schedule.go:189` | Three `active_registration` comparison sites disagree on case sensitivity (`EqualFold` vs `==`/`!=`), so a case-only change can drive a real council write plus an "your permit was updated" notice and a displaced-driver email for a no-op. | done |
| F6 | LOW | end-of-day guest pass | `internal/server/schedule.go:94-97` | `endOfDay` at 23:59:00 with `Resolve`'s exclusive end opens a one-minute hole: the roster reasserts for 60 seconds, costing two council writes and two notifications where one was meant. | done |
| F7 | LOW | notifier down through the lead window | `internal/scheduler/scheduler.go:855` | `now.After(p.EndDate)` compares against a zoneless date parsed as UTC midnight, so the expiry warning stops at ~10-11am local on the final valid day while the permit is still active. | done |
| F8 | LOW | vehicle deletion | `internal/scheduler/scheduler.go:1128-1144` | `want == ""` is a fully silent no-op — no log, no activity row, no notification. Deleting a vehicle cascades its rules/overrides away and the permit then keeps the deleted car's plate indefinitely with no notice that the day is now unscheduled. | done |
| F9 | LOW | ~100 changing permits | `internal/scheduler/scheduler.go:326` | Stale threshold (5×interval) is below the worst-case pass duration given the 3s inter-permit delay, so a large midnight rollover false-alarms "reconcile stalled". Fleet-size dependent. | done |
| F10 | LOW | large DB | `internal/store/store.go:56,84` | `VACUUM INTO` monopolises the single connection; every handler and both loops block with no pool timeout. | done |

## G. Notifications, mail & webhooks

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| G1 | MEDIUM-HIGH | disk full / read-only remount | `internal/notify/notify.go:1001,1022` | `_ = s.store.MarkOutboxSent(...)` discards the error with no log; same for `RescheduleOutbox`. A failed bookkeeping write leaves the row `pending` with `next_attempt` in the past, so the 15s drain re-sends the same email indefinitely, 50 rows a pass — the exact reputation event the suppression list exists to prevent. | done |
| G2 | MEDIUM | any owner | `internal/notify/notify.go:684-701`, `internal/mailer/html.go:109-120` | `SendGuestLink` puts 40 chars of owner-controlled permit label into a DKIM-aligned email to any address the owner types, with `linkify` making any URL in it clickable. Victim's spam report → `SuppressComplaint`, which per `internal/store/suppression.go:169-192` is never pruned and never user-clearable, permanently killing their notifications. | done |
| G3 | LOW-MED | any owner | `internal/notify/notify.go:707-729` | `NotifyDriverDisplaced` mails arbitrary third parties with no per-recipient throttle (every comparable path has one), only a 15-min dedup keyed on the plate — so alternating plates yields ~4-8/hour indefinitely to an address that never opted in. | done |
| G4 | MEDIUM | attacker knows the topic ARN | `internal/server/seshook.go:95,238-253`; `internal/server/server.go:189` | Cert **fetch** happens before the signature and freshness checks, the cache is keyed on the full URL including query, and the route has no limiter — so incrementing `?n=` forces an unbounded outbound TLS GET per request and wipes the 64-entry cache every 64 misses. Separately the cert URL's path/query is unconstrained, so any `sns.<region>.amazonaws.com` bytes containing a PEM block would be accepted as trust anchor (AWS's own verifiers constrain the path). | done |
| G5 | LOW-MED | — | `internal/server/seshook.go:375-381` | SigV1 (RSA-SHA1) is accepted and `SignatureVersion` is itself unsigned, keeping the endpoint's trust on SHA-1 over a payload that includes remote-influenced text (`bounce.diagnosticCode`). | done |
| G6 | LOW | — | `internal/server/seshook.go:281-292` | A cached cert is never re-validated and never expires; no negative caching; the fetch runs outside the lock (thundering herd). | done |
| G7 | LOW | forwarded/archived email | `internal/notify/unsubscribe.go:30-35`; `internal/server/server.go:181-182` | Unsubscribe tokens are eternal, unrevocable bearer capabilities (MAC covers the address only — no expiry, no key version, no serial), they appear in proxy access logs, and `/u/*` is outside every rate limiter. Rotating the at-rest key invalidates every one already mailed. | done |
| G8 | LOW | dev/misconfig | `internal/notify/unsubscribe.go:24-27` | `DeriveUnsubKey("")` is the world-known constant `SHA-256("pstonn-unsubscribe-v1|")`, letting anyone forge an unsubscribe for any address. The `len(key) == 0` guard at `:39` is dead code — the derived key is always 32 bytes. | done |
| G9 | LOW | latent | `internal/notify/notify.go:1075-1089` | On a mixed email+ntfy row an email failure returns an error even though ntfy succeeded, re-pushing on each of 8 retries. `enqueueSplit` prevents mixed rows today, but the invariant belongs in the switch. | done |
| G10 | LOW | — | `internal/server/seshook.go:159,162,178`; `internal/notify/notify.go:1014` | Routine logs carry household-identifying data: recipient address, provider diagnostic, and a subject containing the permit label (typically a street address) plus a plate. | done |
| G11 | LOW | any user | `internal/server/vehicles.go:32` | Vehicle labels get `cleanLabel` but no server-side length cap (client `maxlength` only), unlike permit labels, so a 64 KB nickname inflates every apply notification and its stored outbox row. | done |

## H. Frontend & HTTP surface

| ID | Sev | Trigger | Location | Defect | Status |
|---|---|---|---|---|---|
| H1 | MEDIUM | shared device, Back button | `internal/server/views.go:330-342`, `internal/server/middleware.go:17-31` | `render()` sets only `Content-Type`; no `Cache-Control` anywhere. `/schedule`, `/vehicles`, `/activity`, `/settings`, `/guests`, `/admin` are cacheable, so signing out and pressing Back shows the previous user's data. The `/g/*` routes get this right via `noStore()`. | done |
| H2 | MEDIUM | broken council session | `internal/server/guest.go:387-391,296-315` | `decidedAt` is set only for `SourceOverride`, so `pendingState`'s `stalled` can never be true for a roster-driven target: the visitor page polls every 2.5s forever showing "Changing to X…", and the honest "taking longer than usual" message at `guest.html:132` is dead code. Also no `hx-sync`, so slow polls stack against `guestSlots`. | done |
| H3 | LOW-MED | link sent to a signed-in user | `internal/server/guest.go:885-891`, `internal/server/settings.go:43,56,58` | `?applied=`/`?resent=`/`?shared=` are echoed into the trusted green success banner with no read-path validation (the comment claims otherwise — true only of the write path). Not XSS (escaped text context), but content spoofing in the highest-trust element of an app whose premise is credential custody. | done |
| H4 | LOW (latent) | future caller | `internal/server/helpers.go:52-59` | `messageWithLink` escapes an `href` with `HTMLEscapeString`, which does nothing about the scheme — `javascript:` survives. Safe only because both callers pass `s.logoutURL()`. Same class as `guest.go:852`, which `Fprintf`s `msg` unescaped (safe only because it is a `const`). | done |
| H5 | LOW | control byte in path | `internal/server/guest.go:1128-1133` | Builds JSON with `%q` (Go quoting, not JSON), so a decoded control byte emits `\x01` and the manifest fails to parse. Not injection (`nosniff` + `application/manifest+json`). | done |
| H6 | LOW | — | `internal/server/middleware.go:17-31` | Missing `Strict-Transport-Security` (DNS-only since 2026-07-28, so no proxy adds it), `Permissions-Policy` (the app calls `navigator.wakeLock`), explicit `object-src 'none'`, and any CSP reporting. | done |
| H7 | LOW | — | `internal/server/middleware.go:19` | CSP carries `unsafe-inline` + `unsafe-eval`, so it provides zero XSS containment. Surface is small and quantified: 4 inline `<script>` blocks (all `layout.html`) and 4 inline `on*` attributes (`nav.html:14,27`, `guests.html:256`, `schedule.html:79`). Nonce-ing the scripts and converting the handlers drops `unsafe-inline` entirely; `unsafe-eval` must stay unless moving to the Alpine CSP build. | done |

## I. Test coverage gaps

| ID | Location | Gap | Status |
|---|---|---|---|
| I1 | `internal/identity`, `internal/session`, `internal/secretbox`, `internal/webauth` | **Zero test files** — the authentication and at-rest-crypto core, including the login flow B1 lives in. | done |
| I2 | `internal/scheduler`, `internal/model` | No test loads `Australia/Melbourne` or exercises a DST transition, despite wall-clock scheduling being the core function. Untested: `endOfDay` across transitions, `fillExpiry`'s claimed DST-safety, `ParseInLocation` of nonexistent/ambiguous times, the noon-anchored day count on a 23/25-hour day. | done |
| I3 | `internal/scheduler` | `checkDrift` is executed by no test — the fake council's `CurrentVehicle` always returns `""`, so the external-drift branch never runs. | done |
| I4 | `internal/model` | `Resolve` boundary instants (`now == StartsAt` inclusive, `now == EndsAt` exclusive) are untested; only clearly-before/after is covered. | done |
| I5 | `internal/store` | `Snapshot` has no test involving a failing VACUUM or a pre-existing file (F1). | done |
| I6 | `main.go` | Nothing exercises the shutdown error path or the shared-deadline join (F2). | done |
| I7 | `internal/server` | No coverage of D1-D5 (member invite, oracle, `{oid}` binding, no-op audit row, cross-household log deletion). | done |
| I8 | `internal/scheduler`, `internal/server` | No test runs a handler-style `SetVehicle` concurrently with `reconcileAll` (F3), and none covers the `want == ""` streak hole (F4) or case-variant plates (F5). | done |
| I9 | `internal/store` | `CopySchedule` (including its dropped `guest_token_id`) is untested. | done |
