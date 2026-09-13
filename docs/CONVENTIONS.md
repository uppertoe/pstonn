# p.stonn conventions

How this codebase does things, written down from the code so that a new feature
looks and behaves like the ones already here. `docs/ARCHITECTURE.md` covers the
system's load-bearing invariants (the desired-state loop, the breakers, the
failure-notification episodes); this file covers the everyday shape of a
feature: how an action reaches the server, how the page answers, how the store
is written, how it is tested. Where a rule names a file or line, the code is
authoritative and the rule is a pointer to it.

Read this before building anything. Then find the nearest existing feature and
copy its shape exactly.

## 0. Before you build: the checklist

1. Find the nearest existing feature and copy its shape (section 2 names them).
2. An action whose result belongs inside a card is a targeted htmx request
   with a fragment define, a view struct with `Notice`, and a reply helper
   gated on `isHX(r) && !isBoosted(r)` (section 2a). A plain post is only for
   navigation or a list change (section 2b).
3. Register every route through `s.handle` with a guard; a mutation is
   `guardConsent` unless you write down why not (section 8).
4. After a successful change: `logChange`, and for a destructive act
   `notifyDestructive`; if the change alters what the schedule resolves to,
   `kickScheduler`, and take the permit's apply claim before withdrawing any
   guest authority (section 10).
5. Every store query is owner-scoped; a scoped delete of nothing is
   `ErrNotFound`; timestamps are RFC3339 text; secrets are sealed with a
   context string from `secretbox/context.go` (section 11).
6. Reserve the space every state needs so nothing moves; polls are quiet and
   bounded (section 4).
7. Copy in full sentences, in the fixed vocabulary (section 7).
8. Add golden cases, tests through the real router, then `go test ./...`,
   `gofmt -l .`, `go vet ./...`, and re-stamp goldens in their own commit
   (section 14).
9. Check what you built in a real browser, not from a curl transcript: click
   the control, then read the address bar, the scroll position and the DOM.

## 1. The stack

- **Go, `html/template`, SQLite.** One binary (`main.go`), templates embedded
  from `internal/server/templates/*.html`, static assets embedded and vendored:
  the app makes no external requests (`internal/server/templates.go`).
- **htmx 2.0.3**, loaded in the head with the CSP nonce. The whole signed-in
  app is boosted: `<body hx-boost="true">` (`layout.html`). htmx config sets
  `globalViewTransitions:true`, so every swap cross-fades.
- **Alpine.js 3.14.1**, deferred, for state that lives in the page (open/closed,
  selected tab, a modal). `x-cloak` is defined in `app.css`.
- **No inline event handlers.** The CSP nonce cannot cover `onclick=`; scripts
  live in the head of `layout.html` and wire behaviour by `data-*` attributes
  (`data-confirm`, `data-print`, `data-share-pstonn`, `data-theme-toggle`,
  `data-dispatch`). A new inline script goes in the head for the same reason
  (the comment at `layout.html` "These live in the head, NOT in the body").
- **CSP** (`internal/server/middleware.go`): `script-src 'self' 'nonce-…'
  'unsafe-eval'` (Alpine needs eval), `style-src 'self' 'unsafe-inline'` (the
  colour language is inline `style=`).

## 2. How an action reaches the server

There are exactly two shapes. Choose by asking: *does the result belong inside
the thing the person just touched?*

### 2a. A targeted htmx request: the default for anything inside a card

The form or link carries `hx-post` (or `hx-get`), `hx-target` naming the
fragment that changes, and `hx-swap`. The handler answers with **only that
fragment**, re-rendered, with the outcome inside it. Nothing else on the page
moves, the address bar does not change, and the page does not scroll.

This is how every in-place action in the app works: a roster cell, a one-off
booking, adding or removing a roster week, copying a schedule, clearing a
permit, the visitor-QR modal, the notification settings, a rego's email and
notify toggles, guest activation and revert, and the quick-picker card. The
inventory of every `hx-post`/`hx-get` in the templates is in the table at the
end of this section.

The recipe, taken from the schedule's permit card and the quick-picker card:

1. **A define for the fragment**, kept in the page's own template file, whose
   root carries the id the target names:

   ```html
   {{define "picker-card"}}
   <section class="card fold" id="picker" x-data="{open: {{if .Open}}true{{else}}false{{end}}}">
     …
     {{if .Notice}}<div class="banner ok">{{template "ic-check"}} <span>{{.Notice}}</span></div>{{end}}
     <form method="post" action="/guests/picker/update"
           hx-post="/guests/picker/update" hx-target="#picker" hx-swap="outerHTML">…</form>
   </section>
   {{end}}
   ```

   The page includes it with `{{template "picker-card" .GuestMgmt.PickerCard}}`;
   the handlers render it on its own. Keep `method`/`action` on the form as
   well: that is the no-script fallback (see 2b).

2. **A view struct for the fragment** with a `Notice string` for the outcome
   (`permitView.Notice`, `pickerCardView.Notice`), so the message lands where
   the eye already is.

3. **One reply helper per fragment** that every handler for it ends with:

   ```go
   func (s *Server) respondPickerCard(w, r, owner string, edit bool, notice, flag string) {
       if !isHX(r) || isBoosted(r) {          // no script, or a boosted whole-page post
           http.Redirect(w, r, "/guests?picker="+flag+"#picker", http.StatusSeeOther)
           return
       }
       card := … // rebuild the view from the store
       card.Open, card.Notice = true, notice
       w.Header().Set("Content-Type", "text/html; charset=utf-8")
       templates.ExecuteTemplate(w, "picker-card", card)
   }
   ```

   The schedule's is `renderPermitFragment`/`respondPermitNotice`
   (`internal/server/schedule.go`). Gate on `isHX(r) && !isBoosted(r)`: a
   boosted request also carries the `HX-Request` header but wants a whole
   page, and handing it a fragment blanks the screen.

4. **Validation failures** return `s.formError(w, r, msg)`. For an htmx
   request that is a bare `422` with a plain-text message, which the page shows
   as a five-second toast and does not swap; for a plain request it is the
   branded message page. The form stays on screen for a retry.

5. **Confirms** on an htmx form use `hx-confirm="…"` plus `data-confirm-ok`
   for the button label. The shared `<dialog id="confirm-dlg">` in the layout
   handles both this and plain forms' `data-confirm`.

6. **Tell the rest of the page only by event.** When a fragment's change
   affects something outside its target, set `HX-Trigger: schedule-changed`
   (or a new event) on the reply and let the other element re-fetch itself
   (`#legend` uses `hx-trigger="schedule-changed from:body"`). Do not push
   out-of-band markup; overlapping replies would race.

7. **A reply that changes nothing visible** answers `204 No Content`: htmx
   swaps nothing, so the page only repaints on a real change. The polls do
   this on an unchanged fingerprint (`guestLive`, `guestRequestStatus`,
   `ntfyStatus`), and the per-rego toggles do it on a clean save.

8. **Corrective renders on a `hx-swap="none"` form** use `HX-Retarget` and
   `HX-Reswap` headers (`settings.go`, the notification form): a clean save
   must not re-render, a rejected one must.

### 2b. A plain form under the boosted body: for navigation and list changes

`method="post" action="…"` with no `hx-*`. htmx still submits it, follows the
303, and swaps the whole page in place with a cross-fade, scrolling to the top.
The handler ends with `http.Redirect(…, http.StatusSeeOther)` to a page whose
GET reads a query flag and sets `.Flash` or `.Warn`, which `app.html` renders
as a banner above the section title.

Use this when the action **changes which page you are on or which list you
are looking at**: creating a guest pass (the page then shows the new links),
deleting a pass, adding or removing a rego, permit delete, every account and
council form in Settings, the contact form. Do not use it for an
action whose result belongs inside a card; that is 2a.

Rules that go with it:

- The query flags are **validated on read**, never echoed: a plate must parse
  as a rego, an address as an email, or the flag is dropped (`guestsPage`,
  `settings.go`). Anyone can hand a signed-in user a crafted link.
- Double-submit guards for boosted posts are Alpine, not htmx: mark the form
  sent on submit, release on `htmx:after-request` with status >= 400
  (`guests.html`, the pass form). A 422 leaves the form on the page.
- Links that need head assets or a real navigation (the public pages with
  demo scripts, `target="_blank"` links, the printable poster) carry
  `hx-boost="false"`.

### The inventory

Every targeted request in the templates today, so a new one can copy the
nearest:

| Where | Request | Target, swap | Reply |
|---|---|---|---|
| Schedule legend | `GET /schedule/legend` on `schedule-changed` | `#legend`, outerHTML | `legend` |
| Roster cell, week add/remove/restore, one-off add/delete, clear, copy schedule, dismiss copy offer, rename | `POST /permits/{id}/…` | `#pbody-{id}`, innerHTML | `permit-body` with Notice |
| Plate poll | `GET /permits/{id}/card?n=` on `load delay:Ns` | `closest .nowbadge`, outerHTML, `hx-select=".nowbadge"` | `permit-body`, narrowed |
| Visitor QR from the card | `POST /guests/qr` | `#qrbody-{id}`, innerHTML transition:false | `qr-card` |
| Guest activation, revert, live poll | `POST /g/{token}`, `/revert`, `GET /g/live/{token}` | `#gbody`, innerHTML | `guest-body`, or 204 |
| Printed-QR request status | `GET /g/req/{id}` every 3s | `#reqstatus`, outerHTML | `guest-req-status`, or 204 |
| Notification settings | `POST /notifications` on change, send a test, test push, regen topic, resume email, ntfy status poll | `#notify-body`, innerHTML or none | `notify-body`, 204, or `HX-Retarget` |
| Rego email and notify toggle | `POST /regos/{id}/email`, `/notify` | none | 204 |
| Quick picker create, update, new link, delete, edit, cancel | `POST /guests/picker…`, `GET /guests/picker[/edit]` | `#picker`, outerHTML | `picker-card` with Notice |

## 3. Feedback

- **Banner above the title** (`.banner.ok` / `.banner.warn` in `app.html`)
  for the outcome of a whole-page post. It is the app-wide pattern; do not
  move it.
- **Notice inside the fragment** for a targeted request (section 2a).
- **Toast** (`#toast`, bottom centre) only for errors, raised by the
  `htmx:beforeSwap` handler: a 422 is a five-second toast of the server's
  plain-text message; a 403/409/429/5xx is a sticky, selectable toast of the
  first paragraph of the message page. Never render a success as a toast.
- **Inline refusal before any request** where the form can know: the pass
  form greys its button with a note until a recipient looks like an email;
  the notification form shakes a checkbox it will not allow off. The comment
  on the pass form records why: a person on a phone saw only the toast and left.
- **Confirms** through the shared dialog (`data-confirm` on plain forms,
  `hx-confirm` on htmx ones), with `data-confirm-ok` naming the action on the
  button. `data-plate-confirm` composes the message from the typed plate.
- **Pending states look pending.** A saved-but-not-applied change shows a
  spinner and "Changing to …" in a slot of fixed size; the plate on the
  permit is always the council's actual record, never the intended one. Polls
  are bounded (`platePollDelays`, `armPlatePoll`) and end in an honest
  "couldn't confirm" mark rather than spinning forever.

## 4. Stability: nothing moves unless the person moved it

- **Reserve the space a state needs.** The guest page's status is a two-line
  slot of constant height (`.gstat`/`.gsub`); the plate pill's check sits in a
  fixed `.pslot`; `.phint` is sized in `ch` to its longest text; the mobile
  `.nowbadge` reserves a second row. A new pending or settled state goes in a
  slot like these, measured, not appended.
- **Polls must not animate the page.** Add `.hx-quiet` (no loading bar) and
  `hx-swap="… transition:false"` (no cross-fade) to any `hx-trigger="every …"`
  or `load delay` request, and narrow it with `hx-select` where re-rendering
  the whole fragment would replay entry animations.
- **Keep Alpine state outside the swapped fragment** when the fragment is
  re-rendered often (the schedule's `wk` lives on the card, not in `#pbody`),
  or on the fragment's root when the fragment is replaced whole (the
  quick-picker card's `open`), so it re-initialises cleanly.
- **No ids on elements Alpine binds inside a swapped fragment.** htmx's settle
  writes server-rendered attributes back onto id-matched elements about 20 ms
  after a swap, clobbering the class or style Alpine just set (the week tabs
  snapped back on every roster tap). Use `aria-label`, not `aria-controls`.
- **Modals live outside the swap target** (`permit-modals` beside `#pbody`,
  teleported to `body`), and a test fails if one is rendered inside
  `permit-body`.
- **`hx-preserve` only on poll replies** (`KeepForm`), so a half-filled form
  survives a swap while an action's reply deliberately resets it.
- **The checklist is never swapped live**: it renders from server state on
  page load so ticks never move anything mid-visit.

## 5. Templates

- One file per feature (`templates.go`). `layout.html` dispatches on `.State`
  to a `page-*` define; inside the signed-in app `app.html` dispatches on
  `.Page`. Fragments are defines in the same file as the page that swaps them.
- Shared defines: `appbar`, `appnav`, `checklist` (`nav.html`, `app.html`),
  `pageheader` and `topback` (`public.html`), the `ic-*` icons (`icons.html`).
- Template functions (`templates.go`): `asset` (adds the content hash), `T`
  (the i18n catalog, for copy that interpolates council vocabulary or needs a
  slotted link), `possessive`, `sentence`, `maskRego`, `localTime`,
  `localEnd`, `weekdayName`, `link` with typed options only.
- Icons are bare `<svg viewBox="0 0 24 24">` defines; size and stroke come
  from the global `svg` rule. Inside a button the icon precedes the label; an
  icon-only button carries `title` and `aria-label`.
- Every page and fragment has a golden (`testdata/golden/`). Add a case to
  `templateRenderCases` or `goldenFragmentCases` for each new state, then
  `go test ./internal/server -run Golden -update` in its own commit, so the
  diff of the goldens is the review of the copy.

## 6. CSS

- Tokens at the top of `app.css`: surfaces, ink, line, the semantic
  `--ok/--warn/--danger/--info` pairs, and one hue per tab in `--sec-*`. A
  section's hue is set locally with `style="--hue:var(--sec-guests)"` and
  worn by its title chip, nav tab and hints. Keep new hues clear of the
  semantic colours.
- Families to reuse before inventing: `.card` (and `.card > h2` with its
  `.ic` chip), `.sectitle`, `.subtitle`, `.sub`, `.empty-note`, `.banner`,
  `.plate` (and `.plate.masked`, `.noplate` in the same box), `button` /
  `.ghost` / `.sm` / `.icon` / `.danger`, `.btnlike` for a link that must look
  like a button (it takes the same modifiers: `class="btnlike ghost sm"`; never
  put a `<button>` inside an `<a>`), `.row`, `.fld`, `.toggle`, `.checks`/`.check`, `.qropts`/`.qropt`,
  `.tiles`/`.tile`, `.fold-*`, `.todo-*`.
- Dark theme is three-way: a `[data-theme]` choice on the root, and
  `prefers-color-scheme` for the unstamped default. Define a colour once as a
  token and override the token in both dark blocks.
- The main breakpoint is `max-width:640px` (bottom nav, single columns).
- The stylesheet is served with a `?v=` hash of every static file; any CSS
  change re-stamps every page golden.

## 7. Copy

Plain, educated Australian English, addressed to an equal, in full sentences
with a verb. That applies to captions, summaries and one-line notes as much as
to paragraphs. The vocabulary is fixed: a **rego** goes **on the permit**; a
**booking** is the permit for a period; **number plate** where it already
appears; a **guest pass**, a **visitor QR**, a **printed QR**, the **quick
picker**. Say what happens rather than allude to it, and say where the control
is. Copy that names the council or its portal goes through the i18n catalog
(`internal/i18n/catalog/en-AU.json`).

## 8. Routes and guards

- Every route registers through `s.handle(mux, "METHOD /path", guard, h)`
  in `internal/server/server.go`, which records the guard on `s.routes` so
  tests assert over it. Four guards: `guardPublic` (no wrapper; the handler
  is authenticated by a signed token or wraps itself in `publicGuest` or
  `throttlePerIP`), `guardUser` (signed in, same-origin check on mutations,
  no terms gate), `guardConsent` (`guardUser` plus accepted terms; **the
  default for anything that stores or changes account data**), `guardAdmin`
  (admin group, no CSRF check, so never a mutation).
- `TestMutatingRoutesAreGuarded` fails any POST that is not `guardConsent`
  unless it is listed in `userMutations` or `publicMutations` in
  `routes_test.go` with a written reason. `TestHandlerRoutesNoConflict`
  catches a mux pattern conflict at registration.
- CSRF is the `Origin` header, falling back to `Referer`, both compared to the
  request host; neither present means refused (`sameOrigin`, `contact.go`).
  Do not set `Referrer-Policy: no-referrer` on an app page: `noStoreCache` is
  for signed-in pages, `noStore` (which does set it) is only for public pages
  whose URL carries a live token.
- Public routes that touch the store must be bounded: `publicGuest` (per-IP
  read limit plus a global concurrency cap that sheds with 503) or
  `throttlePerIP`. Key limiters by `rateLimitKey(r)`, which masks IPv6 to a
  /64. Every limiter is a field initialised in `New`, pinned by
  `TestNewInitialisesEveryRateLimiter`.
- A new public path must also be public at the proxy: the `@public` matcher
  in `deploy/pstonn.caddy` (and its live copy in the deploy repo), or the
  gateway bounces it to the login page. Comments in `server.go` name the
  outages this caused.

## 9. Handlers

- A page handler opens with `base, ok := s.appShell(w, r, "page")`, which
  renders the terms, onboarding and permit-picker gates itself and returns
  `ok=false` when it did.
- A mutating handler opens with `user, owner, isPrimary, ok :=
  s.accountForWrite(w, r)`, which fails closed (503) when membership cannot be
  resolved; owner-only actions then return a 403 message on `!isPrimary`.
  The read path, `resolveAccount`, falls back to the caller's own account
  with primary privilege withheld and must not be used to authorise a write.
- Replies: `formError` (422 plain text to htmx, 400 page otherwise),
  `message(w, code, msg)` (the branded message page), `serverError` (500,
  logged), `redirectHome` (303 to `/schedule`). No `HX-Redirect`,
  `HX-Location` or `HX-Push-Url` response headers anywhere; navigation is a
  303. (The `hx-push-url` attribute on the booking button is a client-side
  address-bar tidy, not a reply.)
- `render` executes into a buffer so a mid-render failure never ships a
  truncated 200; on error it emits the dependency-free bare page.
- Query flags read on a GET are validated (`validRego`, `looksLikeEmail`)
  or matched literally as booleans; they are never echoed.
- `pathInt`/`atoi64` turn a bad id into 0, which owner-scoped queries miss;
  `limitBody` caps forms at 64 KB on every state-changing request.

## 10. After a change: log, notify, kick, claim

- `s.logChange(ctx, owner, actor, action, target, detail)` **after** the
  change succeeded. Actions are the stable slugs in
  `internal/store/changelog.go`; the Activity tab's sentence for each lives
  in `changeText` in `internal/server/changelog.go`, and an unknown slug still
  renders. `logChange` also records the once-ever milestone for the "Still to
  try" lines through `milestoneForChange`; the change log is pruned at 90
  days, milestones are not.
- `s.notifyDestructive(ctx, owner, actor, summary)` for anything irreversible
  that other members should hear about (a wiped roster, a deleted rego, a
  revoked pass). Never for the person who did it, never for routine edits.
- `s.kickScheduler()` after anything that changes what the schedule resolves
  to now (a swept booking, a revoked link), so the permit is corrected on the
  next pass rather than the next tick.
- Before withdrawing guest authority, take the permit's apply claim:
  `release := s.claimPermitApplies(ctx, ids)`, mutate, `release()`. An
  activation already holding the claim completes and is then swept; one that
  has not started blocks and fails its re-check.
- A missing row on a repeated or stale submit is tolerated silently: no log
  line, no notice, no error, because the dedup key only suppresses identical
  repeats and announcing a non-event invents one.

## 11. Store

- One pooled SQLite connection (`SetMaxOpenConns(1)`), so a query issued
  inside an open `rows` cursor blocks forever. Materialise rows into a slice,
  then issue follow-ups (`ListGuestGrants` shows the shape).
- Migrations (`migrate.go`) are `CREATE TABLE IF NOT EXISTS` plus a list of
  `ALTER TABLE … ADD COLUMN … NOT NULL DEFAULT …` statements that tolerate
  "duplicate column". Choose the default so no backfill is needed. Every
  statement re-runs on every start; `schemaVersion` is a downgrade fence,
  not a skip, and is bumped only when an older binary must refuse the file.
- Every query carries `WHERE owner = ?`, or joins the owner in from the
  parent table, and ownership is checked inside the transaction before any
  write. A scoped delete or update that affects no rows returns
  `ErrNotFound`, so "not yours" and "not there" are one neutral answer;
  `ErrDuplicate` is detected by SQLite's numeric result code.
- Transactions: `tx, err := s.db.BeginTx(ctx, nil)` … `defer tx.Rollback()`
  … `return tx.Commit()`. Capacity-and-consume is one guarded statement, not
  check-then-act.
- Timestamps are RFC3339 text via `nowUTC()`; `''` means never. Flags are
  `INTEGER` via `boolInt`.
- Secrets at rest go through `s.box.SealCtx` / `OpenCtx` with a context
  string from `internal/secretbox/context.go` (purpose, owner, and tenant
  where it matters). A blob that will not open is treated as absent, never
  as fatal.
- Revoking guest authority sweeps that link's still-live bookings
  (`sweepLiveGuestOverrides`); a grant that still backs a live booking is
  disabled, not deleted, because `override.guest_token_id` has no foreign
  key and an orphaned booking could never be swept.
- Personal data: emails in logs only through `redact.Email`; plates are
  deliberately not redacted; dead links lose their recipient address after 30
  days; deleting an account de-identifies rows that are another household's
  record rather than deleting them. Retention windows are constants in
  `scheduler/housekeeping.go`, changed by review, not by config.

## 12. Notify

- An apply is described by `notify.ApplyOutcome` (`compose.go`): `Source` is
  one of `roster`, `override`, `guest`, `doorqr`, `picker`; `By` names a
  third party's link; `DisplacedReg`/`DisplacedTold` carry a bumped booking.
  Add a new `Source` in `fromSchedule` if it is the household's own change,
  because that is what failures-only mutes.
- From a handler with no reconcile loop behind it, `EnqueueApply` (durable
  outbox); from the scheduler, `NotifyApply`. Both apply
  `mutedByFailuresOnly` per member. Quiet hours hold a routine notice until
  the member's morning; an `actionNeeded` outcome bypasses them and forces
  email even with email off.
- Dedup keys are composed per member and channel and hashed at rest;
  pending rows always dedup, sent rows for fifteen minutes, dead rows never.
- Anything a stranger can trigger is rate-limited per account in the server
  (`guestApplyNotify`, `guestNudge`, `guestScanner`): the change is never
  dropped, only the notification. These are package-level, so tests call
  `isolateGuestBounds(t)`.
- `NotifyAdmin` is for systemic conditions only, paced with `sync.Once`
  where it could repeat, and paired with a log line that carries the detail.
- Every notice has a golden in `internal/notify/testdata/golden`; add a
  `run(...)` case in `golden_test.go` and regenerate with
  `go test ./internal/notify -run Golden -update`.

## 13. Logging

- `var alog = applog.For("pkg")` once per package; `Infof` for best-effort
  failures the request already survived, `Warnf` for a degraded but handled
  condition, `Errorf` for an internal failure the operator must see. Lines
  come out as `level=… msg="…" subsystem=…` with journald's timestamp.
- Never a raw email address in a log line: `redact.Email(addr)`. Error text
  we did not compose goes through `redact.InText`.
- The person sees a plain apology; the operator detail goes to the log.

## 14. Tests and CI

- Harnesses: `newAuthzServer` (forward-auth identity by header, real
  secretbox, no tenant) with `s.doReq(method, path, email, origin, form)`
  through the real router; `newApplyRig` (fake council, real mux and
  scheduler) for anything that applies a plate; `newGuestTestServer` for
  store-backed guest logic; `postGuest`/`getGuest` for `/g/*`;
  `seedDoorQR`; `isolateGuestBounds` whenever `/g/*` is touched. In the
  store, `newTestStore`.
- Lock a new fragment or page state with a golden: a `renderCase` in
  `dashboard_test.go` or a `goldenFragmentCases` entry in `golden_test.go`;
  a new notice with a `run` case in the notify goldens. Regenerate in a commit
  that touches nothing else. Any CSS edit re-stamps every page golden.
- Structural guards to keep green: `TestAuthorizationMatrix`,
  `TestMutatingRoutesAreGuarded`, `TestNoTenantLiteralsOutsideTheRegistry`,
  `TestMilestoneActionConstantsExist`, `TestNewInitialisesEveryRateLimiter`,
  the CSP and no-inline-handler checks in `frontend_security_test.go`, and
  the cache-header tests.
- CI runs `go vet`, `go test -race ./...`, a `CGO_ENABLED=0` build, gofmt and
  govulncheck, then boots the image and probes `/healthz` before pushing.
  `git config core.hooksPath .githooks` runs the same fast checks on push.
  `scripts/e2e.sh` drives the built binary through a dev-shaped and a
  prod-shaped run.

## 15. The dev loop

```sh
COUNCIL_SANDBOX=1 COUNCIL_SANDBOX_APPLY_DELAY=0 DEV_IDENTITY_EMAIL=you@example.com \
  COOKIE_SECURE=false LISTEN_ADDR=127.0.0.1:8099 SQLITE_PATH=./local.db \
  PUBLIC_BASE_URL=http://127.0.0.1:8099 go run .
```

- `DEV_IDENTITY_EMAIL` and `COUNCIL_SANDBOX` refuse to start beside any
  production signal (`DATA_ENCRYPTION_KEY`, `APP_OIDC_ISSUER`, `DOMAIN`, a
  non-loopback `PUBLIC_BASE_URL`). So the sandbox seals with a random key per
  boot: anything sealed (a printed QR, the quick picker's link) cannot be
  opened after a restart and the page offers a new one, which is the
  intended fallback.
- A POST to the sandbox from the shell needs `-H "Origin: http://127.0.0.1:8099"`.
- `COUNCIL_SANDBOX_APPLY_DELAY=0` lands a plate inside the call; the default
  6 s exercises the pending state and the next-tick settle.
