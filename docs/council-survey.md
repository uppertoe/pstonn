# Council survey: visitor-permit models across Victoria

Surveyed 2026-08-30 from public council pages, policies and portal login redirects
(no test accounts). Companion to `council-connections.md`, which describes the
multi-tenant machinery; this document is about *what each council's scheme
actually is* and what p.stonn would need to grow to serve it.

Everything here that says "unverified" needs a live account and a capture
before it becomes a tenant (see the checklist in `council-connections.md`).

## The four permit models

Every council falls into one of these. The model, not the vendor, decides how
much of p.stonn applies.

| Model | What the resident does per visit | p.stonn fit |
|---|---|---|
| **Swap** — a standing visitor permit with no fixed plate; the holder edits the plate online | Log in, change the plate on the permit | Exactly what p.stonn does today (Stonnington) |
| **Re-plate** — no visitor product; the resident temporarily edits the plate on their *own* resident permit | Same as Swap, but the permit normally carries the resident's everyday car | Roster fits; the permit is the household car's, so every swap displaces it — the Stonnington "clobber" footgun is the intended use |
| **Coupon** — a yearly book of single-day allocations (plate + date), auto-approved | Allocate one coupon to a plate for a date | Different job: a *budget* to spend, not a *state* to keep right. Needs new ops, new UI, and a counter |
| **Paper** — hang-tag / sleeve / laminate / booklet | Hand the tag over | Nothing to automate |

Pattern: councils digitise the plate-fixed resident permit first and deliberately
keep the visitor permit on paper *because* paper is trivially swappable (Port
Phillip says so outright). Stonnington and Banyule are the two that digitised the
swap itself — which is what creates the chore p.stonn removes.

## Summary table

| Council | Model | Vendor / portal | Login | Cost & quantity | Confidence |
|---|---|---|---|---|---|
| **Stonnington** | Swap | Orikan ePermits, Angular SPA, `parkingpermits.stonnington.vic.gov.au` | Council-local `/idm`, code+PKCE, `ePermits.ssp.web` | $60/$90/$100 resident (Jan 2026); visitor permits per household | Live (production tenant) |
| **Banyule** | Swap (or paper, resident's choice) | Orikan ePermits **v7**, server-rendered, `epermits-ssp.banyule.vic.gov.au/ssp/` | Council-local `/idm`, **hybrid `code id_token` + form_post, no PKCE**, `ePermits.ssp.web.v7` | Max 3/property in any resident/visitor mix; 1st visitor $50, 2nd $75, conc. $11; expire 31 July | Auth flow + no-`/ssp-svc` confirmed (unauth recon 2026-08-30); permit read/write shape needs a capture |
| **Brimbank** | Re-plate | Orikan ePermits, `epermits.brimbank.vic.gov.au/SSP` | **PayStay** OIDC (`paystay.com.au`), `ePermits.Brimbank` | 1st free, 2nd $46; max 2; one vehicle at a time | Site text + redirect verified |
| **Whitehorse** | Re-plate | Orikan, `whitehorse-epermits.orikan.tech/ssp/` | Council-local ("Digital Permits By Orikan") | Not published | Site FAQ verified; flow unverified |
| **Kingston** | Re-plate | In-house, `residentparkingpermit.kingston.vic.gov.au` | Council in-house | 1st free, 2nd $55; max 2; "change the car any time online" | Site text only |
| **Glen Eira** | Coupon | Orikan ePermits `v7.11.99076`, `epermits.gleneira.vic.gov.au/ssp` + PayStay native app | **PayStay** OIDC, `ePermits.Gleneira.Azure`, implicit `id_token` form_post | 110 free single-day coupons/yr with the (free) 1st resident permit | Guide PDFs + redirect verified |
| **Merri-bek** | Coupon | Orikan, `epermits-merri-bek.orikan.tech/ssp` | **PayStay** ("Login - PayStay") | Books of 10 daily coupons $29.75 ($14.90 conc.); weekly $15.25 | Site text + login branding |
| Monash | Coupon (paper booklet) | TechnologyOne ePathway (apply only) | — | 10 daily permits $50/yr; max 1 booklet/6 months | Site |
| Melbourne | Coupon (paper vouchers) | In-house / Salesforce (apply only) | — | 18 vouchers $66.60; 1 booklet/2 months; 2 areas only | Site |
| Bayside | Paper visitor; digital resident | `bayside.permitportal.com.au` (resident/beach) | Vendor unknown | 4 free + 1 paid visitor | Site |
| Yarra | Paper (sleeve, transferable) | In-house forms | — | $58/$139/$261 | Site + 2026 PDF |
| Port Phillip | Paper (laminated) — explicitly excluded from June 2025 digital switch | TechnologyOne `copp.t1cloud.com` (resident) | — | $137/yr ($29 conc.) | Site |
| Boroondara | Paper (hang-tag) | In-house forms (10-day turnaround) | — | Up to 2 visitor of 3 permits | Site |
| Moonee Valley, Maribyrnong, Hobsons Bay, Frankston, Manningham, Hume, Geelong | Paper | In-house / GreenLight OPM (Hobsons Bay) | — | Various | Site |
| Darebin, Yarra Ranges, Mornington Peninsula, Knox, Nillumbik, Casey | None / unclear | Yarra Ranges + Morn. Pen. are/were Orikan (resident only; Morn. Pen. pilot ended Sept 2024) | — | — | Knox is consulting on introducing visitor permits (Apr–May 2026) — watch |

## Council profiles

### Stonnington (production)

- Swap model. Six apply-time permit types; Resident Permits are also
  holder-changeable in the platform (`PermitTypeAllowsVehicleChangeByHolder=True`)
  but the T&Cs forbid using them that way ("permanently associated with your
  vehicle registration"; a vehicle change needs ownership proof; cl. 7 no
  transfer; breach → infringement and/or cancellation). p.stonn must never offer
  a Resident Permit as schedulable.
- Public sentiment: 4,641-signature petition (Jan 2026) driven by new fees and
  the digital-only switch; the visitor complaint on record is "update online
  every time a visitor comes".

### Banyule — the second-tenant candidate

Known:
- "Digital visitor permits are stored online and can be changed from vehicle
  to vehicle at any time … users must update the vehicle registration number
  online each time they have a new visitor." Physical visitor permits remain an
  option at application time.
- Up to 3 permits per property: 2 resident + 1 visitor, or 2 visitor + 1
  resident. Names/addresses must match VicRoads exactly. Up to 10 business days
  to grant. Permits expire 31 July (so a mid-year pro-rata; renewal cadence is
  a council-wide date, unlike Stonnington's rolling anniversaries).
- Portal is Orikan ePermits v7 on a council-hosted domain with its own IdM —
  tenant-local credentials like Stonnington's, not a PayStay account.

Confirmed by unauthenticated recon (2026-08-30):
- `/ssp-svc/` returns **404** — the Angular SPA's JSON API we drive at Stonnington
  is not here. The permit read is HTML off the server-rendered app; the write is a
  form POST with a `__RequestVerificationToken`. So this is a distinct connector,
  `orikan-ssp-v7`, not a parameterisation of `orikan-ssp`.
- Auth: the SSP web client `ePermits.ssp.web.v7` requests `response_type=code
  id_token`, `response_mode=form_post`, `scope=openid profile`, redirect back to
  `/ssp/` itself, and **no PKCE**. The IdP is a modern Duende IdentityServer that
  *does* advertise `offline_access` and S256, though the web client uses neither.
  The `/idm` login is standard ASP.NET Identity (a `__RequestVerificationToken`
  form POST), the same shape `orikan` already signs in against.

Still unknown (needs a live account — the capture checklist lives in the
`internal/provider/orikanv7` package doc):
- The hybrid callback's POST body and the app session it sets (cookie name/lifetime).
- The permits-page HTML shape and the change-vehicle form's fields.
- Whether visitor permits report `CanChangeVehicle` the same way, and whether
  a permit can be left with no vehicle (`CanClearVehicle`).

### Brimbank — closest stack match, different product

- "You can temporarily transfer the registration on your ePermit to a genuine
  visitor … immediately via the PayStay app." One vehicle at a time; the permit
  is the resident's own.
- Same Orikan SSP as Stonnington but the login is the PayStay account (payment
  card, on-street parking across councils) — a much larger secret to hold.
- Fit: the roster model works unchanged, but every scheduled visitor displaces
  the resident's car. "Return to home vehicle" becomes the default fallback
  rule, not an edge case.

### Whitehorse and Kingston — re-plate, smaller footprint

- Whitehorse FAQ: "Can visitors park using my ePermit? Yes, but their vehicle
  details must be updated in your ePermit account." Orikan, council-local login.
- Kingston: in-house portal; "we do not provide visitor permits but you can
  transfer your valid permit … change the car any time online." Would need a
  brand-new connector (not Orikan).

### Glen Eira — coupon model, good native app

- 110 single-day coupons/yr issued automatically with the first (free) resident
  permit. Allocate plate + date; auto-approved; deletable; several plates per day
  allowed (one coupon each). Coupons are also the tradesperson permit.
- Policy (3.3.1): permits "may be used by more than one vehicle in a household
  or by visitors to a residence" — looser than Stonnington on re-plating the
  resident permit, though the resident permit is still per-plate and edits go
  through the portal.
- Login is the PayStay identity (see Brimbank). The visitor flow lives in the
  native PayStay app's Permits tab; the user's own assessment is that this app is
  far better than Stonnington's SPA. No online complaints found.
- Not a p.stonn tenant on current scope (no swap to schedule; automation spends
  a capped resource; payment-grade credential).

### Merri-bek — coupon model, paid

- Digital "book" of 10 single-use ePermits ($29.75) replacing paper scratchies;
  weekly permits also exist. Orikan + PayStay login. Same feature requirements
  as Glen Eira with money attached to every allocation.

### The paper councils

Nothing to automate today. Worth tracking because each is one procurement
away from a Swap or Coupon scheme: Bayside and Port Phillip have already moved
resident permits to a portal; Darebin's policy already describes digital
single-day permits; Knox is consulting on introducing visitor permits.

## What each model needs from p.stonn

### Swap (Banyule)

Backend
- Orikan v7 connector variant: hybrid form_post callback handling, server
  session capture, and either a `ssp-svc`-shaped API or a form-POST write path.
  Register as a distinct `connector` in `tenants.json` (`orikan-ssp-v7`) rather
  than parameterising `orikan-ssp` until the capture shows they're the same.
- Tenant `policy` gains the council's fixed expiry date (31 July) so renewal
  reminders and the "on permit now" expiry logic use a calendar date, not
  `EndDate` alone, if the portal reports it loosely.
- Otherwise the existing contract holds: `ListPermits`, `SetVehicle`,
  `Refresh`, keep-warm.

Frontend
- Nothing new; copy comes from the tenant's `terms` block. Add a per-council
  landing page (`/councils/banyule`) if launched publicly.

### Re-plate (Brimbank, Whitehorse, Kingston)

Backend
- `Permit` gains a `Role` (visitor / resident / other) derived from tenant
  config, replacing the name-substring `isVisitorPermit`. Re-plate tenants
  mark resident permits schedulable; Stonnington keeps them blocked.
- A **home vehicle** per permit: the resident's own plate, restored whenever no
  roster entry or override applies. Today's "desired = none" semantics become
  "desired = home".
- Tenant `policy.max_concurrent_vehicles` (Brimbank: 1) so a roster can't
  place two visitors at once.
- Credential class on the tenant (`credential: "paystay"`) so the store, the
  admin alerts and the consent gate know a payment-grade login is being held.

Frontend
- Onboarding copy that says plainly: "this schedules your *own* permit; your car
  is off the permit while a visitor is on it."
- Home vehicle setting on the permit; the dashboard's "on permit now" badge
  distinguishes home vs visitor.
- Consent clause and settings copy for the PayStay credential (stronger than
  the current "we keep your council login safe" line; needs approval before it
  reaches prod).

### Coupon (Glen Eira, Merri-bek)

Backend
- New provider ops: `ListCoupons(session) → {book id, total, remaining, expiry}`,
  `AllocateCoupon(session, plate, region, date)`, `ListAllocations`,
  `CancelAllocation`. A coupon tenant declares
  `Capabilities.Model = coupon` and does not implement `SetVehicle`.
- Scheduler: a **date-based** planner rather than the current reconcile-to-
  desired-plate loop. It allocates for each roster day at a lead time (say
  the evening before), never twice for the same plate+date, and cancels when a
  roster entry is removed before the date.
- **Coupon ledger**: per permit, track allocations made by p.stonn vs observed
  remaining on the portal; reconcile on every poll; alert when remaining drops
  below a threshold or when a roster would exhaust the book before expiry.
- Budget guard: a roster's projected annual spend (weekday count × 52) is
  computed and refused/warned when it exceeds the book (a daily carer = ~260 >
  110 at Glen Eira).
- Paid books (Merri-bek): never buy automatically; surface "book exhausted"
  and stop.
- Same PayStay credential class as Re-plate.

Frontend
- **Coupon counter** on the dashboard: remaining / total, expiry, projected
  burn from the current roster, and a "runs out on ~date" line.
- Roster UI is the same weekday grid, but each entry is "allocate a coupon for
  this plate on these days" — no "on permit now" state, instead "allocated for
  today / tomorrow".
- One-offs become "allocate for date X"; multi-plate same-day allowed.
- History view of allocations (coupon spent, date, plate) so the counter is
  auditable.
- Nothing about "return to home vehicle" — there is no home state.

### Cross-cutting

- Tenant registry fields to add: `model` (swap / replate / coupon),
  `credential` (tenant-local / paystay), `connector` variants, fixed-expiry
  date, `max_concurrent_vehicles`, coupon book sizes.
- Guard test that a `coupon` tenant never reaches the plate-swap code path and
  vice versa.
- Landing-page copy per model (the three "what this does" explanations are
  genuinely different).

## Recommended order

1. **Banyule** — same job, same credential model, a real second Swap tenant to
   exercise the multi-tenant work. Cost: a test account and one auth capture.
2. **Brimbank** — only if re-plating the resident permit is a product you want
   to sell; it changes the fallback semantics for everyone.
3. **Coupon model** — a second product, not a second tenant. Do it only if a
   coupon council with real pain appears (Merri-bek's paid books are the most
   plausible; Glen Eira has no visible pain).
4. Watch Knox and Darebin.

## Beyond Victoria: vendors and tenants worth tracking

A connector is per vendor, so each platform below is one integration that
could unlock every council on it. Surveyed 2026-08-30; models per the table
above; "unverified" = read off a public page, no account.

### Orikan ePermits (the platform p.stonn already drives)

| Tenant | State | Visitor model | Host / login | Notes |
|---|---|---|---|---|
| Stonnington | VIC | Swap | council CNAME, council IdM, code+PKCE | production |
| Banyule | VIC | Swap | `epermits-ssp.banyule.vic.gov.au`, council IdM, v7 hybrid | second-tenant candidate |
| **Burwood** | NSW | **Swap** | `epermits.burwood.nsw.gov.au/epermits/` ("Pinforce ePermits", council-local) | "find the visitor ePermit … click Update vehicle"; 1 free visitor ePermit per property + 1 paid; resident plate change = withdraw + reapply |
| Brimbank, Whitehorse | VIC | Re-plate | PayStay / council-local | see profiles |
| Glen Eira, Merri-bek | VIC | Coupon | PayStay | see profiles |
| Bayside | VIC | Paper visitor | `bayside.permitportal.com.au` (Orikan case study confirms vendor) | resident/beach digital only |
| Yarra Ranges | VIC | none | `epermits-yarraranges.orikan.tech`, `ePermits80`, implicit flow | oldest flow seen |
| Blue Mountains | NSW | none (visitor *pay* parking scheme, resident exemption permits) | `epermits.bmcc.nsw.gov.au` | not a visitor-permit scheme |
| Ryde | NSW | unverified | `ryde.nsw.gov.au` e-permits T&Cs exist | check |
| Hume (VIC), Brisbane (QLD), Town of Victoria Park (WA), ANU | — | unverified / not residential | various `*.orikan.tech` | Victoria Park has since launched vPermit — may have moved |

Three hostname patterns (`epermits.<council>`, `epermits-<council>.orikan.tech`,
`<council>-epermits.orikan.tech`), at least three login brandings and three
OIDC flows (implicit `id_token token`, hybrid `code id_token` form_post,
code+PKCE). Any new Orikan tenant needs its own auth capture before the
connector is assumed to fit.

### vPermit (Smarter City Solutions / CellOPark) — `vpermit.com.au/<tenant>`

Plate-based virtual permits, web self-service, no app or public API found.
Tenants: Northern Beaches (multi-use permit = 24 h sessions, 40 free/yr then
$5/day — a Coupon variant with the loudest backlash in the country), Mosman
(first all-virtual council, 2019), Strathfield, **Waverley** (rolling out 2026;
"visitor permits are linked to a vehicle's number plate and managed online" —
looks like Swap, unverified), Town of Victoria Park (WA), UNSW, Thames-
Coromandel (NZ). Worth a look once Waverley is live: a Swap model on a second
vendor would be the first non-Orikan connector, and Sydney's eastern suburbs
have Stonnington-like parking pressure.

### Duncan Solutions "PEMS" — `pems.pemsportal.com.au`

Plate-linked digital permits integrated with their enforcement stack; Port
Stephens (NSW) is the named customer. Visitor model unknown. Duncan also
pitched Bayside VIC. Low priority until a metro council appears on it.

### Council in-house / ERP portals

Kingston (in-house, Re-plate), Port Phillip (TechnologyOne — visitor stays
paper), Monash/Knox/Manningham (TechnologyOne ePathway/t1cloud — apply-only),
Hobsons Bay (GreenLight OPM, paper). None offers a digital visitor swap today;
Kingston is the only one where a connector would have something to do, and it
would be a one-council connector.

### Paper coupon councils to ignore

Woollahra (25 scratch permits/yr), Melbourne, Monash, and every "display on
dashboard" council: nothing to drive.

### Priority beyond Victoria

1. **Burwood (NSW)** — a confirmed Swap on Orikan with a council-local login;
   the cheapest possible third tenant if the connector generalises.
2. **Waverley (NSW)** — first candidate for a vPermit connector, once live.
3. Northern Beaches — only if the Coupon product is built; the pain is real
   and public but the model is sessions-with-a-cap.

## Sources

- Banyule: https://www.banyule.vic.gov.au/Parking-roads/Parking-permit
- Brimbank: https://www.brimbank.vic.gov.au/living-here/local-laws-permits-and-fines/parking/resident-parking-permits
- Whitehorse: https://www.whitehorse.vic.gov.au/residential-parking-epermits-frequently-asked-questions-0
- Kingston: https://www.kingston.vic.gov.au/council/payments-and-permits/resident-parking-permits
- Glen Eira: https://www.gleneira.vic.gov.au/services/parking/parking-permits, guide PDF `media/5f0br330/epermits-how-to-guide.pdf`, policy PDF `media/6388/residential-parking-permit-system-policy-052023.pdf`
- Merri-bek: https://www.merri-bek.vic.gov.au/living-in-merri-bek/parking-and-roads/parking-permits-and-fines/visitor-and-services-parking/
- Stonnington T&Cs / FAQ: https://www.stonnington.vic.gov.au/Services/Parking/Parking-permits/Resident-Parking-Permit-terms-and-conditions, …/About-digital-parking-permits/Parking-permit-FAQs
- Port Phillip: https://www.portphillip.vic.gov.au/council-services/parking-in-port-phillip/parking-permits
- Yarra: https://www.yarracity.vic.gov.au/residents/transport/parking/parking-permits/residential-and-visitor-permits
- Boroondara: https://www.boroondara.vic.gov.au/services/streets-roads-and-parking/parking-permits/residential-parking-permits
- Bayside: https://www.bayside.vic.gov.au/services/parking-and-roads/parking-permits
- Knox consultation: https://www.knox.vic.gov.au/whats-happening/news/help-drive-fairer-public-parking-busy-areas
- Stonnington petition: https://www.change.org/p/stop-stonnington-s-new-digital-parking-system-and-new-resident-permit-fees
- Burwood NSW ePermits: https://www.burwood.nsw.gov.au/For-Residents/Parking-in-Burwood/ePermits
- Waverley NSW digital permits: https://www.waverley.nsw.gov.au/top/news_and_media/council_news/all/2026/digital_parking_permits_coming_soon_to_waverley
- vPermit: https://vpermit.com.au/ ; https://smartercity.com.au/vpermit/
- Northern Beaches multi-use permit: https://www.northernbeaches.nsw.gov.au/services/parking/parking-permits/manly-parking-permit-scheme/manly-multi-use-parking-permit
- Duncan Solutions digital permits: https://duncansolutions.com.au/digital-permits/
- Orikan Bayside case study: https://orikan.com/insights/blog/bayside-city-council-digital-parking-permits/
