package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// The public, token-gated guest surface: the activation menu, the live poll,
// activation and revert, and the shared apply path. Split out of guest.go by its
// banner sections; the view types, token helpers and process-wide bounds they
// share stay in guest.go.

// ================= PUBLIC ACTIVATION (no login) =================

// guestPage renders the activation menu for a token. It has NO side effects, so
// email scanners and link-preview bots that fetch the URL can't trigger anything.
func (s *Server) guestPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)) {
		s.renderGuestInactive(w, r)
		return
	}
	s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "")
}

// guestCurrentPlate is the plate to show as "on the permit now": the tenant's
// own (cached) record when reachable, else our stored belief. Never an error —
// a tenant hiccup must not fail the page.
func (s *Server) guestCurrentPlate(ctx context.Context, gc guestCtx, permit model.Permit) string {
	if gc.Grant.RequestOnly {
		return "" // a printed door QR must not disclose the current plate
	}
	current := permit.ActiveRegistration
	if s.tenant != nil { // a tenant hiccup (or, in tests, no client at all) must not fail the page
		if actual, _, _, err := s.tenant.CurrentVehicleCached(ctx, permit.Owner,
			model.Permit{TenantID: permit.TenantID, CouncilPermitID: permit.CouncilPermitID, PermitTypeID: permit.PermitTypeID}, 5*time.Minute); err == nil {
			// This read just showed the tenant holding a different plate than our
			// stored belief — the one state where the scheduler could wrongly skip a
			// due change as "already correct". Don't wait out the ~6h drift cadence
			// with a guest at the kerb: ask for the owner's drift read on the next
			// warm pass (≤3 min), which verifies and adopts through the normal
			// external-change path. Divergence-gated, so an open guest page polling
			// a healthy permit requests nothing.
			if !model.SamePlate(actual, permit.ActiveRegistration) && s.sched != nil {
				s.sched.RequestDriftSoon(permit.Owner)
			}
			current = actual
		}
	}
	return current
}

// guestPlateCheckedAgo reports how long ago the plate shown to a guest was
// actually confirmed with the tenant, as display text — "" while the reading is
// fresh (or unknown). The guest page's "On the permit now" line is the single
// most load-bearing sentence in the app for a visitor about to walk away from
// their car, and it used to state a cached value as present-tense fact with no
// age bound: during a tenant outage "now" could be days old.
func (s *Server) guestPlateCheckedAgo(ctx context.Context, permit model.Permit) string {
	if s.tenant == nil {
		return ""
	}
	_, age, fresh, err := s.tenant.CurrentVehicleCached(ctx, permit.Owner,
		model.Permit{TenantID: permit.TenantID, CouncilPermitID: permit.CouncilPermitID, PermitTypeID: permit.PermitTypeID}, 5*time.Minute)
	if err != nil || fresh {
		return ""
	}
	now := time.Now()
	return agoText(now, now.Add(-age))
}

// revertPlate decides whether a guest may revert, and to what: the captured
// baseline, only while its window lasts, only when it isn't already on the
// permit, and only when it is NOT one of the link's own cars (those they can
// simply tap; the revert exists to restore a plate they could not pick).
func revertPlate(baseline string, until time.Time, current string, cars []model.Vehicle, now time.Time) string {
	if baseline == "" || !now.Before(until) || model.SamePlate(baseline, current) {
		return ""
	}
	for _, v := range cars {
		if model.SamePlate(v.Registration, baseline) {
			return ""
		}
	}
	return baseline
}

// guestDesired returns the plate the schedule is currently steering the permit
// toward ("" when nothing is scheduled) with its registration state, when that
// decision was made, and when its booking ends (both zero when roster-driven/
// open-ended). It is the same resolution the scheduler acts on — including the
// state: an ad-hoc plate's own, a saved car's — so the page's "still applying"
// state can never disagree with what will be applied, and a guest revert that
// hands the permit back to the schedule restores the plate under the state the
// schedule would have used.
func (s *Server) guestDesired(ctx context.Context, permit model.Permit) (want, state string, decidedAt, until time.Time) {
	now := time.Now().In(s.locForPermit(ctx, permit))
	rules, err := s.store.ListRules(ctx, permit.ID)
	if err != nil {
		return "", "", time.Time{}, time.Time{}
	}
	overrides, err := s.store.ListOverrides(ctx, permit.ID, now)
	if err != nil {
		return "", "", time.Time{}, time.Time{}
	}
	res := model.Resolve(now, rules, overrides)
	if res.Source == model.SourceNone {
		return "", "", time.Time{}, time.Time{}
	}
	if res.Registration != "" {
		want, state = res.Registration, res.State
	} else {
		vehicles, verr := s.store.ListVehiclesFor(ctx, permit.Owner)
		if verr != nil {
			return "", "", time.Time{}, time.Time{}
		}
		for _, v := range vehicles {
			if v.ID == res.VehicleID {
				want, state = v.Registration, v.State
				break
			}
		}
	}
	if res.Source == model.SourceOverride {
		// Re-find the winner with Resolve's own tie-break (freshest CreatedAt, then
		// highest ID): its creation time is when the pending change was asked for
		// (the stall clock) and its end is when the booking lapses (the "until").
		var best *model.Override
		for i := range overrides {
			o := &overrides[i]
			if o.StartsAt.After(now) || (o.EndsAt != nil && !now.Before(*o.EndsAt)) {
				continue
			}
			if best == nil || o.CreatedAt.After(best.CreatedAt) ||
				(o.CreatedAt.Equal(best.CreatedAt) && o.ID > best.ID) {
				best = o
			}
		}
		if best != nil {
			decidedAt = best.CreatedAt
			if best.EndsAt != nil {
				until = *best.EndsAt
			}
		}
	}
	return want, state, decidedAt, until
}

// stateForPlate recovers the registration state to restore a plate under, from
// the owner's saved cars. The tenant's own record reports a plate but not its
// state, so a revert baseline (captured from that record) has no state of its
// own to carry; the only other evidence is a saved car with the same plate.
// Nothing matching means the tenant's home state (""), which is what the
// portal applies by default.
func stateForPlate(vehicles []model.Vehicle, plate string) string {
	for _, v := range vehicles {
		if model.SamePlate(v.Registration, plate) {
			return v.State
		}
	}
	return ""
}

// validRegion reports whether code is a registration state the owner's tenant
// accepts. "" (the home state) is always valid; an unknown code, or no tenant
// wired at all (tests), collapses to "" at the caller rather than reaching the
// portal. Nil-guarded here so every form path shares one rule.
func (s *Server) validRegion(ctx context.Context, permit model.Permit, code string) bool {
	if code == "" {
		return true
	}
	return s.tenant != nil && s.tenant.RegionValid(ctx, permit.Owner, permit.TenantID, code)
}

// formRegion reads the plate_state field of a typed-plate form, validated against
// the permit owner's tenant — "" (the tenant home state) when absent, unknown, or
// for a state-less provider.
func (s *Server) formRegion(r *http.Request, permit model.Permit) string {
	code := strings.ToUpper(strings.TrimSpace(r.FormValue("plate_state")))
	if !s.validRegion(r.Context(), permit, code) {
		return ""
	}
	return code
}

// guestApply is one tenant write made on a guest's authority: the plate (with
// its registration state) to put on the permit, the link doing it, and how the
// activity log should describe it.
type guestApply struct {
	permit model.Permit
	plate  string
	state  string // registration state code ("" = tenant home state)
	// tokenID is the guest token whose authority the write exercises; overrideID
	// is the override it exercises (0 for a revert: authority only, see
	// authoriseGuestApply).
	tokenID, overrideID int64
	okDetail            string // activity-log detail on success ("activated by …")
	logAs               string // server-log prefix on failure ("guest activate")
}

// applyGuestPlate is the one path by which a guest-authorised change reaches the
// tenant: claim the permit's apply slot, re-check authorisation under it, write
// the plate AND its state, record the belief, log the outcome and kick the
// reconcile loop. Activation, revert and door-QR approval all used to carry
// their own copy of this sequence, and the copies drifted — two of the three
// dropped the registration state on the floor, applying an interstate plate
// under the tenant's home state, which is exactly the fine this app exists to
// prevent. One helper means one place for the next capability to be added.
//
// ctx must already be detached from the request (a closed tab mid-apply must not
// cancel the tenant write halfway nor drop the bookkeeping); the tenant budget is
// capped inside, below the server's 20s WriteTimeout, so a slow apply still
// leaves room to write the response.
//
// Returns (denial, err): a denial other than guestApplyAllowed means NOTHING was
// written and the caller should tell the visitor d.message(); otherwise err is
// the tenant result — nil once the tenant confirmed the plate, errApplyBusy when
// another change for the permit held the claim (the change is saved, so the
// scheduler converges on it), or the tenant's own error.
func (s *Server) applyGuestPlate(ctx context.Context, a guestApply) (guestApplyDenial, error) {
	applyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Serialise with the reconcile loop for the duration of the write AND the
	// active_registration write that records it. Without this the loop could be
	// mid-apply of the roster plate, and whichever of us reached the tenant last
	// would decide the plate while whichever wrote the database last decided our
	// belief about it — leaving the tenant holding one car and the row naming
	// another. Every later tick then compares its target against that wrong belief,
	// finds nothing to do, and leaves a car uncovered until the next drift check.
	// Bounded by applyCtx, so a stuck claim cannot hold the request open. Held over
	// the tenant write and the row that records it — those two are the one decision
	// — and released immediately after, so the audit row, the notices and rendering
	// the page never hold up a reconcile pass.
	release, claimed := s.sched.AcquireApply(applyCtx, a.permit.ID)
	err := error(errApplyBusy)
	if claimed {
		// Re-check authorisation HERE, under the claim and immediately before the
		// tenant write. The guarded insert proved the link was live at insert time,
		// but a revocation landing in the gap since then deletes the override and tells
		// the owner the pass has stopped working — this stops us then putting the
		// revoked guest's plate on the real permit anyway.
		if d := s.authoriseGuestApply(applyCtx, a.tokenID, a.overrideID); d != guestApplyAllowed {
			release()
			s.kickScheduler() // let reconcile restore the correct target
			return d, nil
		}
		if err = s.tenant.SetVehicle(applyCtx, a.permit.Owner, a.permit, a.plate, a.state); err == nil {
			if e := s.store.SetPermitActive(ctx, a.permit.ID, a.plate); e != nil {
				// Tenant confirmed the change; only the local record failed. The Kick
				// below drives a reconcile that re-records it (and alerts if it persists).
				log.Printf("guest: applied %q at council for permit %d but local commit failed: %v", a.plate, a.permit.ID, e)
			}
		}
	}
	release()
	// Plain Kick, deliberately: this path already attempted the tenant write
	// itself, so clearing the permit's failure backoff would add tenant pressure
	// without adding a chance of success — and most callers are unauthenticated.
	s.sched.Kick()
	if err == nil {
		_ = s.store.RecordApply(ctx, a.permit.ID, a.plate, "guest", "success", a.okDetail)
		return guestApplyAllowed, nil
	}
	// The activity log is user-facing: record a plain-English detail and keep the
	// raw tenant error in the server log only.
	log.Printf("%s %s on permit %d: %v", a.logAs, a.plate, a.permit.ID, err)
	_ = s.store.RecordApply(ctx, a.permit.ID, a.plate, "guest", "error", guestApplyDetail(err))
	return guestApplyAllowed, err
}

// untilText phrases when the winning booking ends, or "" when there is nothing
// to phrase (no end, open-ended). now and end must be in the display location.
func untilText(now, end time.Time) string {
	if end.IsZero() {
		return ""
	}
	switch {
	case !end.After(dayEndLocal(now, 0)):
		return "until the end of today"
	case !end.After(dayEndLocal(now, 1)):
		return "until the end of tomorrow (" + now.AddDate(0, 0, 1).Weekday().String() + ")"
	default:
		return "until " + end.Format("Mon 2 Jan")
	}
}

// revertPinEnd bounds the revert pin: never past the end of today. The guest's
// own overrides are already swept, so tomorrow belongs to the owner's schedule —
// an overnight mistake must not pin yesterday's plate over tomorrow's roster.
func revertPinEnd(now, baselineUntil time.Time) time.Time {
	if today := dayEndLocal(now, 0); baselineUntil.After(today) {
		return today
	}
	return baselineUntil
}

// pendingState reports whether the tenant record has caught up to the
// schedule's target: a non-empty pendingReg means "still applying"; stalled
// means it has been outstanding past guestApplyTimeout and polling should stop.
//
// since is when the change was asked for: the winning booking's creation time
// when there is one, otherwise when this process first saw the target go
// unconfirmed (see stallClock). A zero since still means "never stalled", so a
// caller with no clock at all understates rather than accusing a healthy apply.
func pendingState(actual, want string, since, now time.Time) (pendingReg string, stalled bool) {
	if want == "" || model.SamePlate(actual, want) {
		return "", false
	}
	return want, !since.IsZero() && now.Sub(since) > guestApplyTimeout
}

// stallSince picks the clock pendingState should judge a target by: the booking's
// own creation time when the schedule resolved to a deliberate booking, else the
// first time we saw this target outstanding. Roster-driven targets have no
// creation time, which is why they could never stall.
func stallSince(permitID int64, current, want string, decidedAt, now time.Time) time.Time {
	if !decidedAt.IsZero() {
		return decidedAt
	}
	if want == "" || model.SamePlate(current, want) {
		guestStalls.forget(permitID, want)
		return time.Time{}
	}
	return guestStalls.since(permitID, want, now)
}

// buildGuestView assembles the activation-menu view model from actual state:
// the tenant-side current plate, the revert offer, and the pending/stalled
// status against the schedule's resolved target.
func (s *Server) buildGuestView(r *http.Request, gc guestCtx, permit model.Permit, current string) guestActView {
	ctx := r.Context()
	cars, _, _, _ := vehicleViews(gc.Vehicles)
	view := guestActView{
		Token: gc.rawToken, PermitLabel: permitLabel(permit),
		Cars: cars, AllowOvernight: gc.Grant.AllowOvernight,
		AllowPlate: gc.Grant.AllowPlate, RequestOnly: gc.Grant.RequestOnly,
	}
	// A typed plate carries its own registration state; the options come from the
	// permit owner's tenant (empty when the provider has no such concept, or — in
	// tests — when no tenant is wired).
	if gc.Grant.AllowPlate && s.tenant != nil {
		view.Regions = s.tenant.Regions(ctx, permit.Owner, permit.TenantID)
	}
	// The label is the owner's own free text (or, failing that, the tenant permit
	// id) and it headlines the page. On a printed door QR — left on a wall for
	// anyone to scan — that leaks whatever the owner typed, typically an address
	// or apartment number, so use a generic heading there. Completes the same
	// redaction set as the owner email and current plate below.
	if gc.Grant.RequestOnly {
		view.PermitLabel = "Visitor parking permit"
	}
	// A door-QR re-scan should answer "what happened to my request?", not present
	// a blank form as if nothing ever happened. The visitor's own request (and
	// only theirs — the cookie carries the request's poll nonce) is shown with
	// its live fate: pending, on the permit, superseded, ended, or denied.
	if gc.Grant.RequestOnly {
		if req, nonce, ok := s.guestReqFromCookie(r, gc); ok {
			status, _ := s.requestLiveState(ctx, permit, req)
			view.Req = &guestWaitView{Plate: req.Plate, ReqID: req.ID, Nonce: nonce, Status: status, Until: req.Until}
		}
	}
	// A printed door QR is meant to be left out in public, so the page must not
	// disclose the holder's email or the plate currently on the permit to anyone
	// who scans it. For emailed links / on-screen QR (a known or present visitor)
	// the current plate and "managed by" address are useful trust signals.
	if !gc.Grant.RequestOnly {
		view.OwnerEmail = permit.Owner
		view.CurrentReg = current
		view.CheckedAgo = s.guestPlateCheckedAgo(ctx, permit)
		want, _, decidedAt, until := s.guestDesired(ctx, permit)
		// Offer "put it back" only while THIS link's activation is still the winning
		// plate. If the owner (or their schedule) has since booked over it, the guest
		// has nothing to undo — and reverting would wrongly displace that deliberate
		// booking. Requiring the link's own live override to match the resolved
		// winner keeps the offer honest and prevents the clobber.
		if gp, ok := s.store.ActiveGuestOverridePlate(ctx, permit.ID, gc.TokenID, time.Now()); ok && model.SamePlate(gp, want) {
			view.RevertPlate = revertPlate(gc.BaselinePlate, gc.BaselineUntil, current, gc.Vehicles, time.Now())
		}
		now := time.Now()
		view.PendingReg, view.Stalled = pendingState(current, want, stallSince(permit.ID, current, want, decidedAt, now), now)
		// A saved override that hasn't landed because the council itself is down
		// (auth circuit open, or the fleet breaker refusing our connection) must not
		// read as an optimistic "Changing to…" — the plate may not be covered until
		// the council is back. Computed HERE, in the shared view, so the POST and the
		// 2.5s poll say the same thing (an earlier fix set a one-off banner in the POST
		// handler, which the next poll silently reverted). Guarded on a real TenantID
		// so an unset row can't read another council's outage (the cross-council footgun).
		if view.PendingReg != "" && permit.TenantID != "" && s.tenant != nil &&
			(s.tenant.AuthGated(permit.TenantID) || s.tenant.Blocked(permit.TenantID)) {
			view.PendingOutage = true
		}
		if !until.IsZero() {
			now := now.In(s.locForPermit(r.Context(), permit))
			view.UntilText = untilText(now, until.In(s.locForPermit(r.Context(), permit)))
		}
		// The highlight follows the guest's choice the moment it is saved; the
		// "on now" pill follows the tenant's actual record as it catches up.
		view.SelectedReg = current
		if view.PendingReg != "" {
			view.SelectedReg = view.PendingReg
		}
	}
	view.FP = guestFP(view)
	return view
}

// guestFP fingerprints the state a poll could change. Everything else on the
// page is static per token, so an unchanged fingerprint means an identical body.
func guestFP(v guestActView) string {
	stalled := "0"
	if v.Stalled {
		stalled = "1"
	}
	sum := sha256.Sum256([]byte(v.CurrentReg + "|" + v.PendingReg + "|" + stalled + "|" + v.RevertPlate + "|" + v.UntilText + "|" + v.CheckedAgo))
	return hex.EncodeToString(sum[:6])
}

// renderGuestMenu renders the activation menu with optional feedback. An htmx
// request gets just the live-updating body fragment (no navigation); anything
// else gets the full page. While a change is still applying, the fragment
// carries a poller so the page keeps showing the tenant's ACTUAL record until
// it matches the schedule's target — never just the intended result.
func (s *Server) renderGuestMenu(w http.ResponseWriter, r *http.Request, gc guestCtx, permit model.Permit, current, flash, warn string) {
	s.renderGuestMenuOpts(w, r, gc, permit, current, flash, warn, false)
}

// renderGuestMenuOpts: keepForm=true (poll responses) renders hx-preserve on the
// form inputs so an in-progress tick/typed plate survives the swap; activation
// responses use false so the overnight box resets — overnight is a deliberate
// per-booking choice, never sticky state.
func (s *Server) renderGuestMenuOpts(w http.ResponseWriter, r *http.Request, gc guestCtx, permit model.Permit, current, flash, warn string, keepForm bool) {
	noStore(w)
	view := s.buildGuestView(r, gc, permit, current)
	view.KeepForm = keepForm
	data := dashboardData{State: "guest", Loc: s.locForPermit(r.Context(), permit), Guest: view, Flash: flash, Warn: warn}
	// The in-page activation swaps (hx-post car/plate, the live poll) want just the
	// #gbody fragment; a boosted link navigation wants the whole page (else it
	// swaps the fragment into <body> and drops the card wrapper/padding).
	if isHX(r) && !isBoosted(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "guest-body", data); err != nil {
			log.Printf("render guest-body: %v", err)
		}
		return
	}
	s.render(w, data)
}

// guestLive is the poll endpoint behind the "still applying" state: public,
// token-gated, side-effect-free. The poll echoes the fingerprint of the state
// it is showing; an unchanged state answers 204 (htmx swaps nothing), so the
// page only repaints — and only replays banner animations — on a REAL change.
// Only pages that rendered a pending banner poll here, so a settled answer
// means the awaited change (or a superseding one) has landed — announce the
// ACTUAL plate now on the tenant record.
func (s *Server) guestLive(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)) {
		s.renderGuestInactive(w, r)
		return
	}
	if gc.Grant.RequestOnly {
		s.renderGuestGone(w, r)
		return
	}
	current := s.guestCurrentPlate(r.Context(), gc, permit)
	view := s.buildGuestView(r, gc, permit, current)
	if r.URL.Query().Get("fp") == view.FP {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	flash := ""
	if view.PendingReg == "" && !view.Stalled {
		if want, _, _, _ := s.guestDesired(r.Context(), permit); want != "" && model.SamePlate(current, want) {
			flash = current + " is now on the permit."
		}
	}
	s.renderGuestMenuOpts(w, r, gc, permit, current, flash, "", true)
}

func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// isBoosted reports an hx-boost navigation (a clicked link/form the app turned
// into an AJAX page load). These want a WHOLE page, not an in-page fragment: a
// boosted request still carries HX-Request, so a fragment-or-page check must
// exclude it or a boosted link to a standalone page (the guest menu) swaps in
// only the inner fragment and loses its wrapper — and its padding.
func isBoosted(r *http.Request) bool { return r.Header.Get("HX-Boosted") == "true" }

// guestActivate performs an activation: it creates a fresh override for the chosen
// car (end of today, or tomorrow if overnight) and applies it to the tenant for
// instant feedback, leaving the scheduler to guarantee eventual consistency. The
// response is the same menu with the result inlined (htmx swaps it in place), so
// a guest can tap one car, then another, then revert, without navigating.
func (s *Server) guestActivate(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		s.guestFail(w, r, "This request could not be verified. Please reopen your link and try again.")
		return
	}
	if !s.guest.allow(rateLimitKey(r)) {
		s.guestFail(w, r, "Too many attempts. Please wait a little while and try again.")
		return
	}
	limitBody(r)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	// A link outlives its permit: a poster stays on the door after the tenant
	// cancels or expires the permit behind it. Without this gate the activation
	// below would put a real plate on the dead permit and tell the visitor they
	// are covered — the exact fine this app exists to prevent. (The scheduler
	// already refuses to reconcile inactive permits, so the override would also
	// never be corrected.)
	if permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)) {
		s.renderGuestInactive(w, r)
		return
	}

	// A printed QR is inert: a scan only REQUESTS the permit. Nothing goes on the
	// permit until the account holder approves it live.
	if gc.Grant.RequestOnly {
		s.guestRequest(w, r, gc, permit)
		return
	}

	now := time.Now().In(s.locForPermit(r.Context(), permit))
	overnight := gc.Grant.AllowOvernight && r.FormValue("overnight") != ""
	end := dayEndLocal(now, 0)
	if overnight {
		end = dayEndLocal(now, 1)
	}
	current := s.guestCurrentPlate(r.Context(), gc, permit)

	// The target is either an arbitrary plate (when the grant allows it, e.g. a
	// visitor QR) or one of the grant's saved cars. Each becomes a fresh override,
	// created now, so it wins the resolution tie-break for its window.
	var reg, name, createdBy, regState string
	var overrideID int64
	if plate := normalizeReg(r.FormValue("plate")); plate != "" && gc.Grant.AllowPlate {
		if !validRego(plate) {
			s.renderGuestMenu(w, r, gc, permit, current, "", plateFormatMsg)
			return
		}
		reg = plate
		// The typed plate's registration state, validated against the owner's tenant.
		regState = s.formRegion(r, permit)
		createdBy = gc.Recipient
		if createdBy == "" {
			createdBy = "visitor (QR)"
		}
		id, err := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, plate, regState, now, &end, createdBy, gc.TokenID)
		if err != nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", guestCreateMessage(err, "Something went wrong saving your plate. Please try again."))
			return
		}
		overrideID = id
	} else {
		vid := atoi64(r.FormValue("vehicle_id"))
		var chosen *model.Vehicle
		for i := range gc.Vehicles {
			if gc.Vehicles[i].ID == vid {
				chosen = &gc.Vehicles[i]
				break
			}
		}
		if chosen == nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", "Please choose one of the cars on your link.")
			return
		}
		reg, name, createdBy, regState = chosen.Registration, chosen.Label, gc.Recipient, chosen.State
		id, err := s.store.CreateGuestOverride(r.Context(), permit.ID, chosen.ID, now, &end, gc.Recipient, gc.TokenID)
		if err != nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", guestCreateMessage(err, "Something went wrong saving your choice. Please try again."))
			return
		}
		overrideID = id
	}

	// Capture (or extend) the revert baseline: the plate that was on the permit
	// when this run of activations began. A later tap within the window must NOT
	// re-capture — that would make "revert" restore the guest's own earlier pick
	// instead of the true pre-existing plate. The window is marked even when the
	// pre-existing plate is unknown ('' baseline: no revert offered), so a mid-run
	// tap can't mistake the guest's own plate for the baseline. Done atomically
	// in SQL: two near-simultaneous activations (a double-tap, or two family
	// members on one shared link) must not both "capture" and record the first
	// activation's own plate as the pre-existing one.
	if bp, bu, err := s.store.CaptureOrExtendGuestBaseline(r.Context(), gc.TokenID, current, end, now); err == nil {
		gc.BaselinePlate, gc.BaselineUntil = bp, bu
	}

	until := untilPhrase(now, overnight)
	// A real person just changed the permit through the household's link: that is
	// the household-liveness evidence the 90-day idle bound wants (see
	// touchGuestActivity) — unlike a GET, which mail scanners and the live poll
	// also make.
	s.touchGuestActivity(r.Context(), permit.Owner)
	// Best-effort synchronous apply so the visitor gets a real result; the
	// scheduler (kicked inside) owns retries and eventual consistency regardless.
	// Detached from the request context: a closed tab mid-apply must not cancel
	// the tenant write halfway, nor silently drop the audit row and the
	// displaced-driver notice after the change has already landed.
	bg := context.WithoutCancel(r.Context())
	d, err := s.applyGuestPlate(bg, guestApply{
		permit: permit, plate: reg, state: regState, tokenID: gc.TokenID, overrideID: overrideID,
		okDetail: "activated by " + createdBy, logAs: "guest activate",
	})
	if d != guestApplyAllowed {
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(bg, gc, permit), "", d.message())
		return
	}
	if err == nil {
		disp, told := s.displacedDriver(bg, permit, current, reg, gc.Recipient)
		s.notifyGuestApply(bg, permit, reg, name, createdBy, disp, told)
		s.renderGuestMenu(w, r, gc, permit, reg, reg+" is now on the permit until "+until+".", "")
		return
	}
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The override is saved; the scheduler will apply it. renderGuestMenu shows the
		// pending state, which buildGuestView renders HONESTLY as "the council is down"
		// when the auth circuit / breaker is open, and as the optimistic "Changing to…"
		// only for a genuine brief blip — and it does so on the poll too, so the message
		// stays consistent rather than reverting after one tick.
		s.renderGuestMenu(w, r, gc, permit, current, "", "")
		return
	}
	// Non-transient: the council REFUSED the plate (FailRejected/FailUnexpected), not a
	// sign-in problem. (NOTE: this copy still says "reconnect / try again", which is
	// wrong for a rejection — flagged as a follow-up needing its own approved copy.)
	s.renderGuestMenu(w, r, gc, permit, current, "", "Couldn't update the permit right now. The account holder may need to reconnect their council login. Please try again shortly.")
}

// guestRevert restores the plate that was on the permit before this link's run
// of activations: it sweeps the link's own overrides, re-pins the baseline for
// the rest of the window, and applies it. Always the ORIGINAL pre-existing
// plate — tapping between several cars first doesn't change what revert restores.
func (s *Server) guestRevert(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		s.guestFail(w, r, "This request could not be verified. Please reopen your link and try again.")
		return
	}
	if !s.guest.allow(rateLimitKey(r)) {
		s.guestFail(w, r, "Too many attempts. Please wait a little while and try again.")
		return
	}
	limitBody(r)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)) {
		s.renderGuestInactive(w, r)
		return
	}
	if gc.Grant.RequestOnly {
		s.renderGuestGone(w, r) // printed QRs never change the permit directly, so there is nothing to revert
		return
	}
	now := time.Now().In(s.locForPermit(r.Context(), permit))
	baseline := normalizeReg(gc.BaselinePlate)
	if baseline == "" || !now.Before(gc.BaselineUntil) || !validRego(baseline) {
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Nothing to put back right now.")
		return
	}

	// Sweep this link's overrides first.
	if err := s.store.DeleteGuestOverrides(r.Context(), permit.ID, gc.TokenID); err != nil {
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Something went wrong. Please try again.")
		return
	}
	createdBy := gc.Recipient
	if createdBy == "" {
		createdBy = "visitor (QR)"
	}

	// Decide what to put back. With the guest's overrides gone, if a deliberate
	// owner booking or the weekly schedule already covers this moment, THAT wins —
	// re-pinning the stale baseline would let a fresh pin leapfrog a booking the
	// owner made after the guest activated. Only when nothing else covers now do we
	// re-pin the pre-existing baseline (capped at end of today; see revertPinEnd).
	// Either way the plate goes back under its OWN registration state: the schedule's
	// resolved state when the schedule wins, else the state of the owner's saved car
	// with that plate (the tenant record the baseline was captured from carries no
	// state, so that is the only evidence; nothing matching means the home state).
	// Restoring an interstate plate under the home state would leave the car it was
	// covering uncovered — the exact fine the revert exists to avoid.
	target := baseline
	targetState := ""
	if want, wantState, _, _ := s.guestDesired(r.Context(), permit); want != "" {
		target, targetState = want, wantState
	} else {
		if saved, err := s.store.ListVehiclesFor(r.Context(), permit.Owner); err == nil {
			targetState = stateForPlate(saved, baseline)
		}
		end := revertPinEnd(now, gc.BaselineUntil)
		if _, err := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, baseline, targetState, now, &end, createdBy+" (undo)", gc.TokenID); err != nil {
			// The sweep above ALREADY committed, so "the permit wasn't changed" would be
			// false. Say what actually happened and let reconcile settle the target.
			log.Printf("guest: revert re-pin for permit %d failed after the sweep: %v", permit.ID, err)
			s.kickScheduler()
			s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "",
				"Your car was taken off the permit, but we couldn't put the previous one back automatically — it will be restored shortly.")
			return
		}
	}
	// Forget the baseline: the revert consumed it, and hiding the button beats
	// offering a second no-op undo. The next activation captures a fresh one.
	_ = s.store.ClearGuestBaseline(r.Context(), gc.TokenID)
	gc.BaselinePlate, gc.BaselineUntil = "", time.Time{}

	// A deliberate act by the link holder: household liveness (see guestActivate).
	s.touchGuestActivity(r.Context(), permit.Owner)
	// Detached from the request (see guestActivate): a disconnect mid-apply must
	// not drop the bookkeeping. A revert is still a tenant write on a guest's
	// authority — overrideID 0 checks the link is still live (it restores the
	// pre-guest plate rather than exercising a vehicle/plate capability), and a
	// revert racing the reconcile loop is the same lost update as an activation,
	// except here the plate left behind would be the one just asked to be removed.
	bg := context.WithoutCancel(r.Context())
	d, err := s.applyGuestPlate(bg, guestApply{
		permit: permit, plate: target, state: targetState, tokenID: gc.TokenID, overrideID: 0,
		okDetail: "put back by " + createdBy, logAs: "guest revert to",
	})
	if d != guestApplyAllowed {
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(bg, gc, permit), "", d.message())
		return
	}
	if err == nil {
		// A revert can't displace a third party: the guest's own overrides were
		// just swept, and the baseline is only re-pinned when nothing else covers
		// now — so there is no displaced booking to chase.
		s.notifyGuestApply(bg, permit, target, "", createdBy+" (undo)", model.DisplacedBooking{}, false)
		s.renderGuestMenu(w, r, gc, permit, target, target+" is back on the permit.", "")
		return
	}
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The restore is saved; renderGuestMenu shows the pending state, rendered
		// honestly by buildGuestView (council-down vs brief blip), consistent on the poll.
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "")
		return
	}
	s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Couldn't update the permit right now. The account holder may need to reconnect their council login. Please try again shortly.")
}

// guestFail reports a pre-resolution failure (bad origin, rate limit). For a
// true htmx fragment request the whole body is swapped for the notice — the
// page's reload link restores the menu; for a boosted (plain-form) post or a
// non-htmx post it falls back to the full result page, since swapping a bare
// fragment into a boosted <body> loses the card wrapper (the same bug class
// renderGuestMenuOpts/renderGuestGone already guard against).
func (s *Server) guestFail(w http.ResponseWriter, r *http.Request, msg string) {
	if isHX(r) && !isBoosted(r) {
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="banner warn" style="margin-top:14px"><span>%s</span></div><p class="empty-note" style="margin-top:12px"><a href="">Reload this page</a> to try again.</p>`,
			template.HTMLEscapeString(msg))
		return
	}
	s.renderGuestResult(w, "", false, msg)
}

// guestCtx bundles a resolved token with the raw token string (for echoing back).
type guestCtx struct {
	store.GuestContext
	rawToken string
}

// resolveGuest validates a raw token and loads its grant + permit. ok=false means
// the link is invalid/revoked/disabled or its permit is gone (caller shows the
// neutral "no longer active" page).
func (s *Server) resolveGuest(r *http.Request, raw string) (guestCtx, model.Permit, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return guestCtx{}, model.Permit{}, false
	}
	gc, err := s.store.GuestContextByTokenHash(r.Context(), hashGuestToken(raw))
	if err != nil {
		return guestCtx{}, model.Permit{}, false
	}
	permit, err := s.store.GetPermit(r.Context(), gc.Grant.PermitID)
	if err != nil || permit.Owner != gc.Grant.Owner {
		return guestCtx{}, model.Permit{}, false
	}
	// Deliberately NO idle-clock touch here. This is the funnel every guest
	// surface passes through, which is exactly why it must not count as liveness:
	// a mail scanner prefetching the emailed link, a link-preview bot, and the
	// 2.5-second /g/live poll from a tab left open all resolve a token, and none
	// of them is a person still relying on the service. The touch lives on the
	// activation, revert and printed-QR request POSTs — a human act — matching
	// tenantConfirm, which likewise refuses to let link-following stand in for a
	// person.
	return guestCtx{GuestContext: gc, rawToken: raw}, permit, true
}

// undeliverableText turns a suppression reason into something an account holder
// can act on. A bounce is usually a typo they can fix; a complaint means the
// person marked our mail as spam, which is theirs to undo, not the owner's.
func undeliverableText(reason string) string {
	switch reason {
	case store.SuppressBounce:
		return "email bounced — check the address, or share the link another way"
	case store.SuppressComplaint:
		return "they marked our email as spam, so we've stopped emailing them"
	case store.SuppressUnsubscribed:
		// Added after this switch was written, and without a case here an
		// unsubscribed recipient rendered as a normal "has a link" row — the silent
		// suppression this page exists to expose. The owner needs to know the link
		// never arrived and that re-sending will not help.
		return "they unsubscribed, so we can't email them — share the link another way"
	case store.SuppressManual:
		return "email disabled for this address"
	default:
		return ""
	}
}

// guestApplyDetail is the user-facing activity-log detail for a failed guest
// apply: the Activity page renders it verbatim, so it must be a plain sentence,
// not a raw tenant error (which goes to the server log instead).
func guestApplyDetail(err error) string {
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		return "Couldn't reach the council; p.stonn will keep trying."
	}
	return "The council did not accept the change."
}

func (s *Server) notifyGuestApply(ctx context.Context, permit model.Permit, reg, name, by string, d model.DisplacedBooking, told bool) {
	if s.notify == nil {
		return
	}
	// Bounded per account (see guestApplyNotify). The change itself is never
	// dropped — it is on the permit, in the activity log, and on the schedule — but
	// the notification is the only part of this path a link holder can trigger at
	// will, and notify's dedup key includes the plate, so cycling plates meant one
	// email and one push per attempt with nothing in the way.
	if !guestApplyNotify.allow("ga:" + permit.Owner) {
		log.Printf("guest apply notify for %s throttled", redact.Email(permit.Owner))
		return
	}
	// Enqueue durably (a fast insert): unlike the scheduler's apply-notify, this
	// path has no reconcile-loop retry behind it, so a fire-and-forget send could
	// silently drop the "a guest put their car on your permit" notice.
	outcome := notify.ApplyOutcome{
		Owner: permit.Owner, TenantID: permit.TenantID, PermitLabel: permitLabel(permit), Reg: reg, Name: name, By: by, Source: "guest", OK: true,
		DisplacedReg: d.Reg, DisplacedTold: told,
	}
	if err := s.notify.EnqueueApply(ctx, outcome); err != nil {
		log.Printf("guest apply notify enqueue for %s: %v", redact.Email(permit.Owner), err)
	}
}

// displacedDriver resolves who should be warned that prev was just taken off a
// permit by actor's change, and notifies them when reachable: the shared
// model.FindDisplaced policy fed the permit's live overrides, the owner's saved
// vehicles, and the account members. Returns what it found so sync-apply paths
// can annotate the account notification (Reg set + no Contact = a booking was
// displaced but its driver couldn't be told). Best-effort: on any store error it
// stays quiet — a missed heads-up is low-harm, the account fanout still fires.
// Returns the displaced booking and whether its driver will genuinely be warned. The
// second value decides between "we've emailed them" and "please tell them yourself", so
// it must reflect what happened — a suppressed address (previous bounce/unsubscribe) is
// guaranteed never to be delivered, and claiming otherwise stands BOTH people down.
func (s *Server) displacedDriver(ctx context.Context, permit model.Permit, prev, next, actor string) (model.DisplacedBooking, bool) {
	if prev == "" || model.SamePlate(prev, next) {
		return model.DisplacedBooking{}, false
	}
	now := time.Now()
	overrides, err := s.store.ListOverrides(ctx, permit.ID, now)
	if err != nil {
		return model.DisplacedBooking{}, false
	}
	saved, err := s.store.ListVehiclesFor(ctx, permit.Owner)
	if err != nil {
		return model.DisplacedBooking{}, false
	}
	vehicles := make(map[int64]model.VehicleInfo, len(saved))
	for _, v := range saved {
		vehicles[v.ID] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email}
	}
	members, err := s.store.AccountEmails(ctx, permit.Owner)
	if err != nil {
		return model.DisplacedBooking{}, false
	}
	d := model.FindDisplaced(overrides, vehicles, prev, actor, members, now)
	if d.Contact == "" || s.notify == nil {
		return d, false
	}
	if sup, serr := s.store.SuppressedAmong(ctx, []string{d.Contact}); serr != nil || len(sup) > 0 {
		if serr != nil {
			log.Printf("suppression check for %s: %v", notify.RedactEmail(d.Contact), serr)
		}
		return d, false // undeliverable (or unknown): ask the account to pass it on
	}
	if err := s.notify.NotifyDriverDisplaced(ctx, permit.Owner, d.Contact, permitLabel(permit), prev, "another car has been put on it", time.Now()); err != nil {
		log.Printf("enqueue driver-displaced for %s: %v", notify.RedactEmail(d.Contact), err)
		return d, false
	}
	return d, true
}

func (s *Server) renderGuestGone(w http.ResponseWriter, r *http.Request) {
	const msg = "This link is no longer active. Ask the account holder for a new one."
	if isHX(r) && !isBoosted(r) {
		// The link died mid-session (revoked, disabled): swap the menu for the notice.
		// A boosted link click, though, is a navigation and wants the whole page.
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="banner warn" style="margin-top:14px"><span>%s</span></div>`, msg)
		return
	}
	noStore(w)
	s.renderStatus(w, http.StatusNotFound, dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation, Warn: msg})
}

// renderStatus renders a full page under a non-200 status. WriteHeader has to
// come AFTER the Content-Type is set (headers are frozen at that moment), so the
// page is rendered to a buffer first — the messagePage pattern. Calling
// WriteHeader then render() sent the status with no Content-Type, and browsers
// were left to sniff the notice page.
func (s *Server) renderStatus(w http.ResponseWriter, code int, data dashboardData) {
	buf, err := s.renderBuf(w, data)
	if err != nil {
		// The bare page, as render() does: the styled notice shares the template
		// set that just failed.
		log.Printf("render %s page: %v", data.State, err)
		s.bareMessage(w, http.StatusInternalServerError, messageView{Text: "Something went wrong rendering this page. Please try again."})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = buf.WriteTo(w)
}

// renderGuestInactive is the notice for a link whose token is still valid but
// whose PERMIT has been cancelled or has expired. Deliberately distinct from
// renderGuestGone: "ask for a new link" would send this guest chasing a link
// that would be exactly as dead. What they need to hear is that the permit
// itself is finished — parking on its say-so no longer protects anyone.
func (s *Server) renderGuestInactive(w http.ResponseWriter, r *http.Request) {
	const msg = "This permit is no longer active, so this code can't put cars on it right now. Please check with your host before parking."
	if isHX(r) && !isBoosted(r) {
		// The permit died mid-session: swap the menu for the notice in place.
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="banner warn" style="margin-top:14px"><span>%s</span></div>`, msg)
		return
	}
	noStore(w)
	s.renderStatus(w, http.StatusGone, dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation, Warn: msg})
}

func (s *Server) renderGuestResult(w http.ResponseWriter, ownerEmail string, ok bool, msg string) {
	noStore(w)
	d := dashboardData{State: "guest-result", Loc: s.locFor(context.Background(), ownerEmail),
		Guest: guestActView{OwnerEmail: ownerEmail}}
	if ok {
		d.Flash = msg
	} else {
		d.Warn = msg
	}
	s.render(w, d)
}
