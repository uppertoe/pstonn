package server

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// The printed door QR: a scan only REQUESTS the permit, the household approves
// live. Split out of guest.go by its banner sections.

// ================= PRINTED QR: REQUEST + APPROVE =================

func randNonce() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		panic("guest request nonce: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// requestLiveState classifies where a printed-QR request stands RIGHT NOW, in
// the template's own status terms, so every surface that shows a request (the
// wait page's poll, a door-QR re-scan, the guests page's recent list) derives
// the same answer from the same resolution the scheduler acts on:
//
//	pending    — awaiting the holder's decision
//	denied     — declined by the holder
//	expired    — aged out unanswered (distinct from an actual "no")
//	ended      — approved, but the granted window has since lapsed
//	superseded — approved, but the schedule now resolves to a different plate
//	             (or to nothing): the pass was overridden, not merely slow
//	applied    — approved AND the tenant's own record shows the plate
//	stalled    — approved but unconfirmed past guestApplyTimeout
//	approved   — approved, tenant catching up (keep polling)
//
// replacedBy is the plate now steering the permit, only for "superseded" ("" =
// nothing scheduled). Owner-facing surfaces may show it; the PUBLIC door-QR
// pages must not — a poster scan must never disclose the permit's current plate.
func (s *Server) requestLiveState(ctx context.Context, permit model.Permit, req store.GuestRequest) (status, replacedBy string) {
	switch req.Status {
	case "pending":
		return "pending", ""
	case "denied":
		return "denied", ""
	case "expired":
		// Aged out unanswered — distinct from an actual "no" on every surface.
		return "expired", ""
	}
	// Approved. Ended is checked first: after the window lapses the schedule
	// naturally resolves elsewhere, which must read as "ended", not "superseded".
	now := time.Now().In(s.locForPermit(ctx, permit))
	end := req.UntilTS
	if end.IsZero() && !req.DecidedAt.IsZero() {
		// Rows approved before until_ts existed: reproduce the approval's window
		// (printed-QR approvals always ran to the end of the approval's day).
		end = dayEndLocal(req.DecidedAt.In(s.locForPermit(ctx, permit)), 0)
	}
	if !end.IsZero() && !now.Before(end) {
		return "ended", ""
	}
	want, _, _, _ := s.guestDesired(ctx, permit)
	if !model.SamePlate(want, req.Plate) {
		return "superseded", want
	}
	if model.SamePlate(permit.ActiveRegistration, req.Plate) {
		return "applied", ""
	}
	if !req.DecidedAt.IsZero() && time.Since(req.DecidedAt) > guestApplyTimeout {
		return "stalled", ""
	}
	return "approved", ""
}

// guestReqCookie remembers the visitor's own printed-QR request in their
// browser: "reqID.nonce", where the nonce is the same per-request secret the
// wait page's poll URL already carries — the cookie only persists it client-
// side, introducing no new secret class. Scoped to /g/ (the public guest
// routes) and long enough to outlive the granted window, so the morning-after
// re-scan can still say "your pass has ended".
const guestReqCookie = "greq"

const guestReqCookieTTL = 48 * time.Hour

func (s *Server) setGuestReqCookie(w http.ResponseWriter, reqID int64, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name:     guestReqCookie,
		Value:    fmt.Sprintf("%d.%s", reqID, nonce),
		Path:     "/g/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.cfg.PublicBaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(guestReqCookieTTL.Seconds()),
	})
}

// guestReqFromCookie resolves the browser's remembered request. It is gated on
// the nonce (a stale, purged, or tampered cookie simply resolves to nothing)
// and pinned to THIS grant, so a request made at one door never surfaces at
// another. Returns the nonce too, for the status fragment's poll URL.
func (s *Server) guestReqFromCookie(r *http.Request, gc guestCtx) (store.GuestRequest, string, bool) {
	c, err := r.Cookie(guestReqCookie)
	if err != nil {
		return store.GuestRequest{}, "", false
	}
	idStr, nonce, ok := strings.Cut(c.Value, ".")
	if !ok || nonce == "" {
		return store.GuestRequest{}, "", false
	}
	id := atoi64(idStr)
	if id <= 0 {
		return store.GuestRequest{}, "", false
	}
	req, err := s.store.GuestRequestForPoll(r.Context(), id, nonce)
	if err != nil || req.GrantID != gc.Grant.ID {
		return store.GuestRequest{}, "", false
	}
	return req, nonce, true
}

// guestRequest handles a printed-QR scan: it records a pending request for the
// plate the visitor typed, notifies the account holder, and shows a page that
// polls until the holder decides. Nothing is put on the permit here — the
// approval is the security boundary.
func (s *Server) guestRequest(w http.ResponseWriter, r *http.Request, gc guestCtx, permit model.Permit) {
	// A printed door QR is public, so the visitor-facing pages here never show the
	// holder's email (unlike the emailed/on-screen flows, where the recipient is known).
	plate := normalizeReg(r.FormValue("plate"))
	if !validRego(plate) {
		// Re-rendered through the shared view builder, which is where the request-only
		// redaction lives. Assembling the view here instead put the permit's LABEL on a
		// page anyone who scans a poster can reach — the owner's own text, typically an
		// address or apartment number — and this branch is not even adversarial:
		// normalizeReg now absorbs the ordinary-visitor spellings ("ABC-123", a pasted
		// non-breaking space), but a mistyped length or a stray symbol still lands here.
		s.renderGuestMenu(w, r, gc, permit, "", "", plateFormatMsg)
		return
	}
	// The door-QR form offers the same state chooser as a typed-plate link (printed
	// grants allow a plate), and the approval applies whatever the row carries — so
	// the state has to be captured HERE or the visitor's interstate plate goes on
	// under the home state after the resident says yes.
	plateState := s.formRegion(r, permit)
	// A visitor asking to park is a person at the door: household liveness (see
	// touchGuestActivity). Counted only once the request is well-formed.
	s.touchGuestActivity(r.Context(), permit.Owner)
	// This browser's own remembered request, resolved before anything is created: it
	// is the only evidence that the person asking is the one who asked before.
	mine, myNonce, haveMine := s.guestReqFromCookie(r, gc)
	ownRepeat := haveMine && mine.Status == "pending" && model.SamePlate(mine.Plate, plate)
	// A re-submission of one's own pending plate consumes no slot, so it is never
	// throttled. Anything else is refused once the queue has grown into the reserved
	// tail IF we have already heard from this requester — either their rate-limit key has
	// spent its scanner token, or their browser already carries a still-pending request
	// for this grant (the greq cookie). Counting the cookie too means a returning browser
	// that hops to a fresh IP is still recognised, where the per-IP signal alone would
	// not. The key is rateLimitKey, so an IPv6 caller is bucketed by its whole /64 — one
	// delegated allocation can no longer masquerade as an unlimited supply of scanners.
	//
	// HONEST LIMIT: this bounds one phone, one persistent browser, and one IPv6 /64 to
	// maxPendingGuestRequests-guestReqReserved slots, so a genuine visitor elsewhere still
	// lands. It does NOT stop a flood from several genuinely distinct addresses (distinct
	// IPv4s, or distinct /64s): each looks like a real newcomer, and a public door QR
	// cannot tell them apart from real visitors without turning legitimate newcomers away.
	// That residual is why approval, not the request, is the security boundary here.
	heardFrom := !guestScanner.allow("greq:"+rateLimitKey(r)) || (haveMine && mine.Status == "pending")
	if !ownRepeat && heardFrom {
		if reserved, err := s.store.PendingGuestRequestsInReserve(r.Context(), gc.Grant.ID); err == nil && reserved {
			s.renderGuestResult(w, "", false, "There are already several requests waiting for the resident. Please knock or contact them directly.")
			return
		}
	}
	reqID, nonce, created, err := s.store.CreateGuestRequest(r.Context(), gc.Grant.ID, permit.ID, permit.Owner, plate, plateState, randNonce())
	if errors.Is(err, store.ErrGuestRequestLimit) {
		s.renderGuestResult(w, "", false, "There are already several requests waiting for the resident. Please knock or contact them directly.")
		return
	}
	if err != nil {
		s.renderGuestResult(w, "", false, "Something went wrong sending your request. Please try again.")
		return
	}
	if !created {
		// The plate already has a pending request, so this scan reused it — and the
		// nonce that came back is THAT request's poll secret. Two visitors can type the
		// same plate (a shared work ute, a plate typed wrong the same way twice), and
		// the store cannot tell them apart, so it is only handed over to a browser that
		// can already present it. Anyone else is told the truth about the plate they
		// typed and given no way to read a stranger's request.
		if haveMine && mine.ID == reqID {
			s.setGuestReqCookie(w, mine.ID, myNonce)
			s.render(w, dashboardData{State: "guest-wait", Loc: s.locForPermit(r.Context(), permit),
				Wait: &guestWaitView{Plate: mine.Plate, ReqID: mine.ID, Nonce: myNonce, Status: mine.Status}})
			return
		}
		s.renderGuestResult(w, "", true, "A request for "+plate+" is already waiting for the resident to approve. There's nothing more to do here — if it isn't approved shortly, try knocking.")
		return
	}
	s.notifyGuestRequest(r.Context(), permit, plate, reqID)
	// Remember the request in this browser (the one that made it), so a later
	// re-scan of the same door code shows its fate instead of a blank form.
	s.setGuestReqCookie(w, reqID, nonce)
	s.render(w, dashboardData{State: "guest-wait", Loc: s.locForPermit(r.Context(), permit),
		Wait: &guestWaitView{Plate: plate, ReqID: reqID, Nonce: nonce, Status: "pending"}})
}

// guestRequestStatus is the visitor's poll endpoint: public and nonce-gated so a
// request id can't be enumerated. While pending it re-renders a polling fragment;
// once decided it renders a static result.
func (s *Server) guestRequestStatus(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	id, nonce := pathInt(r, "id"), r.URL.Query().Get("n")
	req, err := s.store.GuestRequestForPoll(r.Context(), id, nonce)
	var v guestWaitView
	switch {
	case err == nil:
		// Status passes through as-is: "expired" (aged out unanswered) renders its
		// own message, distinct from an actual "denied".
		v = guestWaitView{Plate: req.Plate, ReqID: req.ID, Nonce: nonce, Status: req.Status, Until: req.Until}
		// One permit read for this poll: the referral tenant view AND the live-state
		// refinement below both need it (this used to fetch it twice per 3s tick).
		permit, perr := s.store.GetPermit(r.Context(), req.PermitID)
		if perr == nil {
			cv := s.tenantViewFor(r.Context(), permit.Owner)
			v.tenant = &cv
		}
		// "approved" means the resident said yes; requestLiveState only reports it
		// as ON the permit once the tenant's own record actually shows the plate
		// ("applied"), flags a long-unconfirmed apply ("stalled"), and — the states
		// this endpoint couldn't see before — notices when the pass has since been
		// overridden ("superseded") or its window has lapsed ("ended"), instead of
		// misreading either as a stall.
		if req.Status == "approved" {
			if perr == nil {
				v.Status, _ = s.requestLiveState(r.Context(), permit, req)
				// A CONFIRMED council outage (auth circuit open, or the fleet breaker
				// refusing our connection): tell the visitor honestly rather than the
				// optimistic "putting it on" spinner or a generic "stalled" — the apply
				// won't land until the council is back. Kept polling, so it flips to
				// "on the permit" on its own on recovery. Scoped to THIS visitor-facing
				// poll; the shared requestLiveState (resident's page too) is unchanged.
				if (v.Status == "approved" || v.Status == "stalled") &&
					(s.tenant.AuthGated(permit.TenantID) || s.tenant.Blocked(permit.TenantID)) {
					v.Status = "outage"
				}
			}
			// A permit lookup error keeps Status "approved": transient — keep polling.
		}
	case errors.Is(err, store.ErrNotFound):
		v = guestWaitView{Status: "denied"} // wrong nonce / unknown id — a real terminal
	default:
		// A transient DB error must NOT strand the visitor on a false "Not approved":
		// keep polling.
		log.Printf("guest poll %d: %v", id, err)
		v = guestWaitView{ReqID: id, Nonce: nonce, Status: "pending"}
	}
	if !isHX(r) {
		// A direct navigation (bookmark, or a browser that landed here after a
		// network hiccup) gets the full wait page — with styling and the poller —
		// not the bare fragment.
		s.render(w, dashboardData{State: "guest-wait", Loc: s.cfg.DisplayLocation, Wait: &v})
		return
	}
	if e := templates.ExecuteTemplate(w, "guest-req-status", v); e != nil {
		log.Printf("render guest-req-status: %v", e)
	}
}

// guestApplyTimeout is how long an approved printed-QR request may sit unconfirmed
// on the tenant before the visitor's page stops spinning and suggests checking
// with the resident (the scheduler keeps retrying regardless).
const guestApplyTimeout = 8 * time.Minute

func (s *Server) notifyGuestRequest(ctx context.Context, permit model.Permit, plate string, reqID int64) {
	if s.notify == nil {
		return
	}
	// Throttled per ACCOUNT, not per plate (see guestNudge): the request itself is
	// always recorded and always visible in the approvals queue — only the alarm is
	// rationed, because the alarm is the part a stranger with a poster can aim at a
	// household at 3am.
	if !guestNudge.allow("n:" + permit.Owner) {
		log.Printf("guest request nudge for %s throttled", redact.Email(permit.Owner))
		return
	}
	// Enqueue durably (a fast DB insert) so the holder's "approve this?" nudge
	// survives a restart and is retried — the printed-QR flow depends on it.
	url := s.cfg.PublicBaseURL + "/guests"
	if err := s.notify.NotifyGuestRequest(ctx, permit.Owner, permitLabel(permit), plate, url, reqID); err != nil {
		log.Printf("guest request notify enqueue for %s: %v", redact.Email(permit.Owner), err)
	}
}

// showPrintedQR mints a durable request-only grant and renders a QR to print and
// leave out (e.g. at the door). A scan of it only requests the permit; the holder
// approves live. It replaces any existing printed QR for the permit.
// mintPrintedGrant creates (or replaces) a permit's door QR, sealing the raw token
// at rest so the same code can be reprinted later. Returns the new grant id.
func (s *Server) mintPrintedGrant(ctx context.Context, owner, createdBy string, permitID int64) (int64, error) {
	raw, hash := newGuestToken()
	sealed, err := s.box.SealCtx(secretbox.GuestToken(owner), raw)
	if err != nil {
		return 0, err
	}
	return s.store.CreatePrintedGrant(ctx, owner, createdBy, permitID, hash, sealed)
}

// showPrintedQR handles "Print a door QR" for a permit. It is idempotent: if the
// permit already has a door QR it reopens that (same code) rather than rotating the
// token, so a copy already on the fridge keeps working.
func (s *Server) showPrintedQR(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	permitID := atoi64(r.FormValue("permit_id"))
	// Checked before the idempotent reopen too: reprinting a poster for a dead
	// permit is as misleading as minting a fresh one. Fails closed on a store
	// error, for the same reason as createGuestGrant's gate.
	switch permit, perr := s.store.GetPermit(r.Context(), permitID); {
	case errors.Is(perr, store.ErrNotFound):
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Owner == owner && permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)):
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
		return
	}
	if g, err := s.store.PrintedGrantForPermit(r.Context(), owner, permitID); err == nil {
		http.Redirect(w, r, fmt.Sprintf("/guests/door/%d/view", g.GrantID), http.StatusSeeOther)
		return
	}
	grantID, err := s.mintPrintedGrant(r.Context(), owner, user, permitID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionDoorQRCreate, s.permitLabelByID(r.Context(), owner, permitID), "")
	http.Redirect(w, r, fmt.Sprintf("/guests/door/%d/view", grantID), http.StatusSeeOther)
}

// viewDoorQR renders the durable, printable poster for an existing door QR. It never
// rotates the token, so it can be reopened and reprinted as often as needed.
func (s *Server) viewDoorQR(w http.ResponseWriter, r *http.Request) {
	// The poster embeds the durable door-QR token, so it must stay out of caches —
	// via the app helper, not the guest routes' noStore, because this is a signed-in
	// page and noStore's Referrer-Policy: no-referrer would weaken the CSRF Referer
	// fallback on every link out of it (see noStoreCache).
	noStoreCache(w)
	_, owner, _ := s.resolveAccount(r.Context())
	g, err := s.store.PrintedGrantByID(r.Context(), owner, atoi64(r.PathValue("id")))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusNotFound, "That door QR is no longer available.")
			return
		}
		s.serverError(w, err)
		return
	}
	// The POST mint gate calls reprinting a dead permit's poster "as misleading
	// as minting a fresh one" — and this view page IS the printable poster, so
	// it carries the same gate. Fails closed like the mint gates.
	switch permit, perr := s.store.GetPermit(r.Context(), g.PermitID); {
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)):
		s.message(w, http.StatusConflict, permitInactiveNoPoster)
		return
	}
	raw, _, err := s.box.OpenCtx(secretbox.GuestToken(owner), g.TokenSealed)
	if err != nil {
		// The at-rest key changed, so we can't reproduce the printed code. Ask the
		// holder to replace it (which mints a fresh one they can reprint).
		s.message(w, http.StatusConflict, "This code can't be shown again on this server. Remove it on the Guests page, then create a new printed QR for this permit.")
		return
	}
	url := s.guestLink(raw)
	img, err := qrDataURI(url)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	base.State = "doorqr"
	base.DoorQR = &doorQRView{
		GrantID: g.GrantID, PermitLabel: g.PermitLabel, OwnerEmail: owner,
		ImageURI: template.URL(img), URL: url,
		CreatedAt: g.CreatedAt.In(s.locFor(r.Context(), owner)).Format("2 Jan 2006"),
	}
	s.render(w, base)
}

// revokeDoorQR retires a door QR for good (its code stops working).
func (s *Server) revokeDoorQR(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Claim the permit first, exactly as deleteGuestGrant/revokeGuestToken/toggleGuests
	// do. Without it an in-flight door-QR approval could write the visitor's plate to
	// the tenant AFTER the household was told the code had stopped working.
	if pid, perr := s.store.GuestGrantPermit(r.Context(), owner, atoi64(r.PathValue("id"))); perr == nil {
		defer s.claimPermitApplies(r.Context(), []int64{pid})()
	}
	label := s.grantLabel(r.Context(), owner, atoi64(r.PathValue("id")))
	// As in deleteGuestGrant: a no-op must not announce itself to the household.
	err := s.store.RevokePrintedGrant(r.Context(), owner, atoi64(r.PathValue("id")))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionDoorQRRevoke, label, "")
		s.notifyDestructive(r.Context(), owner, user,
			user+" removed a printed QR code on your p.stonn account. Any copy already printed and put up has stopped working, and p.stonn is taking any car approved through it back off the permit now — check the permit directly if this is urgent.")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) approveGuestRequest(w http.ResponseWriter, r *http.Request) {
	s.decideRequest(w, r, true)
}
func (s *Server) denyGuestRequest(w http.ResponseWriter, r *http.Request) {
	s.decideRequest(w, r, false)
}

// decideOutcome is what running a decision produced, so the two front doors —
// the signed-in approvals page and the signed email link — can each respond in
// their own idiom (redirects with query flags versus a rendered outcome page)
// while sharing one implementation of the delicate approve path.
type decideOutcome struct {
	kind  decideKind
	plate string
	err   error
}

type decideKind int

const (
	decideErr            decideKind = iota // err holds the cause
	decideAlreadyDecided                   // decline raced: no longer pending
	decideDeclined
	decideGone           // approve: request/permit gone, not ours, or raced
	decideCapFull        // permit at its guest-booking sub-cap
	decidePermitInactive // approve: the permit itself is cancelled or expired
	decideRevoked        // door QR revoked, or guest passes paused, before the plate went on
	decideApplied        // approved and the tenant confirmed the plate
	decideApproving
)

// decideCapFullMessage is shown when an approval hits the guest-booking
// sub-cap; shared by both front doors so the wording can never drift.
const decideCapFullMessage = "This permit already has the maximum number of active guest bookings. Remove one before approving another."

// decidePermitInactiveMessage: approving a request against a permit the tenant
// has since cancelled (or that has expired) must refuse loudly. Silently
// "approving" would strand the visitor on a permit that protects nobody.
const decidePermitInactiveMessage = "This permit is no longer active (cancelled or expired), so nothing can go on it. The visitor has not been approved — let them know."

// permitInactiveNoNewLinks refuses minting any guest surface (pass, visitor QR,
// door QR) for a permit that is cancelled or expired: every link would promise
// parking cover the permit can no longer give.
const permitInactiveNoNewLinks = "That permit is no longer active, so guest links and QR codes can't be created for it."

// permitInactivePassFrozen refuses re-sending or editing a pass whose permit has
// died — a re-send would rotate away the recipient's token (the very thing that
// starts working again after a renewal copy) and email a born-dead link in its
// place; an edit can add recipients, which is minting by another door.
const permitInactivePassFrozen = "That pass's permit is no longer active, so its links can't be re-sent or offered to new people. Renewed the permit? Use “Copy schedule from another permit” — the pass moves across and its links start working again."

// permitInactiveNoPoster refuses showing the printable poster for a dead
// permit's door QR: the POST mint gate calls reprinting one "as misleading as
// minting a fresh one", and the view page is the same artifact one click later.
const permitInactiveNoPoster = "That permit is no longer active, so its printed QR can't be shown or reprinted. Renewed the permit? Use “Copy schedule from another permit” — the door QR moves across and the printed poster keeps working."

// refuseDeadGrantPermit answers the request with msg when the grant's permit is
// cancelled or expired, reporting whether it wrote a response. An unknown grant
// returns false so the handler's own ownership path can give its usual answer;
// a store error fails closed (these gates guard link-minting surfaces).
func (s *Server) refuseDeadGrantPermit(w http.ResponseWriter, r *http.Request, owner string, grantID int64, msg string) bool {
	pid, err := s.store.GuestGrantPermit(r.Context(), owner, grantID)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		s.serverError(w, err)
		return true
	}
	switch permit, err := s.store.GetPermit(r.Context(), pid); {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		s.serverError(w, err)
		return true
	case permit.Inactive(time.Now(), s.locFor(r.Context(), owner)):
		s.message(w, http.StatusConflict, msg)
		return true
	}
	return false
}

// decideRequest approves or denies a pending printed-QR request. On approval it
// puts the plate on the permit (end of day) and applies it best-effort.
func (s *Server) decideRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	out := s.runDecideRequest(r, owner, user, pathInt(r, "id"), approve)
	switch out.kind {
	case decideErr:
		s.serverError(w, out.err)
	case decideAlreadyDecided:
		http.Redirect(w, r, "/guests?alreadydecided=1", http.StatusSeeOther)
	case decideDeclined:
		http.Redirect(w, r, "/guests?declined=1", http.StatusSeeOther)
	case decideGone:
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
	case decideCapFull:
		s.message(w, http.StatusConflict, decideCapFullMessage)
	case decidePermitInactive:
		s.message(w, http.StatusConflict, decidePermitInactiveMessage)
	case decideRevoked:
		http.Redirect(w, r, "/guests?revoked=1", http.StatusSeeOther)
	default: // decideApplied / decideApproving
		q := url.Values{}
		if out.kind == decideApplied {
			q.Set("applied", out.plate)
		} else {
			q.Set("approving", out.plate)
		}
		http.Redirect(w, r, "/guests?"+q.Encode(), http.StatusSeeOther)
	}
}

// runDecideRequest is the shared decision core: owner scopes the request, user
// is recorded as the decider in the change log. Callers have already
// authenticated user as a member of owner's account (session or signed link).
func (s *Server) runDecideRequest(r *http.Request, owner, user string, id int64, approve bool) decideOutcome {
	now := time.Now().In(s.locFor(r.Context(), owner))

	if !approve {
		switch _, err := s.store.DecideGuestRequest(r.Context(), owner, id, false, "", user, time.Time{}); {
		case errors.Is(err, store.ErrNotFound):
			// The row is no longer pending — another member approved (or it expired)
			// first. Record NOTHING: the change log is the household's account of who
			// authorised a plate change, so logging a decline that never happened would
			// misattribute a plate that is in fact going ON the permit.
			return decideOutcome{kind: decideAlreadyDecided}
		case err != nil:
			return decideOutcome{kind: decideErr, err: err}
		}
		s.logChange(r.Context(), owner, user, store.ActionRequestNo, "", "")
		return decideOutcome{kind: decideDeclined}
	}

	// Approve: set up the plate override BEFORE finalising the approval, so we can
	// never leave a request marked "approved" that the scheduler has nothing to act
	// on (which would strand the visitor and mislead the holder).
	req, rerr := s.store.GuestRequestByID(r.Context(), id)
	if rerr != nil || req.Status != "pending" {
		return decideOutcome{kind: decideGone} // gone / already decided
	}
	permit, perr := s.store.GetPermit(r.Context(), req.PermitID)
	if perr != nil || permit.Owner != owner {
		return decideOutcome{kind: decideGone} // not ours / permit removed
	}
	// The request may have been made (and the approval email sent) while the
	// permit was still alive. Approving now would create an override the
	// scheduler refuses to act on — a visitor told "approved" with nothing
	// behind it.
	if permit.Inactive(now, s.locFor(r.Context(), owner)) {
		return decideOutcome{kind: decidePermitInactive}
	}
	end := dayEndLocal(now, 0)
	// Tagged with the door QR's own token, so removing the poster (or pausing guest
	// passes) can take this plate back off the permit. Untagged, the row was
	// indistinguishable from a booking the household made itself, and "that code has
	// stopped working" left the visitor parked on the permit for the rest of the day.
	// A token we cannot resolve tags nothing (0) rather than blocking the approval.
	doorToken, terr := s.store.GrantTokenID(r.Context(), req.GrantID)
	if terr != nil {
		log.Printf("doorqr approve: no token for grant %d: %v", req.GrantID, terr)
	}
	// The state the visitor chose at the door travels with the request row, so the
	// override (what the scheduler applies) and the write below agree with it.
	ovID, cerr := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, req.Plate, req.State, now, &end, "visitor (printed QR)", doorToken)
	if errors.Is(cerr, store.ErrGuestOverrideRefused) {
		// Refused for one of two reasons the store folds into one error: the door
		// QR's authority is gone (revoked, its grant disabled, or every pass paused),
		// or the permit is at its guest-booking sub-cap. Tell the two apart, because
		// "too many bookings" is the wrong thing to tell a household that just paused
		// its passes. The request stays pending either way — nothing was set up for
		// the scheduler, so nothing may say "approved". Told plainly instead of
		// returning a 500 — approving a door-QR request must not look like the app
		// is broken.
		if doorToken != 0 {
			if live, lerr := s.store.GuestTokenStillLive(r.Context(), doorToken); lerr == nil && !live {
				return decideOutcome{kind: decideRevoked}
			}
		}
		return decideOutcome{kind: decideCapFull}
	}
	if cerr != nil {
		return decideOutcome{kind: decideErr, err: cerr} // don't approve if we couldn't set up the change
	}
	if _, err := s.store.DecideGuestRequest(r.Context(), owner, id, true, untilPhrase(now, false), user, end); err != nil {
		// The approval didn't land — raced with a concurrent deny (ErrNotFound: the
		// row is no longer pending) or a DB error. Roll back the override we
		// optimistically created, so a denied or undecided request can never leave a
		// live plate the scheduler would put on the permit.
		_ = s.store.DeleteOverride(r.Context(), owner, ovID)
		if errors.Is(err, store.ErrNotFound) {
			return decideOutcome{kind: decideGone}
		}
		return decideOutcome{kind: decideErr, err: err}
	}
	// Best-effort synchronous apply for instant feedback; the scheduler converges
	// otherwise (a claim we cannot get means we simply don't apply here — the
	// override is saved, and both front doors have a wording for "approving"
	// versus "applied"). Detached from the request (see guestActivate): a
	// disconnect mid-apply must not drop the bookkeeping. This was once the one
	// guest path that wrote to the tenant without re-checking authorisation under
	// the claim; applyGuestPlate makes that impossible to leave out again.
	prev := permit.ActiveRegistration
	bg := context.WithoutCancel(r.Context())
	d, applyErr := s.applyGuestPlate(bg, guestApply{
		permit: permit, plate: req.Plate, state: req.State, tokenID: doorToken, overrideID: ovID,
		okDetail: "approved a printed-QR request", logAs: "doorqr approve",
	})
	if d != guestApplyAllowed {
		// A door QR revoked between the approval and here: the household was told the
		// code had stopped, so the plate must not go on. Don't leave the override for
		// the scheduler either.
		_ = s.store.DeleteOverride(bg, owner, ovID)
		return decideOutcome{kind: decideRevoked}
	}
	if applyErr == nil {
		// The approved plate may have bumped a still-live booking's car off the
		// permit; warn that driver if they're reachable. The approving member saw
		// the change happen, but the OTHER members didn't — fan the confirmation
		// out like every other plate change (the guest-link path does the same).
		disp, told := s.displacedDriver(bg, permit, prev, req.Plate, user)
		outcome := notify.ApplyOutcome{
			Owner: permit.Owner, TenantID: permit.TenantID, PermitLabel: permitLabel(permit), Reg: req.Plate, By: user, Source: "doorqr", OK: true,
			DisplacedReg: disp.Reg, DisplacedTold: told,
		}
		if s.notify != nil {
			if err := s.notify.EnqueueApply(bg, outcome); err != nil {
				log.Printf("doorqr apply notify enqueue for %s: %v", redact.Email(permit.Owner), err)
			}
		}
	}

	s.logChange(bg, owner, user, store.ActionRequestOK, req.Plate, "")
	if applyErr == nil {
		return decideOutcome{kind: decideApplied, plate: req.Plate}
	}
	return decideOutcome{kind: decideApproving, plate: req.Plate}
}

// guestCreateMessage turns a refused guest-override insert into something true for the
// visitor. A refusal means the link was revoked or disabled between opening the page
// and submitting (or the permit is at its booking cap) — "please try again" would have
// them retrying a link that will never work again.
func guestCreateMessage(err error, fallback string) string {
	if errors.Is(err, store.ErrGuestOverrideRefused) {
		return "This link is no longer active, so the permit wasn't changed. Please ask the household for a new one."
	}
	return fallback
}

// guestApplyDenial says why a guest tenant write must not proceed: revoked (the
// owner withdrew the authority) or unverifiable (we could not check). They are
// different things to tell a visitor — calling a database blip "the owner turned your
// link off" starts an argument at the kerb over something that did not happen.
type guestApplyDenial int

const (
	guestApplyAllowed guestApplyDenial = iota
	guestApplyRevoked
	guestApplyUnverified
)

// authoriseGuestApply is the single gate EVERY public guest path must pass immediately
// before writing to the tenant, while holding that permit's apply claim.
//
// It exists as one helper on purpose: activation was fixed first and revert was left
// behind, which is the recurring shape of bugs here — a capability check added to one
// path and not its sibling. Anything that writes to the tenant on a guest's behalf
// goes through this.
//
// overrideID != 0 checks the FULL capability of that specific override (token, grant,
// permit, account switch, and the vehicle/plate permission it exercised). overrideID 0
// checks only that the link still carries authority at all — the revert case, which
// restores the pre-guest plate rather than exercising a capability.
func (s *Server) authoriseGuestApply(ctx context.Context, tokenID, overrideID int64) guestApplyDenial {
	var ok bool
	var err error
	if overrideID != 0 {
		ok, err = s.store.GuestOverrideStillAuthorised(ctx, overrideID, tokenID)
	} else {
		ok, err = s.store.GuestTokenStillLive(ctx, tokenID)
	}
	switch {
	case err != nil:
		log.Printf("guest: could not verify authorisation for token %d (override %d): %v", tokenID, overrideID, err)
		return guestApplyUnverified
	case !ok:
		return guestApplyRevoked
	}
	return guestApplyAllowed
}

func (d guestApplyDenial) message() string {
	if d == guestApplyRevoked {
		return "This link was turned off just now, so the permit wasn't changed."
	}
	return "We couldn't check your link just now, so the permit wasn't changed. Please try again."
}

// claimPermitApplies takes the per-permit apply claim for every id before a revocation
// mutates guest authority, and returns a release for all of them.
//
// Holding the claim is what gives revocation a real linearization point: an activation
// that already holds it completes (it WAS authorised), and the sweep then removes its
// override; an activation that has not started yet blocks, and its re-check afterwards
// fails. Without this, "revoked" could still be overtaken by a tenant write. ids are
// claimed in a stable order so two multi-permit revocations cannot deadlock, and a
// claim we cannot get is logged and skipped — a revocation must never fail to revoke.
func (s *Server) claimPermitApplies(ctx context.Context, ids []int64) func() {
	if s.sched == nil {
		return func() {}
	}
	sorted := append([]int64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var releases []func()
	for _, id := range sorted {
		if id == 0 {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		release, ok := s.sched.AcquireApply(cctx, id)
		cancel()
		if !ok {
			log.Printf("guest: revoking without the apply claim for permit %d (busy); a guest write in flight may still land and be reconciled away", id)
			release()
			continue
		}
		releases = append(releases, release)
	}
	return func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
}
