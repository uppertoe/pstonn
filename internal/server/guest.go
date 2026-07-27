package server

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
	"rsc.io/qr"
)

// qrTTL is how long a visitor QR stays valid after the resident shows it. Kept
// short: it's an in-person, show-it-now flow, so a tight window limits exposure.
const qrTTL = 15 * time.Minute

// qrDataURI renders text as a QR code PNG in a data: URI (CSP allows img data:).
// Level Q (~25% error correction) is a robust choice for a code scanned off a
// screen at an angle or with glare, without making it much denser for a short URL.
func qrDataURI(text string) (string, error) {
	c, err := qr.Encode(text, qr.Q)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()), nil
}

// ---- guest-pass view types ----

// guestActView drives the public activation menu (State "guest").
type guestActView struct {
	Token          string         // raw token, echoed into the POST form
	OwnerEmail     string         // account holder, shown for trust
	PermitLabel    string         // which permit this affects
	CurrentReg     string         // what is on the permit right now ("" if unknown)
	Cars           []vehicleView  // the cars this link may activate
	AllowOvernight bool           // whether the overnight checkbox is offered
	AllowPlate     bool           // whether the visitor may type an arbitrary plate
	RequestOnly    bool           // printed QR: entering a plate only requests approval
	RevertPlate    string         // pre-existing plate the guest may put back ("" = no revert offered)
	PendingReg     string         // plate the schedule targets but the council doesn't show yet ("" = settled)
	Stalled        bool           // the pending change has taken suspiciously long; stop polling
	SelectedReg    string         // the schedule's target plate: highlights the chosen car IMMEDIATELY, while "on now" tracks the actual record
	UntilText      string         // when the winning booking ends ("until the end of today"), "" when open-ended/roster-driven
	KeepForm       bool           // poll responses only: render hx-preserve so a half-filled form survives the swap; activation responses omit it so the form resets
	FP             string         // fingerprint of the visible state; polls echo it so an unchanged page is a 204, not a re-render
	Req            *guestWaitView // printed door QR only: this browser's own remembered request (from the greq cookie), so a re-scan shows its fate instead of a blank form
}

// guestWaitView drives the visitor's "waiting for approval" page (State
// "guest-wait"), which polls the status endpoint.
type guestWaitView struct {
	OwnerEmail string
	Plate      string
	ReqID      int64
	Nonce      string
	Status     string // template-ready state: "pending" | "approved" | "applied" | "stalled" | "denied" | "expired" | "superseded" | "ended"
	Until      string // set when approved
}

// guestReqView is one pending request in the holder's approvals queue.
type guestReqView struct {
	ID          int64
	Plate       string
	PermitLabel string
	Ago         string // "2 min ago"
}

// guestDecidedView is one recently decided printed-QR request on the guests
// page. It exists for the member who DIDN'T decide: everyone on the account got
// the "approve this?" nudge, so everyone can come back later and see how it was
// resolved — and where the approved plate stands now.
type guestDecidedView struct {
	Plate       string
	PermitLabel string
	Outcome     string // "Approved" | "Declined" | "Not answered"
	DecidedBy   string // deciding member ("" for expired-unanswered)
	Ago         string // "2 hr ago" (since the decision)
	Live        string // approved rows: where the plate stands now ("" = nothing to add)
	Warn        bool   // amber the live note (superseded / stalled)
}

// qrShowView drives the on-screen visitor QR the resident shows in person (instant,
// short-lived). The durable printed door QR uses doorQRView / the poster instead.
type qrShowView struct {
	PermitLabel string
	ImageURI    template.URL // the QR as a data: URI (trusted: server-generated)
	URL         string       // the activation URL (also printed under the QR)
	ExpiresAt   string       // human-readable expiry
}

// doorQRView drives the styled, printable door-QR poster (State "doorqr"). It is a
// durable artifact: the same code reprints because the token is kept sealed.
type doorQRView struct {
	GrantID     int64
	PermitLabel string
	OwnerEmail  string
	ImageURI    template.URL
	URL         string
	CreatedAt   string // "20 Jul 2026"
}

// doorGrantView is one durable door QR in the holder's management list.
type doorGrantView struct {
	GrantID     int64
	PermitLabel string
	CreatedAt   string
}

// guestGrantView + guestRecipientView drive the account holder's management page.
type guestGrantView struct {
	ID             int64
	Label          string
	PermitLabel    string
	AllowOvernight bool
	Cars           []vehicleView
	Recipients     []guestRecipientView
}

// editGrantView drives the create/edit form when editing an existing grant (nil
// on the dashboardData means "create mode").
type editGrantView struct {
	ID             int64
	Label          string
	PermitLabel    string
	AllowOvernight bool
	Selected       map[int64]bool // vehicle ids currently on the grant (pre-checked)
	Recipients     []guestRecipientView
}

type guestRecipientView struct {
	TokenID int64
	Email   string
	Revoked bool
	// Undeliverable explains why mail to this address is being skipped (a bounce
	// or a spam complaint reported by the mail provider). Without surfacing it,
	// the owner sees "has a link" for someone who never received one and never
	// will — the typo'd-address case that is otherwise completely invisible.
	Undeliverable string
}

type permitOpt struct {
	ID    int64
	Label string
}

// guestLinkView is a freshly-minted link shown once, right after grant creation
// (the raw token is never stored, so this is the only chance to copy it).
type guestLinkView struct {
	Email string
	URL   string
}

// ---- token helpers ----

// newGuestToken returns a random URL token and its storage hash. Only the hash is
// ever persisted; the raw token lives in the emailed link.
func newGuestToken() (raw, hash string) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		// Fail closed: never mint a predictable (e.g. all-zero) token. A crypto/rand
		// failure is catastrophic and effectively never happens; the panic is
		// recovered by net/http into a 500, so no weak token is issued.
		panic("guest token: crypto/rand failed: " + err.Error())
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashGuestToken(raw)
}

func hashGuestToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Server) guestLink(raw string) string {
	return s.cfg.PublicBaseURL + "/g/" + raw
}

func permitLabel(p model.Permit) string {
	if p.Label != "" {
		return p.Label
	}
	return "Permit " + p.CouncilPermitID
}

// dayEndLocal is midnight at the start of the day `extraDays` after t's day, in
// t's location: extraDays=0 → end of today, extraDays=1 → end of tomorrow.
func dayEndLocal(t time.Time, extraDays int) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d+1+extraDays, 0, 0, 0, 0, t.Location())
}

func untilPhrase(now time.Time, overnight bool) string {
	if overnight {
		return "the end of tomorrow (" + now.AddDate(0, 0, 1).Weekday().String() + ")"
	}
	return "the end of today"
}

// noStore keeps the token link and its page out of caches and referrers.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

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
	s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "")
}

// guestCurrentPlate is the plate to show as "on the permit now": the council's
// own (cached) record when reachable, else our stored belief. Never an error —
// a council hiccup must not fail the page.
func (s *Server) guestCurrentPlate(ctx context.Context, gc guestCtx, permit model.Permit) string {
	if gc.Grant.RequestOnly {
		return "" // a printed door QR must not disclose the current plate
	}
	current := permit.ActiveRegistration
	if s.council != nil { // a council hiccup (or, in tests, no client at all) must not fail the page
		if actual, _, err := s.council.CurrentVehicleCached(ctx, permit.Owner,
			model.Permit{CouncilPermitID: permit.CouncilPermitID, PermitTypeID: permit.PermitTypeID}, 5*time.Minute); err == nil {
			current = actual
		}
	}
	return current
}

// revertPlate decides whether a guest may revert, and to what: the captured
// baseline, only while its window lasts, only when it isn't already on the
// permit, and only when it is NOT one of the link's own cars (those they can
// simply tap; the revert exists to restore a plate they could not pick).
func revertPlate(baseline string, until time.Time, current string, cars []model.Vehicle, now time.Time) string {
	if baseline == "" || !now.Before(until) || strings.EqualFold(baseline, current) {
		return ""
	}
	for _, v := range cars {
		if strings.EqualFold(v.Registration, baseline) {
			return ""
		}
	}
	return baseline
}

// guestDesired returns the plate the schedule is currently steering the permit
// toward ("" when nothing is scheduled), when that decision was made, and when
// its booking ends (both zero when roster-driven/open-ended). It is the same
// resolution the scheduler acts on, so the page's "still applying" state can
// never disagree with what will be applied.
func (s *Server) guestDesired(ctx context.Context, permit model.Permit) (want string, decidedAt, until time.Time) {
	now := time.Now().In(s.cfg.DisplayLocation)
	rules, err := s.store.ListRules(ctx, permit.ID)
	if err != nil {
		return "", time.Time{}, time.Time{}
	}
	overrides, err := s.store.ListOverrides(ctx, permit.ID, now)
	if err != nil {
		return "", time.Time{}, time.Time{}
	}
	res := model.Resolve(now, rules, overrides)
	if res.Source == model.SourceNone {
		return "", time.Time{}, time.Time{}
	}
	if res.Registration != "" {
		want = res.Registration
	} else {
		vehicles, verr := s.store.ListVehiclesFor(ctx, permit.Owner)
		if verr != nil {
			return "", time.Time{}, time.Time{}
		}
		for _, v := range vehicles {
			if v.ID == res.VehicleID {
				want = v.Registration
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
	return want, decidedAt, until
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

// pendingState reports whether the council record has caught up to the
// schedule's target: a non-empty pendingReg means "still applying"; stalled
// means it has been outstanding past guestApplyTimeout and polling should stop.
func pendingState(actual, want string, decidedAt, now time.Time) (pendingReg string, stalled bool) {
	if want == "" || strings.EqualFold(actual, want) {
		return "", false
	}
	return want, !decidedAt.IsZero() && now.Sub(decidedAt) > guestApplyTimeout
}

// buildGuestView assembles the activation-menu view model from actual state:
// the council-side current plate, the revert offer, and the pending/stalled
// status against the schedule's resolved target.
func (s *Server) buildGuestView(r *http.Request, gc guestCtx, permit model.Permit, current string) guestActView {
	ctx := r.Context()
	cars, _, _, _ := vehicleViews(gc.Vehicles)
	view := guestActView{
		Token: gc.rawToken, PermitLabel: permitLabel(permit),
		Cars: cars, AllowOvernight: gc.Grant.AllowOvernight,
		AllowPlate: gc.Grant.AllowPlate, RequestOnly: gc.Grant.RequestOnly,
	}
	// The label is the owner's own free text (or, failing that, the council permit
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
		want, decidedAt, until := s.guestDesired(ctx, permit)
		// Offer "put it back" only while THIS link's activation is still the winning
		// plate. If the owner (or their schedule) has since booked over it, the guest
		// has nothing to undo — and reverting would wrongly displace that deliberate
		// booking. Requiring the link's own live override to match the resolved
		// winner keeps the offer honest and prevents the clobber.
		if gp, ok := s.store.ActiveGuestOverridePlate(ctx, permit.ID, gc.TokenID, time.Now()); ok && strings.EqualFold(gp, want) {
			view.RevertPlate = revertPlate(gc.BaselinePlate, gc.BaselineUntil, current, gc.Vehicles, time.Now())
		}
		view.PendingReg, view.Stalled = pendingState(current, want, decidedAt, time.Now())
		if !until.IsZero() {
			now := time.Now().In(s.cfg.DisplayLocation)
			view.UntilText = untilText(now, until.In(s.cfg.DisplayLocation))
		}
		// The highlight follows the guest's choice the moment it is saved; the
		// "on now" pill follows the council's actual record as it catches up.
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
	sum := sha256.Sum256([]byte(v.CurrentReg + "|" + v.PendingReg + "|" + stalled + "|" + v.RevertPlate + "|" + v.UntilText))
	return hex.EncodeToString(sum[:6])
}

// renderGuestMenu renders the activation menu with optional feedback. An htmx
// request gets just the live-updating body fragment (no navigation); anything
// else gets the full page. While a change is still applying, the fragment
// carries a poller so the page keeps showing the council's ACTUAL record until
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
	data := dashboardData{State: "guest", Loc: s.cfg.DisplayLocation, Guest: view, Flash: flash, Warn: warn}
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
// ACTUAL plate now on the council record.
func (s *Server) guestLive(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
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
		if want, _, _ := s.guestDesired(r.Context(), permit); want != "" && strings.EqualFold(current, want) {
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
// car (end of today, or tomorrow if overnight) and applies it to the council for
// instant feedback, leaving the scheduler to guarantee eventual consistency. The
// response is the same menu with the result inlined (htmx swaps it in place), so
// a guest can tap one car, then another, then revert, without navigating.
func (s *Server) guestActivate(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		s.guestFail(w, r, "This request could not be verified. Please reopen your link and try again.")
		return
	}
	if !s.guest.allow(clientIP(r)) {
		s.guestFail(w, r, "Too many attempts. Please wait a little while and try again.")
		return
	}
	limitBody(r)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}

	// A printed QR is inert: a scan only REQUESTS the permit. Nothing goes on the
	// permit until the account holder approves it live.
	if gc.Grant.RequestOnly {
		s.guestRequest(w, r, gc, permit)
		return
	}

	now := time.Now().In(s.cfg.DisplayLocation)
	overnight := gc.Grant.AllowOvernight && r.FormValue("overnight") != ""
	end := dayEndLocal(now, 0)
	if overnight {
		end = dayEndLocal(now, 1)
	}
	current := s.guestCurrentPlate(r.Context(), gc, permit)

	// The target is either an arbitrary plate (when the grant allows it, e.g. a
	// visitor QR) or one of the grant's saved cars. Each becomes a fresh override,
	// created now, so it wins the resolution tie-break for its window.
	var reg, name, createdBy string
	if plate := normalizeReg(r.FormValue("plate")); plate != "" && gc.Grant.AllowPlate {
		if !validRego(plate) {
			s.renderGuestMenu(w, r, gc, permit, current, "", "Enter a valid number plate (letters and numbers, e.g. ABC123).")
			return
		}
		reg = plate
		createdBy = gc.Recipient
		if createdBy == "" {
			createdBy = "visitor (QR)"
		}
		if _, err := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, plate, now, &end, createdBy, gc.TokenID); err != nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", "Something went wrong saving your plate. Please try again.")
			return
		}
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
		reg, name, createdBy = chosen.Registration, chosen.Label, gc.Recipient
		if _, err := s.store.CreateGuestOverride(r.Context(), permit.ID, chosen.ID, now, &end, gc.Recipient, gc.TokenID); err != nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", "Something went wrong saving your choice. Please try again.")
			return
		}
	}
	_ = s.store.TouchGuestTokenUsed(r.Context(), gc.TokenID)

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
	// Best-effort synchronous apply so the visitor gets a real result; the
	// scheduler (kicked below) owns retries and eventual consistency regardless.
	// Detached from the request context: a closed tab mid-apply must not cancel
	// the council write halfway, nor silently drop the audit row and the
	// displaced-driver notice after the change has already landed. Capped below
	// the server's 20s WriteTimeout so a slow apply still leaves room to write
	// the response.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	err := s.council.SetVehicle(applyCtx, permit.Owner, permit, reg)
	// Plain Kick, deliberately: this handler already attempted the council write
	// itself, so clearing the permit's failure backoff would add council pressure
	// without adding a chance of success — and this path is unauthenticated.
	s.sched.Kick()
	if err == nil {
		_ = s.store.SetPermitActive(bg, permit.ID, reg)
		_ = s.store.RecordApply(bg, permit.ID, reg, "guest", "success", "activated by "+createdBy)
		d := s.displacedDriver(bg, permit, current, reg, gc.Recipient)
		s.notifyGuestApply(bg, permit, reg, name, createdBy, d)
		s.renderGuestMenu(w, r, gc, permit, reg, reg+" is now on the permit until "+until+".", "")
		return
	}
	// The activity log is user-facing: record a plain-English detail and keep the
	// raw council error in the server log only.
	log.Printf("guest activate %s on permit %d: %v", reg, permit.ID, err)
	_ = s.store.RecordApply(bg, permit.ID, reg, "guest", "error", guestApplyDetail(err))
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The override is saved and the scheduler will apply it shortly; the pending
		// banner + poller (from renderGuestMenu) track the ACTUAL result — no claim.
		s.renderGuestMenu(w, r, gc, permit, current, "", "")
		return
	}
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
	if !s.guest.allow(clientIP(r)) {
		s.guestFail(w, r, "Too many attempts. Please wait a little while and try again.")
		return
	}
	limitBody(r)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if gc.Grant.RequestOnly {
		s.renderGuestGone(w, r) // printed QRs never change the permit directly, so there is nothing to revert
		return
	}
	now := time.Now().In(s.cfg.DisplayLocation)
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
	target := baseline
	if want, _, _ := s.guestDesired(r.Context(), permit); want != "" {
		target = want
	} else {
		end := revertPinEnd(now, gc.BaselineUntil)
		if _, err := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, baseline, now, &end, createdBy+" (undo)", gc.TokenID); err != nil {
			s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Something went wrong. Please try again.")
			return
		}
	}
	// Forget the baseline: the revert consumed it, and hiding the button beats
	// offering a second no-op undo. The next activation captures a fresh one.
	_ = s.store.ClearGuestBaseline(r.Context(), gc.TokenID)
	gc.BaselinePlate, gc.BaselineUntil = "", time.Time{}

	// Detached from the request (see guestActivate): a disconnect mid-apply must
	// not drop the bookkeeping, and the budget stays under the WriteTimeout.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	err := s.council.SetVehicle(applyCtx, permit.Owner, permit, target)
	s.sched.Kick()
	if err == nil {
		_ = s.store.SetPermitActive(bg, permit.ID, target)
		_ = s.store.RecordApply(bg, permit.ID, target, "guest", "success", "put back by "+createdBy)
		// A revert can't displace a third party: the guest's own overrides were
		// just swept, and the baseline is only re-pinned when nothing else covers
		// now — so there is no displaced booking to chase.
		s.notifyGuestApply(bg, permit, target, "", createdBy+" (undo)", model.DisplacedBooking{})
		s.renderGuestMenu(w, r, gc, permit, target, target+" is back on the permit.", "")
		return
	}
	log.Printf("guest revert to %s on permit %d: %v", target, permit.ID, err)
	_ = s.store.RecordApply(bg, permit.ID, target, "guest", "error", guestApplyDetail(err))
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The restore is saved; the pending banner + poller track the actual result.
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
	case store.SuppressManual:
		return "email disabled for this address"
	default:
		return ""
	}
}

// guestApplyDetail is the user-facing activity-log detail for a failed guest
// apply: the Activity page renders it verbatim, so it must be a plain sentence,
// not a raw council error (which goes to the server log instead).
func guestApplyDetail(err error) string {
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		return "Couldn't reach the council; p.stonn will keep trying."
	}
	return "The council did not accept the change."
}

func (s *Server) notifyGuestApply(ctx context.Context, permit model.Permit, reg, name, by string, d model.DisplacedBooking) {
	// Enqueue durably (a fast insert): unlike the scheduler's apply-notify, this
	// path has no reconcile-loop retry behind it, so a fire-and-forget send could
	// silently drop the "a guest put their car on your permit" notice.
	outcome := notify.ApplyOutcome{
		Owner: permit.Owner, PermitLabel: permitLabel(permit), Reg: reg, Name: name, By: by, Source: "guest", OK: true,
		DisplacedReg: d.Reg, DisplacedTold: d.Contact != "",
	}
	if err := s.notify.EnqueueApply(ctx, outcome); err != nil {
		log.Printf("guest apply notify enqueue for %s: %v", permit.Owner, err)
	}
}

// displacedDriver resolves who should be warned that prev was just taken off a
// permit by actor's change, and notifies them when reachable: the shared
// model.FindDisplaced policy fed the permit's live overrides, the owner's saved
// vehicles, and the account members. Returns what it found so sync-apply paths
// can annotate the account notification (Reg set + no Contact = a booking was
// displaced but its driver couldn't be told). Best-effort: on any store error it
// stays quiet — a missed heads-up is low-harm, the account fanout still fires.
func (s *Server) displacedDriver(ctx context.Context, permit model.Permit, prev, next, actor string) model.DisplacedBooking {
	if prev == "" || strings.EqualFold(prev, next) {
		return model.DisplacedBooking{}
	}
	now := time.Now()
	overrides, err := s.store.ListOverrides(ctx, permit.ID, now)
	if err != nil {
		return model.DisplacedBooking{}
	}
	saved, err := s.store.ListVehiclesFor(ctx, permit.Owner)
	if err != nil {
		return model.DisplacedBooking{}
	}
	vehicles := make(map[int64]model.VehicleInfo, len(saved))
	for _, v := range saved {
		vehicles[v.ID] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email}
	}
	members, err := s.store.AccountEmails(ctx, permit.Owner)
	if err != nil {
		return model.DisplacedBooking{}
	}
	d := model.FindDisplaced(overrides, vehicles, prev, actor, members, now)
	if d.Contact != "" {
		if err := s.notify.NotifyDriverDisplaced(ctx, permit.Owner, d.Contact, permitLabel(permit), prev, next); err != nil {
			log.Printf("enqueue driver-displaced for %s: %v", d.Contact, err)
		}
	}
	return d
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
	w.WriteHeader(http.StatusNotFound)
	s.render(w, dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation, Warn: msg})
}

func (s *Server) renderGuestResult(w http.ResponseWriter, ownerEmail string, ok bool, msg string) {
	noStore(w)
	d := dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation,
		Guest: guestActView{OwnerEmail: ownerEmail}}
	if ok {
		d.Flash = msg
	} else {
		d.Warn = msg
	}
	s.render(w, d)
}

// ================= ACCOUNT-HOLDER MANAGEMENT (login required) =================

// guestsPage lists the owner's guest passes and the create form.
func (s *Server) guestsPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	// Success feedback after deciding a printed-QR request (structured params, so
	// the message is composed here, not reflected from the URL). The plate is
	// rego-validated on the way in.
	switch q := r.URL.Query(); {
	case q.Get("applied") != "":
		base.Flash = q.Get("applied") + " is now on the permit."
	case q.Get("approving") != "":
		base.Flash = "Approved — " + q.Get("approving") + " is being put on the permit."
	case q.Get("declined") != "":
		base.Flash = "Request declined."
	case q.Get("resent") != "":
		base.Flash = "A fresh link has been sent to " + q.Get("resent") + ". Their previous link has been replaced."
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, base)
}

// editGuestGrant renders the guests page with the pass form pre-filled for the
// grant to edit.
func (s *Server) editGuestGrant(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, pathInt(r, "id")); err != nil {
		s.serverError(w, err)
		return
	}
	if base.Edit == nil { // no such grant for this owner
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	s.render(w, base)
}

// loadGuests fills the guest-management fields (grants, permit/vehicle choices,
// kill-switch state) on base. When editID > 0 and matches one of the owner's
// grants, it also populates base.Edit so the form renders in edit mode.
func (s *Server) loadGuests(ctx context.Context, base *dashboardData, editID int64) error {
	owner := base.Owner
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return err
	}
	labelByPermit := map[int64]string{}
	for _, p := range permits {
		labelByPermit[p.ID] = permitLabel(p)
		base.PermitOpts = append(base.PermitOpts, permitOpt{ID: p.ID, Label: permitLabel(p)})
	}
	vehicles, err := s.store.ListVehiclesFor(ctx, owner)
	if err != nil {
		return err
	}
	base.Vehicles, _, _, _ = vehicleViews(vehicles)

	details, err := s.store.ListGuestGrants(ctx, owner)
	if err != nil {
		return err
	}
	// Annotate recipients whose address the mail provider has told us is dead.
	// One query for the whole page rather than one per recipient.
	var allRecipients []string
	for _, d := range details {
		for _, t := range d.Tokens {
			allRecipients = append(allRecipients, t.RecipientEmail)
		}
	}
	undeliverable, err := s.store.SuppressedAmong(ctx, allRecipients)
	if err != nil {
		// Best-effort annotation: never fail the page over it.
		log.Printf("guests: suppression lookup for %s: %v", owner, err)
		undeliverable = map[string]string{}
	}
	for _, d := range details {
		cars, _, _, _ := vehicleViews(d.Vehicles)
		var recips []guestRecipientView
		for _, t := range d.Tokens {
			recips = append(recips, guestRecipientView{
				TokenID: t.ID, Email: t.RecipientEmail, Revoked: t.Revoked,
				Undeliverable: undeliverableText(undeliverable[t.RecipientEmail]),
			})
		}
		base.Guests = append(base.Guests, guestGrantView{
			ID: d.Grant.ID, Label: d.Grant.Label, PermitLabel: labelByPermit[d.Grant.PermitID],
			AllowOvernight: d.Grant.AllowOvernight, Cars: cars, Recipients: recips,
		})
		if editID > 0 && d.Grant.ID == editID {
			sel := map[int64]bool{}
			for _, v := range d.Vehicles {
				sel[v.ID] = true
			}
			base.Edit = &editGrantView{
				ID: d.Grant.ID, Label: d.Grant.Label, PermitLabel: labelByPermit[d.Grant.PermitID],
				AllowOvernight: d.Grant.AllowOvernight, Selected: sel, Recipients: recips,
			}
		}
	}
	if reqs, rerr := s.store.ListPendingRequests(ctx, owner); rerr == nil {
		now := time.Now()
		for _, rq := range reqs {
			base.PendingRequests = append(base.PendingRequests, guestReqView{
				ID: rq.ID, Plate: rq.Plate, PermitLabel: labelByPermit[rq.PermitID], Ago: agoText(now, rq.RequestedAt),
			})
		}
	}
	// Recently decided printed-QR requests: every member got the "approve this?"
	// nudge, so every member can see how it was resolved — including the live
	// fate of an approved plate (on the permit / superseded / ended). Best-effort
	// like the queue above: an error just hides the section.
	if recent, rerr := s.store.ListRecentDecidedRequests(ctx, owner, time.Now().Add(-guestReqCookieTTL)); rerr == nil {
		now := time.Now()
		permitByID := map[int64]model.Permit{}
		for _, p := range permits {
			permitByID[p.ID] = p
		}
		for _, rq := range recent {
			v := guestDecidedView{
				Plate: rq.Plate, PermitLabel: labelByPermit[rq.PermitID],
				DecidedBy: rq.DecidedBy, Ago: agoText(now, rq.DecidedAt),
			}
			switch rq.Status {
			case "approved":
				v.Outcome = "Approved"
				if p, ok := permitByID[rq.PermitID]; ok {
					switch st, replacedBy := s.requestLiveState(ctx, p, rq); st {
					case "applied":
						v.Live = "On the permit until " + rq.Until + "."
					case "approved":
						v.Live = "Being put on the permit…"
					case "stalled":
						v.Live, v.Warn = "Not yet confirmed on the permit — check the permit's schedule.", true
					case "superseded":
						// Members may see the superseding plate (unlike the public door-QR
						// pages, which never disclose the permit's current plate).
						v.Live, v.Warn = "No longer on the permit — since replaced.", true
						if replacedBy != "" {
							v.Live = "No longer on the permit — since replaced by " + replacedBy + "."
						}
					case "ended":
						v.Live = "The pass has ended."
					}
				}
			case "denied":
				v.Outcome = "Declined"
			default: // "expired": aged out with nobody answering
				v.Outcome = "Not answered"
			}
			base.RecentRequests = append(base.RecentRequests, v)
		}
	}
	if doors, derr := s.store.ListPrintedGrants(ctx, owner); derr == nil {
		for _, d := range doors {
			base.DoorGrants = append(base.DoorGrants, doorGrantView{
				GrantID: d.GrantID, PermitLabel: d.PermitLabel,
				CreatedAt: d.CreatedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006"),
			})
		}
	}
	base.GuestsEnabled, err = s.store.GuestsEnabled(ctx, owner)
	return err
}

// agoText is a coarse "how long ago" for the approvals queue.
func agoText(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	}
}

// createGuestGrant creates a grant + a per-recipient token, emails each link, and
// re-renders the page showing the links once (the only time we hold the raw token).
func (s *Server) createGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	permitID := atoi64(r.FormValue("permit_id"))
	label := strings.TrimSpace(r.FormValue("label"))
	allowOvernight := r.FormValue("allow_overnight") != ""
	var vehicleIDs []int64
	for _, v := range r.Form["vehicle_id"] {
		if id := atoi64(v); id > 0 {
			vehicleIDs = append(vehicleIDs, id)
		}
	}
	recipients, droppedEmails := parseEmails(r.FormValue("recipients"))
	if len(vehicleIDs) == 0 {
		s.formError(w, r, "Choose at least one car this link may activate.")
		return
	}
	if len(recipients) == 0 {
		if len(droppedEmails) > 0 {
			s.formError(w, r, "None of those recipient emails look valid. Check them and try again.")
			return
		}
		s.formError(w, r, "Add at least one recipient email.")
		return
	}

	recs, links := s.mintLinks(recipients)
	if _, err := s.store.CreateGuestGrant(r.Context(), owner, user, permitID, label, allowOvernight, vehicleIDs, recs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit or car isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	sent := s.emailLinks(r.Context(), owner, permitLabel(permit), links)

	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.NewGuestLinks = links
	switch {
	case sent == len(links):
		base.Flash = "Guest pass created and links emailed."
	case sent > 0:
		base.Flash = "Guest pass created. Some links couldn't be emailed — copy the links below to be sure everyone gets theirs."
	default:
		base.Flash = "Guest pass created. Copy the links below to share them."
	}
	base.Flash += skippedNote(droppedEmails)
	s.logChange(r.Context(), owner, user, store.ActionGuestCreate, strings.Join(recipients, ", "), label)
	s.render(w, base)
}

// guestManifest serves a per-recipient web app manifest, so a guest can install
// their link to the home screen (Android/Chrome "Install") and have the icon open
// straight to THEIR menu (start_url is their own link). Public and token-scoped;
// icons are the app's static PNGs. No token validation: a manifest for a dead link
// is harmless (the page it points to just shows "no longer active").
func (s *Server) guestManifest(w http.ResponseWriter, r *http.Request) {
	// {token} is a single clean path segment (base64url); %q JSON-escapes it.
	startURL := fmt.Sprintf("%q", "/g/"+r.PathValue("token"))
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `{
  "name": "p.stonn parking permit",
  "short_name": "p.stonn",
  "start_url": `+startURL+`,
  "scope": "/g/",
  "display": "standalone",
  "theme_color": "#0d9488",
  "background_color": "#eceff5",
  "icons": [
    {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
    {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
  ]
}`)
}

// resendGuestLink emails a recipient a FRESH link for a guest pass they already
// have. The original link can't be re-sent (only its hash is stored), so this
// mints a new token and supersedes the old one. Owner-only.
func (s *Server) resendGuestLink(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	recipient := strings.TrimSpace(r.FormValue("recipient"))
	if recipient == "" {
		s.formError(w, r, "No recipient to re-send to.")
		return
	}
	// Don't rotate the token when we can't deliver the replacement — that would
	// break the recipient's current link with nothing to replace it.
	if !s.notify.EmailAvailable() {
		s.formError(w, r, "Email isn't set up, so links can't be re-sent.")
		return
	}
	raw, hash := newGuestToken()
	permitID, err := s.store.ResetGuestToken(r.Context(), owner, pathInt(r, "id"), recipient, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That guest pass or recipient isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	links := []guestLinkView{{Email: recipient, URL: s.guestLink(raw)}}
	if s.emailLinks(r.Context(), owner, permitLabel(permit), links) == 0 {
		// The send failed at runtime (SMTP up-check passed, delivery didn't). The
		// old token is already superseded, so claiming success would leave the
		// recipient with a dead link and nothing delivered. Show the fresh link
		// once on-page instead, like create/update do, so the owner can pass it on.
		base, ok := s.appShell(w, r, "guests")
		if !ok {
			return
		}
		if err := s.loadGuests(r.Context(), &base, 0); err != nil {
			s.serverError(w, err)
			return
		}
		base.NewGuestLinks = links
		base.Flash = "The email could not be sent. Copy the fresh link below and share it yourself — the old link no longer works."
		s.render(w, base)
		return
	}
	http.Redirect(w, r, "/guests?resent="+url.QueryEscape(recipient), http.StatusSeeOther)
}

// updateGuestGrant edits a grant's label, cars, and overnight option, and adds
// any new recipients (each getting a fresh emailed link). The permit is fixed.
func (s *Server) updateGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	id := pathInt(r, "id")
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	allowOvernight := r.FormValue("allow_overnight") != ""
	var vehicleIDs []int64
	for _, v := range r.Form["vehicle_id"] {
		if vid := atoi64(v); vid > 0 {
			vehicleIDs = append(vehicleIDs, vid)
		}
	}
	if len(vehicleIDs) == 0 {
		s.formError(w, r, "Choose at least one car this pass may activate.")
		return
	}
	if err := s.store.UpdateGuestGrant(r.Context(), owner, id, label, allowOvernight, vehicleIDs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That pass or car isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}

	// New recipients (if any) each get a fresh token + link.
	var newLinks []guestLinkView
	emails, droppedEmails := parseEmails(r.FormValue("recipients"))
	if len(emails) > 0 {
		recs, links := s.mintLinks(emails)
		added, err := s.store.AddGuestTokens(r.Context(), owner, id, recs)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, err)
			return
		}
		addedSet := map[string]bool{}
		for _, e := range added {
			addedSet[e] = true
		}
		for _, l := range links {
			if addedSet[l.Email] {
				newLinks = append(newLinks, l)
			}
		}
	}

	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	if len(newLinks) > 0 {
		plabel := ""
		for _, g := range base.Guests {
			if g.ID == id {
				plabel = g.PermitLabel
			}
		}
		sent := s.emailLinks(r.Context(), owner, plabel, newLinks)
		base.NewGuestLinks = newLinks
		switch {
		case sent == len(newLinks):
			base.Flash = "Guest pass updated and new links emailed."
		case sent > 0:
			base.Flash = "Guest pass updated. Some links couldn't be emailed — copy the links below to be sure everyone gets theirs."
		default:
			base.Flash = "Guest pass updated. Copy the new links below to share them."
		}
	} else {
		base.Flash = "Guest pass updated."
	}
	base.Flash += skippedNote(droppedEmails)
	s.logChange(r.Context(), owner, user, store.ActionGuestUpdate, label, "")
	s.render(w, base)
}

// mintLinks generates a fresh token per email: the store records to persist (only
// the hash) and the display links to email or show once.
func (s *Server) mintLinks(emails []string) ([]store.GuestRecipient, []guestLinkView) {
	recs := make([]store.GuestRecipient, 0, len(emails))
	links := make([]guestLinkView, 0, len(emails))
	for _, e := range emails {
		raw, hash := newGuestToken()
		recs = append(recs, store.GuestRecipient{Email: e, TokenHash: hash})
		links = append(links, guestLinkView{Email: e, URL: s.guestLink(raw)})
	}
	return recs, links
}

// emailLinks sends each link best-effort (no-op without SMTP) and returns how
// many were accepted. Failures are logged so a guest who never received their
// link can be traced; the caller's flash + the shown-once links panel are the
// user-facing fallback.
//
// Throttled two ways, like the member invite: these mails go to arbitrary
// addresses the user types, and each one carries a live capability over their
// permit — so an account must not be able to mail-bomb a stranger (per-recipient)
// or burn the SMTP reputation everyone shares (per-owner). A throttled link is
// not lost: the caller always shows it on screen to copy.
func (s *Server) emailLinks(ctx context.Context, owner, permitLabel string, links []guestLinkView) int {
	sent := 0
	for _, l := range links {
		if !s.guestLinkOut.allow("o:"+owner) || !s.guestLinkTo.allow("t:"+l.Email) {
			log.Printf("guest link email to %s for %s throttled", l.Email, owner)
			continue
		}
		if err := s.notify.SendGuestLink(ctx, l.Email, owner, permitLabel, l.URL); err == nil {
			sent++
		} else {
			log.Printf("guest link email to %s for %s: %v", l.Email, owner, err)
		}
	}
	return sent
}

// showVisitorQR mints a short-lived, plate-entry grant for a permit and renders a
// QR the resident shows on-screen. A visitor scans it, types their plate, and it
// goes on the permit until the end of the day. The grant self-expires (qrTTL).
func (s *Server) showVisitorQR(w http.ResponseWriter, r *http.Request) {
	noStore(w) // the page embeds a live activation token; keep it out of caches
	user, owner, _ := s.resolveAccount(r.Context())
	permitID := atoi64(r.FormValue("permit_id"))
	raw, hash := newGuestToken()
	if _, err := s.store.CreateQRGrant(r.Context(), owner, user, permitID, hash, qrTTL); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	url := s.guestLink(raw)
	img, err := qrDataURI(url)
	if err != nil {
		s.serverError(w, err)
		return
	}
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.QR = &qrShowView{
		PermitLabel: permitLabel(permit),
		ImageURI:    template.URL(img),
		URL:         url,
		ExpiresAt:   time.Now().In(s.cfg.DisplayLocation).Add(qrTTL).Format("3:04pm"),
	}
	s.render(w, base)
}

func (s *Server) deleteGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	// Name it before deleting, so the log and the notice can say which pass died.
	label := s.grantLabel(r.Context(), owner, pathInt(r, "id"))
	if err := s.store.DeleteGuestGrant(r.Context(), owner, pathInt(r, "id")); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionGuestDelete, label, "")
	s.notifyDestructive(r.Context(), owner, user,
		user+" deleted a guest pass"+optional(label, " (")+closeParen(label)+" on your p.stonn account. Anyone holding those links can no longer use your permit.")
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) revokeGuestToken(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	if err := s.store.RevokeGuestToken(r.Context(), owner, pathInt(r, "tid")); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionGuestRevoke, "", "")
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) toggleGuests(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	enabled := r.FormValue("enabled") != ""
	if err := s.store.SetGuestsEnabled(r.Context(), owner, enabled); err != nil {
		s.serverError(w, err)
		return
	}
	state := "on"
	if !enabled {
		state = "off"
	}
	s.logChange(r.Context(), owner, user, store.ActionGuestToggle, "", state)
	if !enabled {
		// Pausing kills every guest link at once — a visitor at the kerb just sees
		// "no longer active", so the household should know it was deliberate.
		s.notifyDestructive(r.Context(), owner, user,
			user+" paused all guest passes on your p.stonn account. Existing guest links and printed door QRs will not work until they are resumed.")
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) setVehicleEmail(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email != "" && !looksLikeEmail(email) {
		s.formError(w, r, "Enter a valid email address, or leave it blank.")
		return
	}
	if err := s.store.SetVehicleEmail(r.Context(), owner, pathInt(r, "id"), email); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/vehicles?saved=1", http.StatusSeeOther)
}

// parseEmails splits a free-text recipient list (comma/space/semicolon/newline
// separated), lower-cases, validates, and de-duplicates. Invalid tokens are
// dropped so one typo doesn't discard the rest, and returned separately so the
// caller can tell the user who was skipped.
func parseEmails(s string) (out, dropped []string) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	seen := map[string]bool{}
	for _, f := range fields {
		e := strings.ToLower(strings.TrimSpace(f))
		if e == "" || seen[e] {
			continue
		}
		if !looksLikeEmail(e) {
			dropped = append(dropped, e)
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out, dropped
}

// skippedNote turns parseEmails' dropped tokens into a flash suffix, so a
// typo'd recipient doesn't vanish without a trace.
func skippedNote(dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return " Skipped (not a valid email): " + strings.Join(dropped, ", ") + "."
}

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
//	applied    — approved AND the council's own record shows the plate
//	stalled    — approved but unconfirmed past guestApplyTimeout
//	approved   — approved, council catching up (keep polling)
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
	now := time.Now().In(s.cfg.DisplayLocation)
	end := req.UntilTS
	if end.IsZero() && !req.DecidedAt.IsZero() {
		// Rows approved before until_ts existed: reproduce the approval's window
		// (printed-QR approvals always ran to the end of the approval's day).
		end = dayEndLocal(req.DecidedAt.In(s.cfg.DisplayLocation), 0)
	}
	if !end.IsZero() && !now.Before(end) {
		return "ended", ""
	}
	want, _, _ := s.guestDesired(ctx, permit)
	if !strings.EqualFold(want, req.Plate) {
		return "superseded", want
	}
	if strings.EqualFold(permit.ActiveRegistration, req.Plate) {
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
		s.render(w, dashboardData{State: "guest", Loc: s.cfg.DisplayLocation,
			Warn: "Enter a valid number plate (letters and numbers, e.g. ABC123).",
			Guest: guestActView{Token: gc.rawToken,
				PermitLabel: permitLabel(permit), AllowPlate: true, RequestOnly: true}})
		return
	}
	reqID, nonce, created, err := s.store.CreateGuestRequest(r.Context(), gc.Grant.ID, permit.ID, permit.Owner, plate, randNonce())
	if errors.Is(err, store.ErrGuestRequestLimit) {
		s.renderGuestResult(w, "", false, "There are already several requests waiting for the resident. Please knock or contact them directly.")
		return
	}
	if err != nil {
		s.renderGuestResult(w, "", false, "Something went wrong sending your request. Please try again.")
		return
	}
	if created { // a re-scan of the same plate reuses the pending request; don't re-nudge
		s.notifyGuestRequest(r.Context(), permit, plate)
	}
	// Remember the request in this browser (the one that made it), so a later
	// re-scan of the same door code shows its fate instead of a blank form.
	s.setGuestReqCookie(w, reqID, nonce)
	s.render(w, dashboardData{State: "guest-wait", Loc: s.cfg.DisplayLocation,
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
		// "approved" means the resident said yes; requestLiveState only reports it
		// as ON the permit once the council's own record actually shows the plate
		// ("applied"), flags a long-unconfirmed apply ("stalled"), and — the states
		// this endpoint couldn't see before — notices when the pass has since been
		// overridden ("superseded") or its window has lapsed ("ended"), instead of
		// misreading either as a stall.
		if req.Status == "approved" {
			if permit, perr := s.store.GetPermit(r.Context(), req.PermitID); perr == nil {
				v.Status, _ = s.requestLiveState(r.Context(), permit, req)
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
// on the council before the visitor's page stops spinning and suggests checking
// with the resident (the scheduler keeps retrying regardless).
const guestApplyTimeout = 8 * time.Minute

func (s *Server) notifyGuestRequest(ctx context.Context, permit model.Permit, plate string) {
	// Enqueue durably (a fast DB insert) so the holder's "approve this?" nudge
	// survives a restart and is retried — the printed-QR flow depends on it.
	url := s.cfg.PublicBaseURL + "/guests"
	if err := s.notify.NotifyGuestRequest(ctx, permit.Owner, permitLabel(permit), plate, url); err != nil {
		log.Printf("guest request notify enqueue for %s: %v", permit.Owner, err)
	}
}

// showPrintedQR mints a durable request-only grant and renders a QR to print and
// leave out (e.g. at the door). A scan of it only requests the permit; the holder
// approves live. It replaces any existing printed QR for the permit.
// mintPrintedGrant creates (or replaces) a permit's door QR, sealing the raw token
// at rest so the same code can be reprinted later. Returns the new grant id.
func (s *Server) mintPrintedGrant(ctx context.Context, owner, createdBy string, permitID int64) (int64, error) {
	raw, hash := newGuestToken()
	sealed, err := s.box.Seal(raw)
	if err != nil {
		return 0, err
	}
	return s.store.CreatePrintedGrant(ctx, owner, createdBy, permitID, hash, sealed)
}

// showPrintedQR handles "Print a door QR" for a permit. It is idempotent: if the
// permit already has a door QR it reopens that (same code) rather than rotating the
// token, so a copy already on the fridge keeps working.
func (s *Server) showPrintedQR(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	permitID := atoi64(r.FormValue("permit_id"))
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
	noStore(w) // the poster embeds the durable door-QR token; keep it out of caches
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
	raw, err := s.box.Open(g.TokenSealed)
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
		CreatedAt: g.CreatedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006"),
	}
	s.render(w, base)
}

// revokeDoorQR retires a door QR for good (its code stops working).
func (s *Server) revokeDoorQR(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	label := s.grantLabel(r.Context(), owner, atoi64(r.PathValue("id")))
	if err := s.store.RevokePrintedGrant(r.Context(), owner, atoi64(r.PathValue("id"))); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionDoorQRRevoke, label, "")
	s.notifyDestructive(r.Context(), owner, user,
		user+" removed a printed door QR on your p.stonn account. Any copy already printed and put up has stopped working.")
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) approveGuestRequest(w http.ResponseWriter, r *http.Request) {
	s.decideRequest(w, r, true)
}
func (s *Server) denyGuestRequest(w http.ResponseWriter, r *http.Request) {
	s.decideRequest(w, r, false)
}

// decideRequest approves or denies a pending printed-QR request. On approval it
// puts the plate on the permit (end of day) and applies it best-effort.
func (s *Server) decideRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	user, owner, _ := s.resolveAccount(r.Context())
	id := pathInt(r, "id")
	now := time.Now().In(s.cfg.DisplayLocation)

	if !approve {
		if _, err := s.store.DecideGuestRequest(r.Context(), owner, id, false, "", user, time.Time{}); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.serverError(w, err)
			return
		}
		s.logChange(r.Context(), owner, user, store.ActionRequestNo, "", "")
		http.Redirect(w, r, "/guests?declined=1", http.StatusSeeOther)
		return
	}

	// Approve: set up the plate override BEFORE finalising the approval, so we can
	// never leave a request marked "approved" that the scheduler has nothing to act
	// on (which would strand the visitor and mislead the holder).
	req, rerr := s.store.GuestRequestByID(r.Context(), id)
	if rerr != nil || req.Status != "pending" {
		http.Redirect(w, r, "/guests", http.StatusSeeOther) // gone / already decided
		return
	}
	permit, perr := s.store.GetPermit(r.Context(), req.PermitID)
	if perr != nil || permit.Owner != owner {
		http.Redirect(w, r, "/guests", http.StatusSeeOther) // not ours / permit removed
		return
	}
	end := dayEndLocal(now, 0)
	ovID, cerr := s.store.CreatePlateOverride(r.Context(), permit.ID, req.Plate, now, &end, "visitor (printed QR)")
	if cerr != nil {
		s.serverError(w, cerr) // don't approve if we couldn't set up the change
		return
	}
	if _, err := s.store.DecideGuestRequest(r.Context(), owner, id, true, untilPhrase(now, false), user, end); err != nil {
		// The approval didn't land — raced with a concurrent deny (ErrNotFound: the
		// row is no longer pending) or a DB error. Roll back the override we
		// optimistically created, so a denied or undecided request can never leave a
		// live plate the scheduler would put on the permit.
		_ = s.store.DeleteOverride(r.Context(), owner, ovID)
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/guests", http.StatusSeeOther)
			return
		}
		s.serverError(w, err)
		return
	}
	// Best-effort synchronous apply for instant feedback; the scheduler converges
	// otherwise. SetVehicle returns nil only once the council confirms the plate.
	confirmed := false
	prev := permit.ActiveRegistration
	// Detached from the request (see guestActivate): a disconnect mid-apply must
	// not drop the bookkeeping, and the budget stays under the WriteTimeout.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	if err := s.council.SetVehicle(applyCtx, permit.Owner, permit, req.Plate); err == nil {
		_ = s.store.SetPermitActive(bg, permit.ID, req.Plate)
		_ = s.store.RecordApply(bg, permit.ID, req.Plate, "guest", "success", "approved a printed-QR request")
		confirmed = true
		// The approved plate may have bumped a still-live booking's car off the
		// permit; warn that driver if they're reachable. The approving member saw
		// the change happen, but the OTHER members didn't — fan the confirmation
		// out like every other plate change (the guest-link path does the same).
		d := s.displacedDriver(bg, permit, prev, req.Plate, user)
		outcome := notify.ApplyOutcome{
			Owner: permit.Owner, PermitLabel: permitLabel(permit), Reg: req.Plate, By: user, Source: "doorqr", OK: true,
			DisplacedReg: d.Reg, DisplacedTold: d.Contact != "",
		}
		if err := s.notify.EnqueueApply(bg, outcome); err != nil {
			log.Printf("doorqr apply notify enqueue for %s: %v", permit.Owner, err)
		}
	}
	cancel()
	s.sched.Kick()

	s.logChange(bg, owner, user, store.ActionRequestOK, req.Plate, "")
	q := url.Values{}
	if confirmed {
		q.Set("applied", req.Plate)
	} else {
		q.Set("approving", req.Plate)
	}
	http.Redirect(w, r, "/guests?"+q.Encode(), http.StatusSeeOther)
}
