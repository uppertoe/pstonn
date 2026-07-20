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
	Token          string        // raw token, echoed into the POST form
	OwnerEmail     string        // account holder, shown for trust
	PermitLabel    string        // which permit this affects
	CurrentReg     string        // what is on the permit right now ("" if unknown)
	Cars           []vehicleView // the cars this link may activate
	AllowOvernight bool          // whether the overnight checkbox is offered
	AllowPlate     bool          // whether the visitor may type an arbitrary plate
	RequestOnly    bool          // printed QR: entering a plate only requests approval
}

// guestWaitView drives the visitor's "waiting for approval" page (State
// "guest-wait"), which polls the status endpoint.
type guestWaitView struct {
	OwnerEmail string
	Plate      string
	ReqID      int64
	Nonce      string
	Status     string // "pending" | "approved" | "denied"
	Until      string // set when approved
}

// guestReqView is one pending request in the holder's approvals queue.
type guestReqView struct {
	ID          int64
	Plate       string
	PermitLabel string
	Ago         string // "2 min ago"
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
		s.renderGuestGone(w)
		return
	}
	// A printed door QR is meant to be left out in public, so the page must not
	// disclose the holder's email or the plate currently on the permit to anyone
	// who scans it. For emailed links / on-screen QR (a known or present visitor)
	// the current plate and "managed by" address are useful trust signals.
	var ownerEmail, current string
	if !gc.Grant.RequestOnly {
		ownerEmail = permit.Owner
		current = permit.ActiveRegistration // best-effort; never fail the page on a council hiccup
		if actual, err := s.council.CurrentVehicleCached(r.Context(), permit.Owner,
			model.Permit{CouncilPermitID: permit.CouncilPermitID, PermitTypeID: permit.PermitTypeID}, 5*time.Minute); err == nil {
			current = actual
		}
	}
	cars, _, _, _ := vehicleViews(gc.Vehicles)
	s.render(w, dashboardData{
		State: "guest", Loc: s.cfg.DisplayLocation,
		Guest: guestActView{
			Token: gc.rawToken, OwnerEmail: ownerEmail, PermitLabel: permitLabel(permit),
			CurrentReg: current, Cars: cars, AllowOvernight: gc.Grant.AllowOvernight,
			AllowPlate: gc.Grant.AllowPlate, RequestOnly: gc.Grant.RequestOnly,
		},
	})
}

// guestActivate performs an activation: it creates a fresh override for the chosen
// car (end of today, or tomorrow if overnight) and applies it to the council for
// instant feedback, leaving the scheduler to guarantee eventual consistency.
func (s *Server) guestActivate(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		s.renderGuestResult(w, "", false, "This request could not be verified. Please reopen your link and try again.")
		return
	}
	if !s.guest.allow(clientIP(r)) {
		s.renderGuestResult(w, "", false, "Too many attempts. Please wait a little while and try again.")
		return
	}
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w)
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

	// The target is either an arbitrary plate (when the grant allows it, e.g. a
	// visitor QR) or one of the grant's saved cars. Each becomes a fresh override,
	// created now, so it wins the resolution tie-break for its window.
	var reg, name, createdBy string
	if plate := normalizeReg(r.FormValue("plate")); plate != "" && gc.Grant.AllowPlate {
		if !validRego(plate) {
			s.renderGuestResult(w, permit.Owner, false, "Enter a valid number plate (letters and numbers, e.g. ABC123).")
			return
		}
		reg = plate
		createdBy = gc.Recipient
		if createdBy == "" {
			createdBy = "visitor (QR)"
		}
		if _, err := s.store.CreatePlateOverride(r.Context(), permit.ID, plate, now, &end, createdBy); err != nil {
			s.renderGuestResult(w, permit.Owner, false, "Something went wrong saving your plate. Please try again.")
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
			s.renderGuestResult(w, permit.Owner, false, "Please choose one of the cars on your link.")
			return
		}
		reg, name, createdBy = chosen.Registration, chosen.Label, gc.Recipient
		if _, err := s.store.CreateOverride(r.Context(), permit.ID, chosen.ID, now, &end, gc.Recipient); err != nil {
			s.renderGuestResult(w, permit.Owner, false, "Something went wrong saving your choice. Please try again.")
			return
		}
	}
	_ = s.store.TouchGuestTokenUsed(r.Context(), gc.TokenID)

	until := untilPhrase(now, overnight)
	// Best-effort synchronous apply so the visitor gets a real result; the
	// scheduler (kicked below) owns retries and eventual consistency regardless.
	applyCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	err := s.council.SetVehicle(applyCtx, permit.Owner, permit, reg)
	s.sched.Kick()
	if err == nil {
		_ = s.store.SetPermitActive(r.Context(), permit.ID, reg)
		_ = s.store.RecordApply(r.Context(), permit.ID, reg, "guest", "success", "activated by "+createdBy)
		s.notifyGuestApply(permit, reg, name, createdBy)
		s.renderGuestResult(w, permit.Owner, true, reg+" is now on the permit until "+until+".")
		return
	}
	_ = s.store.RecordApply(r.Context(), permit.ID, reg, "guest", "error", err.Error())
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The override is saved; the scheduler will apply it shortly.
		s.renderGuestResult(w, permit.Owner, true, "Saved "+reg+". It should be on the permit within a minute (until "+until+").")
		return
	}
	s.renderGuestResult(w, permit.Owner, false, "Couldn't update the permit right now. The account holder may need to reconnect their council login. Please try again shortly.")
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

func (s *Server) notifyGuestApply(permit model.Permit, reg, name, by string) {
	outcome := notify.ApplyOutcome{
		Owner: permit.Owner, PermitLabel: permitLabel(permit), Reg: reg, Name: name, By: by, Source: "guest", OK: true,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = s.notify.NotifyApply(ctx, outcome)
	}()
}

func (s *Server) renderGuestGone(w http.ResponseWriter) {
	noStore(w)
	w.WriteHeader(http.StatusNotFound)
	s.render(w, dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation,
		Warn: "This link is no longer active. Ask the account holder for a new one."})
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
	for _, d := range details {
		cars, _, _, _ := vehicleViews(d.Vehicles)
		var recips []guestRecipientView
		for _, t := range d.Tokens {
			recips = append(recips, guestRecipientView{TokenID: t.ID, Email: t.RecipientEmail, Revoked: t.Revoked})
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
	_, owner, _ := s.resolveAccount(r.Context())
	if err := r.ParseForm(); err != nil {
		s.message(w, http.StatusBadRequest, "Could not read the form. Please try again.")
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
	recipients := parseEmails(r.FormValue("recipients"))
	if len(vehicleIDs) == 0 {
		s.message(w, http.StatusBadRequest, "Choose at least one car this link may activate.")
		return
	}
	if len(recipients) == 0 {
		s.message(w, http.StatusBadRequest, "Add at least one recipient email.")
		return
	}

	recs, links := s.mintLinks(recipients)
	if _, err := s.store.CreateGuestGrant(r.Context(), owner, permitID, label, allowOvernight, vehicleIDs, recs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit or car isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	sent := s.emailLinks(owner, permitLabel(permit), links)

	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.NewGuestLinks = links
	if sent > 0 {
		base.Flash = "Guest pass created and links emailed."
	} else {
		base.Flash = "Guest pass created. Copy the links below to share them."
	}
	s.render(w, base)
}

// updateGuestGrant edits a grant's label, cars, and overnight option, and adds
// any new recipients (each getting a fresh emailed link). The permit is fixed.
func (s *Server) updateGuestGrant(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	id := pathInt(r, "id")
	if err := r.ParseForm(); err != nil {
		s.message(w, http.StatusBadRequest, "Could not read the form. Please try again.")
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
		s.message(w, http.StatusBadRequest, "Choose at least one car this pass may activate.")
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
	if emails := parseEmails(r.FormValue("recipients")); len(emails) > 0 {
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
		sent := s.emailLinks(owner, plabel, newLinks)
		base.NewGuestLinks = newLinks
		if sent > 0 {
			base.Flash = "Guest pass updated and new links emailed."
		} else {
			base.Flash = "Guest pass updated. Copy the new links below to share them."
		}
	} else {
		base.Flash = "Guest pass updated."
	}
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
// many were accepted.
func (s *Server) emailLinks(owner, permitLabel string, links []guestLinkView) int {
	sent := 0
	for _, l := range links {
		if err := s.notify.SendGuestLink(l.Email, owner, permitLabel, l.URL); err == nil {
			sent++
		}
	}
	return sent
}

// showVisitorQR mints a short-lived, plate-entry grant for a permit and renders a
// QR the resident shows on-screen. A visitor scans it, types their plate, and it
// goes on the permit until the end of the day. The grant self-expires (qrTTL).
func (s *Server) showVisitorQR(w http.ResponseWriter, r *http.Request) {
	noStore(w) // the page embeds a live activation token; keep it out of caches
	_, owner, _ := s.resolveAccount(r.Context())
	permitID := atoi64(r.FormValue("permit_id"))
	raw, hash := newGuestToken()
	if _, err := s.store.CreateQRGrant(r.Context(), owner, permitID, hash, qrTTL); err != nil {
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
	_, owner, _ := s.resolveAccount(r.Context())
	if err := s.store.DeleteGuestGrant(r.Context(), owner, pathInt(r, "id")); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) revokeGuestToken(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	if err := s.store.RevokeGuestToken(r.Context(), owner, pathInt(r, "tid")); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) toggleGuests(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	enabled := r.FormValue("enabled") != ""
	if err := s.store.SetGuestsEnabled(r.Context(), owner, enabled); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) setVehicleEmail(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email != "" && !looksLikeEmail(email) {
		s.message(w, http.StatusBadRequest, "Enter a valid email address, or leave it blank.")
		return
	}
	if err := s.store.SetVehicleEmail(r.Context(), owner, pathInt(r, "id"), email); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/vehicles", http.StatusSeeOther)
}

// parseEmails splits a free-text recipient list (comma/space/semicolon/newline
// separated), lower-cases, validates, and de-duplicates. Invalid tokens are
// dropped silently so one typo doesn't discard the rest.
func parseEmails(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	seen := map[string]bool{}
	var out []string
	for _, f := range fields {
		e := strings.ToLower(strings.TrimSpace(f))
		if e == "" || seen[e] || !looksLikeEmail(e) {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out
}

// ================= PRINTED QR: REQUEST + APPROVE =================

func randNonce() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		panic("guest request nonce: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
	nonce := randNonce()
	reqID, err := s.store.CreateGuestRequest(r.Context(), gc.Grant.ID, permit.ID, permit.Owner, plate, nonce)
	if err != nil {
		s.renderGuestResult(w, "", false, "Something went wrong sending your request. Please try again.")
		return
	}
	s.notifyGuestRequest(r.Context(), permit, plate)
	s.render(w, dashboardData{State: "guest-wait", Loc: s.cfg.DisplayLocation,
		Wait: &guestWaitView{Plate: plate, ReqID: reqID, Nonce: nonce, Status: "pending"}})
}

// guestRequestStatus is the visitor's poll endpoint: public and nonce-gated so a
// request id can't be enumerated. While pending it re-renders a polling fragment;
// once decided it renders a static result.
func (s *Server) guestRequestStatus(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	nonce := r.URL.Query().Get("n")
	req, err := s.store.GuestRequestForPoll(r.Context(), pathInt(r, "id"), nonce)
	v := guestWaitView{Status: "denied"} // unknown/expired reads as not-approved
	if err == nil {
		v = guestWaitView{Plate: req.Plate, ReqID: req.ID, Nonce: nonce, Status: req.Status, Until: req.Until}
	}
	if e := templates.ExecuteTemplate(w, "guest-req-status", v); e != nil {
		log.Printf("render guest-req-status: %v", e)
	}
}

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
func (s *Server) mintPrintedGrant(ctx context.Context, owner string, permitID int64) (int64, error) {
	raw, hash := newGuestToken()
	sealed, err := s.box.Seal(raw)
	if err != nil {
		return 0, err
	}
	return s.store.CreatePrintedGrant(ctx, owner, permitID, hash, sealed)
}

// showPrintedQR handles "Print a door QR" for a permit. It is idempotent: if the
// permit already has a door QR it reopens that (same code) rather than rotating the
// token, so a copy already on the fridge keeps working.
func (s *Server) showPrintedQR(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	permitID := atoi64(r.FormValue("permit_id"))
	if g, err := s.store.PrintedGrantForPermit(r.Context(), owner, permitID); err == nil {
		http.Redirect(w, r, fmt.Sprintf("/guests/door/%d/view", g.GrantID), http.StatusSeeOther)
		return
	}
	grantID, err := s.mintPrintedGrant(r.Context(), owner, permitID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
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
		s.message(w, http.StatusConflict, "This code can't be shown again on this server. Use Replace to print a new one.")
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
	_, owner, _ := s.resolveAccount(r.Context())
	if err := s.store.RevokePrintedGrant(r.Context(), owner, atoi64(r.PathValue("id"))); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
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
	_, owner, _ := s.resolveAccount(r.Context())
	now := time.Now().In(s.cfg.DisplayLocation)
	until := untilPhrase(now, false)
	req, err := s.store.DecideGuestRequest(r.Context(), owner, pathInt(r, "id"), approve, until)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/guests", http.StatusSeeOther)
			return
		}
		s.serverError(w, err)
		return
	}
	if approve {
		if permit, perr := s.store.GetPermit(r.Context(), req.PermitID); perr == nil && permit.Owner == owner {
			end := dayEndLocal(now, 0)
			if _, cerr := s.store.CreatePlateOverride(r.Context(), permit.ID, req.Plate, now, &end, "visitor (printed QR)"); cerr == nil {
				applyCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				if err := s.council.SetVehicle(applyCtx, permit.Owner, permit, req.Plate); err == nil {
					_ = s.store.SetPermitActive(r.Context(), permit.ID, req.Plate)
					_ = s.store.RecordApply(r.Context(), permit.ID, req.Plate, "guest", "success", "approved a printed-QR request")
				}
				cancel()
				s.sched.Kick()
			}
		}
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}
