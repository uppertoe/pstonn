package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// The account holder's guest-pass management (login required): the guests page,
// creating/editing/deleting passes, links, the on-screen visitor QR, and the
// kill-switch. Split out of guest.go by its banner sections.

// ================= ACCOUNT-HOLDER MANAGEMENT (login required) =================

// guestsPage lists the owner's guest passes and the create form.
func (s *Server) guestsPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	// Success feedback after deciding a printed-QR request. These values land in the
	// green success banner — the most trusted element on a page whose whole premise is
	// custody of a tenant password — and although our own redirects write them, nothing
	// stops someone handing a signed-in user a crafted /guests?resent=… link. So each is
	// VALIDATED on the read path (not just the write path, which the old comment here
	// described): a plate must parse as a rego, a recipient as an email, or it is dropped.
	// This mirrors settings.go, which was hardened for exactly this (H3); /guests was the
	// untouched half.
	switch q := r.URL.Query(); {
	case validRego(normalizeReg(q.Get("applied"))):
		base.Flash = normalizeReg(q.Get("applied")) + " is now on the permit."
	case validRego(normalizeReg(q.Get("approving"))):
		base.Flash = "Approved — " + normalizeReg(q.Get("approving")) + " is being put on the permit."
	case q.Get("declined") != "":
		base.Flash = "Request declined."
	// The two refusals decideRequest lands here with. They arrive as bare flags
	// (nothing to validate) and used to be dropped on the floor, so a member who
	// pressed Approve was shown the guests page with no word on what happened.
	case q.Get("alreadydecided") != "":
		base.Flash = "That request has already been answered, or it expired before anyone answered it."
	case q.Get("revoked") != "":
		base.Warn = "That request couldn't be put on the permit: its printed QR code may have been removed, or guest passes paused."
	case looksLikeEmail(q.Get("resent")):
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
	// Gated before the page shell: the form this renders posts to
	// updateGuestGrant, which refuses a dead permit — say so up front instead of
	// letting the edit be filled in for nothing.
	_, owner, _ := s.resolveAccount(r.Context())
	if s.refuseDeadGrantPermit(w, r, owner, pathInt(r, "id"), permitInactivePassFrozen) {
		return
	}
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
	base.GuestMgmt = &guestMgmt{}
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return err
	}
	labelByPermit := map[int64]string{}
	deadPermit := map[int64]bool{}
	now := time.Now()
	for _, p := range permits {
		if p.Inactive(now, s.locFor(ctx, base.Owner)) {
			// Existing passes and request history still name the permit, but say
			// plainly that it's finished — and never offer it for NEW links. The
			// pass card itself carries a pill and the way out (see PermitDead): a
			// suffix on a bare permit number was not read as "your guests' links
			// are dead" by the one household this happened to (2026-08-22).
			labelByPermit[p.ID] = permitLabel(p) + " — no longer active"
			deadPermit[p.ID] = true
			continue
		}
		labelByPermit[p.ID] = permitLabel(p)
		base.GuestMgmt.PermitOpts = append(base.GuestMgmt.PermitOpts, permitOpt{ID: p.ID, Label: permitLabel(p)})
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
		alog.Infof("guests: suppression lookup for %s: %v", redact.Email(owner), err)
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
		base.GuestMgmt.Guests = append(base.GuestMgmt.Guests, guestGrantView{
			ID: d.Grant.ID, Label: d.Grant.Label, PermitLabel: labelByPermit[d.Grant.PermitID],
			PermitDead:     deadPermit[d.Grant.PermitID],
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
			base.GuestMgmt.PendingRequests = append(base.GuestMgmt.PendingRequests, guestReqView{
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
			base.GuestMgmt.RecentRequests = append(base.GuestMgmt.RecentRequests, v)
		}
	}
	if doors, derr := s.store.ListPrintedGrants(ctx, owner); derr == nil {
		for _, d := range doors {
			base.GuestMgmt.DoorGrants = append(base.GuestMgmt.DoorGrants, doorGrantView{
				GrantID: d.GrantID, PermitLabel: d.PermitLabel,
				CreatedAt: d.CreatedAt.In(s.locFor(ctx, base.Owner)).Format("2 Jan 2006"),
			})
		}
	}
	base.GuestMgmt.GuestsEnabled, err = s.store.GuestsEnabled(ctx, owner)
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
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	default:
		// The stale-plate caption can be days old (a cached reading has no upper
		// age bound during a tenant outage); "78 hr ago" hides that.
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// createGuestGrant creates a grant + a per-recipient token, emails each link, and
// re-renders the page showing the links once (the only time we hold the raw token).
func (s *Server) createGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	permitID := atoi64(r.FormValue("permit_id"))
	label := guestGrantLabel(r.FormValue("label"))
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
	if len(recipients) > maxGuestRecipients {
		s.formError(w, r, tooManyRecipients)
		return
	}

	// Refuse a dead target before minting anything, and FAIL CLOSED on a store
	// error — a gate that shrugs on error would mint and email a link for a
	// permit it couldn't check. Unknown permits fall through: CreateGuestGrant's
	// atomic ownership check answers those with a clean 403.
	switch permit, perr := s.store.GetPermit(r.Context(), permitID); {
	case errors.Is(perr, store.ErrNotFound):
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Owner == owner && permit.Inactive(time.Now(), s.locFor(r.Context(), owner)):
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
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
	sent := s.emailLinks(r.Context(), owner, permit.TenantID, permitLabel(permit), links)

	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.GuestMgmt.NewGuestLinks = links
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

// tokenShape matches the SHAPE of a token this app mints: base64url, and long
// enough to be one. The bound is loose on purpose — this is not an existence check
// (see guestManifest) and a token that is merely an unfamiliar length must still
// be allowed to work.
var tokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// guestManifest serves a per-recipient web app manifest, so a guest can install
// their link to the home screen (Android/Chrome "Install") and have the icon open
// straight to THEIR menu (start_url is their own link). Public and token-scoped;
// icons are the app's static PNGs. Existence is deliberately not checked: a
// manifest for a dead link is harmless (the page it points to just shows "no
// longer active"), and checking would put a DB query on an anonymous route.
func (s *Server) guestManifest(w http.ResponseWriter, r *http.Request) {
	// The shape gate keeps anything that isn't a token out of the document, and
	// json.Marshal — not %q, which is Go quoting and emits \x01 for a decoded
	// control byte — makes what does get in valid JSON. With %q a single such byte
	// broke the whole manifest, so "Install" silently stopped working.
	token := r.PathValue("token")
	if !tokenShape.MatchString(token) {
		http.NotFound(w, r)
		return
	}
	start, err := json.Marshal("/g/" + token)
	if err != nil {
		s.serverError(w, err)
		return
	}
	startURL := string(start)
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `{
  "id": `+startURL+`,
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
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	recipient := strings.TrimSpace(r.FormValue("recipient"))
	if recipient == "" {
		s.formError(w, r, "No recipient to re-send to.")
		return
	}
	// Don't rotate the token when the permit is dead: the guest's link 410ing is
	// the very symptom that prompts a re-send, and rotating would trade their
	// token — which comes back to life after a renewal copy — for a fresh one
	// that is just as dead.
	if s.refuseDeadGrantPermit(w, r, owner, pathInt(r, "id"), permitInactivePassFrozen) {
		return
	}
	// Nor when we can't deliver the replacement — that would break the
	// recipient's current link with nothing to replace it.
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
	// Logged because this ROTATES the token: the recipient's old link is now dead.
	// A member silently re-keying someone else's access is exactly the kind of
	// change the household should be able to see after the fact.
	s.logChange(r.Context(), owner, user, store.ActionGuestResend, recipient, "")
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	links := []guestLinkView{{Email: recipient, URL: s.guestLink(raw)}}
	if s.emailLinks(r.Context(), owner, permit.TenantID, permitLabel(permit), links) == 0 {
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
		base.GuestMgmt.NewGuestLinks = links
		base.Flash = "The email could not be sent. Copy the fresh link below and share it yourself — the old link no longer works."
		s.render(w, base)
		return
	}
	http.Redirect(w, r, "/guests?resent="+url.QueryEscape(recipient), http.StatusSeeOther)
}

// updateGuestGrant edits a grant's label, cars, and overnight option, and adds
// any new recipients (each getting a fresh emailed link). The permit is fixed.
func (s *Server) updateGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	id := pathInt(r, "id")
	// An edit can add recipients — minting by another door — so it shares the
	// dead-permit refusal with the create surfaces.
	if s.refuseDeadGrantPermit(w, r, owner, id, permitInactivePassFrozen) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	label := guestGrantLabel(r.FormValue("label"))
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
	// Parse and validate the recipients BEFORE mutating anything: returning an error
	// after the label/cars were already committed left the pass changed while telling
	// the user it failed.
	emails, droppedEmails := parseEmails(r.FormValue("recipients"))
	if len(emails) > maxGuestRecipients {
		s.formError(w, r, tooManyRecipients)
		return
	}
	swept, err := s.store.UpdateGuestGrant(r.Context(), owner, id, label, allowOvernight, vehicleIDs)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That pass or car isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	if swept > 0 {
		// A car was unticked mid-booking: its live overrides were just removed, so ask
		// reconcile to take it off the permit now rather than at the next tick.
		s.kickScheduler()
	}

	// New recipients (if any) each get a fresh token + link.
	var newLinks []guestLinkView
	if len(emails) > 0 {
		recs, links := s.mintLinks(emails)
		// NOTE: the grant update above has already committed. These errors must not claim
		// the whole edit failed.
		added, err := s.store.AddGuestTokens(r.Context(), owner, id, recs)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			// A 500 here would tell the user the whole edit failed when the label/cars
			// are already committed. Send them back to the pass, which shows its real
			// current state and lets them add the recipients again.
			alog.Errorf("guest: pass %d updated but adding recipients failed: %v", id, err)
			http.Redirect(w, r, "/guests", http.StatusSeeOther)
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
		// By here the grant is updated AND any new tokens are live. A 500 would strand
		// them: this render is the only place the links are shown, and emailLinks below
		// never runs. Redirect instead — the pass and its recipients are listed on the
		// guests page, so the household can re-send a link rather than being left with
		// live tokens they never saw.
		alog.Errorf("guest: pass %d updated but the guests page could not be rendered: %v", id, err)
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	if len(newLinks) > 0 {
		plabel := ""
		for _, g := range base.GuestMgmt.Guests {
			if g.ID == id {
				plabel = g.PermitLabel
			}
		}
		// The mail names the permit's own council; the grant knows its permit.
		tenantID := ""
		if pid, err := s.store.GuestGrantPermit(r.Context(), owner, id); err == nil {
			if p, err := s.store.GetPermit(r.Context(), pid); err == nil {
				tenantID = p.TenantID
			}
		}
		sent := s.emailLinks(r.Context(), owner, tenantID, plabel, newLinks)
		base.GuestMgmt.NewGuestLinks = newLinks
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

// maxGuestRecipients bounds one submission's recipient list. Every address on it
// becomes a LIVE token over the household's permit and an outbound email, and the
// list is free text inside a 64 KB body — which is room for roughly four thousand
// of them, each costing token rows, a mail attempt and a management row on the
// guests page. Far above any real household's list; far below anything that turns
// one form post into a bulk mailer.
const maxGuestRecipients = 20

const tooManyRecipients = "That's too many recipients for one pass. Add up to 20 at a time."

// maxGuestGrantLabel matches the permit-label cap, for the same reasons: the label
// headlines the guest's page and rides into the email that carries their link, so
// an unbounded one inflates every stored notification along the way.
const maxGuestGrantLabel = 40

// guestGrantLabel cleans and caps a pass name the same way a permit's is (control
// characters stripped, trimmed, truncated by runes so a multi-byte name can't be
// cut in half).
func guestGrantLabel(s string) string {
	label := cleanLabel(s)
	if rs := []rune(label); len(rs) > maxGuestGrantLabel {
		label = string(rs[:maxGuestGrantLabel])
	}
	return label
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
func (s *Server) emailLinks(ctx context.Context, owner, tenantID, permitLabel string, links []guestLinkView) int {
	sent := 0
	for _, l := range links {
		if !s.guestLinkOut.allow("o:"+owner) || !s.guestLinkTo.allow("t:"+l.Email) {
			alog.Infof("guest link email to %s for %s throttled", notify.RedactEmail(l.Email), notify.RedactEmail(owner))
			continue
		}
		if err := s.notify.SendGuestLink(ctx, l.Email, owner, tenantID, permitLabel, l.URL); err == nil {
			sent++
		} else {
			alog.Infof("guest link email to %s for %s: %v", notify.RedactEmail(l.Email), notify.RedactEmail(owner), err)
		}
	}
	return sent
}

// visitorQR returns the permit's on-screen visitor QR, reusing the current one if
// it is still working and minting a fresh one otherwise.
//
// Reuse is what lets this be a one-tap action from the schedule page. A resident
// whose visitor mis-scans will simply tap again; minting each time would leave
// several working codes for one doorstep, invalidate nothing, and make the stated
// stop-working time true of only the newest. It also means re-opening the modal
// cannot race a scan already in progress.
func (s *Server) visitorQR(ctx context.Context, owner, user string, permit model.Permit) (*qrShowView, error) {
	raw, expires, err := s.reuseVisitorQR(ctx, owner, permit.ID)
	switch {
	case err == nil: // still live: same code, its own original deadline
	case errors.Is(err, store.ErrNotFound):
		raw, expires, err = s.mintVisitorQR(ctx, owner, user, permit)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	img, err := qrDataURI(s.guestLink(raw))
	if err != nil {
		return nil, err
	}
	return &qrShowView{
		PermitLabel: permitLabel(permit),
		ImageURI:    template.URL(img),
		URL:         s.guestLink(raw),
		StopsAt:     expires.In(s.locFor(ctx, owner)).Format("3:04pm"),
	}, nil
}

// reuseVisitorQR opens the sealed token of a still-working QR for this permit.
// A token we cannot unseal is treated as absent, so a key problem yields a fresh
// code rather than a dead end at the door.
func (s *Server) reuseVisitorQR(ctx context.Context, owner string, permitID int64) (string, time.Time, error) {
	sealed, expires, err := s.store.LiveQRGrant(ctx, owner, permitID, time.Now())
	if err != nil {
		return "", time.Time{}, err
	}
	raw, _, err := s.box.OpenCtx(secretbox.GuestToken(owner), sealed)
	if err != nil {
		alog.Warnf("visitor QR: could not open a live token for permit %d (%v); minting a fresh one", permitID, err)
		return "", time.Time{}, store.ErrNotFound
	}
	return raw, expires, nil
}

// mintVisitorQR creates a new short-lived plate-entry grant and logs it.
func (s *Server) mintVisitorQR(ctx context.Context, owner, user string, permit model.Permit) (string, time.Time, error) {
	raw, hash := newGuestToken()
	sealed, err := s.box.SealCtx(secretbox.GuestToken(owner), raw)
	if err != nil {
		return "", time.Time{}, err
	}
	if _, err := s.store.CreateQRGrant(ctx, owner, user, permit.ID, hash, sealed, qrTTL); err != nil {
		return "", time.Time{}, err
	}
	// This mints a live, if short-lived, capability: whoever scans the screen can
	// put a plate on the permit without further approval. Every other way of
	// handing out permit access is logged, so this one is too. Only a genuinely NEW
	// code is logged — re-opening the same one is not a new grant of access.
	s.logChange(ctx, owner, user, store.ActionDoorQRShow, permitLabel(permit), "")
	return raw, time.Now().Add(qrTTL), nil
}

// showVisitorQR renders the on-screen visitor QR for a permit. A visitor scans it,
// types their plate, and it goes on the permit until the end of the day.
//
// Serves a bare card to htmx (the schedule page's modal) and a full page otherwise,
// so the same action works from the permit card and from the guests page.
func (s *Server) showVisitorQR(w http.ResponseWriter, r *http.Request) {
	// The response embeds a live activation token, so it must stay out of caches —
	// but this is a signed-in app page, so it takes the app helper, not the guest
	// routes' noStore: that one also sets Referrer-Policy: no-referrer, which strips
	// the same-origin Referer the CSRF check falls back on (see noStoreCache).
	noStoreCache(w)
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	permit, err := s.store.GetPermit(r.Context(), atoi64(r.FormValue("permit_id")))
	if err != nil || permit.Owner != owner {
		s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
		return
	}
	if permit.Inactive(time.Now(), s.locForPermit(r.Context(), permit)) {
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
		return
	}
	qr, err := s.visitorQR(r.Context(), owner, user, permit)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	// A boosted link is a navigation and wants the whole page; a plain hx-post from
	// the permit card's button wants just the card to drop into its modal.
	if isHX(r) && !isBoosted(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "qr-card", dashboardData{QR: qr, Loc: s.locForPermit(r.Context(), permit)}); err != nil {
			alog.Infof("render qr-card: %v", err)
		}
		return
	}
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.QR = qr
	s.render(w, base)
}

func (s *Server) deleteGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Name it before deleting, so the log and the notice can say which pass died.
	label := s.grantLabel(r.Context(), owner, pathInt(r, "id"))
	// A missing row is tolerated (a double-submitted form, a stale page) but must
	// not be announced: logging it and emailing the household "a guest pass was
	// deleted, those links have stopped working" for an id that never existed
	// invents an event, and the dedup key only suppresses identical repeats.
	// Take the permit's apply claim BEFORE revoking, so an in-flight guest activation
	// either completes first (and its override is then swept) or cannot start — a
	// revocation must not be overtaken by a tenant write on the authority it removed.
	pid, _ := s.store.GuestGrantPermit(r.Context(), owner, pathInt(r, "id"))
	releaseClaims := s.claimPermitApplies(r.Context(), []int64{pid})
	err := s.store.DeleteGuestGrant(r.Context(), owner, pathInt(r, "id"))
	releaseClaims()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionGuestDelete, label, "")
		s.notifyDestructive(r.Context(), owner, user,
			user+" deleted a guest pass"+optional(label, " (")+closeParen(label)+" on your p.stonn account. Anyone holding those links can no longer use your permit, and p.stonn is taking any car they had put on it back off now — check the permit directly if this is urgent.")
		// The sweep changed what the schedule resolves to, so the permit is now out of
		// date. Without a kick it stays that way until the next pass — and the point of
		// revoking was that the guest's plate comes off NOW.
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) revokeGuestToken(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Name the recipient before their link dies, so the audit row says whose access
	// was taken away rather than merely that some access was.
	recipient, _ := s.store.GuestTokenRecipient(r.Context(), owner, pathInt(r, "tid"))
	// Tolerate a missing row, but don't log an action that didn't happen.
	pid, _ := s.store.GuestTokenPermit(r.Context(), owner, pathInt(r, "tid"))
	releaseClaims := s.claimPermitApplies(r.Context(), []int64{pid}) // see deleteGuestGrant
	err := s.store.RevokeGuestToken(r.Context(), owner, pathInt(r, "tid"))
	releaseClaims()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionGuestRevoke, recipient, "")
		// Told to the household like every other withdrawal of access (deleting a pass,
		// removing a door QR): one member cutting off a person the others invited is
		// exactly the change silence hides.
		s.notifyDestructive(r.Context(), owner, user,
			user+" revoked a guest link"+optional(recipient, " (")+closeParen(recipient)+" on your p.stonn account. That link no longer works, and p.stonn is taking any car it had put on your permit back off now — check the permit directly if this is urgent.")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

// kickScheduler asks the reconcile loop to run now. Tolerates a Server built
// without one (tests construct one directly): a revocation must still take the
// guest's authority away even when nothing is running to re-apply the schedule.
func (s *Server) kickScheduler() {
	if s.sched != nil {
		s.sched.Kick()
	}
}

func (s *Server) toggleGuests(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	enabled := r.FormValue("enabled") != ""
	// Pausing is a revocation across every permit on the account: claim them all (in a
	// stable order) so no guest apply can be in flight as the switch flips.
	var releaseClaims = func() {}
	if !enabled {
		var ids []int64
		if ps, perr := s.store.ListPermitsFor(r.Context(), owner); perr == nil {
			for _, p := range ps {
				ids = append(ids, p.ID)
			}
		}
		releaseClaims = s.claimPermitApplies(r.Context(), ids)
	}
	err := s.store.SetGuestsEnabled(r.Context(), owner, enabled)
	releaseClaims()
	if err != nil {
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
			user+" paused all guest passes on your p.stonn account. Existing guest links and printed QR codes will not work until they are resumed, and p.stonn is taking any car a guest had put on a permit back off now — check the permit directly if this is urgent.")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) setVehicleEmail(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email != "" && !looksLikeEmail(email) {
		s.formError(w, r, "Enter a valid email address, or leave it blank.")
		return
	}
	switch err := s.store.SetVehicleEmail(r.Context(), owner, pathInt(r, "id"), email); {
	case errors.Is(err, store.ErrNotFound):
		// A car that is no longer there (deleted in another tab, a stale page) is
		// tolerated, but NOT logged: the row below says an address was set or
		// removed, and nothing was. The Activity page is the household's account of
		// what happened, so it must not record a change that did not.
	case err != nil:
		s.serverError(w, err)
		return
	default:
		// Worth logging precisely because of what it is: the one action that adds
		// ANOTHER PERSON's email address to the account. It was the only change
		// missing from the Activity page.
		detail := "removed"
		if email != "" {
			detail = "set"
		}
		s.logChange(r.Context(), owner, user, store.ActionVehicleEmail,
			s.plateOf(r.Context(), owner, pathInt(r, "id")), detail)
	}
	if r.Header.Get("HX-Request") != "" {
		w.WriteHeader(http.StatusNoContent) // live save from the Vehicles page; no reload
		return
	}
	http.Redirect(w, r, "/vehicles?saved=1", http.StatusSeeOther)
}

// setVehicleNotify toggles the per-car "email the driver when this car goes on
// the permit" flag. A live htmx save from the checkbox on the Vehicles page: an
// unchecked box sends no field, so absence means off. Replies 204 (nothing to
// swap).
func (s *Server) setVehicleNotify(w http.ResponseWriter, r *http.Request) {
	_, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	on := r.FormValue("notify") != ""
	if err := s.store.SetVehicleNotifyDriver(r.Context(), owner, pathInt(r, "id"), on); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
