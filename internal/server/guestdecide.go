package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// The decide link is the no-sign-in front door for answering a printed-QR
// request, reached from the notification email. The trust argument mirrors the
// unsubscribe link: sign-in IS an emailed code, so the inbox already holds the
// keys to the whole account — a signed link in that same inbox that can answer
// one request grants strictly less. The token binds request id + recipient
// (see internal/notify/decide.go); single-use comes from the request row,
// since a decision only ever lands on a row still 'pending'.
//
// GET renders the request with Approve/Decline buttons; POST acts. The split
// is load-bearing exactly as it is for unsubscribe and renewal-confirm: mail
// scanners and link-prefetchers follow GETs, and a prefetch must never put a
// plate on the permit.

// decideNeutral is the answer for any link that does not verify or resolve.
// Deliberately vague and 200: this page is reachable by anyone holding a URL,
// and distinguishing "bad signature" from "unknown request" from "not a member
// any more" would leak which requests and addresses exist.
const decideNeutral = "This link isn't valid or has expired. Open p.stonn and check Guest passes for anything still waiting on you."

// guestDecidePage shows the request and its Approve/Decline buttons — or, once
// it has been answered (by anyone, through any door), what happened to it.
func (s *Server) guestDecidePage(w http.ResponseWriter, r *http.Request) {
	if s.decideThrottled(w, r) {
		return
	}
	req, addr, ok := s.resolveDecideRequest(r)
	if !ok {
		s.message(w, http.StatusOK, decideNeutral)
		return
	}
	noStore(w)
	s.render(w, dashboardData{
		State: "guestdecide", Loc: s.cfg.DisplayLocation, Contact: s.cfg.ContactEnabled(),
		Decide: s.decideViewFor(r.Context(), req, addr, r.URL.Path, ""),
	})
}

// guestDecideApply performs the decision named in the form and renders the
// outcome. A race with another member (or expiry) lands on the same page the
// GET shows for a settled request, which is the truthful answer to "what
// happened?" — never an error.
func (s *Server) guestDecideApply(w http.ResponseWriter, r *http.Request) {
	if s.decideThrottled(w, r) {
		return
	}
	req, addr, ok := s.resolveDecideRequest(r)
	if !ok {
		s.message(w, http.StatusOK, decideNeutral)
		return
	}
	var approve bool
	switch r.FormValue("decision") {
	case "approve":
		approve = true
	case "decline":
	default:
		s.message(w, http.StatusBadRequest, "Missing decision.")
		return
	}
	// A member deciding via the emailed one-tap link is household activity every
	// bit as much as a signed-in visit — but this route carries no session, so
	// the middleware's touch never sees it. Reset the idle clock here.
	s.touchGuestActivity(r.Context(), req.Owner)
	out := s.runDecideRequest(r, req.Owner, addr, req.ID, approve)
	switch out.kind {
	case decideErr:
		s.serverError(w, out.err)
		return
	case decideCapFull:
		s.message(w, http.StatusConflict, decideCapFullMessage)
		return
	case decidePermitInactive:
		s.message(w, http.StatusConflict, decidePermitInactiveMessage)
		return
	case decideAlreadyDecided, decideGone:
		// Someone else got there first (or it expired mid-tap). Show the settled
		// state rather than an error: re-render exactly what the GET would.
		http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
		return
	}
	outcome := ""
	switch out.kind {
	case decideDeclined:
		outcome = "declined"
	case decideRevoked:
		outcome = "revoked"
	case decideApplied:
		outcome = "applied"
	case decideApproving:
		outcome = "approving"
	}
	// Re-read the row so the page reflects the decision it just made (until
	// phrase, decided-by) without trusting anything from the form.
	fresh, err := s.store.GuestRequestByID(r.Context(), req.ID)
	if err != nil {
		fresh = req
	}
	noStore(w)
	s.render(w, dashboardData{
		State: "guestdecide", Loc: s.cfg.DisplayLocation, Contact: s.cfg.ContactEnabled(),
		Decide: s.decideViewFor(r.Context(), fresh, addr, r.URL.Path, outcome),
	})
}

// resolveDecideRequest validates the signed link and confirms the recipient is
// still part of the household the request belongs to. Everything failing here
// collapses into one neutral answer at the caller.
func (s *Server) resolveDecideRequest(r *http.Request) (store.GuestRequest, string, bool) {
	addr, ok := notify.DecodeUnsubAddress(r.PathValue("addr"))
	if !ok {
		return store.GuestRequest{}, "", false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return store.GuestRequest{}, "", false
	}
	if !notify.VerifyDecideToken(s.decideKey, id, addr, r.PathValue("token")) {
		return store.GuestRequest{}, "", false
	}
	req, err := s.store.GuestRequestByID(r.Context(), id)
	if err != nil {
		return store.GuestRequest{}, "", false // purged (or never existed)
	}
	// The recipient must STILL be the owner or a member of the owning account:
	// a link minted for someone who has since left the household must die with
	// their access, token expiry notwithstanding.
	if addr != req.Owner {
		if owner, ok, err := s.store.MemberAccount(r.Context(), addr); err != nil || !ok || owner != req.Owner {
			return store.GuestRequest{}, "", false
		}
	}
	return req, addr, true
}

// decideViewFor assembles the page model for a request as it stands now.
// outcome is "" on a plain view, or what the POST just did.
func (s *Server) decideViewFor(ctx context.Context, req store.GuestRequest, addr, path, outcome string) *decideView {
	v := &decideView{
		Plate:     req.Plate,
		Requested: req.RequestedAt.In(s.cfg.DisplayLocation).Format("Mon 2 Jan, 3:04pm"),
		Path:      path,
		Status:    req.Status,
		DecidedBy: req.DecidedBy,
		Until:     req.Until,
		Viewer:    addr,
		Outcome:   outcome,
	}
	if permit, err := s.store.GetPermit(ctx, req.PermitID); err == nil {
		v.PermitLabel = permitLabel(permit)
	}
	return v
}

// decideThrottled sheds a request over the per-IP limit. Like unsubscribe,
// this route sits outside the session/CSRF gate (the token is the auth), so a
// throttle is the only thing pacing someone walking ids or replaying a link
// from a forwarded email. A real person taps once or twice.
func (s *Server) decideThrottled(w http.ResponseWriter, r *http.Request) bool {
	if s.decideLimit.allow(rateLimitKey(r)) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	s.message(w, http.StatusTooManyRequests, "Too many requests. Please wait a moment and try again.")
	return true
}
