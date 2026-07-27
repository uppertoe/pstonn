package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// councilLink onboards the user's council account via a headless login: it takes
// their council credentials and exchanges them for a session cookie. The password
// is discarded unless the user opts in to auto-reconnect, in which case it is
// sealed (DATA_ENCRYPTION_KEY) and stored so the scheduler can silently re-link if
// the council session later expires.
func (s *Server) councilLink(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	// Only the account owner links the council account; a secondary uses the
	// primary's connection and cannot change it.
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can connect the council account.")
		return
	}
	// The council username is FIXED to the owner's verified email (from the
	// forward-auth layer), so a user can only ever link the Stonnington account
	// that matches their own verified email; they supply just the password.
	password := r.FormValue("council_password")
	if password == "" {
		s.formError(w, r, "Enter your council password.")
		return
	}
	// Throttle password attempts per user: every submit forwards the password to
	// the council's own login, and hammering it could trip the council's lockout
	// on the user's real account (the username is pinned to their email, so this
	// is no oracle against anyone else's).
	if !s.councilTry.allow(user) {
		s.message(w, http.StatusTooManyRequests, "Too many attempts in a short time. Please wait 15 minutes and try again.")
		return
	}
	savePassword := r.FormValue("save_password") != ""
	// The headless council login is several round trips; cap it inside the
	// server's 20s WriteTimeout so a slow portal yields the error message below
	// (the user can retry) instead of a dropped connection.
	linkCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.council.Link(linkCtx, user, user, password, savePassword, true); err != nil {
		log.Printf("council link for %s: %v", user, err)
		if errors.Is(err, parking.ErrCouncilBusy) {
			s.message(w, http.StatusBadGateway, "The council portal is not accepting sign-ins right now. Your password was not the problem — please try again in a little while.")
			return
		}
		if errors.Is(err, parking.ErrLoginRejected) {
			// The council tells us only that no session cookie came back, so we
			// genuinely cannot distinguish a wrong password from "no ePermits account
			// exists for this email". Name both, rather than blaming the password —
			// for a curious first-time visitor the second is the likelier cause, and
			// wrongly asserting the first sends them round a 5-attempt lockout.
			s.message(w, http.StatusBadGateway,
				"The council portal wouldn't accept that sign-in. Either the password is wrong, or there is no City of Stonnington ePermits account for "+user+
					". p.stonn can only manage a permit you already hold: check you can sign in at the council's own ePermits site with this email address first. If your ePermits account uses a different email, sign out and sign back in to p.stonn with that address instead.")
			return
		}
		s.message(w, http.StatusBadGateway, "Couldn't link your council account. This looks like a problem at our end or on the council's site rather than your password — please try again shortly.")
		return
	}
	// ?linked=1 turns into the "Council account linked." flash — after a first
	// link the user lands on the permit picker, so this is the only confirmation
	// the sign-in worked.
	http.Redirect(w, r, "/schedule?linked=1", http.StatusSeeOther)
}

// councilUnlink removes the account's stored council session but keeps its
// permits, vehicles and schedule, so a later re-link resumes where it left off.
// Owner-only: a secondary cannot disconnect the shared connection.
func (s *Server) councilUnlink(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can disconnect the council account.")
		return
	}
	if err := s.store.DeleteCouncilSession(r.Context(), user); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}

// confirmTokenTTL is how long a renewal-confirm link stays usable after its
// reminder email went out: the reminder lead itself (so it covers the whole
// window the mail is about) plus a fortnight for someone who reads mail late.
// After that the session lapses the normal way and they re-link in the app.
func (s *Server) confirmTokenTTL() time.Duration {
	lead := s.cfg.Council.ReminderLead
	if lead <= 0 {
		lead = 7 * 24 * time.Hour
	}
	return lead + 14*24*time.Hour
}

// hasSavedPassword reports whether the account currently has a saved council
// password (auto-reconnect on). Used to default the link form's "save my
// password" checkbox to the user's existing choice, so a deliberate opt-out isn't
// silently reversed on a later re-link.
func (s *Server) hasSavedPassword(ctx context.Context, owner string) bool {
	cs, err := s.store.GetCouncilSession(ctx, owner)
	return err == nil && cs.Password != ""
}

// councilForgetPassword drops the saved (sealed) council password so p.stonn will
// no longer reconnect automatically, without disturbing the live session. Owner-
// only. After this, a session expiry once again requires a manual re-link.
func (s *Server) councilForgetPassword(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can change this.")
		return
	}
	if err := s.store.ClearCouncilPassword(r.Context(), user); err != nil {
		s.serverError(w, err)
		return
	}
	if r.Header.Get("HX-Request") != "" {
		s.settingsPage(w, r)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// accountDelete erases all of the owner's data (session, permits, vehicles,
// schedule, apply log, and any shared access). Owner-only and guarded by a typed
// confirmation. A secondary leaves via /account/leave instead.
func (s *Server) accountDelete(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "You have shared access to this account, so you cannot delete it. Use 'Leave this account' instead.")
		return
	}
	if strings.TrimSpace(r.FormValue("confirm")) != "DELETE" {
		s.formError(w, r, "Type DELETE to confirm removing all your data.")
		return
	}
	if err := s.store.DeleteAllForOwner(r.Context(), user); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}

// addMember (owner only) grants another verified email shared access to the
// account, up to two people. Access takes effect when that person signs in with
// the same email (via the one-time code), so there is no new secret to share.
func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	user, owner, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can share access.")
		return
	}
	ctx := r.Context()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" || !looksLikeEmail(email) {
		s.formError(w, r, "Enter a valid email address.")
		return
	}
	if email == user {
		s.formError(w, r, "That is your own email.")
		return
	}
	if isP, _ := s.store.IsPrimary(ctx, email); isP {
		s.message(w, http.StatusConflict, "That person already shares their own account with others, so they cannot join yours.")
		return
	}
	// Block someone who already runs their own account: joining would hide their
	// own permits and connection. They would need a different email, or to remove
	// their own data first.
	if has, _ := s.store.HasOwnData(ctx, email); has {
		s.message(w, http.StatusConflict, "That person already uses p.stonn with their own account. Ask them to use a different email, or to remove their own account first.")
		return
	}
	// Add atomically under the cap of two (the count check and insert are one
	// statement, so concurrent adds cannot exceed it).
	if err := s.store.AddMemberCapped(ctx, owner, email, 2); err != nil {
		if errors.Is(err, store.ErrMemberLimit) {
			s.message(w, http.StatusConflict, "You can share access with at most two people. Remove one first.")
			return
		}
		log.Printf("add member %s to %s: %v", email, owner, err)
		s.message(w, http.StatusConflict, "That email already has access to an account.")
		return
	}
	// Courtesy heads-up (best-effort; not a login code) so they know to sign in.
	// Throttled so a primary can't email-bomb an address (target: 1/day) or
	// mass-send via SMTP (fanout: a few/hour per owner). The member is still added
	// regardless; only the email is rate-limited — and the flash tells the owner
	// whether a heads-up went out, so a skipped email doesn't leave the new member
	// waiting for an invitation that never comes.
	mailed := false
	if s.notify.EmailAvailable() && s.inviteFanout.allow("o:"+owner) && s.inviteTarget.allow("t:"+email) {
		mailed = true
		go func(to, from string) {
			// Detached from the request: the handler returns immediately, so use a
			// fresh bounded context rather than r.Context() (already cancelled).
			nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if e := s.notify.SendInvite(nctx, to, from); e != nil {
				log.Printf("invite email to %s: %v", to, e)
			}
		}(email, owner)
	} else {
		log.Printf("invite email to %s skipped (throttled or email not configured)", email)
	}
	q := url.Values{"shared": {email}}
	if mailed {
		q.Set("mailed", "1")
	}
	http.Redirect(w, r, "/settings?"+q.Encode(), http.StatusSeeOther)
}

// removeMember (owner only) revokes a secondary's shared access.
func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	_, owner, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can change shared access.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	// Removal also revokes any guest pass or door QR that member minted — those
	// are bearer links that would otherwise keep working after they lose access.
	// Report the count: the primary needs to know their household's links changed.
	revoked, err := s.store.RemoveMember(r.Context(), owner, email)
	if err != nil {
		s.serverError(w, err)
		return
	}
	q := url.Values{"removed": {email}}
	if revoked > 0 {
		q.Set("revoked", strconv.FormatInt(revoked, 10))
	}
	http.Redirect(w, r, "/settings?"+q.Encode(), http.StatusSeeOther)
}

// leaveAccount lets a secondary give up their shared access, returning them to
// their own (separate) account. A primary has nothing to leave.
func (s *Server) leaveAccount(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if isPrimary {
		s.formError(w, r, "You own this account, so there is nothing to leave.")
		return
	}
	if _, err := s.store.RemoveMembership(r.Context(), user); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}

// councilConfirm renders the "keep it running" page from a renewal-reminder
// email. It is public and token-only (no login), so it stays one tap.
//
// GET only RENDERS a button; the POST below performs it. Mail scanners, corporate
// link-checkers and mailbox previewers all follow links, so a GET that acted would
// let a machine satisfy the very human-liveness check this flow exists to make —
// quietly keeping a departed user's council session alive for another full cycle.
func (s *Server) councilConfirm(w http.ResponseWriter, r *http.Request) {
	noStore(w) // the URL carries a live single-use token; keep it out of caches
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	s.render(w, dashboardData{State: "confirm", Loc: s.cfg.DisplayLocation,
		Confirm: &confirmView{Token: token, Stale: token == ""}})
}

// councilConfirmApply consumes the single-use token and extends the session by
// another SessionMaxAge. A used, unknown or aged-out token is reported as
// "nothing to do" rather than an error: the first use already extended it, so the
// user is genuinely fine either way.
func (s *Server) councilConfirmApply(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	token := strings.TrimSpace(r.FormValue("token"))
	// A confirm link is only good for the reminder window it was sent for (plus
	// slack for a user who opens mail late), not forever.
	owner, err := s.store.ConfirmSession(r.Context(), token, s.confirmTokenTTL())
	if err != nil {
		s.render(w, dashboardData{State: "confirm", Loc: s.cfg.DisplayLocation,
			Confirm: &confirmView{Stale: true}})
		return
	}
	log.Printf("council session for %s confirmed via email link", owner)
	v := &confirmView{Done: true}
	if s.cfg.Council.SessionMaxAge > 0 {
		v.Until = time.Now().Add(s.cfg.Council.SessionMaxAge).In(s.cfg.DisplayLocation).Format("2 January 2006")
	}
	s.render(w, dashboardData{State: "confirm", Loc: s.cfg.DisplayLocation, Confirm: v})
}
