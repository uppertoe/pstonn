package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	if err := s.council.Link(r.Context(), user, user, password, savePassword, true); err != nil {
		log.Printf("council link for %s: %v", user, err)
		if errors.Is(err, parking.ErrCouncilBusy) {
			s.message(w, http.StatusBadGateway, "The council portal is not accepting sign-ins right now. Your password was not the problem — please try again in a little while.")
			return
		}
		s.message(w, http.StatusBadGateway, "Couldn't link your council account. Check that your password is correct and that your council account uses this email address.")
		return
	}
	redirectHome(w, r)
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
	// regardless; only the email is rate-limited.
	if s.inviteFanout.allow("o:"+owner) && s.inviteTarget.allow("t:"+email) {
		go func(to, from string) {
			if e := s.notify.SendInvite(to, from); e != nil {
				log.Printf("invite email to %s: %v", to, e)
			}
		}(email, owner)
	} else {
		log.Printf("invite email to %s throttled", email)
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// removeMember (owner only) revokes a secondary's shared access.
func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	_, owner, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can change shared access.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if err := s.store.RemoveMember(r.Context(), owner, email); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// leaveAccount lets a secondary give up their shared access, returning them to
// their own (separate) account. A primary has nothing to leave.
func (s *Server) leaveAccount(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if isPrimary {
		s.formError(w, r, "You own this account, so there is nothing to leave.")
		return
	}
	if err := s.store.RemoveMembership(r.Context(), user); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}

// councilConfirm consumes the single-use token from a renewal-reminder email and
// extends the session another SessionMaxAge. It is public and token-only (no
// login) so it stays a genuine one-click. Because the first hit extends the
// session, a used/unknown token still means "you're fine", so its message
// reassures rather than alarms (covers email-scanner prefetch consuming it).
func (s *Server) councilConfirm(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	owner, err := s.store.ConfirmSession(r.Context(), token)
	if err != nil {
		s.message(w, http.StatusOK,
			"This confirmation link has already been used, so no further action is needed. Your permit scheduler will keep running. If it ever stops, just open the app to reconnect your council account.")
		return
	}
	log.Printf("council session for %s confirmed via email link", owner)
	msg := "Thanks. Your visitor-permit scheduler will keep running."
	if s.cfg.Council.SessionMaxAge > 0 {
		next := time.Now().Add(s.cfg.Council.SessionMaxAge).In(s.cfg.DisplayLocation).Format("2 January 2006")
		msg = fmt.Sprintf("Thanks. Your visitor-permit scheduler will keep running. We'll check in again around %s.", next)
	}
	s.message(w, http.StatusOK, msg)
}
