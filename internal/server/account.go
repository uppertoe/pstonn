package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// tenantLink onboards the user's tenant account via a headless login: it takes
// their tenant credentials and exchanges them for a session cookie. The password
// is discarded unless the user opts in to auto-reconnect, in which case it is
// sealed (DATA_ENCRYPTION_KEY) and stored so the scheduler can silently re-link if
// the tenant session later expires.
func (s *Server) tenantLink(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	// Only the account owner links the tenant account; a secondary uses the
	// primary's connection and cannot change it.
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can connect the council account.")
		return
	}
	// The tenant username is FIXED to the owner's verified email (from the
	// forward-auth layer), so a user can only ever link the Stonnington account
	// that matches their own verified email; they supply just the password.
	password := r.FormValue("portal_password")
	if password == "" {
		s.formError(w, r, "Enter your council password.")
		return
	}
	// Which tenant. With one enabled tenant the choice is implicit; with several
	// the form names it (the sign-up choice, or "connect another area"), and the
	// selection is recorded BEFORE the login so the session and permits are filed
	// under it. A tenant the process is not serving is refused.
	tenantID := ""
	if s.registry != nil {
		chosen := s.registry.Default
		if enabled := s.registry.Enabled(); len(enabled) > 1 {
			c, ok := s.registry.ByID(r.FormValue("tenant_id"))
			if !ok || !c.Enabled {
				s.formError(w, r, "Choose your council.")
				return
			}
			chosen = c
		}
		if err := s.store.SetAccountTenant(r.Context(), user, chosen.ID); err != nil {
			s.serverError(w, err)
			return
		}
		tenantID = chosen.ID
	}
	// Throttle password attempts per user: every submit forwards the password to
	// the tenant's own login, and hammering it could trip the tenant's lockout
	// on the user's real account (the username is pinned to their email, so this
	// is no oracle against anyone else's).
	if !s.tenantTry.allow(user) {
		// Land back on the onboarding page (same pattern as link=rejected), where
		// the banner pairs the wait with the likely fixes. The bare 429 message
		// page was the last thing the second community sign-up saw before leaving
		// (observed live 2026-08-11: three rejected logins, two throttle walls,
		// gone). A 429 status can't carry that page: this is a browser form flow.
		http.Redirect(w, r, "/schedule?link=throttled", http.StatusSeeOther)
		return
	}
	// Capacity check, before we take their password anywhere near the tenant.
	// Only a NEW household counts: anyone we already serve must never be locked out
	// of their own running service.
	//
	// "Already linked" is NOT the right test on its own, because the two paths that
	// end a session — the idle bound and a rejected saved password — DELETE the row.
	// A returning household then looks brand new while their permits, vehicles and
	// schedule are all still here, so a full deployment would refuse to let them
	// restart the service they were already using. HasOwnData covers that: a session,
	// a permit, or a vehicle all mean this is a re-link, not a signup.
	if s.cfg.MaxAccounts > 0 {
		// Hold the admission boundary across the count AND the link below. Counting then
		// releasing let concurrent newcomers all observe 499 and all save — the login
		// serialisation downstream does not help, because the capacity DECISION was
		// already made before entering it. Unlocked on every exit path via defer.
		s.admitMu.Lock()
		defer s.admitMu.Unlock()
		// FAIL CLOSED on a read error. Logging and proceeding meant database trouble
		// silently lifted the cap — exactly when the service is least able to absorb
		// new households. An existing user is never affected: HasOwnData short-circuits
		// them before any counting.
		known, kerr := s.store.HasOwnData(r.Context(), user)
		if kerr != nil {
			log.Printf("capacity check for %s: %v", redact.Email(user), kerr)
			s.message(w, http.StatusServiceUnavailable, "We couldn't check availability just now. Please try again in a moment.")
			return
		}
		if !known {
			n, cerr := s.store.CountLinkedAccounts(r.Context())
			if cerr != nil {
				log.Printf("capacity check for %s: %v", redact.Email(user), cerr)
				s.message(w, http.StatusServiceUnavailable, "We couldn't check availability just now. Please try again in a moment.")
				return
			} else if n >= s.cfg.MaxAccounts {
				log.Printf("capacity: refused a new link for %s (%d/%d accounts)", redact.Email(user), n, s.cfg.MaxAccounts)
				s.message(w, http.StatusServiceUnavailable, s.say(r.Context(), user, "capacity.full"))
				return
			}
		}
	}
	savePassword := r.FormValue("save_password") != ""
	// The headless tenant login is several round trips; cap it inside the
	// server's 20s WriteTimeout so a slow portal yields the error message below
	// (the user can retry) instead of a dropped connection.
	linkCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.tenant.Link(linkCtx, user, tenantID, user, password, savePassword, true, 0); err != nil {
		log.Printf("council link for %s: %v", redact.Email(user), err)
		if errors.Is(err, parking.ErrCouncilBusy) {
			s.message(w, http.StatusBadGateway, "The council portal is not accepting sign-ins right now. Your password was not the problem — please try again in a little while.")
			return
		}
		if errors.Is(err, parking.ErrLoginRejected) {
			// The tenant tells us only that no session cookie came back, so we
			// genuinely cannot distinguish a wrong password from "no ePermits account
			// exists for this email". This failure needs a NEXT STEP, not just an
			// explanation: the likely remedy is signing out and back in with the
			// ePermits email, and a toast can describe that journey but not offer
			// it. Land back on the onboarding page instead (same pattern as the
			// post-addPermit outcomes), where appShell renders the two causes and
			// a real sign-out button (LinkHelp). Observed live 2026-08-10: the
			// first community sign-up hit this exact wall three times and left.
			http.Redirect(w, r, "/schedule?link=rejected", http.StatusSeeOther)
			return
		}
		if errors.Is(err, store.ErrSecondaryAccount) {
			// The tenant sign-in actually SUCCEEDED; we refused to keep it because this
			// address joined another household while the sign-in was in flight. Saying
			// "a problem at our end" here would be a lie about their password and leave
			// them retrying something that can never work.
			s.message(w, http.StatusConflict,
				"You've joined another p.stonn household, so this address now shares that household's permits instead of holding its own council link. "+
					"Your council password was accepted — there is nothing wrong with it. If you meant to manage your own permits, leave the shared household from Settings first, then link again.")
			return
		}
		s.message(w, http.StatusBadGateway, "Could not link your council account. This appears to be a problem at our end or on the council's site rather than your password. Please try again shortly.")
		return
	}
	s.logChange(r.Context(), user, user, store.ActionCouncilLink, "", "")
	// Drop any queued auto-reconnect for the OLD session: the user just established a
	// fresh one, and stale recovery work must not act on it (the scheduler's generation
	// check is the hard guard; this is the fast path).
	s.sched.CancelReconnect(user)
	// A fresh link plausibly fixes every permit on this account, so clear their
	// failure backoffs and reconcile now rather than making the user wait out a
	// stretched retry window they just made obsolete. Scoped to this owner.
	s.sched.KickOwner(r.Context(), user)
	// ?linked=1 turns into the "Council account linked." flash — after a first
	// link the user lands on the permit picker, so this is the only confirmation
	// the sign-in worked.
	http.Redirect(w, r, "/schedule?linked=1", http.StatusSeeOther)
}

// tenantSelect switches the account's current tenant (the user menu's area
// switcher). Linked there already → the schedule; not yet → the picker, which
// offers the link form for that tenant.
func (s *Server) tenantSelect(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	if s.registry == nil {
		redirectHome(w, r)
		return
	}
	c, ok := s.registry.ByID(r.FormValue("tenant_id"))
	if !ok || !c.Enabled {
		s.formError(w, r, "That area isn't available.")
		return
	}
	if err := s.store.SetAccountTenant(r.Context(), owner, c.ID); err != nil {
		s.serverError(w, err)
		return
	}
	_ = user
	if s.tenant.Linked(r.Context(), owner, c.ID) {
		redirectHome(w, r)
		return
	}
	http.Redirect(w, r, "/permits/new", http.StatusSeeOther)
}

// tenantArg resolves the tenant a settings action names (hidden tenant_id on the
// per-tenant cards), defaulting to the account's current tenant.
func (s *Server) tenantArg(r *http.Request, owner string) (string, error) {
	if id := r.FormValue("tenant_id"); id != "" {
		if s.registry != nil {
			if _, ok := s.registry.ByID(id); !ok {
				return "", store.ErrNotFound
			}
		}
		return id, nil
	}
	return s.store.TenantIDFor(r.Context(), owner)
}

// tenantUnlink removes the account's session with one tenant but keeps its
// permits, vehicles and schedule, so a later re-link resumes where it left off.
// Owner-only: a secondary cannot disconnect the shared connection.
func (s *Server) tenantUnlink(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can disconnect the council account.")
		return
	}
	tenant, err := s.tenantArg(r, user)
	if err != nil {
		s.formError(w, r, "That area isn't available.")
		return
	}
	if err := s.store.DeleteTenantSessionIn(r.Context(), user, tenant); err != nil {
		s.serverError(w, err)
		return
	}
	s.sched.CancelReconnect(user) // no session to reconnect; drop any queued attempt
	s.logChange(r.Context(), user, user, store.ActionCouncilUnlink, "", "")
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

// hasSavedPassword reports whether the account currently has a saved tenant
// password (auto-reconnect on). Used to default the link form's "save my
// password" checkbox to the user's existing choice, so a deliberate opt-out isn't
// silently reversed on a later re-link.
func (s *Server) hasSavedPassword(ctx context.Context, owner string) bool {
	cs, err := s.store.GetTenantSession(ctx, owner)
	return err == nil && cs.Password != ""
}

// tenantForgetPassword drops the saved (sealed) tenant password so p.stonn will
// no longer reconnect automatically, without disturbing the live session. Owner-
// only. After this, a session expiry once again requires a manual re-link.
func (s *Server) tenantForgetPassword(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can change this.")
		return
	}
	tenant, err := s.tenantArg(r, user)
	if err != nil {
		s.formError(w, r, "That area isn't available.")
		return
	}
	if err := s.store.ClearTenantPasswordIn(r.Context(), user, tenant); err != nil {
		s.serverError(w, err)
		return
	}
	// Drop any queued reconnect: the user just opted out of saved-password recovery.
	// ClearTenantPassword also bumped the session generation, so an ALREADY-running
	// reconnect's generation-conditioned save lands nowhere and can't restore the
	// password — this only cancels not-yet-started work.
	s.sched.CancelReconnect(user)
	s.logChange(r.Context(), user, user, store.ActionCouncilForget, "", "")
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
	// Cancel any queued auto-reconnect: the tenant row is gone, and an in-flight
	// attempt must not keep replaying the third-party password for a deleted account.
	// (The generation-conditioned save also lands nowhere now the row is gone.)
	s.sched.CancelReconnect(user)
	// The account is gone, so any session still holding it must go too — otherwise a
	// signed cookie keeps asserting an identity whose data no longer exists.
	s.revokeSessions(r.Context(), user)
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
	// Nothing here inspects the invited address. It used to: two probes rejected an
	// address that was already a primary, or already had permits/vehicles of its own,
	// each with its own message. Since neither outcome depends on anything the
	// inviter knows, the endpoint answered "does this person use p.stonn, and is their
	// permit set up?" for any address, with no write and no email — a membership
	// oracle over a service whose users are all in one small area. Those constraints
	// are really about the INVITEE's account, so they are checked when the invitee
	// accepts, where the answer is about themselves and leaks nothing.
	//
	// Add atomically under the cap of two (the count check and insert are one
	// statement, so concurrent adds cannot exceed it). The invite starts pending and
	// grants nothing until accepted.
	err := s.store.AddMemberCapped(ctx, owner, email, 2)
	// The cap is a fact about the INVITER's own account, so reporting it precisely
	// tells them nothing they could not already see on this page.
	if errors.Is(err, store.ErrMemberLimit) {
		s.message(w, http.StatusConflict, "You can share access with at most two people. Remove one first.")
		return
	}
	if err != nil {
		// Anything else is a fact about the invited address — most likely that it
		// already holds an invite or membership somewhere. Fall through to the same
		// confirmation AND the same audit entry the success path writes, so neither the
		// response nor the owner's own activity log can be used to probe whether an
		// address already uses p.stonn. A pending invite grants nothing, so not creating
		// one is safe.
		log.Printf("add member %s to %s: %v", notify.RedactEmail(email), notify.RedactEmail(owner), err)
		s.logChange(ctx, owner, user, store.ActionMemberAdd, email, "")
		s.inviteSent(w, r, email, false)
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
				log.Printf("invite email to %s: %v", notify.RedactEmail(to), e)
			}
		}(email, owner)
	} else {
		log.Printf("invite email to %s skipped (throttled or email not configured)", notify.RedactEmail(email))
	}
	s.logChange(ctx, owner, user, store.ActionMemberAdd, email, "")
	s.inviteSent(w, r, email, mailed)
}

// inviteSent renders the one confirmation every addMember outcome shares, so the
// response cannot distinguish "invited" from "that address could not be invited".
// The wording is deliberately about what happens next rather than about the invited
// person, because we must not assert anything the inviter is not entitled to know.
func (s *Server) inviteSent(w http.ResponseWriter, r *http.Request, email string, mailed bool) {
	q := url.Values{"invited": {email}}
	if mailed {
		q.Set("mailed", "1")
	}
	http.Redirect(w, r, "/settings?"+q.Encode(), http.StatusSeeOther)
}

// acceptInvite is the invited person accepting shared access to someone's account.
// This is the consent step the flow previously had no place for.
//
// The checks that used to run at invite time run HERE, because they are about the
// person acting: joining an account hides your own permits and connection, so
// someone who already runs their own account has to be told rather than silently
// folded into another household.
func (s *Server) acceptInvite(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromContext(r.Context())
	ctx := r.Context()
	owner, ok, err := s.store.PendingInvite(ctx, u.Email)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !ok {
		redirectHome(w, r)
		return
	}
	// The form carries the account it was rendered for, so a stale page cannot enrol
	// them somewhere they never saw.
	if shown := strings.ToLower(strings.TrimSpace(r.FormValue("owner"))); shown != "" && shown != owner {
		redirectHome(w, r)
		return
	}
	// Both prerequisites FAIL CLOSED. Discarding these errors meant a transient
	// database fault could let someone with their own permits (or their own
	// dependants) join another account — which hides their data behind a different
	// owner and is not something the accept flow can undo cleanly.
	isP, err := s.store.IsPrimary(ctx, u.Email)
	if err != nil {
		log.Printf("acceptInvite: cannot check primary status for %s: %v", redact.Email(u.Email), err)
		s.message(w, http.StatusServiceUnavailable, "We couldn't check your account just now. Please try again in a moment.")
		return
	}
	if isP {
		s.message(w, http.StatusConflict, "You already share your own account with someone else, so you cannot also join another. Remove them first, or decline this invitation.")
		return
	}
	has, err := s.store.HasOwnData(ctx, u.Email)
	if err != nil {
		log.Printf("acceptInvite: cannot check own data for %s: %v", redact.Email(u.Email), err)
		s.message(w, http.StatusServiceUnavailable, "We couldn't check your account just now. Please try again in a moment.")
		return
	}
	if has {
		s.message(w, http.StatusConflict, "You already have your own permits in p.stonn, and joining another account would hide them. Decline this invitation, or remove your own account first if you would rather share.")
		return
	}
	// The checks above are for a clear message; the STORE decides. Its update re-tests
	// the same prerequisites in the statement itself, so a tenant link or first vehicle
	// landing in between cannot slip an invite through behind them.
	switch err := s.store.AcceptInvite(ctx, u.Email, owner); {
	case errors.Is(err, store.ErrInviteBlocked):
		s.message(w, http.StatusConflict, "You've started your own p.stonn account since this invitation was sent, so joining another would hide your own permits. Decline it, or remove your own account first if you would rather share.")
		return
	case errors.Is(err, store.ErrNotFound):
		redirectHome(w, r)
		return
	case err != nil:
		s.serverError(w, err)
		return
	}
	s.logChange(ctx, owner, u.Email, store.ActionMemberAdd, u.Email, "accepted the invitation")
	http.Redirect(w, r, "/settings?joined="+url.QueryEscape(owner), http.StatusSeeOther)
}

// declineInvite is the invited person refusing. It removes the pending row outright,
// so the address is free to be invited again or to start its own account.
func (s *Server) declineInvite(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromContext(r.Context())
	if err := s.store.DeclineInvite(r.Context(), u.Email); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/settings?declined=1", http.StatusSeeOther)
}

// removeMember (owner only) revokes a secondary's shared access.
func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	user, owner, isPrimary := s.resolveAccount(r.Context())
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can change shared access.")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	// Removal also revokes any guest pass or door QR that member minted — those
	// are bearer links that would otherwise keep working after they lose access.
	// Report the count: the primary needs to know their household's links changed.
	// wasActive distinguishes revoking a real member from withdrawing a still-pending
	// invitation: only the former is a loss of access, so only the former revokes
	// sessions. Withdrawing an offer touches nothing that belongs to that address.
	revoked, wasActive, err := s.store.RemoveMember(r.Context(), owner, email)
	if errors.Is(err, store.ErrNotFound) {
		// Not associated with this account: a stale form, or someone probing another
		// household's address. There is nothing to do — and the response must match the
		// removal path so it cannot be used to confirm who else has an account. Same
		// 303 and the same banner as a real removal (nothing was actually touched).
		http.Redirect(w, r, "/settings?removed="+url.QueryEscape(email), http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !wasActive {
		// A pending invitation withdrawn. It granted nothing, so there is nothing to
		// revoke and no session to end; just record it and confirm accurately.
		s.logChange(r.Context(), owner, user, store.ActionMemberRemove, email, "invitation withdrawn")
		http.Redirect(w, r, "/settings?withdrawn="+url.QueryEscape(email), http.StatusSeeOther)
		return
	}
	// They have lost access to this household's data; a session issued while they had
	// it must stop working now, not whenever its cookie happens to lapse.
	s.revokeSessions(r.Context(), email)
	detail := ""
	if revoked > 0 {
		detail = fmt.Sprintf("%d guest pass(es) they created were revoked", revoked)
	}
	s.logChange(r.Context(), owner, user, store.ActionMemberRemove, email, detail)
	q := url.Values{"removed": {email}}
	if revoked > 0 {
		q.Set("revoked", strconv.FormatInt(revoked, 10))
	}
	http.Redirect(w, r, "/settings?"+q.Encode(), http.StatusSeeOther)
}

// leaveAccount lets a secondary give up their shared access, returning them to
// their own (separate) account. A primary has nothing to leave.
func (s *Server) leaveAccount(w http.ResponseWriter, r *http.Request) {
	// MUTATING handler: fail CLOSED. On a membership-lookup blip the lenient resolver
	// would report a secondary as a primary (isPrimary=true) and turn a genuine "leave"
	// into a misleading "you own this account". accountForWrite refuses with a 503
	// instead of guessing wrong, and — resolving the owner once here — also removes the
	// second, separately-fallible resolveAccount call this used for the audit scope.
	user, leftOwner, isPrimary, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if isPrimary {
		s.formError(w, r, "You own this account, so there is nothing to leave.")
		return
	}
	revoked, err := s.store.RemoveMembership(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	// They chose to leave, so their sessions were scoped to an account they no longer
	// belong to. Revoking makes the next request resolve them to their own account
	// rather than continuing to act inside the household they just left.
	s.revokeSessions(r.Context(), user)
	// Leaving revokes the departing member's guest passes and door QRs exactly as
	// being removed does, so the primary has to hear about it the same way. This is
	// in fact the likelier path — mint a pass, then leave — and until now it was
	// silent: the household's visitor links simply stopped working with nothing
	// anywhere to explain why.
	detail := ""
	if revoked > 0 {
		detail = fmt.Sprintf("%d guest pass(es) they created were revoked", revoked)
		s.notifyDestructive(r.Context(), leftOwner, user, fmt.Sprintf(
			"%s left the account. %d guest pass(es) or printed QR(s) they created have stopped working.", user, revoked))
	}
	s.logChange(r.Context(), leftOwner, user, store.ActionMemberLeave, "", detail)
	redirectHome(w, r)
}

// tenantConfirm renders the "keep it running" page from a renewal-reminder
// email. It is public and token-only (no login), so it stays one tap.
//
// GET only RENDERS a button; the POST below performs it. Mail scanners, corporate
// link-checkers and mailbox previewers all follow links, so a GET that acted would
// let a machine satisfy the very human-liveness check this flow exists to make —
// quietly keeping a departed user's tenant session alive for another full cycle.
func (s *Server) tenantConfirm(w http.ResponseWriter, r *http.Request) {
	noStore(w) // the URL carries a live single-use token; keep it out of caches
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	s.render(w, dashboardData{State: "confirm", Loc: s.cfg.DisplayLocation,
		Confirm: &confirmView{Token: token, Stale: token == ""}})
}

// tenantConfirmApply consumes the single-use token and extends the session by
// another SessionMaxAge. A used, unknown or aged-out token is reported as
// "nothing to do" rather than an error: the first use already extended it, so the
// user is genuinely fine either way.
func (s *Server) tenantConfirmApply(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	// This route is PUBLIC (the link comes from an email, so there is no session)
	// and it mutates, which puts it outside withUser's blanket protections. Both
	// have to be applied by hand: without the body cap, r.FormValue on a multipart
	// body buffers 32MB and spills to disk unauthenticated, and without the
	// throttle the token is an unmetered guessing oracle that also competes with
	// the scheduler for the single SQLite connection.
	limitBody(r)
	if !s.confirmLimit.allow(rateLimitKey(r)) {
		w.Header().Set("Retry-After", "60")
		s.message(w, http.StatusTooManyRequests, "Too many attempts. Please wait a moment and try the link in your email again.")
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	// A confirm link is only good for the reminder window it was sent for (plus
	// slack for a user who opens mail late), not forever.
	owner, err := s.store.ConfirmSession(r.Context(), token, s.confirmTokenTTL())
	if err != nil {
		s.render(w, dashboardData{State: "confirm", Loc: s.cfg.DisplayLocation,
			Confirm: &confirmView{Stale: true}})
		return
	}
	log.Printf("council session for %s confirmed via email link", redact.Email(owner))
	v := &confirmView{Done: true}
	if s.cfg.Council.SessionMaxAge > 0 {
		v.Until = time.Now().Add(s.cfg.Council.SessionMaxAge).In(s.cfg.DisplayLocation).Format("2 January 2006")
	}
	s.render(w, dashboardData{State: "confirm", Loc: s.cfg.DisplayLocation, Confirm: v})
}

// revokeSessions invalidates every session already issued to a person, after their
// authority has been taken away (account deleted, shared access removed).
//
// Best-effort by design: the authority change itself has already been committed, so
// failing here must not undo it or block the user's own request. It is logged loudly
// because the consequence — a signed cookie that keeps working after access was
// withdrawn — is exactly what the epoch exists to prevent.
//
// A no-op when the app runs behind forward-auth, where there is no app-issued session
// to revoke and identity comes from the proxy on every request.
func (s *Server) revokeSessions(ctx context.Context, email string) {
	if s.store == nil || email == "" {
		return
	}
	epoch, err := s.store.BumpSessionEpoch(ctx, email)
	if err != nil {
		log.Printf("SECURITY: could not revoke sessions for %s (%v); an existing sign-in may keep working until it expires", redact.Email(email), err)
		return
	}
	if s.sessions != nil {
		s.sessions.RevokeTo(email, epoch)
	}
}
