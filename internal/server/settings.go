package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// settingsPage shows the tenant connection, re-authorise deadline, and account
// controls.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "settings")
	if !ok {
		return
	}
	ctx := r.Context()
	owner := base.Owner
	user := base.User.Email // the signed-in person; notification prefs are theirs
	base.Settings = &settingsData{}
	if cs, err := s.store.GetTenantSession(ctx, owner); err == nil {
		base.Settings.TenantLinked = true
		base.AutoReconnect = cs.Password != ""
		// The deadline is measured from the last time anyone on the account used the
		// app, so it moves forward as the household keeps using it. Showing it from
		// the link date would be wrong (and alarming).
		idleSince := cs.LastActive
		if idleSince.IsZero() {
			idleSince = cs.LinkedAt
		}
		if !idleSince.IsZero() && s.cfg.Council.SessionMaxAge > 0 {
			base.Settings.RelinkBy = idleSince.Add(s.cfg.Council.SessionMaxAge).In(s.locFor(ctx, owner)).Format("2 Jan 2006")
		}
		if base.AutoReconnect && !cs.ReconnectedAt.IsZero() {
			base.Settings.LastReconnect = cs.ReconnectedAt.In(s.locFor(ctx, owner)).Format("2 Jan 2006, 3:04pm")
		}
	}
	// Other tenants this account is linked to get a card each (the current
	// tenant's card is the one above).
	if sessions, err := s.store.ListTenantSessionsFor(ctx, owner); err == nil && len(sessions) > 1 && s.registry != nil {
		current, _ := s.store.TenantIDFor(ctx, owner)
		for _, cs := range sessions {
			if cs.TenantID == current || cs.Cookie == "" {
				continue
			}
			c, ok := s.registry.ByID(cs.TenantID)
			if !ok {
				continue
			}
			cv := connectionView{ID: c.ID, Name: c.Name, AutoReconnect: cs.Password != ""}
			idle := cs.LastActive
			if idle.IsZero() {
				idle = cs.LinkedAt
			}
			if !idle.IsZero() && s.cfg.Council.SessionMaxAge > 0 {
				cv.RelinkBy = idle.Add(s.cfg.Council.SessionMaxAge).In(c.Location()).Format("2 Jan 2006")
			}
			base.Settings.OtherConnections = append(base.Settings.OtherConnections, cv)
		}
	}
	if r.URL.Query().Get("tested") == "1" {
		base.Flash = "Test notification sent."
		if r.URL.Query().Get("confirm") == "1" {
			base.Flash = "Test notification sent. Tap Confirm on the one that reaches your phone — once you have, you can turn off email."
		}
	}
	// Every address below is validated before it is composed into a message. These
	// are written by our own redirects, but nothing stops someone handing a signed-in
	// user a crafted /settings?... link: the value lands in the green success banner,
	// which is the most trusted element on the page, in an app whose whole premise is
	// holding tenant credentials. It is not an injection (html/template escapes it),
	// but "phone this number to restore your permit" in our own voice is worth
	// refusing outright. A value that is not a plausible address is dropped.
	if removed := r.URL.Query().Get("removed"); looksLikeEmail(removed) {
		base.Flash = removed + " no longer has access."
		if n := atoi(r.URL.Query().Get("revoked")); n > 0 {
			// Name the count: guest links they created have stopped working, and the
			// owner should not first learn that from a visitor whose link is dead.
			pass := "guest pass"
			if n > 1 {
				pass = "guest passes"
			}
			base.Flash += fmt.Sprintf(" %d %s they created also stopped working, so anyone holding those links can no longer use the permit.", n, pass)
		}
	}
	// An invitation is an offer, not access, so the wording must not promise the
	// latter. It is also deliberately identical whether or not a row was created —
	// see inviteSent.
	if invited := r.URL.Query().Get("invited"); looksLikeEmail(invited) {
		if r.URL.Query().Get("mailed") == "1" {
			base.Flash = "Invitation sent to " + invited + ". They will be asked to accept it the next time they sign in, and will have access only once they do."
		} else {
			base.Flash = "Invitation recorded for " + invited + ". No email was sent, so you will need to tell them to sign in and accept it."
		}
	}
	if wd := r.URL.Query().Get("withdrawn"); looksLikeEmail(wd) {
		base.Flash = "Invitation to " + wd + " withdrawn. It granted no access, so nothing of theirs was changed."
	}
	if joined := r.URL.Query().Get("joined"); looksLikeEmail(joined) {
		base.Flash = "You now share " + joined + "'s account."
	}
	if r.URL.Query().Get("declined") == "1" {
		base.Flash = "Invitation declined. Nothing was shared, and your own account is unaffected."
	}
	// Notification preferences are per-person: each user (primary or secondary)
	// controls how THEY are notified, keyed to their own signed-in email.
	pref, err := s.store.GetNotifyPref(ctx, user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Ensure the user always has their own ntfy topic to subscribe to, even before enabling it.
	if pref.NtfyTopic == "" {
		pref.Owner = user
		pref.NtfyTopic = notify.RandomTopic()
		_ = s.store.SetNotifyPref(ctx, pref)
	}
	base.Settings.Notify = s.notifyViewOf(ctx, user, pref)
	// Terms acceptance is per person; show the signed-in user's own consent.
	if c, err := s.store.LatestConsent(ctx, base.User.Email); err == nil {
		base.Terms.Accepted = fmt.Sprintf("v%s on %s", c.Version, c.AgreedAt.In(s.locFor(ctx, owner)).Format("2 Jan 2006"))
	}
	base.Terms.Clauses = s.terms.Clauses
	// Shared access: the owner sees who has access; a secondary sees whose account.
	if base.IsPrimary {
		if ms, err := s.store.ListMembers(ctx, owner); err == nil {
			for _, m := range ms {
				base.Members = append(base.Members, memberView{
					Email:   m.Email,
					Added:   m.AddedAt.In(s.locFor(ctx, owner)).Format("2 Jan 2006"),
					Pending: m.Pending,
				})
			}
		}
		// An invitation aimed at this person, which they have not answered. Offered even
		// to a primary: they cannot accept while they run their own account, but they are
		// entitled to know it exists and to decline it.
		if from, ok, err := s.store.PendingInvite(ctx, base.User.Email); err == nil && ok {
			inv := &inviteView{Owner: from}
			// Mirror acceptInvite's refusals so the card says so up front.
			if n, cerr := s.store.CountMembers(ctx, base.User.Email); cerr == nil && n > 0 {
				inv.Blocked = "shared"
			} else if has, herr := s.store.HasOwnData(ctx, base.User.Email); herr == nil && has {
				inv.Blocked = "own"
			}
			base.Invite = inv
		}
	} else if from, ok, err := s.store.PendingInvite(ctx, base.User.Email); err == nil && ok {
		base.Invite = &inviteView{Owner: from}
	}
	s.render(w, base)
}

// renderNotify renders the swappable notifications fragment (auto-save target),
// or falls back to a redirect for a non-htmx request.
func (s *Server) renderNotify(w http.ResponseWriter, r *http.Request, user string, pref store.NotifyPref, status, errMsg string) {
	nv := s.notifyViewOf(r.Context(), user, pref)
	nv.Status, nv.Error = status, errMsg
	s.renderNotifyView(w, r, nv)
}

// renderNotifyView is renderNotify for a caller that has already shaped the view.
func (s *Server) renderNotifyView(w http.ResponseWriter, r *http.Request, nv notifyView) {
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "notify-body", nv); err != nil {
			alog.Infof("render notify-body: %v", err)
		}
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// resumeEmail clears the acting user's own self-service unsubscribe, restoring
// routine email. A dedicated endpoint rather than a side effect of saveNotify so
// the Settings banner can offer one button that touches nothing else (posting a
// partial form through saveNotify would clobber the other preferences). Only an
// unsubscribe is clearable — a bounce or complaint stays until the operator
// intervenes, which is exactly what the banner says for those.
func (s *Server) resumeEmail(w http.ResponseWriter, r *http.Request) {
	user, _, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	pref, err := s.store.GetNotifyPref(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	status := "Email resumed."
	if cleared, err := s.store.UnsuppressIfUnsubscribed(r.Context(), user); err != nil {
		s.serverError(w, err)
		return
	} else if !cleared {
		status = "" // nothing to clear (or not clearable: bounce/complaint)
	} else {
		alog.Infof("resubscribe: %s resumed email from the Settings banner", redact.Email(user))
	}
	// The banner state changed, so force the fragment to re-render even though
	// the form normally saves with hx-swap:none.
	w.Header().Set("HX-Retarget", "#notify-body")
	w.Header().Set("HX-Reswap", "innerHTML")
	s.renderNotify(w, r, user, pref, status, "")
}

// saveNotify auto-saves the user's channel choices on every toggle, requiring at
// least one channel to stay on (else it reverts and warns).
func (s *Server) saveNotify(w http.ResponseWriter, r *http.Request) {
	user, _, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	pref, err := s.store.GetNotifyPref(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	pref.Owner = user
	email := r.FormValue("email_enabled") != ""
	ntfy := r.FormValue("ntfy_enabled") != ""
	if (s.notify.EmailAvailable() || s.notify.NtfyAvailable()) && !email && !ntfy {
		// Revert: render the still-saved pref (re-checks the box) with a warning.
		// The form saves with hx-swap:none so a clean save changes no DOM; these
		// headers force the corrective re-render only when the state was rejected.
		w.Header().Set("HX-Retarget", "#notify-body")
		w.Header().Set("HX-Reswap", "innerHTML")
		s.renderNotify(w, r, user, pref, "", "Keep at least one method on.")
		return
	}
	// Email may only go off in favour of a push channel that has PROVED it delivers:
	// a test push whose Confirm button was tapped on a device (ntfyConfirm). A typed
	// topic proves nothing — the phone may never subscribe, or the OS may have
	// notification permission denied — and the failure mode is a household that
	// believes it is being told about its permit and never is (observed 2026-08-31:
	// push on, email off, no device ever subscribed). Once confirmed, either channel
	// may be turned off, never both (the guard above).
	//
	// Only where email is on offer at all: a deployment without a mailer renders
	// no email checkbox, so "email off" is every save's shape there, and the guard
	// used to refuse each one (quiet hours, failures-only, the lot) until a push
	// had been confirmed.
	if s.notify.EmailAvailable() && !email && ntfy && !pref.NtfyConfirmed() {
		w.Header().Set("HX-Retarget", "#notify-body")
		w.Header().Set("HX-Reswap", "innerHTML")
		s.renderNotify(w, r, user, pref, "", "You can turn off email once you've confirmed push notifications on your phone: tap Send a test to my phone, then Confirm on the notification.")
		return
	}
	pref.EmailEnabled, pref.NtfyEnabled = email, ntfy
	// Turning email back on is how someone undoes their own unsubscribe: the opt-out
	// lives in the suppression list (so it applies to people with no account too),
	// and without this the toggle would appear to work while mail stayed blocked.
	// Only clears a self-requested unsubscribe — never a bounce or a complaint.
	if email {
		if cleared, err := s.store.UnsuppressIfUnsubscribed(r.Context(), user); err != nil {
			alog.Infof("resubscribe %s: %v", redact.Email(user), err)
		} else if cleared {
			alog.Infof("resubscribe: %s re-enabled email after unsubscribing", redact.Email(user))
		}
	}
	// Failures-only: the sender has always honoured this, but nothing ever wrote
	// it — so the "only tell me when something's wrong" preference was unreachable.
	pref.FailuresOnly = r.FormValue("failures_only") != ""
	// Quiet hours: hold overnight notices and deliver them at a chosen local hour.
	nudged, nudgeMsg := false, "The two times must differ; end time moved."
	if r.FormValue("quiet_enabled") != "" {
		pref.QuietFrom = clampHour(r.FormValue("quiet_from"), 22)
		pref.QuietUntil = clampHour(r.FormValue("quiet_until"), 6)
		if pref.QuietFrom == pref.QuietUntil {
			pref.QuietUntil = (pref.QuietFrom + 1) % 24 // equal would disable; nudge apart
			nudged = true
		}
		// The hold applies to failure notices too, so an over-wide window is a
		// day of "your permit couldn't be updated" sitting unread. Cap it here so
		// the form reflects what will actually happen (quietDefer enforces the
		// same bound at delivery for values stored before the cap existed).
		if span := ((pref.QuietUntil - pref.QuietFrom) + 24) % 24; span > notify.MaxQuietHours {
			pref.QuietUntil = (pref.QuietFrom + notify.MaxQuietHours) % 24
			nudged = true
			nudgeMsg = fmt.Sprintf("Quiet hours are capped at %d hours; end time moved.", notify.MaxQuietHours)
		}
	} else {
		pref.QuietFrom, pref.QuietUntil = 0, 0 // equal ⇒ disabled (immediate delivery)
	}
	if err := s.store.SetNotifyPref(r.Context(), pref); err != nil {
		s.serverError(w, err)
		return
	}
	if nudged {
		// The saved value differs from what the form shows; re-render to sync.
		w.Header().Set("HX-Retarget", "#notify-body")
		w.Header().Set("HX-Reswap", "innerHTML")
		s.renderNotify(w, r, user, pref, nudgeMsg, "")
		return
	}
	s.renderNotify(w, r, user, pref, "Saved", "")
}

// regenTopic gives the signed-in user a fresh personal ntfy topic (live), enabling ntfy.
func (s *Server) regenTopic(w http.ResponseWriter, r *http.Request) {
	user, _, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	pref, err := s.store.GetNotifyPref(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	pref.Owner, pref.NtfyTopic, pref.NtfyEnabled = user, notify.RandomTopic(), true
	// No device has subscribed to the new topic, so its confirmation starts over —
	// and a household running push-only would now have no proven channel at all, so
	// email comes back on until the new topic is confirmed (the same rule saveNotify
	// applies when they try to switch it off).
	status := "New topic. Subscribe to it in the ntfy app, then tap Send a test to my phone and Confirm on the notification."
	pref.NtfyConfirmedAt = ""
	if !pref.EmailEnabled {
		pref.EmailEnabled = true
		status += " Email is back on until you have."
	}
	if err := s.store.SetNotifyPref(r.Context(), pref); err != nil {
		s.serverError(w, err)
		return
	}
	// The one write on this page that silently changes what a phone must be
	// subscribed to; without a line here a "my pushes stopped" report cannot be
	// told apart from a subscription that was never made.
	alog.Infof("ntfy topic regenerated for %s", redact.Email(user))
	s.renderNotify(w, r, user, pref, status, "")
}

// testNotify sends a test message on the signed-in user's own enabled channels.
func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	user, _, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Throttled: it is the one authenticated button that sends mail on demand, so
	// leaving it unbounded lets one account burn shared SMTP quota by holding it
	// down. Their own address, so a low limit costs nothing legitimate.
	if !s.testNotifyLimit.allow("u:" + user) {
		s.formError(w, r, "You've sent a few test notifications already. Please wait a little while before sending another.")
		return
	}
	confirmURL, awaiting := s.ntfyConfirmURL(r.Context(), user)
	if err := s.notify.SendTest(r.Context(), user, confirmURL); err != nil {
		// Details (SMTP hosts, dial errors, ntfy URLs) go to the log, not the
		// browser.
		alog.Infof("test notify %s: %v", redact.Email(user), err)
		s.message(w, http.StatusBadGateway, "Couldn't send the test notification. Check your channels in Settings, and ask the operator to check the logs if it keeps failing.")
		return
	}
	if awaiting {
		http.Redirect(w, r, "/settings?tested=1&confirm=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?tested=1", http.StatusSeeOther)
}

// ntfyConfirmURL mints the Confirm-button URL for an UNCONFIRMED push channel:
// tapping it is the proof that lets email be turned off (see saveNotify /
// ntfyConfirm). A confirmed channel gets "" (nothing left to prove), as does one
// that is off. awaiting says whether a button went out, for the flash copy.
func (s *Server) ntfyConfirmURL(ctx context.Context, user string) (confirmURL string, awaiting bool) {
	pref, err := s.store.GetNotifyPref(ctx, user)
	if err != nil || !pref.NtfyEnabled || pref.NtfyTopic == "" || pref.NtfyConfirmed() || !s.notify.NtfyAvailable() {
		return "", false
	}
	tok, err := s.mintNtfyConfirm(user, pref.NtfyTopic, time.Now().Add(ntfyConfirmTTL))
	if err != nil {
		alog.Infof("test notify %s: mint confirm token: %v", redact.Email(user), err)
		return "", false
	}
	return s.cfg.PublicBaseURL + "/ntfy/confirm/" + tok, true
}

// testPush is the button INSIDE the push set-up steps: a test to the phone only.
// The page-level "Send a test notification" goes to every enabled channel, which
// is the wrong tool while someone is wiring up their phone — it also mails them,
// and a mail failure would report the push as failed too. Answers over htmx into
// the notifications fragment so the person stays next to the steps, with a status
// that says what to do on the phone.
func (s *Server) testPush(w http.ResponseWriter, r *http.Request) {
	user, _, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	pref, err := s.store.GetNotifyPref(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("HX-Retarget", "#notify-body")
	w.Header().Set("HX-Reswap", "innerHTML")
	if !s.testNotifyLimit.allow("u:" + user) {
		s.renderNotify(w, r, user, pref, "", "You've sent a few test notifications already. Please wait a little while before sending another.")
		return
	}
	confirmURL, awaiting := s.ntfyConfirmURL(r.Context(), user)
	if err := s.notify.SendTestPush(r.Context(), user, confirmURL); err != nil {
		if errors.Is(err, notify.ErrNoPush) {
			s.renderNotify(w, r, user, pref, "", "Turn on push notifications first.")
			return
		}
		alog.Infof("test push %s: %v", redact.Email(user), err)
		s.renderNotify(w, r, user, pref, "", "Couldn't reach the push server just now. Please try again shortly.")
		return
	}
	nv := s.notifyViewOf(r.Context(), user, pref)
	nv.Status = "Test sent to your phone."
	if awaiting {
		// The box itself shows "sent" and what to do next, and starts polling
		// ntfyStatus so the page flips to confirmed on its own when the phone is
		// tapped — the person is looking at this box, not at a status line below it.
		nv.PushSent = true
		nv.Status = "Test sent to your phone — tap Confirm on the notification when it arrives."
	}
	s.renderNotifyView(w, r, nv)
}

// ntfyStatus is polled by the notifications fragment while a test push awaits its
// Confirm tap. It answers 204 (htmx: leave the page alone) until the channel is
// confirmed, then the fragment itself so the box turns green without a reload.
// Never re-renders an unconfirmed box: that would clobber whatever the person is
// editing in the same form every few seconds.
func (s *Server) ntfyStatus(w http.ResponseWriter, r *http.Request) {
	user, _, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	pref, err := s.store.GetNotifyPref(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !pref.NtfyConfirmed() {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.renderNotify(w, r, user, pref, "Your phone is confirmed.", "")
}

// connectionView is one non-current tenant's connection card on Settings.
type connectionView struct {
	ID, Name      string
	AutoReconnect bool
	RelinkBy      string
}
