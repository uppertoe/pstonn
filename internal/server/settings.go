package server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// settingsPage shows the council connection, re-authorise deadline, and account
// controls.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "settings")
	if !ok {
		return
	}
	ctx := r.Context()
	owner := base.Owner
	user := base.User.Email // the signed-in person; notification prefs are theirs
	if cs, err := s.store.GetCouncilSession(ctx, owner); err == nil {
		base.CouncilLinked = true
		base.AutoReconnect = cs.Password != ""
		if !cs.LinkedAt.IsZero() && s.cfg.Council.SessionMaxAge > 0 {
			base.RelinkBy = cs.LinkedAt.Add(s.cfg.Council.SessionMaxAge).In(s.cfg.DisplayLocation).Format("2 Jan 2006")
		}
		if base.AutoReconnect && !cs.ReconnectedAt.IsZero() {
			base.LastReconnect = cs.ReconnectedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006, 3:04pm")
		}
	}
	if r.URL.Query().Get("tested") == "1" {
		base.Flash = "Test notification sent."
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
	base.Notify = s.notifyViewOf(user, pref)
	// Terms acceptance is per person; show the signed-in user's own consent.
	if c, err := s.store.LatestConsent(ctx, base.User.Email); err == nil {
		base.Terms.Accepted = fmt.Sprintf("v%s on %s", c.Version, c.AgreedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006"))
	}
	base.Terms.Clauses = s.terms.Clauses
	// Shared access: the owner sees who has access; a secondary sees whose account.
	if base.IsPrimary {
		if ms, err := s.store.ListMembers(ctx, owner); err == nil {
			for _, m := range ms {
				base.Members = append(base.Members, memberView{Email: m.Email, Added: m.AddedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006")})
			}
		}
	}
	s.render(w, base)
}

// renderNotify renders the swappable notifications fragment (auto-save target),
// or falls back to a redirect for a non-htmx request.
func (s *Server) renderNotify(w http.ResponseWriter, r *http.Request, user string, pref store.NotifyPref, status, errMsg string) {
	nv := s.notifyViewOf(user, pref)
	nv.Status, nv.Error = status, errMsg
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "notify-body", nv); err != nil {
			log.Printf("render notify-body: %v", err)
		}
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// saveNotify auto-saves the user's channel choices on every toggle, requiring at
// least one channel to stay on (else it reverts and warns).
func (s *Server) saveNotify(w http.ResponseWriter, r *http.Request) {
	user, _, _ := s.resolveAccount(r.Context())
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
	pref.EmailEnabled, pref.NtfyEnabled = email, ntfy
	// Quiet hours: hold overnight notices and deliver them at a chosen local hour.
	nudged := false
	if r.FormValue("quiet_enabled") != "" {
		pref.QuietFrom = clampHour(r.FormValue("quiet_from"), 22)
		pref.QuietUntil = clampHour(r.FormValue("quiet_until"), 6)
		if pref.QuietFrom == pref.QuietUntil {
			pref.QuietUntil = (pref.QuietFrom + 1) % 24 // equal would disable; nudge apart
			nudged = true
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
		s.renderNotify(w, r, user, pref, "The two times must differ; end time moved.", "")
		return
	}
	s.renderNotify(w, r, user, pref, "Saved", "")
}

// regenTopic gives the signed-in user a fresh personal ntfy topic (live), enabling ntfy.
func (s *Server) regenTopic(w http.ResponseWriter, r *http.Request) {
	user, _, _ := s.resolveAccount(r.Context())
	pref, err := s.store.GetNotifyPref(r.Context(), user)
	if err != nil {
		s.serverError(w, err)
		return
	}
	pref.Owner, pref.NtfyTopic, pref.NtfyEnabled = user, notify.RandomTopic(), true
	if err := s.store.SetNotifyPref(r.Context(), pref); err != nil {
		s.serverError(w, err)
		return
	}
	s.renderNotify(w, r, user, pref, "New topic. Re-subscribe in the ntfy app.", "")
}

// testNotify sends a test message on the signed-in user's own enabled channels.
func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	user, _, _ := s.resolveAccount(r.Context())
	if err := s.notify.SendTest(r.Context(), user); err != nil {
		// Details (SMTP hosts, dial errors, ntfy URLs) go to the log, not the
		// browser.
		log.Printf("test notify %s: %v", user, err)
		s.message(w, http.StatusBadGateway, "Couldn't send the test notification. Check your channels in Settings, and ask the operator to check the logs if it keeps failing.")
		return
	}
	http.Redirect(w, r, "/settings?tested=1", http.StatusSeeOther)
}
