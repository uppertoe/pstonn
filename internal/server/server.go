// Package server wires the HTTP routes and renders the dashboard. User identity
// is resolved by identity.Middleware (forward_auth headers, else the app's own
// OIDC session cookie, else a dev fallback); mutating routes require a
// signed-in user and re-run the scheduler so changes take effect immediately.
package server

import (
	"net/http"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/session"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/webauth"
)

// Server holds the dependencies shared by the handlers.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	sessions *session.Manager
	auth     *webauth.Authenticator // nil when OIDC login is disabled
	council  *parking.Client
	sched    *scheduler.Scheduler
	notify   *notify.Service
	mail     *mailer.Mailer // nil when SMTP is unconfigured; used by the contact form
	box      *secretbox.Box // at-rest cipher; seals the reprintable door-QR token
	terms    Terms
	contact  *rateLimiter // per-IP throttle on the public contact form
	// invite-email throttles so a primary can't email-bomb an address or mass-send
	// via SMTP: fanout caps per-owner sends, target dedups per recipient.
	inviteFanout *rateLimiter
	inviteTarget *rateLimiter
	guest        *rateLimiter // per-IP throttle on the public guest-activation link
	councilTry   *rateLimiter // per-user throttle on council password attempts (councilLink)
}

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, sessions *session.Manager, auth *webauth.Authenticator, council *parking.Client, sched *scheduler.Scheduler, notifier *notify.Service, mail *mailer.Mailer, box *secretbox.Box) *Server {
	return &Server{
		cfg: cfg, store: st, sessions: sessions, auth: auth, council: council,
		sched: sched, notify: notifier, mail: mail, box: box, terms: loadTerms(cfg.TermsPath),
		contact:      newRateLimiter(3, 10*time.Minute),  // 3 messages / 10 min per IP
		inviteFanout: newRateLimiter(6, time.Hour),       // <=6 invite emails / hour per owner
		inviteTarget: newRateLimiter(1, 24*time.Hour),    // <=1 invite email / day per recipient
		guest:        newRateLimiter(20, 10*time.Minute), // 20 activation attempts / 10 min per IP
		councilTry:   newRateLimiter(5, 15*time.Minute),  // 5 council password attempts / 15 min per user
	}
}

// Handler builds the routed, identity-aware http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.Handle("GET /static/", cacheStatic(http.StripPrefix("/static/", http.FileServerFS(staticSub))))

	if s.auth != nil {
		mux.HandleFunc("GET /auth/login", s.auth.Login)
		mux.HandleFunc("GET /auth/callback", s.auth.Callback)
		// Logout stays a GET (it is linked, not a form) but requires a same-origin
		// Origin/Referer: without it any third-party page (or a link prefetcher)
		// could embed /auth/logout and forcibly sign users out. App pages send a
		// Referer under our same-origin Referrer-Policy, so real clicks pass.
		mux.HandleFunc("GET /auth/logout", func(w http.ResponseWriter, r *http.Request) {
			if !sameOrigin(r) {
				s.message(w, http.StatusForbidden, "Sign out using the link inside the app.")
				return
			}
			s.auth.Logout(w, r)
		})
	}

	mux.HandleFunc("POST /terms/accept", s.withUser(s.acceptTerms))
	mux.HandleFunc("POST /terms/decline", s.withUser(s.declineTerms))
	mux.HandleFunc("POST /council/link", s.withConsent(s.councilLink))
	mux.HandleFunc("POST /council/unlink", s.withUser(s.councilUnlink)) // allow leaving without re-consent
	mux.HandleFunc("POST /council/forget-password", s.withUser(s.councilForgetPassword))
	mux.HandleFunc("POST /account/delete", s.withUser(s.accountDelete)) // allow leaving without re-consent
	mux.HandleFunc("POST /account/members", s.withConsent(s.addMember))
	mux.HandleFunc("POST /account/members/remove", s.withConsent(s.removeMember))
	mux.HandleFunc("POST /account/leave", s.withUser(s.leaveAccount)) // secondary can always leave
	mux.HandleFunc("POST /notifications", s.withConsent(s.saveNotify))
	mux.HandleFunc("POST /notifications/regen-topic", s.withConsent(s.regenTopic))
	mux.HandleFunc("POST /notifications/test", s.withConsent(s.testNotify))
	// Public, token-only: the renewal-confirm link from the reminder email. It
	// carries a single-use token and requires no login (so it stays one click).
	mux.HandleFunc("GET /council/confirm", s.councilConfirm)

	// Public, token-only: the guest-pass activation link. GET renders a menu with
	// NO side effects (scanner/prefetch-safe); POST performs the activation.
	mux.HandleFunc("GET /g/{token}", s.guestPage)
	// Literal "manifest" first segment so it can't clash with /g/req/{id} (a
	// /g/{token}/manifest.webmanifest would overlap it and panic the mux). Stays
	// under /g/* so the public Caddy matcher covers it.
	mux.HandleFunc("GET /g/manifest/{token}", s.guestManifest)
	mux.HandleFunc("POST /g/{token}", s.guestActivate)
	mux.HandleFunc("POST /g/{token}/revert", s.guestRevert)
	mux.HandleFunc("GET /g/live/{token}", s.guestLive)
	// Public, nonce-gated: a printed-QR visitor polls their request's status here.
	mux.HandleFunc("GET /g/req/{id}", s.guestRequestStatus)

	mux.HandleFunc("GET /{$}", s.landing)                   // public, not behind forward-auth
	mux.HandleFunc("GET /about", s.about)                   // public
	mux.HandleFunc("GET /why", s.why)                       // public
	mux.HandleFunc("GET /contact", s.contactPage)           // public
	mux.HandleFunc("POST /contact", s.submitContact)        // public, rate-limited
	mux.HandleFunc("GET /schedule", s.withUser(s.schedule)) // appShell gates internally too; wrapped for uniformity with the other app pages
	mux.HandleFunc("GET /vehicles", s.withUser(s.vehiclesPage))
	mux.HandleFunc("GET /activity", s.withUser(s.activityPage))
	mux.HandleFunc("GET /settings", s.withUser(s.settingsPage))
	mux.HandleFunc("GET /admin", s.requireAdmin(s.adminPage))
	mux.HandleFunc("GET /status", s.statusJSON) // machine watchdog; bearer-token gated
	mux.HandleFunc("GET /permits/new", s.withUser(s.pickerPage))
	mux.HandleFunc("GET /permits/{id}/card", s.withUser(s.permitCard))
	mux.HandleFunc("GET /guests", s.withUser(s.guestsPage))
	mux.HandleFunc("GET /guests/{id}/edit", s.withUser(s.editGuestGrant))
	mux.HandleFunc("POST /guests", s.withConsent(s.createGuestGrant))
	mux.HandleFunc("POST /guests/qr", s.withConsent(s.showVisitorQR))
	mux.HandleFunc("POST /guests/printed", s.withConsent(s.showPrintedQR))
	mux.HandleFunc("GET /guests/door/{id}/view", s.withConsent(s.viewDoorQR))
	mux.HandleFunc("POST /guests/door/{id}/revoke", s.withConsent(s.revokeDoorQR))
	mux.HandleFunc("POST /guests/requests/{id}/approve", s.withConsent(s.approveGuestRequest))
	mux.HandleFunc("POST /guests/requests/{id}/deny", s.withConsent(s.denyGuestRequest))
	mux.HandleFunc("POST /guests/{id}", s.withConsent(s.updateGuestGrant))
	mux.HandleFunc("POST /guests/toggle", s.withConsent(s.toggleGuests))
	mux.HandleFunc("POST /guests/{id}/delete", s.withConsent(s.deleteGuestGrant))
	mux.HandleFunc("POST /guests/{id}/resend", s.withConsent(s.resendGuestLink))
	mux.HandleFunc("POST /guests/tokens/{tid}/revoke", s.withConsent(s.revokeGuestToken))
	mux.HandleFunc("POST /vehicles", s.withConsent(s.addVehicle))
	mux.HandleFunc("POST /vehicles/{id}/delete", s.withConsent(s.deleteVehicle))
	mux.HandleFunc("POST /vehicles/{id}/email", s.withConsent(s.setVehicleEmail))
	mux.HandleFunc("POST /permits", s.withConsent(s.addPermit))
	mux.HandleFunc("POST /permits/{id}/delete", s.withConsent(s.deletePermit))
	mux.HandleFunc("POST /permits/{id}/name", s.withConsent(s.renamePermit))
	mux.HandleFunc("POST /permits/{id}/rules", s.withConsent(s.setRule))
	mux.HandleFunc("POST /permits/{id}/copy-schedule", s.withConsent(s.copySchedule))
	mux.HandleFunc("POST /permits/{id}/override", s.withConsent(s.addOverride))
	mux.HandleFunc("POST /permits/{id}/overrides/{oid}/delete", s.withConsent(s.deleteOverride))

	var decode identity.Decoder
	if s.sessions != nil {
		decode = s.sessions.Decode
	}
	// Trust forward-auth Remote-* headers only when the app is NOT running its own
	// OIDC login (s.auth == nil). In OIDC mode the headers are ignored so they
	// cannot override the verified session cookie.
	trustForwardAuth := s.auth == nil
	return securityHeaders(identity.Middleware(s.cfg.DevIdentityEmail, decode, trustForwardAuth)(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
