// Package server wires the HTTP routes and renders the dashboard. User identity
// is resolved by identity.Middleware (forward_auth headers, else the app's own
// OIDC session cookie, else a dev fallback); mutating routes require a
// signed-in user and re-run the scheduler so changes take effect immediately.
package server

import (
	"net/http"
	"sync"
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
	guestRead    *rateLimiter // per-IP throttle on the public guest READ/poll endpoints
	guestLinkOut *rateLimiter // per-owner throttle on guest-pass link emails
	guestLinkTo  *rateLimiter // per-recipient throttle on guest-pass link emails
	councilTry   *rateLimiter // per-user throttle on council password attempts (councilLink)
	// testNotifyLimit throttles the on-demand "send test" button (per user): the
	// only authenticated control that sends mail whenever it is pressed.
	testNotifyLimit *rateLimiter
	// statusLimit throttles the machine status endpoint: its bearer token is the
	// only thing standing between a caller and the user roster.
	statusLimit *rateLimiter
	// councilRead throttles the two routes that make an UNCACHED, synchronous
	// council read (the permit picker and adding a permit). Every other council
	// read path has a cache and in-flight dedup; these did not, so one signed-in
	// user could turn HTTP requests into council requests one-for-one.
	councilRead *rateLimiter
	// guestSlots bounds CONCURRENT public guest requests. The store runs on a
	// single SQLite connection shared with the scheduler, so unbounded anonymous
	// reads don't merely slow pages down — they starve the reconcile loop, and a
	// permit that stops being updated is a parking fine. A door-QR token is
	// public by design (it's printed on a poster), so possession of a valid token
	// cannot be the only limit.
	guestSlots chan struct{}
	// snsCert caches SES/SNS signing certificates for the bounce webhook.
	snsCert *certCache
	// unsubKey verifies the signed per-address unsubscribe links in outgoing mail.
	unsubKey []byte
	// lastTouch throttles idle-clock writes: one per person per hour is ample
	// against a 90-day bound, and the store shares one connection with the
	// scheduler. Guarded by touchMu.
	touchMu   sync.Mutex
	lastTouch map[string]time.Time
}

// maxConcurrentGuest is how many public guest requests may be in flight at once.
// Comfortably above real household use (a handful of visitors, each polling
// every 2.5s) and far below what it takes to saturate the DB connection.
const maxConcurrentGuest = 24

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, sessions *session.Manager, auth *webauth.Authenticator, council *parking.Client, sched *scheduler.Scheduler, notifier *notify.Service, mail *mailer.Mailer, box *secretbox.Box) *Server {
	return &Server{
		cfg: cfg, store: st, sessions: sessions, auth: auth, council: council,
		sched: sched, notify: notifier, mail: mail, box: box, terms: loadTerms(cfg.TermsPath),
		contact:      newRateLimiter(3, 10*time.Minute),  // 3 messages / 10 min per IP
		inviteFanout: newRateLimiter(6, time.Hour),       // <=6 invite emails / hour per owner
		inviteTarget: newRateLimiter(1, 24*time.Hour),    // <=1 invite email / day per recipient
		guest:        newRateLimiter(20, 10*time.Minute), // 20 activation attempts / 10 min per IP
		// Reads/polls are legitimately frequent (the visitor page polls every
		// 2.5s = ~240 hits/10 min, and several visitors can share one NAT address),
		// so this is deliberately loose: it exists to stop a firehose from one
		// source, not to police normal polling.
		guestRead:       newRateLimiter(1200, 10*time.Minute),
		guestLinkOut:    newRateLimiter(20, time.Hour),     // <=20 guest-link emails / hour per owner
		guestLinkTo:     newRateLimiter(5, 24*time.Hour),   // <=5 guest-link emails / day per recipient
		councilTry:      newRateLimiter(5, 15*time.Minute), // 5 council password attempts / 15 min per user
		testNotifyLimit: newRateLimiter(5, time.Hour),      // 5 test notifications / hour per user
		councilRead:     newRateLimiter(12, 5*time.Minute), // 12 uncached council reads / 5 min per user
		guestSlots:      make(chan struct{}, maxConcurrentGuest),
		snsCert:         newCertCache(),
		unsubKey:        notify.DeriveUnsubKey(cfg.DataEncryptionKey),
	}
}

// publicGuest wraps a public /g/* handler with the global concurrency cap and a
// loose per-IP read throttle. Shedding with 503 + Retry-After is the honest
// answer under overload: the alternative is queueing on the single DB
// connection, which stalls the scheduler for every user.
// Tolerates a zero-valued Server (tests construct one directly): a nil limiter
// or semaphore simply means "no shedding", never a panic on a public route.
func (s *Server) publicGuest(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.guestRead.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			s.message(w, http.StatusTooManyRequests, "Too many requests. Please wait a moment and reload.")
			return
		}
		if s.guestSlots != nil {
			select {
			case s.guestSlots <- struct{}{}:
				defer func() { <-s.guestSlots }()
			default:
				w.Header().Set("Retry-After", "5")
				s.message(w, http.StatusServiceUnavailable, "p.stonn is busy right now. Please reload in a few seconds.")
				return
			}
		}
		h(w, r)
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
	// Public, token-only: the renewal-confirm link from the reminder email.
	mux.HandleFunc("GET /council/confirm", s.councilConfirm)
	mux.HandleFunc("POST /council/confirm", s.councilConfirmApply)

	// Public, signed-token: unsubscribe. GET confirms, POST acts (RFC 8058
	// one-click). No login — most recipients have no account.
	mux.HandleFunc("GET /u/{addr}/{token}", s.unsubscribePage)
	mux.HandleFunc("POST /u/{addr}/{token}", s.unsubscribeApply)

	// Public, signature-verified: SES bounce/complaint events via SNS. Registered
	// only when a topic ARN is configured, so an unwired deployment 404s rather
	// than exposing an idle handler. SNS cannot send a bearer token, so trust
	// comes from the message signature + topic ARN (see sesHook).
	if s.cfg.SESHookEnabled() {
		mux.HandleFunc("POST /hooks/ses", s.sesHook)
	}

	// Public, token-only: the guest-pass activation link. GET renders a menu with
	// NO side effects (scanner/prefetch-safe); POST performs the activation.
	mux.HandleFunc("GET /g/{token}", s.publicGuest(s.guestPage))
	// Literal "manifest" first segment so it can't clash with /g/req/{id} (a
	// /g/{token}/manifest.webmanifest would overlap it and panic the mux). Stays
	// under /g/* so the public Caddy matcher covers it.
	mux.HandleFunc("GET /g/manifest/{token}", s.publicGuest(s.guestManifest))
	mux.HandleFunc("POST /g/{token}", s.publicGuest(s.guestActivate))
	mux.HandleFunc("POST /g/{token}/revert", s.publicGuest(s.guestRevert))
	mux.HandleFunc("GET /g/live/{token}", s.publicGuest(s.guestLive))
	// Public, nonce-gated: a printed-QR visitor polls their request's status here.
	mux.HandleFunc("GET /g/req/{id}", s.publicGuest(s.guestRequestStatus))

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
	mux.HandleFunc("GET /permits/{id}/card", s.withConsent(s.permitCard))
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
