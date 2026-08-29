// Package server wires the HTTP routes and renders the dashboard. User identity
// is resolved by identity.Middleware (forward_auth headers, else the app's own
// OIDC session cookie, else a dev fallback); mutating routes require a
// signed-in user and re-run the scheduler so changes take effect immediately.
package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/council"
	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/session"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/webauth"
)

// Council is everything the handlers need from a council connection. It is the
// server-side counterpart of scheduler.Council: the handlers never name the
// concrete client, so a per-council driver (or a multiplexer over several) can be
// substituted without touching them. *parking.Client satisfies it.
// See docs/council-connections.md.
type Council interface {
	// Link performs the credential login for owner with one tenant (council) and
	// stores the session; councilID "" means the owner's current tenant.
	Link(ctx context.Context, owner, councilID, username, password string, savePassword, interactive bool, expectedGen int64) error
	// Linked reports whether owner holds a session with the tenant.
	Linked(ctx context.Context, owner, councilID string) bool
	// ListPermitsComplete reads owner's permits with the tenant and reports whether the list was whole.
	ListPermitsComplete(ctx context.Context, owner, councilID string) ([]parking.PermitInfo, bool, error)
	// CurrentVehicleCached is the bounded-read plate lookup the pages use.
	CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (reg string, age time.Duration, fresh bool, err error)
	// RefreshFailingFor reports how long background plate refreshes have been failing.
	RefreshFailingFor(owner string, p model.Permit) time.Duration
	// ForgetPermit drops cached state for a permit the owner stopped managing.
	ForgetPermit(owner, councilID, councilPermitID string)
	SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error
	ClearVehicle(ctx context.Context, owner string, p model.Permit) error
	// Stats is the traffic / breaker snapshot shown on /status.
	Stats() parking.Stats
}

// The mux (what main wires) satisfies both interfaces; a mismatch is a compile
// error here, not a wiring failure in main.
var (
	_ Council           = (*council.Mux)(nil)
	_ scheduler.Council = (*council.Mux)(nil)
)

// Server holds the dependencies shared by the handlers.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	sessions *session.Manager
	auth     *webauth.Authenticator // nil when OIDC login is disabled
	council  Council                // nil only in tests that never touch the council
	councils *council.Registry      // the councils this process serves (names, links, permit policy)
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
	// admitMu serialises NEW-household admission: the capacity count and the council
	// link that consumes the slot must be one decision, or concurrent newcomers all
	// read 499 and all save. Held across the link (already globally serialised by the
	// council client's login flow, so this adds no contention in practice). Taken before
	// we know whether this is a signup or a re-link, so re-links serialise too; council
	// links are rare and already serialised downstream, so that costs nothing.
	admitMu sync.Mutex
	// testNotifyLimit throttles the on-demand "send test" button (per user): the
	// only authenticated control that sends mail whenever it is pressed.
	testNotifyLimit *rateLimiter
	// statusLimit throttles the machine status endpoint: its bearer token is the
	// only thing standing between a caller and the user roster.
	statusLimit *rateLimiter
	// authLogin throttles the OIDC login kickoff. It is anonymous and it WRITES
	// (a pending authorization row, plus a sweep of expired ones) on the single
	// SQLite connection the reconcile loop needs, so it cannot be the one public
	// route with no bound — a permit that stops being updated is a parking fine.
	authLogin *rateLimiter
	// sesHookLimit throttles the SNS bounce webhook. Verifying a message means
	// fetching a signing certificate, so an unthrottled caller who knows the topic
	// ARN (an identifier, not a secret) can turn one POST into one outbound TLS
	// request.
	sesHookLimit *rateLimiter
	// unsubLimit throttles the unsubscribe endpoint. It is deliberately outside the
	// CSRF gate (RFC 8058 one-click posts cross-origin), so this is the only thing
	// pacing a replay of a token that never expires.
	unsubLimit *rateLimiter
	// confirmLimit throttles the public renewal-confirm POST, whose single-use
	// token is the only thing gating a 90-day extension of a council session.
	confirmLimit *rateLimiter
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
	// decideKey verifies the signed no-sign-in approve/decline links in
	// guest-request emails (minted in internal/notify/decide.go).
	decideKey []byte
	// decideLimit throttles the decide-link endpoint; like unsubLimit it sits
	// outside the session/CSRF gate, so per-IP pacing is the only brake on
	// someone walking request ids under a forged or found link.
	decideLimit *rateLimiter
	// lastTouch throttles idle-clock writes: one per person per hour is ample
	// against a 90-day bound, and the store shares one connection with the
	// scheduler. Guarded by touchMu.
	touchMu   sync.Mutex
	lastTouch map[string]time.Time
	// renameAlertOnce paces the "council may have renamed permit types" operator
	// alert (see renderPicker): systemic, so once per process is enough.
	renameAlertOnce sync.Once
}

// maxConcurrentGuest is how many public guest requests may be in flight at once.
// Comfortably above real household use (a handful of visitors, each polling
// every 2.5s) and far below what it takes to saturate the DB connection.
const maxConcurrentGuest = 24

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, sessions *session.Manager, auth *webauth.Authenticator, council Council, councils *council.Registry, sched *scheduler.Scheduler, notifier *notify.Service, mail *mailer.Mailer, box *secretbox.Box) *Server {
	return &Server{
		cfg: cfg, store: st, sessions: sessions, auth: auth, council: council, councils: councils,
		sched: sched, notify: notifier, mail: mail, box: box, terms: loadTerms(cfg.TermsPath),
		contact:      newRateLimiter(3, 10*time.Minute),  // 3 messages / 10 min per IP
		inviteFanout: newRateLimiter(6, time.Hour),       // <=6 invite emails / hour per owner
		inviteTarget: newRateLimiter(1, 24*time.Hour),    // <=1 invite email / day per recipient
		guest:        newRateLimiter(20, 10*time.Minute), // 20 activation attempts / 10 min per IP
		// Reads/polls are legitimately frequent (the visitor page polls every
		// 2.5s = ~240 hits/10 min, and several visitors can share one NAT address),
		// so this is deliberately loose: it exists to stop a firehose from one
		// source, not to police normal polling.
		guestRead:    newRateLimiter(1200, 10*time.Minute),
		guestLinkOut: newRateLimiter(20, time.Hour),   // <=20 guest-link emails / hour per owner
		guestLinkTo:  newRateLimiter(5, 24*time.Hour), // <=5 guest-link emails / day per recipient
		// 4, not 5. The council's actual lockout policy is UNKNOWN — nothing in
		// the live captures shows one being tripped, and whether lockout is even
		// enabled is the council's server-side config. What is known: ASP.NET
		// Core Identity (which Duende sites commonly sit on) ships a default of
		// 5 failed attempts → lockout when enabled. Four stays strictly below
		// that default while giving one careful retry after the third rejection —
		// which is where a typo case converts (observed live 2026-08-11: a real
		// sign-up burned all three on what looked like retypes, hit the wall and
		// left). The backstop if the budget is ever exhausted anyway: this window
		// (15 min) outlasts ASP.NET Identity's default 5-minute lockout, so a
		// locked council account is unlocked again before we permit another try —
		// the throttle can never hold a lockout open.
		councilTry:      newRateLimiter(4, 15*time.Minute), // 4 council password attempts / 15 min per user
		testNotifyLimit: newRateLimiter(5, time.Hour),      // 5 test notifications / hour per user
		councilRead:     newRateLimiter(12, 5*time.Minute), // 12 uncached council reads / 5 min per user
		// The watchdog polls every 10 minutes, so this is ~30x real use: it exists
		// to stop the bearer token being brute-forced, not to pace the watchdog.
		statusLimit: newRateLimiter(30, 10*time.Minute), // 30 status polls / 10 min per IP
		// A real user clicks the emailed link once, maybe retries a couple of times.
		confirmLimit: newRateLimiter(10, 10*time.Minute), // 10 confirm attempts / 10 min per IP
		// A person signing in redirects once. Generous enough for a shared NAT
		// address, far below what it takes to make the state sweep hurt.
		authLogin: newRateLimiter(30, 10*time.Minute), // 30 login starts / 10 min per IP
		// SES delivers each event once and retries a handful of times; a real topic
		// produces nothing like this volume.
		sesHookLimit: newRateLimiter(60, 10*time.Minute), // 60 events / 10 min per IP
		// One click per email, plus a provider's one-click POST and the odd retry.
		unsubLimit:  newRateLimiter(20, 10*time.Minute), // 20 attempts / 10 min per IP
		decideLimit: newRateLimiter(20, 10*time.Minute), // 20 decide-link hits / 10 min per IP
		guestSlots:  make(chan struct{}, maxConcurrentGuest),
		snsCert:     newCertCache(),
		unsubKey:    notify.DeriveUnsubKey(cfg.DataEncryptionKey),
		decideKey:   notify.DeriveDecideKey(cfg.DataEncryptionKey),
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
		if !s.guestRead.allow(rateLimitKey(r)) {
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

// throttlePerIP wraps a public handler with a per-IP fixed-window limit, shedding
// with 429 + Retry-After. Tolerates a nil limiter (tests build a Server directly),
// because a throttle must never be the reason a public route panics.
func (s *Server) throttlePerIP(rl *rateLimiter, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(rateLimitKey(r)) {
			w.Header().Set("Retry-After", "60")
			s.message(w, http.StatusTooManyRequests, "Too many requests. Please wait a moment and try again.")
			return
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
		// Both of these are anonymous and both WRITE to the store (Login inserts a
		// pending authorization and sweeps expired ones; Callback consumes one), so
		// they are throttled like every other public route rather than left as the
		// one unbounded path onto the shared SQLite connection.
		mux.HandleFunc("GET /auth/login", s.throttlePerIP(s.authLogin, s.auth.Login))
		mux.HandleFunc("GET /auth/callback", s.throttlePerIP(s.authLogin, s.auth.Callback))
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
	mux.HandleFunc("POST /council/select", s.withConsent(s.councilSelect))
	mux.HandleFunc("POST /council/unlink", s.withUser(s.councilUnlink)) // allow leaving without re-consent
	mux.HandleFunc("POST /council/forget-password", s.withUser(s.councilForgetPassword))
	mux.HandleFunc("POST /account/delete", s.withUser(s.accountDelete)) // allow leaving without re-consent
	mux.HandleFunc("POST /account/members", s.withConsent(s.addMember))
	mux.HandleFunc("POST /account/members/remove", s.withConsent(s.removeMember))
	mux.HandleFunc("POST /account/leave", s.withUser(s.leaveAccount)) // secondary can always leave
	// Answering an invitation is the invited person's own consent step, and it must
	// stay reachable before they have accepted anything — so withUser, not
	// withConsent: a pending invite grants no access, and declining one should never
	// require agreeing to terms first.
	mux.HandleFunc("POST /account/invite/accept", s.withUser(s.acceptInvite))
	mux.HandleFunc("POST /account/invite/decline", s.withUser(s.declineInvite))
	mux.HandleFunc("GET /schedule/legend", s.withConsent(s.legendFragment))
	mux.HandleFunc("POST /notifications", s.withConsent(s.saveNotify))
	mux.HandleFunc("POST /notifications/resume-email", s.withConsent(s.resumeEmail))
	mux.HandleFunc("POST /notifications/regen-topic", s.withConsent(s.regenTopic))
	mux.HandleFunc("POST /notifications/test", s.withConsent(s.testNotify))
	// Public, token-only: the renewal-confirm link from the reminder email.
	mux.HandleFunc("GET /council/confirm", s.councilConfirm)
	mux.HandleFunc("POST /council/confirm", s.councilConfirmApply)

	// Public, signed-token: unsubscribe. GET confirms, POST acts (RFC 8058
	// one-click). No login — most recipients have no account.
	mux.HandleFunc("GET /u/{addr}/{token}", s.unsubscribePage)
	mux.HandleFunc("POST /u/{addr}/{token}", s.unsubscribeApply)
	// No-sign-in guest-request decide links from the notification email. Public
	// like /u/: the signed token is the authentication. Must be listed in the
	// Caddy @public matcher or the gateway bounces it to the login page.
	mux.HandleFunc("GET /r/{id}/{addr}/{token}", s.guestDecidePage)
	mux.HandleFunc("POST /r/{id}/{addr}/{token}", s.guestDecideApply)

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

	mux.HandleFunc("GET /{$}", s.landing) // public, not behind forward-auth
	// Catch-all 404: anything no route claims gets the styled message page
	// instead of the mux's bare text. Registered at "/" (the landing owns the
	// exact root via /{$}). Known trade: a wrong-METHOD request on a real path
	// now lands here as a 404 rather than the mux's automatic 405 — nothing
	// machine-facing relies on 405s, and a person sees the same "nothing here".
	mux.HandleFunc("/", s.notFound)
	mux.HandleFunc("GET /security", s.security)             // public
	mux.HandleFunc("GET /how", s.how)                       // public
	mux.HandleFunc("GET /faq", s.faq)                       // public
	mux.HandleFunc("GET /guide/{slug}", s.guide)            // public question pages
	mux.HandleFunc("GET /robots.txt", s.robotsTxt)          // public (SEO)
	mux.HandleFunc("GET /sitemap.xml", s.sitemapXML)        // public (SEO)
	mux.HandleFunc("GET /favicon.ico", s.faviconICO)        // public
	mux.HandleFunc("GET /site.webmanifest", s.siteManifest) // public
	mux.HandleFunc("GET /contact", s.contactPage)           // public
	mux.HandleFunc("POST /contact", s.submitContact)        // public, rate-limited
	mux.HandleFunc("GET /schedule", s.withUser(s.schedule)) // appShell gates internally too; wrapped for uniformity with the other app pages
	mux.HandleFunc("GET /vehicles", s.withUser(s.vehiclesPage))
	mux.HandleFunc("GET /activity", s.withUser(s.activityPage))
	mux.HandleFunc("GET /settings", s.withUser(s.settingsPage))
	mux.HandleFunc("GET /share", s.withConsent(s.sharePage))
	mux.HandleFunc("GET /share/card", s.withConsent(s.shareCard))
	mux.HandleFunc("POST /share/invite", s.withConsent(s.sendReferral))
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
	mux.HandleFunc("POST /permits/{id}/copy-offer/dismiss", s.withConsent(s.dismissCopyOffer))
	mux.HandleFunc("POST /permits/{id}/clear", s.withConsent(s.clearPermit))
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
