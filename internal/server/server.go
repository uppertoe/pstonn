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
	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/scheduler"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/session"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
	"github.com/uppertoe/pstonn/internal/webauth"
)

// Tenant is everything the handlers need from a tenant connection. It is the
// server-side counterpart of scheduler.Tenant: the handlers never name the
// concrete client, so a per-tenant driver (or a multiplexer over several) can be
// substituted without touching them. *parking.Client satisfies it.
// See docs/council-connections.md.
type Tenant interface {
	// Link performs the credential login for owner with one tenant (tenant) and
	// stores the session; tenantID "" means the owner's current tenant.
	Link(ctx context.Context, owner, tenantID, username, password string, savePassword, interactive bool, expectedGen int64) error
	// Linked reports whether owner holds a session with the tenant.
	Linked(ctx context.Context, owner, tenantID string) bool
	// ListPermitsComplete reads owner's permits with the tenant and reports whether the list was whole.
	ListPermitsComplete(ctx context.Context, owner, tenantID string) ([]parking.PermitInfo, bool, error)
	// CurrentVehicleCached is the bounded-read plate lookup the pages use.
	CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (reg string, age time.Duration, fresh bool, err error)
	// RefreshFailingFor reports how long background plate refreshes have been failing.
	RefreshFailingFor(owner string, p model.Permit) time.Duration
	// ForgetPermit drops cached state for a permit the owner stopped managing.
	ForgetPermit(owner, tenantID, tenantPermitID string)
	SetVehicle(ctx context.Context, owner string, p model.Permit, registration, region string) error
	ClearVehicle(ctx context.Context, owner string, p model.Permit) error
	// Capabilities is what the named tenant's portal supports (tenantID "" =
	// the owner's current tenant); pages adapt to it rather than assume.
	Capabilities(ctx context.Context, owner, tenantID string) provider.Capabilities
	// Regions are the registration jurisdictions a vehicle's state may be, for
	// the chooser: the named tenant's (a permit-scoped page passes its permit's
	// tenant), or with "" the union over every tenant served (the account-wide
	// vehicles page). Empty = no such concept, so no chooser.
	Regions(ctx context.Context, owner, tenantID string) []provider.Region
	// RegionValid reports whether a submitted state code is one the named tenant
	// offers ("" — the tenant home state — is always valid).
	RegionValid(ctx context.Context, owner, tenantID, code string) bool
	// Stats is the traffic / breaker snapshot shown on /status.
	Stats() parking.Stats
	// Blocked (fleet edge breaker open) and AuthGated (auth circuit open) report a
	// CONFIRMED, sustained council outage for the named tenant — as opposed to a
	// brief blip — so a synchronous handler (a guest activating at the kerb) can say
	// the council is down rather than showing an optimistic "being applied".
	Blocked(tenantID string) bool
	AuthGated(tenantID string) bool
}

// The mux (what main wires) satisfies both interfaces; a mismatch is a compile
// error here, not a wiring failure in main.
var (
	_ Tenant           = (*tenant.Mux)(nil)
	_ scheduler.Tenant = (*tenant.Mux)(nil)
)

// Server holds the dependencies shared by the handlers.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	sessions *session.Manager
	auth     *webauth.Authenticator // nil when OIDC login is disabled
	tenant   Tenant                 // nil only in tests that never touch the tenant
	registry *tenant.Registry       // the registry this process serves (names, links, permit policy)
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
	tenantTry    *rateLimiter // per-user throttle on tenant password attempts (tenantLink)
	// admitMu serialises NEW-household admission: the capacity count and the tenant
	// link that consumes the slot must be one decision, or concurrent newcomers all
	// read 499 and all save. Held across the link (already globally serialised by the
	// tenant client's login flow, so this adds no contention in practice). Taken before
	// we know whether this is a signup or a re-link, so re-links serialise too; tenant
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
	// token is the only thing gating a 90-day extension of a tenant session.
	confirmLimit *rateLimiter
	// tenantRead throttles the two routes that make an UNCACHED, synchronous
	// tenant read (the permit picker and adding a permit). Every other tenant
	// read path has a cache and in-flight dedup; these did not, so one signed-in
	// user could turn HTTP requests into tenant requests one-for-one.
	tenantRead *rateLimiter
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
	// routes records every func route registered by Handler with the access guard
	// it sits behind, so the guard choice is data a test can assert over rather than
	// a property re-derived by reading Handler by eye. Rebuilt on each Handler call.
	// See handle and TestMutatingRoutesAreGuarded.
	routes []routeInfo
}

// guardKind tags a route with the access wrapper Handler registers it behind.
type guardKind int

const (
	// guardPublic applies no auth wrapper: truly public pages, routes whose auth is
	// a signed token or an internal bearer check (/status), and handlers the caller
	// has already wrapped (publicGuest, throttlePerIP). CSRF-exempt by design.
	guardPublic guardKind = iota
	// guardUser is withUser: signed in, with the CSRF same-origin check on mutations,
	// but no terms-consent gate — for the actions that must work before/around consent
	// (accept/decline terms, answer an invite, leave/unlink/delete).
	guardUser
	// guardConsent is withConsent: guardUser plus the terms-acceptance gate. The
	// default for any route that stores or changes account data.
	guardConsent
	// guardAdmin is requireAdmin: signed in and in the admin group.
	guardAdmin
)

type routeInfo struct {
	methodPattern string
	guard         guardKind
}

// handle registers one func route and records its guard. Centralising the
// guard→wrapper mapping means the wrapper can never disagree with the recorded
// tag the tests assert over. guardPublic passes the handler through untouched, so
// a caller may hand it a handler it has already wrapped (publicGuest / throttle).
func (s *Server) handle(mux *http.ServeMux, methodPattern string, guard guardKind, h http.HandlerFunc) {
	s.routes = append(s.routes, routeInfo{methodPattern, guard})
	switch guard {
	case guardUser:
		h = s.withUser(h)
	case guardConsent:
		h = s.withConsent(h)
	case guardAdmin:
		h = s.requireAdmin(h)
	case guardPublic:
		// no wrapper: public, token/bearer-authenticated, or already wrapped
	}
	mux.HandleFunc(methodPattern, h)
}

// maxConcurrentGuest is how many public guest requests may be in flight at once.
// Comfortably above real household use (a handful of visitors, each polling
// every 2.5s) and far below what it takes to saturate the DB connection.
const maxConcurrentGuest = 24

// New constructs a Server.
func New(cfg *config.Config, st *store.Store, sessions *session.Manager, auth *webauth.Authenticator, tenant Tenant, registry *tenant.Registry, sched *scheduler.Scheduler, notifier *notify.Service, mail *mailer.Mailer, box *secretbox.Box) *Server {
	return &Server{
		cfg: cfg, store: st, sessions: sessions, auth: auth, tenant: tenant, registry: registry,
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
		// 4, not 5. The tenant's actual lockout policy is UNKNOWN — nothing in
		// the live captures shows one being tripped, and whether lockout is even
		// enabled is the tenant's server-side config. What is known: ASP.NET
		// Core Identity (which Duende sites commonly sit on) ships a default of
		// 5 failed attempts → lockout when enabled. Four stays strictly below
		// that default while giving one careful retry after the third rejection —
		// which is where a typo case converts (observed live 2026-08-11: a real
		// sign-up burned all three on what looked like retypes, hit the wall and
		// left). The backstop if the budget is ever exhausted anyway: this window
		// (15 min) outlasts ASP.NET Identity's default 5-minute lockout, so a
		// locked tenant account is unlocked again before we permit another try —
		// the throttle can never hold a lockout open.
		tenantTry:       newRateLimiter(4, 15*time.Minute), // 4 tenant password attempts / 15 min per user
		testNotifyLimit: newRateLimiter(5, time.Hour),      // 5 test notifications / hour per user
		tenantRead:      newRateLimiter(12, 5*time.Minute), // 12 uncached tenant reads / 5 min per user
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

// Handler builds the routed, identity-aware http.Handler. Every func route is
// registered through s.handle with an explicit guardKind, so the access wrapper
// each one sits behind is recorded data (see s.routes) that the tests assert over
// rather than a property re-derived by reading this method line by line.
func (s *Server) Handler() http.Handler {
	s.routes = s.routes[:0]
	mux := http.NewServeMux()
	s.handle(mux, "GET /healthz", guardPublic, s.health)
	mux.Handle("GET /static/app.css", cacheStatic(http.HandlerFunc(serveAppCSS)))
	mux.Handle("GET /static/", cacheStatic(http.StripPrefix("/static/", http.FileServerFS(staticSub))))

	if s.auth != nil {
		// Both of these are anonymous and both WRITE to the store (Login inserts a
		// pending authorization and sweeps expired ones; Callback consumes one), so
		// they are throttled like every other public route rather than left as the
		// one unbounded path onto the shared SQLite connection.
		s.handle(mux, "GET /auth/login", guardPublic, s.throttlePerIP(s.authLogin, s.auth.Login))
		s.handle(mux, "GET /auth/callback", guardPublic, s.throttlePerIP(s.authLogin, s.auth.Callback))
		// Logout stays a GET (it is linked, not a form) but requires a same-origin
		// Origin/Referer: without it any third-party page (or a link prefetcher)
		// could embed /auth/logout and forcibly sign users out. App pages send a
		// Referer under our same-origin Referrer-Policy, so real clicks pass.
		s.handle(mux, "GET /auth/logout", guardPublic, func(w http.ResponseWriter, r *http.Request) {
			if !sameOrigin(r) {
				s.message(w, http.StatusForbidden, "Sign out using the link inside the app.")
				return
			}
			s.auth.Logout(w, r)
		})
	}

	s.handle(mux, "POST /terms/accept", guardUser, s.acceptTerms)
	s.handle(mux, "POST /terms/decline", guardUser, s.declineTerms)
	s.handle(mux, "POST /tenant/link", guardConsent, s.tenantLink)
	s.handle(mux, "POST /tenant/select", guardConsent, s.tenantSelect)
	s.handle(mux, "GET /tenant/connect", guardUser, s.connectArea)
	s.handle(mux, "POST /tenant/unlink", guardUser, s.tenantUnlink) // allow leaving without re-consent
	s.handle(mux, "POST /tenant/forget-password", guardUser, s.tenantForgetPassword)
	s.handle(mux, "POST /account/delete", guardUser, s.accountDelete) // allow leaving without re-consent
	s.handle(mux, "POST /account/members", guardConsent, s.addMember)
	s.handle(mux, "POST /account/members/remove", guardConsent, s.removeMember)
	s.handle(mux, "POST /account/leave", guardUser, s.leaveAccount) // secondary can always leave
	// Answering an invitation is the invited person's own consent step, and it must
	// stay reachable before they have accepted anything — so withUser, not
	// withConsent: a pending invite grants no access, and declining one should never
	// require agreeing to terms first.
	s.handle(mux, "POST /account/invite/accept", guardUser, s.acceptInvite)
	s.handle(mux, "POST /account/invite/decline", guardUser, s.declineInvite)
	s.handle(mux, "GET /schedule/legend", guardConsent, s.legendFragment)
	s.handle(mux, "POST /notifications", guardConsent, s.saveNotify)
	s.handle(mux, "POST /notifications/resume-email", guardConsent, s.resumeEmail)
	s.handle(mux, "POST /notifications/regen-topic", guardConsent, s.regenTopic)
	s.handle(mux, "POST /notifications/test", guardConsent, s.testNotify)
	s.handle(mux, "POST /notifications/test-push", guardConsent, s.testPush)
	s.handle(mux, "GET /notifications/ntfy-status", guardConsent, s.ntfyStatus)
	// Public, token-only: the Confirm button on a test push, posted by the ntfy app
	// from the phone (no session). Must be listed as public at the proxy.
	s.handle(mux, "POST /ntfy/confirm/{token}", guardPublic, s.ntfyConfirm)
	// Public, token-only: the renewal-confirm link from the reminder email.
	s.handle(mux, "GET /tenant/confirm", guardPublic, s.tenantConfirm)
	// The renewal-confirm link is in emails already sent under the old path; keep it answering.
	s.handle(mux, "GET /council/confirm", guardPublic, s.tenantConfirm)
	s.handle(mux, "POST /tenant/confirm", guardPublic, s.tenantConfirmApply)
	s.handle(mux, "POST /council/confirm", guardPublic, s.tenantConfirmApply)

	// Public, signed-token: unsubscribe. GET confirms, POST acts (RFC 8058
	// one-click). No login — most recipients have no account.
	s.handle(mux, "GET /u/{addr}/{token}", guardPublic, s.unsubscribePage)
	s.handle(mux, "POST /u/{addr}/{token}", guardPublic, s.unsubscribeApply)
	// No-sign-in guest-request decide links from the notification email. Public
	// like /u/: the signed token is the authentication. Must be listed in the
	// Caddy @public matcher or the gateway bounces it to the login page.
	s.handle(mux, "GET /r/{id}/{addr}/{token}", guardPublic, s.guestDecidePage)
	s.handle(mux, "POST /r/{id}/{addr}/{token}", guardPublic, s.guestDecideApply)

	// Public, signature-verified: SES bounce/complaint events via SNS. Registered
	// only when a topic ARN is configured, so an unwired deployment 404s rather
	// than exposing an idle handler. SNS cannot send a bearer token, so trust
	// comes from the message signature + topic ARN (see sesHook).
	if s.cfg.SESHookEnabled() {
		s.handle(mux, "POST /hooks/ses", guardPublic, s.sesHook)
	}

	// Public, token-only: the guest-pass activation link. GET renders a menu with
	// NO side effects (scanner/prefetch-safe); POST performs the activation. The
	// handlers are pre-wrapped with publicGuest (concurrency cap + read throttle),
	// so they register as guardPublic.
	s.handle(mux, "GET /g/{token}", guardPublic, s.publicGuest(s.guestPage))
	// Literal "manifest" first segment so it can't clash with /g/req/{id} (a
	// /g/{token}/manifest.webmanifest would overlap it and panic the mux). Stays
	// under /g/* so the public Caddy matcher covers it.
	s.handle(mux, "GET /g/manifest/{token}", guardPublic, s.publicGuest(s.guestManifest))
	s.handle(mux, "POST /g/{token}", guardPublic, s.publicGuest(s.guestActivate))
	s.handle(mux, "POST /g/{token}/revert", guardPublic, s.publicGuest(s.guestRevert))
	s.handle(mux, "GET /g/live/{token}", guardPublic, s.publicGuest(s.guestLive))
	// Public, nonce-gated: a printed-QR visitor polls their request's status here.
	s.handle(mux, "GET /g/req/{id}", guardPublic, s.publicGuest(s.guestRequestStatus))

	s.handle(mux, "GET /{$}", guardPublic, s.landing) // public, not behind forward-auth
	// The landing page's Sign in button. A dedicated path, forward-auth gated at
	// the edge, that only ever bounces onward to the app: the button used to link
	// to /schedule, and when the edge started sending anonymous /schedule to the
	// landing page (shared-link hygiene) every sign-in silently looped back to the
	// landing page for two days (2026-08-28..30). A path whose one job is "start
	// signing in" cannot be caught by a rule about shared app URLs.
	s.handle(mux, "GET /signin", guardPublic, s.signin)
	// Catch-all 404: anything no route claims gets the styled message page
	// instead of the mux's bare text. Registered at "/" (the landing owns the
	// exact root via /{$}). Known trade: a wrong-METHOD request on a real path
	// now lands here as a 404 rather than the mux's automatic 405 — nothing
	// machine-facing relies on 405s, and a person sees the same "nothing here".
	s.handle(mux, "/", guardPublic, s.notFound)
	s.handle(mux, "GET /security", guardPublic, s.security) // public
	s.handle(mux, "GET /features", guardPublic, s.features) // public
	// The signed-in twin of /features. The edge's public block strips identity
	// on purpose, so /features itself can never know who you are; Caddy
	// redirects session-cookie holders here, where the protected catch-all
	// delivers full identity and the same handler renders the app chrome.
	s.handle(mux, "GET /features/app", guardPublic, s.features)
	s.handle(mux, "GET /how", guardPublic, s.howRedirect)               // public; the page's old address
	s.handle(mux, "GET /faq", guardPublic, s.faq)                       // public
	s.handle(mux, "GET /guide/{slug}", guardPublic, s.guide)            // public question pages
	s.handle(mux, "GET /robots.txt", guardPublic, s.robotsTxt)          // public (SEO)
	s.handle(mux, "GET /sitemap.xml", guardPublic, s.sitemapXML)        // public (SEO)
	s.handle(mux, "GET /favicon.ico", guardPublic, s.faviconICO)        // public
	s.handle(mux, "GET /site.webmanifest", guardPublic, s.siteManifest) // public
	s.handle(mux, "GET /contact", guardPublic, s.contactPage)           // public
	s.handle(mux, "POST /contact", guardPublic, s.submitContact)        // public, rate-limited
	s.handle(mux, "GET /schedule", guardUser, s.schedule)               // appShell gates internally too; wrapped for uniformity with the other app pages
	s.handle(mux, "GET /vehicles", guardUser, s.vehiclesPage)
	s.handle(mux, "GET /activity", guardUser, s.activityPage)
	s.handle(mux, "GET /settings", guardUser, s.settingsPage)
	s.handle(mux, "GET /share", guardConsent, s.sharePage)
	s.handle(mux, "GET /share/card", guardConsent, s.shareCard)
	s.handle(mux, "POST /share/invite", guardConsent, s.sendReferral)
	s.handle(mux, "GET /admin", guardAdmin, s.adminPage)
	s.handle(mux, "GET /status", guardPublic, s.statusJSON) // machine watchdog; bearer-token gated
	s.handle(mux, "GET /permits/new", guardUser, s.pickerPage)
	s.handle(mux, "GET /permits/{id}/card", guardConsent, s.permitCard)
	s.handle(mux, "GET /guests", guardUser, s.guestsPage)
	s.handle(mux, "GET /guests/{id}/edit", guardUser, s.editGuestGrant)
	s.handle(mux, "POST /guests", guardConsent, s.createGuestGrant)
	s.handle(mux, "POST /guests/qr", guardConsent, s.showVisitorQR)
	s.handle(mux, "POST /guests/printed", guardConsent, s.showPrintedQR)
	s.handle(mux, "GET /guests/door/{id}/view", guardConsent, s.viewDoorQR)
	s.handle(mux, "POST /guests/door/{id}/revoke", guardConsent, s.revokeDoorQR)
	s.handle(mux, "POST /guests/requests/{id}/approve", guardConsent, s.approveGuestRequest)
	s.handle(mux, "POST /guests/requests/{id}/deny", guardConsent, s.denyGuestRequest)
	s.handle(mux, "POST /guests/{id}", guardConsent, s.updateGuestGrant)
	s.handle(mux, "POST /guests/toggle", guardConsent, s.toggleGuests)
	s.handle(mux, "POST /guests/{id}/delete", guardConsent, s.deleteGuestGrant)
	s.handle(mux, "POST /guests/{id}/resend", guardConsent, s.resendGuestLink)
	s.handle(mux, "POST /guests/tokens/{tid}/revoke", guardConsent, s.revokeGuestToken)
	s.handle(mux, "POST /vehicles", guardConsent, s.addVehicle)
	s.handle(mux, "POST /vehicles/{id}/delete", guardConsent, s.deleteVehicle)
	s.handle(mux, "POST /vehicles/{id}/email", guardConsent, s.setVehicleEmail)
	s.handle(mux, "POST /vehicles/{id}/notify", guardConsent, s.setVehicleNotify)
	s.handle(mux, "POST /permits", guardConsent, s.addPermit)
	s.handle(mux, "POST /permits/{id}/delete", guardConsent, s.deletePermit)
	s.handle(mux, "POST /permits/{id}/name", guardConsent, s.renamePermit)
	s.handle(mux, "POST /permits/{id}/rules", guardConsent, s.setRule)
	s.handle(mux, "POST /permits/{id}/weeks/add", guardConsent, s.addCycleWeek)
	s.handle(mux, "POST /permits/{id}/weeks/remove", guardConsent, s.removeCycleWeek)
	s.handle(mux, "POST /permits/{id}/weeks/restore", guardConsent, s.restoreCycleWeek)
	s.handle(mux, "POST /permits/{id}/copy-schedule", guardConsent, s.copySchedule)
	s.handle(mux, "POST /permits/{id}/copy-offer/dismiss", guardConsent, s.dismissCopyOffer)
	s.handle(mux, "POST /permits/{id}/clear", guardConsent, s.clearPermit)
	s.handle(mux, "POST /permits/{id}/override", guardConsent, s.addOverride)
	s.handle(mux, "POST /permits/{id}/overrides/{oid}/delete", guardConsent, s.deleteOverride)

	var decode identity.Decoder
	if s.sessions != nil {
		decode = s.sessions.Decode
	}
	// Trust forward-auth Remote-* headers only when the app is NOT running its own
	// OIDC login (s.auth == nil). In OIDC mode the headers are ignored so they
	// cannot override the verified session cookie.
	trustForwardAuth := s.auth == nil
	return securityHeaders(identity.Middleware(s.cfg.DevIdentityEmail, decode, trustForwardAuth, s.cfg.ProxySecret)(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
