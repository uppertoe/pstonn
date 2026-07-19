// Package server wires the HTTP routes and renders the dashboard. User identity
// is resolved by identity.Middleware (forward_auth headers, else the app's own
// OIDC session cookie, else a dev fallback); mutating routes require a
// signed-in user and re-run the scheduler so changes take effect immediately.
package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
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
		mux.HandleFunc("GET /auth/logout", s.auth.Logout)
	}

	mux.HandleFunc("POST /terms/accept", s.withUser(s.acceptTerms))
	mux.HandleFunc("POST /terms/decline", s.withUser(s.declineTerms))
	mux.HandleFunc("POST /council/link", s.withConsent(s.councilLink))
	mux.HandleFunc("POST /council/unlink", s.withUser(s.councilUnlink)) // allow leaving without re-consent
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
	mux.HandleFunc("POST /g/{token}", s.guestActivate)
	// Public, nonce-gated: a printed-QR visitor polls their request's status here.
	mux.HandleFunc("GET /g/req/{id}", s.guestRequestStatus)

	mux.HandleFunc("GET /{$}", s.landing)            // public, not behind forward-auth
	mux.HandleFunc("GET /about", s.about)            // public
	mux.HandleFunc("GET /why", s.why)                // public
	mux.HandleFunc("GET /contact", s.contactPage)    // public
	mux.HandleFunc("POST /contact", s.submitContact) // public, rate-limited
	mux.HandleFunc("GET /schedule", s.schedule)
	mux.HandleFunc("GET /vehicles", s.withUser(s.vehiclesPage))
	mux.HandleFunc("GET /activity", s.withUser(s.activityPage))
	mux.HandleFunc("GET /settings", s.withUser(s.settingsPage))
	mux.HandleFunc("GET /permits/new", s.withUser(s.pickerPage))
	mux.HandleFunc("GET /guests", s.withUser(s.guestsPage))
	mux.HandleFunc("GET /guests/{id}/edit", s.withUser(s.editGuestGrant))
	mux.HandleFunc("POST /guests", s.withConsent(s.createGuestGrant))
	mux.HandleFunc("POST /guests/qr", s.withConsent(s.showVisitorQR))
	mux.HandleFunc("POST /guests/printed", s.withConsent(s.showPrintedQR))
	mux.HandleFunc("GET /guests/door/{id}/view", s.withConsent(s.viewDoorQR))
	mux.HandleFunc("POST /guests/door/{id}/replace", s.withConsent(s.replaceDoorQR))
	mux.HandleFunc("POST /guests/door/{id}/revoke", s.withConsent(s.revokeDoorQR))
	mux.HandleFunc("POST /guests/requests/{id}/approve", s.withConsent(s.approveGuestRequest))
	mux.HandleFunc("POST /guests/requests/{id}/deny", s.withConsent(s.denyGuestRequest))
	mux.HandleFunc("POST /guests/{id}", s.withConsent(s.updateGuestGrant))
	mux.HandleFunc("POST /guests/toggle", s.withConsent(s.toggleGuests))
	mux.HandleFunc("POST /guests/{id}/delete", s.withConsent(s.deleteGuestGrant))
	mux.HandleFunc("POST /guests/tokens/{tid}/revoke", s.withConsent(s.revokeGuestToken))
	mux.HandleFunc("POST /vehicles", s.withConsent(s.addVehicle))
	mux.HandleFunc("POST /vehicles/{id}/delete", s.withConsent(s.deleteVehicle))
	mux.HandleFunc("POST /vehicles/{id}/email", s.withConsent(s.setVehicleEmail))
	mux.HandleFunc("POST /permits", s.withConsent(s.addPermit))
	mux.HandleFunc("POST /permits/{id}/delete", s.withConsent(s.deletePermit))
	mux.HandleFunc("POST /permits/{id}/rules", s.withConsent(s.setRule))
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

// securityHeaders sets defensive response headers on every request. The CSP
// keeps all resource loads and form posts same-origin (blocking exfiltration and
// external form hijack) and forbids framing (clickjacking). Alpine needs
// 'unsafe-eval' and the few inline <script>/style blocks need 'unsafe-inline';
// everything else is locked to 'self'.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// staticSub serves the embedded assets rooted at the static/ directory.
var staticSub = mustSub(staticFS, "static")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// cacheStatic marks vendored assets cacheable long-term (they are versioned by
// the release image, so immutable within a deploy).
func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// logoutURL returns the sign-out link: the app's own OIDC logout when enabled,
// else the forward-auth provider's logout URL (vps-scaffold-auth). "" hides it.
func (s *Server) logoutURL() string {
	if s.auth != nil {
		return "/auth/logout"
	}
	return s.cfg.AuthLogoutURL
}

// landing is the PUBLIC marketing page (not behind forward-auth): what the app
// does and how, with a sign-in button. Signed-in visitors get an "Open the app"
// button instead.
func (s *Server) landing(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{
		State: "landing", OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(),
		SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation,
	})
}

// about is the PUBLIC page describing the security model and notifications
// frankly (no promises).
func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "about", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}

// why is the PUBLIC "how it works" page: a plain explainer, the animated demos,
// and how to get set up with a council ePermit.
func (s *Server) why(w http.ResponseWriter, r *http.Request) {
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "why", SignedIn: signedIn, Contact: s.cfg.ContactEnabled(), Loc: s.cfg.DisplayLocation})
}

// contactPage renders the PUBLIC contact form. When contact is not configured it
// redirects home rather than showing a dead form.
func (s *Server) contactPage(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ContactEnabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_, signedIn := identity.FromContext(r.Context())
	s.render(w, dashboardData{State: "contact", SignedIn: signedIn, Contact: true, Loc: s.cfg.DisplayLocation})
}

// submitContact validates and delivers a contact-form message to the operator
// (CONTACT_TO) over the existing SMTP mailer. It is public and unauthenticated,
// so it is rate-limited per IP and carries a honeypot field; the submitter's
// address, if given, becomes the Reply-To. No user address is ever exposed.
func (s *Server) submitContact(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.ContactEnabled() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !sameOrigin(r) {
		s.message(w, http.StatusForbidden, "This request could not be verified. Please reload the page and try again.")
		return
	}
	_, signedIn := identity.FromContext(r.Context())
	base := dashboardData{State: "contact", SignedIn: signedIn, Contact: true, Loc: s.cfg.DisplayLocation}

	if err := r.ParseForm(); err != nil {
		base.Warn = "Could not read the form. Please try again."
		s.render(w, base)
		return
	}
	// Honeypot: a hidden field real users leave blank. Pretend success on a hit.
	if strings.TrimSpace(r.PostForm.Get("website")) != "" {
		base.Flash = "Thanks. Your message has been sent."
		s.render(w, base)
		return
	}

	message := strings.TrimSpace(r.PostForm.Get("message"))
	replyTo := strings.TrimSpace(r.PostForm.Get("email"))
	base.ContactVal, base.ContactFrom = message, replyTo

	if len(message) < 10 {
		base.Warn = "Please enter a message of at least a few words."
		s.render(w, base)
		return
	}
	if len(message) > 4000 {
		base.Warn = "That message is too long. Please shorten it to under 4000 characters."
		s.render(w, base)
		return
	}
	if replyTo != "" && !looksLikeEmail(replyTo) {
		base.Warn = "That doesn't look like a valid email address. Leave it blank or correct it."
		s.render(w, base)
		return
	}
	if !s.contact.allow(clientIP(r)) {
		base.Warn = "You've sent a few messages already. Please wait a little while before sending another."
		s.render(w, base)
		return
	}

	body := message
	if replyTo != "" {
		body += "\n\nReply-to: " + replyTo
	} else {
		body += "\n\n(No reply address given.)"
	}
	if err := s.mail.SendWithReplyTo(s.cfg.ContactTo, replyTo, "p.stonn contact form", body); err != nil {
		log.Printf("contact form send failed: %v", err)
		base.Warn = "Sorry, the message could not be sent right now. Please try again later."
		s.render(w, base)
		return
	}
	base.ContactVal, base.ContactFrom = "", "" // clear on success
	base.Flash = "Thanks. Your message has been sent."
	s.render(w, base)
}

// user returns the signed-in identity, or redirects/errs and reports ok=false.
func (s *Server) user(w http.ResponseWriter, r *http.Request) (identity.User, bool) {
	if u, ok := identity.FromContext(r.Context()); ok {
		return u, true
	}
	if s.auth != nil {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	} else {
		s.message(w, http.StatusUnauthorized, "Sign-in isn't configured. Run behind the forward-auth layer, set APP_OIDC_*, or use DEV_IDENTITY_EMAIL for local use.")
	}
	return identity.User{}, false
}

// resolveAccount resolves which account the signed-in user acts within.
//   - user is the raw signed-in email (used for per-user consent and for audit).
//   - owner is the email that scopes all shared account data: the user's own
//     when they run their own account, or the primary they are a secondary of.
//   - isPrimary is false when the user is a secondary (a guest on someone's
//     account), which gates the owner-only actions (council link/unlink, account
//     delete, managing members).
func (s *Server) resolveAccount(ctx context.Context) (user, owner string, isPrimary bool) {
	u, _ := identity.FromContext(ctx)
	user = u.Email
	if primary, ok, err := s.store.MemberAccount(ctx, user); err == nil && ok && primary != "" {
		return user, primary, false
	}
	return user, user, true
}

func (s *Server) withUser(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.user(w, r); !ok {
			return
		}
		// CSRF: every authenticated mutation must come from our own origin. This
		// wraps all mutating routes (withConsent calls withUser), so a cross-site
		// POST can't trigger link/unlink/delete/schedule changes.
		if isStateChanging(r) && !sameOrigin(r) {
			s.message(w, http.StatusForbidden, "This request could not be verified. Please reload the page and try again.")
			return
		}
		h(w, r)
	}
}

// withConsent is withUser plus a terms-acceptance gate, used for every action
// that stores or changes user data (so nothing happens, and no council login is
// stored, before the user has accepted the current terms).
func (s *Server) withConsent(h http.HandlerFunc) http.HandlerFunc {
	return s.withUser(func(w http.ResponseWriter, r *http.Request) {
		u, _ := identity.FromContext(r.Context())
		if ok, _ := s.consentStatus(r.Context(), u.Email); !ok {
			redirectHome(w, r) // schedule handler re-renders the terms gate
			return
		}
		h(w, r)
	})
}

// consentStatus reports whether the user has accepted the CURRENT terms, and
// whether they had accepted an earlier version (so the UI can say "terms
// changed" rather than "welcome").
func (s *Server) consentStatus(ctx context.Context, owner string) (accepted bool, hadPrevious bool) {
	c, err := s.store.LatestConsent(ctx, owner)
	if err != nil {
		return false, false // never accepted
	}
	if c.Hash == s.terms.Hash() {
		return true, false
	}
	return false, true // accepted an older version; terms have changed
}

// acceptTerms records the user's acceptance of the current terms (all clauses
// must be ticked) and returns them to the app.
func (s *Server) acceptTerms(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromContext(r.Context())
	for i := range s.terms.Clauses {
		if r.FormValue(fmt.Sprintf("agree%d", i)) == "" {
			s.message(w, http.StatusBadRequest, "Please tick all three boxes to continue.")
			return
		}
	}
	if err := s.store.RecordConsent(r.Context(), u.Email, s.terms.Version, s.terms.Hash()); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}

// declineTerms handles a user declining updated terms. A primary has their
// council account disconnected (so the app stops acting without consent) and is
// notified. A secondary simply leaves the shared account (they never held the
// council connection), leaving the primary's account untouched.
func (s *Server) declineTerms(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	ctx := r.Context()

	if !isPrimary {
		if err := s.store.RemoveMembership(ctx, user); err != nil {
			s.serverError(w, err)
			return
		}
		log.Printf("secondary %s declined updated terms, left the shared account", user)
		msg := "You declined the updated terms, so your shared access has been removed. The account owner's data is unaffected."
		if s.logoutURL() != "" {
			msg += ` <a href="` + s.logoutURL() + `">Sign out</a>.`
		}
		s.message(w, http.StatusOK, msg)
		return
	}

	_, err := s.store.GetCouncilSession(ctx, user)
	wasLinked := err == nil
	if derr := s.store.DeleteCouncilSession(ctx, user); derr != nil {
		s.serverError(w, derr)
		return
	}
	if wasLinked {
		log.Printf("user %s declined updated terms, council account disconnected", user)
		go func() {
			nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if e := s.notify.NotifyDisconnected(nctx, user); e != nil {
				log.Printf("notify disconnect %s: %v", user, e)
			}
		}()
	}
	msg := "You declined the updated terms, so your council account has been disconnected and p.stonn is no longer managing your permit. Please check your visitor permit with the council."
	if s.logoutURL() != "" {
		msg += ` <a href="` + s.logoutURL() + `">Sign out</a>, or accept the terms below to reconnect.`
	}
	s.message(w, http.StatusOK, msg)
}

func (s *Server) requireAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.user(w, r)
		if !ok {
			return
		}
		if !u.IsAdmin() {
			s.message(w, http.StatusForbidden, "This action is limited to administrators.")
			return
		}
		h(w, r)
	}
}

// ---- view models ----

// vehiclePalette is a small, accessible categorical palette. Each vehicle is
// assigned a stable colour by its position in the owner's (ordered) vehicle
// list, so the same car reads identically everywhere, the core at-a-glance cue.
var vehiclePalette = []string{
	"#2f6feb", "#127a49", "#b54708", "#7a5af8",
	"#0e7490", "#be185d", "#4d7c0f", "#9333ea",
}

func vehicleColor(i int) string {
	if len(vehiclePalette) == 0 {
		return "#667085"
	}
	return vehiclePalette[i%len(vehiclePalette)]
}

func shortDay(w time.Weekday) string { return w.String()[:3] }

type dashboardData struct {
	User        identity.User
	OIDCEnabled bool
	State       string // "landing" | "terms" | "onboarding" | "picker" | "app"
	Page        string // when State=="app": "schedule" | "vehicles" | "activity" | "settings"
	LogoutURL   string // sign-out link (app OIDC or forward-auth provider); "" hides it
	SignedIn    bool   // landing: whether the visitor already has an identity
	Contact     bool   // whether the public contact link/form is available
	ContactVal  string // contact form: the message text to redisplay after a validation error
	ContactFrom string // contact form: the reply-to address to redisplay after a validation error
	Relink      bool   // council session expired → prompt re-link
	Flash       string // success (green)
	Warn        string // problem / caution (amber)
	Loc         *time.Location
	// shared access
	Owner      string       // effective account owner (email) that scopes the data
	IsPrimary  bool         // whether the signed-in user owns this account
	SharedWith string       // for a secondary: the primary account's email
	Members    []memberView // for a primary: the secondaries with access
	// dashboard state
	Vehicles []vehicleView
	Permits  []permitView
	Log      []store.ApplyRecord
	RelinkBy string     // human date the session must be re-authorised by ("" if unknown)
	Notify   notifyView // settings: notification channels
	Terms    termsView  // terms state + settings display
	// picker state
	Pick []pickView
	// guest passes
	Guests          []guestGrantView // management page: existing grants
	GuestsEnabled   bool             // kill-switch state (default on)
	PermitOpts      []permitOpt      // create-grant permit choices
	NewGuestLinks   []guestLinkView  // links shown once, right after a grant is created
	Edit            *editGrantView   // non-nil puts the pass form in edit mode
	QR              *qrShowView      // non-nil shows the on-screen visitor QR
	DoorQR          *doorQRView      // non-nil renders the printable door-QR poster (State "doorqr")
	DoorGrants      []doorGrantView  // durable door QRs in the management list
	PendingRequests []guestReqView   // printed-QR requests awaiting the holder's decision
	Guest           guestActView     // public activation menu (State "guest")
	Wait            *guestWaitView   // public "waiting for approval" page (State "guest-wait")
}

type termsView struct {
	Version  string
	Intro    string
	Clauses  []string
	Updated  bool   // re-consent (terms changed) vs first acceptance
	Accepted string // settings: "vX on 18 Jul 2026", "" if none
	OIDC     bool   // whether a sign-out option is available on the terms gate
}

type notifyView struct {
	EmailAvailable bool // operator configured SMTP
	NtfyAvailable  bool // operator configured an ntfy server
	EmailEnabled   bool
	NtfyEnabled    bool
	NtfyTopic      string
	NtfyBase       string
	UserEmail      string
	Shared         bool   // account has secondaries, so email goes to everyone with access
	Status         string // transient confirmation after auto-save
	Error          string // transient error (e.g. tried to turn everything off)
}

type vehicleView struct {
	ID           int64
	Label        string
	Registration string
	Color        string
	Email        string // optional driver email (shown on the Vehicles page)
}

type memberView struct {
	Email string
	Added string // human date the access was granted
}

type permitView struct {
	Permit        model.Permit
	DesiredReg    string
	DesiredSource string
	Days          []dayView
	Cal           []calView
	Overrides     []overrideView
	Vehicles      []vehicleView
	Loc           *time.Location
}

type dayView struct {
	PermitID   int64
	WeekdayNum int
	Name       string // short, e.g. "Mon"
	VehicleID  int64
	Reg        string
	Label      string
	Color      string
}

type calView struct {
	DayLabel  string // e.g. "Mon 21"
	Reg       string
	Color     string
	Source    string // "roster" | "override" | ""
	HasOneoff bool
	IsToday   bool
	Past      bool // earlier this week; shown dimmed for context
}

type overrideView struct {
	ID        int64
	PermitID  int64
	Reg       string
	Label     string
	Color     string
	StartsAt  time.Time
	EndsAt    *time.Time
	CreatedBy string
}

type pickView struct {
	CouncilPermitID string
	PermitTypeID    string
	PermitNumber    string
	PermitType      string
	CurrentRego     string
	Addable         bool   // a visitor permit whose vehicle the holder can change
	Reason          string // why it can't be added (shown greyed-out when !Addable)
}

// vehicleViews builds the per-user vehicle view models plus id→colour and
// id→registration lookups (colour is stable by list position).
func vehicleViews(vs []model.Vehicle) (views []vehicleView, colorByID, regByID, labelByID map[int64]string) {
	views = make([]vehicleView, len(vs))
	colorByID = map[int64]string{}
	regByID = map[int64]string{}
	labelByID = map[int64]string{}
	for i, v := range vs {
		c := vehicleColor(i)
		views[i] = vehicleView{ID: v.ID, Label: v.Label, Registration: v.Registration, Color: c, Email: v.Email}
		colorByID[v.ID] = c
		regByID[v.ID] = v.Registration
		labelByID[v.ID] = v.Label
	}
	return views, colorByID, regByID, labelByID
}

func (s *Server) render(w http.ResponseWriter, data dashboardData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "dashboard", data); err != nil {
		log.Printf("render dashboard: %v", err)
	}
}

// appShell resolves the signed-in user and the pre-app gating (must be linked,
// must have nominated a permit). It renders onboarding or the permit picker
// itself and returns ok=false when the user isn't ready for the app pages;
// otherwise it returns a base with State "app" for a page handler to fill in.
func (s *Server) appShell(w http.ResponseWriter, r *http.Request, page string) (dashboardData, bool) {
	u, ok := s.user(w, r)
	if !ok {
		return dashboardData{}, false
	}
	ctx := r.Context()
	user, owner, isPrimary := s.resolveAccount(ctx)
	base := dashboardData{User: u, Owner: owner, IsPrimary: isPrimary, OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(), Loc: s.cfg.DisplayLocation, Page: page}
	if !isPrimary {
		base.SharedWith = owner
	}
	if r.URL.Query().Get("linked") == "1" {
		base.Flash = "Council account linked."
	}
	// Terms gate: before anything else (and before we ever store a council login),
	// each user must accept the current terms individually, and re-accept if they
	// change. Consent is per person (the raw signed-in email), not per account.
	if ok, updated := s.consentStatus(ctx, user); !ok {
		base.State = "terms"
		base.Terms = termsView{Version: s.terms.Version, Intro: s.terms.Intro, Clauses: s.terms.Clauses, Updated: updated, OIDC: s.auth != nil}
		s.render(w, base)
		return dashboardData{}, false
	}
	if !s.council.Linked(ctx, owner) {
		// The council account belongs to the primary; a secondary can only wait
		// for them to connect it (the template shows the right message per role).
		base.State = "onboarding"
		s.render(w, base)
		return dashboardData{}, false
	}
	managed, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return dashboardData{}, false
	}
	if len(managed) == 0 {
		s.renderPicker(w, r, base)
		return dashboardData{}, false
	}
	base.State = "app"
	return base, true
}

// schedule is the primary day-to-day page: permit status, weekly roster, 14-day
// calendar, and the chronological one-offs.
func (s *Server) schedule(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "schedule")
	if !ok {
		return
	}
	ctx := r.Context()
	owner := base.Owner
	now := time.Now().In(s.cfg.DisplayLocation)
	vehicles, err := s.store.ListVehiclesFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	vviews, colorByID, regByID, labelByID := vehicleViews(vehicles)
	managed, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	var pvs []permitView
	for _, p := range managed {
		pv, err := s.buildPermitView(ctx, p, vviews, colorByID, regByID, labelByID, now)
		if err != nil {
			s.serverError(w, err)
			return
		}
		pvs = append(pvs, pv)
	}
	base.Vehicles = vviews
	base.Permits = pvs
	s.render(w, base)
}

// vehiclesPage manages the owner's plates.
func (s *Server) vehiclesPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "vehicles")
	if !ok {
		return
	}
	vehicles, err := s.store.ListVehiclesFor(r.Context(), base.Owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base.Vehicles, _, _, _ = vehicleViews(vehicles)
	s.render(w, base)
}

// activityPage shows the recent-changes log.
func (s *Server) activityPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "activity")
	if !ok {
		return
	}
	logs, err := s.store.ListApplyLogFor(r.Context(), base.Owner, 100)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base.Log = logs
	s.render(w, base)
}

// settingsPage shows the council connection, re-authorise deadline, and account
// controls.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "settings")
	if !ok {
		return
	}
	ctx := r.Context()
	owner := base.Owner
	if cs, err := s.store.GetCouncilSession(ctx, owner); err == nil && !cs.LinkedAt.IsZero() && s.cfg.Council.SessionMaxAge > 0 {
		base.RelinkBy = cs.LinkedAt.Add(s.cfg.Council.SessionMaxAge).In(s.cfg.DisplayLocation).Format("2 Jan 2006")
	}
	if r.URL.Query().Get("tested") == "1" {
		base.Flash = "Test notification sent."
	}
	pref, err := s.store.GetNotifyPref(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Ensure the account always has an ntfy topic to subscribe to, even before enabling it.
	if pref.NtfyTopic == "" {
		pref.Owner = owner
		pref.NtfyTopic = notify.RandomTopic()
		_ = s.store.SetNotifyPref(ctx, pref)
	}
	shared := false
	if n, err := s.store.CountMembers(ctx, owner); err == nil && n > 0 {
		shared = true
	}
	base.Notify = notifyView{
		EmailAvailable: s.notify.EmailAvailable(), NtfyAvailable: s.notify.NtfyAvailable(),
		EmailEnabled: pref.EmailEnabled, NtfyEnabled: pref.NtfyEnabled,
		NtfyTopic: pref.NtfyTopic, NtfyBase: s.notify.NtfyBase(), UserEmail: owner, Shared: shared,
	}
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
func (s *Server) renderNotify(w http.ResponseWriter, r *http.Request, owner string, pref store.NotifyPref, status, errMsg string) {
	shared := false
	if n, err := s.store.CountMembers(r.Context(), owner); err == nil && n > 0 {
		shared = true
	}
	nv := notifyView{
		EmailAvailable: s.notify.EmailAvailable(), NtfyAvailable: s.notify.NtfyAvailable(),
		EmailEnabled: pref.EmailEnabled, NtfyEnabled: pref.NtfyEnabled,
		NtfyTopic: pref.NtfyTopic, NtfyBase: s.notify.NtfyBase(), UserEmail: owner, Shared: shared,
		Status: status, Error: errMsg,
	}
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
	_, owner, _ := s.resolveAccount(r.Context())
	pref, err := s.store.GetNotifyPref(r.Context(), owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	pref.Owner = owner
	email := r.FormValue("email_enabled") != ""
	ntfy := r.FormValue("ntfy_enabled") != ""
	if (s.notify.EmailAvailable() || s.notify.NtfyAvailable()) && !email && !ntfy {
		// Revert: render the still-saved pref (re-checks the box) with a warning.
		s.renderNotify(w, r, owner, pref, "", "Keep at least one method on.")
		return
	}
	pref.EmailEnabled, pref.NtfyEnabled = email, ntfy
	if err := s.store.SetNotifyPref(r.Context(), pref); err != nil {
		s.serverError(w, err)
		return
	}
	s.renderNotify(w, r, owner, pref, "Saved", "")
}

// regenTopic gives the account a fresh ntfy topic (live), enabling ntfy.
func (s *Server) regenTopic(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	pref, err := s.store.GetNotifyPref(r.Context(), owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	pref.Owner, pref.NtfyTopic, pref.NtfyEnabled = owner, notify.RandomTopic(), true
	if err := s.store.SetNotifyPref(r.Context(), pref); err != nil {
		s.serverError(w, err)
		return
	}
	s.renderNotify(w, r, owner, pref, "New topic. Re-subscribe in the ntfy app.", "")
}

// testNotify sends a test message on every enabled channel.
func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	if err := s.notify.SendTest(r.Context(), owner); err != nil {
		log.Printf("test notify %s: %v", owner, err)
		s.message(w, http.StatusBadGateway, "Couldn't send the test notification: "+err.Error())
		return
	}
	http.Redirect(w, r, "/settings?tested=1", http.StatusSeeOther)
}

// buildPermitView assembles one permit's roster grid, 14-day at-a-glance
// calendar (resolved per day), and upcoming one-offs.
func (s *Server) buildPermitView(ctx context.Context, p model.Permit, vviews []vehicleView, colorByID, regByID, labelByID map[int64]string, now time.Time) (permitView, error) {
	// Refresh "on permit now" from the council (cached ≤5 min), so the display is
	// truthful and external portal changes are caught. On any error, keep the
	// stored belief, never block the page on a council call.
	if actual, err := s.council.CurrentVehicleCached(ctx, p.Owner,
		model.Permit{CouncilPermitID: p.CouncilPermitID, PermitTypeID: p.PermitTypeID}, 5*time.Minute); err == nil && actual != p.ActiveRegistration {
		p.ActiveRegistration = actual
		_ = s.store.SetPermitActive(ctx, p.ID, actual)
	}
	rules, err := s.store.ListRules(ctx, p.ID)
	if err != nil {
		return permitView{}, err
	}
	overrides, err := s.store.ListOverrides(ctx, p.ID, now)
	if err != nil {
		return permitView{}, err
	}
	res := model.Resolve(now, rules, overrides)

	// dispReg resolves what to show for a resolution or override: a saved vehicle's
	// reg/label/colour, or an ad-hoc one-off plate (no saved name, neutral colour).
	dispReg := func(vid int64, plate string) (reg, label, color string) {
		if plate != "" {
			return plate, "One-off plate", ""
		}
		return regByID[vid], labelByID[vid], colorByID[vid]
	}

	ruleByWeekday := map[time.Weekday]int64{}
	for _, ru := range rules {
		ruleByWeekday[ru.Weekday] = ru.VehicleID
	}
	var days []dayView
	for _, wd := range weekdaysDisplay {
		vid := ruleByWeekday[wd]
		days = append(days, dayView{
			PermitID: p.ID, WeekdayNum: int(wd), Name: shortDay(wd),
			VehicleID: vid, Reg: regByID[vid], Label: labelByID[vid], Color: colorByID[vid],
		})
	}

	loc := s.cfg.DisplayLocation
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	// Align the fortnight grid to weekday columns (Sunday first) so the same
	// weekday sits in the same column as the roster above. The grid starts on the
	// Sunday of the current week; days already gone this week show dimmed.
	gridStart := today.AddDate(0, 0, -int(today.Weekday())) // Weekday(): Sunday==0
	var cal []calView
	for d := 0; d < 14; d++ {
		day := gridStart.AddDate(0, 0, d)
		dayEnd := day.AddDate(0, 0, 1)
		isToday := day.Equal(today)
		past := day.Before(today)
		// Today reflects the plate right now (local time); other days are
		// representative, resolved at midday.
		resolveAt := day.Add(12 * time.Hour)
		if isToday {
			resolveAt = now
		}
		r := model.Resolve(resolveAt, rules, overrides)
		hasOneoff := false
		for i := range overrides {
			o := overrides[i]
			if o.StartsAt.Before(dayEnd) && (o.EndsAt == nil || o.EndsAt.After(day)) {
				hasOneoff = true
				break
			}
		}
		src := ""
		if r.Source != model.SourceNone {
			src = string(r.Source)
		}
		calReg, _, calColor := dispReg(r.VehicleID, r.Registration)
		cal = append(cal, calView{
			DayLabel: day.Format("Mon 2"), Reg: calReg, Color: calColor,
			Source: src, HasOneoff: hasOneoff, IsToday: isToday, Past: past,
		})
	}

	var ovs []overrideView
	for _, o := range overrides {
		reg, label, color := dispReg(o.VehicleID, o.Registration)
		ovs = append(ovs, overrideView{
			ID: o.ID, PermitID: p.ID, Reg: reg, Label: label,
			Color: color, StartsAt: o.StartsAt, EndsAt: o.EndsAt, CreatedBy: o.CreatedBy,
		})
	}
	source := ""
	if res.Source != model.SourceNone {
		source = string(res.Source)
	}
	desiredReg, _, _ := dispReg(res.VehicleID, res.Registration)
	return permitView{
		Permit: p, DesiredReg: desiredReg, DesiredSource: source,
		Days: days, Cal: cal, Overrides: ovs, Vehicles: vviews, Loc: loc,
	}, nil
}

// pickerPage renders the permit picker on its own route (for "manage another
// permit" from the dashboard).
func (s *Server) pickerPage(w http.ResponseWriter, r *http.Request) {
	u, ok := s.user(w, r)
	if !ok {
		return
	}
	_, owner, isPrimary := s.resolveAccount(r.Context())
	base := dashboardData{User: u, Owner: owner, IsPrimary: isPrimary, OIDCEnabled: s.auth != nil, Loc: s.cfg.DisplayLocation}
	if !isPrimary {
		base.SharedWith = owner
	}
	if !s.council.Linked(r.Context(), owner) {
		base.State = "onboarding"
		s.render(w, base)
		return
	}
	s.renderPicker(w, r, base)
}

// renderPicker lists the user's council permits (excluding already-managed ones)
// for them to nominate. A dead session cookie routes back to onboarding.
func (s *Server) renderPicker(w http.ResponseWriter, r *http.Request, base dashboardData) {
	ctx := r.Context()
	owner := base.Owner
	permits, err := s.council.ListPermits(ctx, owner)
	if err != nil {
		base.State = "onboarding"
		if errors.Is(err, parking.ErrSessionExpired) {
			base.Relink = true
		} else {
			log.Printf("list council permits for %s: %v", owner, err)
			base.Warn = "Couldn't reach the council to load your permits. Try re-linking."
		}
		s.render(w, base)
		return
	}
	managed, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	already := map[string]bool{}
	for _, p := range managed {
		already[p.CouncilPermitID] = true
	}
	for _, p := range permits {
		if already[p.CouncilPermitID] {
			continue
		}
		// Show every permit the account holds, but only a visitor permit whose
		// holder can change the vehicle can actually be scheduled. The rest are
		// listed greyed-out with the reason, so the user sees them and isn't left
		// wondering where a permit went.
		visitor := isVisitorPermit(p.PermitType)
		addable := visitor && p.CanChangeVehicle
		reason := ""
		switch {
		case !visitor:
			reason = "Only visitor permits can be scheduled."
		case !p.CanChangeVehicle:
			reason = "Your council account can't change this permit's vehicle."
		}
		base.Pick = append(base.Pick, pickView{
			CouncilPermitID: p.CouncilPermitID, PermitTypeID: p.PermitTypeID,
			PermitNumber: p.PermitNumber, PermitType: p.PermitType, CurrentRego: p.CurrentRego,
			Addable: addable, Reason: reason,
		})
	}
	base.State = "picker"
	s.render(w, base)
}

// ---- mutations ----

func (s *Server) addVehicle(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	reg := normalizeReg(r.FormValue("registration"))
	label := strings.TrimSpace(r.FormValue("label"))
	if !validRego(reg) {
		s.message(w, http.StatusBadRequest, "Enter a valid number plate (letters and numbers, e.g. ABC123).")
		return
	}
	if _, err := s.store.CreateVehicle(r.Context(), owner, reg, label); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			s.message(w, http.StatusConflict, "You already have a vehicle with that plate.")
			return
		}
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/vehicles", http.StatusSeeOther)
}

func (s *Server) deleteVehicle(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	if err := s.store.DeleteVehicle(r.Context(), owner, pathInt(r, "id")); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/vehicles", http.StatusSeeOther)
}

// isVisitorPermit reports whether a council permit type is a visitor permit, the
// only kind p.stonn schedules. The council names them like "(A) 1st Visitor
// Permit", so a case-insensitive "visitor" match is the reliable signal.
func isVisitorPermit(permitType string) bool {
	return strings.Contains(strings.ToLower(permitType), "visitor")
}

func (s *Server) addPermit(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	ctx := r.Context()
	cpid := strings.TrimSpace(r.FormValue("council_permit_id"))
	if cpid == "" {
		s.message(w, http.StatusBadRequest, "Council permit ID is required.")
		return
	}

	// Authorize the permit against the account's council record. The council
	// username is pinned to the primary's verified email, so ListPermits only
	// returns permits the account actually holds; a forged council_permit_id (not
	// from the picker) is rejected here. We take the permit type and current plate
	// from the authoritative council record, never from the form.
	permits, err := s.council.ListPermits(ctx, owner)
	if err != nil {
		if errors.Is(err, parking.ErrSessionExpired) || errors.Is(err, parking.ErrNotLinked) {
			s.message(w, http.StatusConflict, "Your council sign-in has expired. Please re-link and try again.")
			return
		}
		log.Printf("addPermit list council permits for %s: %v", owner, err)
		s.message(w, http.StatusBadGateway, "Couldn't reach the council to confirm the permit. Try again shortly.")
		return
	}
	var match *parking.PermitInfo
	for i := range permits {
		if permits[i].CouncilPermitID == cpid {
			match = &permits[i]
			break
		}
	}
	if match == nil {
		s.message(w, http.StatusForbidden, "That permit isn't one your council account can manage.")
		return
	}
	// Enforce the same rule the picker shows: p.stonn only schedules visitor
	// permits whose vehicle the holder can change. This is the authoritative
	// gate (the greyed-out picker button is only a UI hint).
	if !isVisitorPermit(match.PermitType) {
		s.message(w, http.StatusForbidden, "p.stonn only manages visitor permits.")
		return
	}
	if !match.CanChangeVehicle {
		s.message(w, http.StatusForbidden, "Your council account can't change the vehicle on that permit.")
		return
	}

	// Never take over a permit another account already manages (e.g. a shared
	// household permit both council accounts can see).
	if existing, err := s.store.PermitByCouncilID(ctx, cpid); err == nil && existing.Owner != owner {
		s.message(w, http.StatusConflict, "That permit is already being managed by another account.")
		return
	}

	pid, err := s.store.UpsertPermit(ctx, owner, cpid, match.PermitTypeID,
		strings.TrimSpace(r.FormValue("label")))
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Seed "on permit now" from the plate the council record already reports, so
	// it shows immediately instead of "unknown" until the first live refresh.
	if match.CurrentRego != "" {
		_ = s.store.SetPermitActive(ctx, pid, match.CurrentRego)
	}
	redirectHome(w, r)
}

// deletePermit stops p.stonn administering a permit: it drops the permit and its
// schedule (weekly rules + one-offs) and history. The council permit is left
// exactly as it is; we simply stop changing its plate. Any account member may do
// this, like adding one — it's part of managing the schedule.
func (s *Server) deletePermit(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	if err := s.store.DeletePermit(r.Context(), p.ID, owner); err != nil {
		s.serverError(w, err)
		return
	}
	// Re-evaluate so the scheduler drops the now-removed permit promptly.
	s.sched.Kick()
	redirectHome(w, r)
}

// councilLink onboards the user's council account via a headless login: it takes
// their council credentials, exchanges them for a session cookie, and discards
// the password. The credentials are never stored.
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
		s.message(w, http.StatusBadRequest, "Enter your council password.")
		return
	}
	if err := s.council.Link(r.Context(), user, user, password); err != nil {
		log.Printf("council link for %s: %v", user, err)
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
		s.message(w, http.StatusBadRequest, "Type DELETE to confirm removing all your data.")
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
		s.message(w, http.StatusBadRequest, "Enter a valid email address.")
		return
	}
	if email == user {
		s.message(w, http.StatusBadRequest, "That is your own email.")
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
		s.message(w, http.StatusBadRequest, "You own this account, so there is nothing to leave.")
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

func (s *Server) setRule(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	weekday := time.Weekday(atoi(r.FormValue("weekday")))
	vehicleID := atoi64(r.FormValue("vehicle_id"))
	var err error
	if vehicleID == 0 {
		err = s.store.ClearRule(r.Context(), p.ID, weekday)
	} else {
		if !s.ownsVehicle(w, r, owner, vehicleID) {
			return
		}
		err = s.store.SetRule(r.Context(), p.ID, weekday, vehicleID)
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.sched.Kick()
	s.respondPermit(w, r, owner, p)
}

func (s *Server) addOverride(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	startsAt := time.Now()
	if raw := strings.TrimSpace(r.FormValue("from")); raw != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, s.cfg.DisplayLocation)
		if err != nil {
			s.message(w, http.StatusBadRequest, "Couldn't read the start time.")
			return
		}
		startsAt = t
	}
	var endsAt *time.Time
	if raw := strings.TrimSpace(r.FormValue("until")); raw != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, s.cfg.DisplayLocation)
		if err != nil {
			s.message(w, http.StatusBadRequest, "Couldn't read the end time.")
			return
		}
		endsAt = &t
	}
	if endsAt != nil && !endsAt.After(startsAt) {
		s.message(w, http.StatusBadRequest, "The end time must be after the start time.")
		return
	}
	// Either a saved vehicle, or a one-off plate that is NOT saved as a vehicle
	// (a visitor's car, a hire car). CreatedBy records the actual person who made
	// the booking (audit), even though the permit belongs to the shared account.
	plate := normalizeReg(r.FormValue("plate"))
	vehicleID := atoi64(r.FormValue("vehicle_id"))
	switch {
	case plate != "":
		if !validRego(plate) {
			s.message(w, http.StatusBadRequest, "Enter a valid number plate (letters and numbers, e.g. ABC123).")
			return
		}
		if _, err := s.store.CreatePlateOverride(r.Context(), p.ID, plate, startsAt, endsAt, user); err != nil {
			s.serverError(w, err)
			return
		}
	case vehicleID != 0:
		if !s.ownsVehicle(w, r, owner, vehicleID) {
			return
		}
		if _, err := s.store.CreateOverride(r.Context(), p.ID, vehicleID, startsAt, endsAt, user); err != nil {
			s.serverError(w, err)
			return
		}
	default:
		s.message(w, http.StatusBadRequest, "Choose a saved car or enter a one-off plate.")
		return
	}
	s.sched.Kick()
	s.respondPermit(w, r, owner, p)
}

func (s *Server) deleteOverride(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	if err := s.store.DeleteOverride(r.Context(), owner, pathInt(r, "oid")); err != nil {
		s.serverError(w, err)
		return
	}
	s.sched.Kick()
	s.respondPermit(w, r, owner, p)
}

// ownedPermit loads the permit named by the {id} path value and confirms it
// belongs to the owner, guarding against cross-user access.
func (s *Server) ownedPermit(w http.ResponseWriter, r *http.Request, owner string) (model.Permit, bool) {
	p, err := s.store.GetPermit(r.Context(), pathInt(r, "id"))
	if err != nil || p.Owner != owner {
		s.message(w, http.StatusNotFound, "Permit not found.")
		return model.Permit{}, false
	}
	return p, true
}

// ownsVehicle confirms the given vehicle id belongs to owner before it is bound
// into a rule or override. Without this a user could point their own permit at
// another user's vehicle id (sequential ints) and have the scheduler read that
// user's registration. Renders a 404 and returns false when not owned.
func (s *Server) ownsVehicle(w http.ResponseWriter, r *http.Request, owner string, vehicleID int64) bool {
	ok, err := s.store.VehicleOwnedBy(r.Context(), owner, vehicleID)
	if err != nil {
		s.serverError(w, err)
		return false
	}
	if !ok {
		s.message(w, http.StatusNotFound, "Vehicle not found.")
		return false
	}
	return true
}

// respondPermit re-renders just the permit's body for htmx swaps, or falls back
// to a full-page redirect for non-htmx submits.
func (s *Server) respondPermit(w http.ResponseWriter, r *http.Request, owner string, p model.Permit) {
	if r.Header.Get("HX-Request") == "" {
		redirectHome(w, r)
		return
	}
	ctx := r.Context()
	vehicles, err := s.store.ListVehiclesFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	vviews, colorByID, regByID, labelByID := vehicleViews(vehicles)
	pv, err := s.buildPermitView(ctx, p, vviews, colorByID, regByID, labelByID, time.Now().In(s.cfg.DisplayLocation))
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "permit-body", pv); err != nil {
		log.Printf("render permit-body: %v", err)
	}
}

// ---- helpers ----

func (s *Server) message(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	// Escape msg: callers pass server-constructed strings today, but escaping
	// here removes the reflected-XSS foot-gun if a future caller ever forwards
	// user input into this sink.
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:16px system-ui;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1a2233">`+
		`<p>%s</p><p><a href="/">&larr; Back</a></p>`, template.HTMLEscapeString(msg))
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	log.Printf("server error: %v", err)
	s.message(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/schedule", http.StatusSeeOther)
}

func normalizeReg(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
}

// validRego reports whether s (already normalised: upper-case, no spaces) is a
// plausible number plate: 2–8 alphanumeric characters. It is a sanity gate to
// catch typos and junk, not a strict format check — Australian plates vary by
// state and custom plates differ, so we stay lenient; the council makes the
// authoritative check when the plate is actually set.
func validRego(s string) bool {
	if len(s) < 2 || len(s) > 8 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func pathInt(r *http.Request, name string) int64 { return atoi64(r.PathValue(name)) }

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
