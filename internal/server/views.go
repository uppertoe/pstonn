package server

import (
	"bytes"
	"log"
	"net/http"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

// logoutURL returns the sign-out link: the app's own OIDC logout when enabled,
// else the forward-auth provider's logout URL (vps-scaffold-auth). "" hides it.
func (s *Server) logoutURL() string {
	if s.auth != nil {
		return "/auth/logout"
	}
	return s.cfg.AuthLogoutURL
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
	Vehicles       []vehicleView
	Permits        []permitView
	ExpiredPermits []expiredPermitView // collapsed: expired/cancelled permits kept as copy sources
	Log            []store.ApplyRecord
	RelinkBy       string     // human date the session must be re-authorised by ("" if unknown)
	CouncilLinked  bool       // settings: an active council session exists
	AutoReconnect  bool       // settings: a saved password lets p.stonn auto-reconnect
	Notify         notifyView // settings: notification channels
	Terms          termsView  // terms state + settings display
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
	Admin           *adminView       // admin dashboard (State "admin")
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
	QuietEnabled   bool   // hold overnight notices and deliver at QuietUntil
	QuietFrom      int    // window start hour (local)
	QuietUntil     int    // deliver-at hour (local)
	Status         string // transient confirmation after auto-save
	Error          string // transient error (e.g. tried to turn everything off)
}

// notifyViewOf builds the settings view of a member's notification preferences.
func (s *Server) notifyViewOf(user string, pref store.NotifyPref) notifyView {
	return notifyView{
		EmailAvailable: s.notify.EmailAvailable(), NtfyAvailable: s.notify.NtfyAvailable(),
		EmailEnabled: pref.EmailEnabled, NtfyEnabled: pref.NtfyEnabled,
		NtfyTopic: pref.NtfyTopic, NtfyBase: s.notify.NtfyBase(), UserEmail: user,
		QuietEnabled: pref.QuietFrom != pref.QuietUntil, QuietFrom: pref.QuietFrom, QuietUntil: pref.QuietUntil,
	}
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
	// Expiry surfacing (empty ExpiryLabel = expiry unknown).
	ExpiryLabel string // "3 Aug 2026"
	ExpiryIn    string // "in 12 days" / "tomorrow" / "today" / "3 days ago"
	ExpiresSoon bool   // within the UI lead window (approaching)
	Expired     bool   // already past the end date
	Detail      string // council identifier line: "VPP24714 · 1st Visitor Permit"
	// Copy-schedule affordance (for a renewed/replacement permit).
	RosterEmpty bool        // no weekly rules yet — a fresh permit
	CopyFrom    []permitOpt // this owner's OTHER permits, to copy a schedule from
}

// expiredPermitView is the compact row shown for a permit p.stonn no longer acts
// on (expired or cancelled). It's kept so its schedule can still be copied onto a
// renewed permit, and offers a one-click remove.
type expiredPermitView struct {
	ID         int64
	Label      string
	Detail     string // "VPP24714 · 1st Visitor Permit" (council identifiers)
	StatusText string // "Expired 1 Jul 2026" / "Cancelled"
}

// buildExpiredView makes the compact row for an inactive permit (no council call).
func buildExpiredView(p model.Permit, now time.Time, loc *time.Location) expiredPermitView {
	label := p.Label
	if label == "" {
		label = "Permit " + p.CouncilPermitID
	}
	var st string
	switch {
	case !p.EndDate.IsZero() && now.After(p.EndDate):
		st = "Expired " + p.EndDate.In(loc).Format("2 Jan 2006")
	case p.Status != "":
		st = p.Status
	default:
		st = "Inactive"
	}
	return expiredPermitView{ID: p.ID, Label: label, Detail: permitDetail(p), StatusText: st}
}

// permitDetail is the council identifier line — permit number and/or type — shown
// under a permit's name. Empty if the council hasn't reported either yet.
func permitDetail(p model.Permit) string {
	switch {
	case p.PermitNumber != "" && p.PermitType != "":
		return p.PermitNumber + " · " + p.PermitType
	case p.PermitNumber != "":
		return p.PermitNumber
	default:
		return p.PermitType
	}
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
		c := v.Color // stable, assigned at creation (see store.CreateVehicle)
		if c == "" {
			c = "#667085" // defensive: a pre-backfill row with no colour
		}
		views[i] = vehicleView{ID: v.ID, Label: v.Label, Registration: v.Registration, Color: c, Email: v.Email}
		colorByID[v.ID] = c
		regByID[v.ID] = v.Registration
		labelByID[v.ID] = v.Label
	}
	return views, colorByID, regByID, labelByID
}

func (s *Server) render(w http.ResponseWriter, data dashboardData) {
	// Execute into a buffer first: writing straight to w means a mid-render
	// failure (a nil pointer in a view model) ships a truncated page with a 200
	// that looks like success. Pages are small; the copy is negligible.
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "dashboard", data); err != nil {
		log.Printf("render dashboard: %v", err)
		s.message(w, http.StatusInternalServerError, "Something went wrong rendering this page. Please try again.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
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
	base := dashboardData{User: u, Owner: owner, IsPrimary: isPrimary, OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(), Loc: s.cfg.DisplayLocation, Page: page, Contact: s.cfg.ContactEnabled()}
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
		base.AutoReconnect = s.hasSavedPassword(ctx, owner) // drives the save-password default
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
