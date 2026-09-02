package server

import (
	"bytes"
	"context"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/i18n"
	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
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

// tenantView is the tenant as every page and message sees it: names, links,
// facts and vocabulary. Templates reach it through dashboardData.Tenant.
type tenantView struct {
	ID, Name, Short string
	Links           tenant.Links
	Phone           string
	Suburbs         []string
	SuburbList      string // "Prahran, Windsor, … and Kooyong"
	PortalHost      string // the portal's bare host, for prose
	Terms           map[string]string
}

// tr renders a catalog message with a tenant and extra fields, for Go-composed
// page text (SEO titles, FAQ entries, guides). HTML markup in the message is
// trusted; interpolated fields are escaped.
func tr(c tenantView, key string, extra map[string]any, slots i18n.Slots) template.HTML {
	data := map[string]any{"Tenant": c}
	for k, v := range extra {
		data[k] = v
	}
	out, err := catalog.For(i18n.DefaultLocale).HTML(key, data, slots)
	if err != nil {
		log.Printf("i18n: %v", err)
		return template.HTML(template.HTMLEscapeString(key))
	}
	return out
}

// trText is tr as plain text (titles, descriptions, JSON-LD).
func trText(c tenantView, key string) string {
	out, err := catalog.For(i18n.DefaultLocale).Text(key, map[string]any{"Tenant": c})
	if err != nil {
		log.Printf("i18n: %v", err)
		return key
	}
	return out
}

// tenantViewOf builds the view for a descriptor.
func tenantViewOf(c *tenant.Tenant) tenantView {
	v := tenantView{ID: c.ID, Name: c.Name, Short: c.Short, Links: c.Links, Phone: c.Copy.Phone,
		Suburbs: c.Copy.Suburbs, Terms: catalog.For(i18n.DefaultLocale).Terms(c.Terms)}
	switch n := len(c.Copy.Suburbs); {
	case n == 0:
	case n == 1:
		v.SuburbList = c.Copy.Suburbs[0]
	default:
		v.SuburbList = strings.Join(c.Copy.Suburbs[:n-1], ", ") + " and " + c.Copy.Suburbs[n-1]
	}
	if u, err := url.Parse(c.Links.Portal); err == nil {
		v.PortalHost = u.Host
	}
	return v
}

// defaultTenantView is Stonnington, for pages rendered outside a request (tests)
// and as the fallback when no tenant can be resolved.
var defaultTenantView = tenantViewOf(tenant.Default())

// tenantViewFor is the view for an owner's tenant (the registry default, or
// Stonnington, when none resolves).
func (s *Server) tenantViewFor(ctx context.Context, owner string) tenantView {
	if s.registry == nil {
		return defaultTenantView
	}
	return tenantViewOf(s.tenantFor(ctx, owner))
}

type dashboardData struct {
	// Nonce is the CSP script nonce for this response, stamped on every inline
	// <script> in layout.html. render() fills it in from the response's own CSP
	// header, so no handler has to remember to set it — and a page rendered with
	// no policy in force simply gets "" (see scriptNonce).
	Nonce string
	// tenant is the resolved tenant for this page; Tenant() serves it, or the
	// default when a page is rendered without one (fragments, tests).
	tenant      *tenantView
	User        identity.User
	OIDCEnabled bool
	State       string // "landing" | "terms" | "onboarding" | "picker" | "app"
	Page        string // when State=="app": "schedule" | "vehicles" | "activity" | "settings"
	// SEO fields, filled by render() from the State (see seoFor). BaseURL is the
	// public origin (PUBLIC_BASE_URL); CanonicalPath is "" for non-indexable pages
	// (app/guest/token), which suppresses the canonical/OG tags and emits noindex.
	BaseURL       string
	Title         string
	Description   string
	CanonicalPath string
	JSONLD        template.JS // JSON-LD structured data for this page, or ""
	FAQ           []faqItem   // only the FAQ page fills this
	Guide         *guidePage  // a /guide/<slug> page: its own title, description, canonical and FAQ structured data
	LogoutURL     string      // sign-out link (app OIDC or forward-auth provider); "" hides it
	SignedIn      bool        // landing: whether the visitor already has an identity
	Contact       bool        // whether the public contact link/form is available
	ContactVal    string      // contact form: the message text to redisplay after a validation error
	ContactFrom   string      // contact form: the reply-to address to redisplay after a validation error
	// TenantOptions is the sign-up choice, offered only when more than one is enabled.
	TenantOptions []tenantOption
	// Tenants drives the user menu's area switcher: only the areas the account has
	// LINKED (empty when the deployment serves one area). Switching between them.
	Tenants []tenantChoice
	// CanConnectArea: a multi-area deployment still has an area this account has not
	// linked, so the menu offers "Connect another area…" → the connect-area picker.
	CanConnectArea bool
	// Areas is the unlinked-area list the connect-area picker renders (State "connectarea").
	Areas []tenantChoice
	// OtherConnections are the account\'s sessions with tenants other than the current one (Settings).
	OtherConnections []connectionView
	Relink           bool // tenant session expired → prompt re-link
	// CapacityFull hides the onboarding link form from a NEW household when the
	// deployment is at MaxAccounts, so the refusal arrives before terms are read
	// and a third-party password is typed — not after, as a toast. tenantLink
	// keeps the authoritative (locked) check; this is the courtesy copy.
	CapacityFull bool
	// LinkHelp renders the rejected-tenant-login remedy on the onboarding page:
	// a real sign-out button plus "sign back in with your ePermits email". The
	// instruction existed in three places as prose; the affordance existed in
	// none of them, and the icon-only account menu is where the remedy went to
	// die on a phone.
	LinkHelp bool
	// LinkThrottled renders the too-many-attempts landing on the onboarding page.
	// The throttle used to answer with a bare 429 message page — a dead end that
	// was the last thing an early sign-up saw before leaving. The wait is real,
	// but it should arrive WITH the likely fix (wrong password vs wrong ePermits
	// email) so the pause becomes checking time, not giving-up time.
	LinkThrottled bool
	// InAppBrowser marks a visitor inside a social app's built-in webview
	// (Facebook, Messenger, Instagram), where password managers don't auto-fill.
	// The onboarding page uses it to suggest opening the real browser BEFORE the
	// tenant password ask becomes a dead end: nearly every stalled signup in the
	// 2026-08 cohort arrived exactly this way (fbclid + FBAN/FBAV user agents).
	InAppBrowser bool
	Flash        string // success (green)
	Warn         string // problem / caution (amber)
	// CouncilTrouble marks a SUSTAINED council-side problem (the connector state is
	// degraded or worse — see councilTroubled), so the Schedule page can say plainly
	// that changes may be delayed. Distinct from Relink, which is a per-account
	// re-link the user must act on; this is the council's system, and nothing the
	// user can do about it. CouncilName is the account's own tenant's name for the
	// copy (the state signal is currently the account-wide worst — see schedule.go).
	CouncilTrouble bool
	CouncilName    string
	Loc            *time.Location
	// shared access
	Owner      string       // effective account owner (email) that scopes the data
	IsPrimary  bool         // whether the signed-in user owns this account
	SharedWith string       // for a secondary: the primary account's email
	Members    []memberView // for a primary: the secondaries with access (and any unanswered invites)
	Invite     *inviteView  // an invitation awaiting the signed-in person's answer
	// ShowShareHint puts a quiet shared-access pointer on the Schedule page for a
	// primary with no members. The feature's only other surface is a card in
	// Settings, which new households demonstrably never open; the hint is
	// server-gated here and dismissed per-browser in the template (localStorage),
	// because seeing it once more on a new device is harmless.
	ShowShareHint bool
	// ShowInstallHint offers the add-to-home-screen tip on the Schedule page once
	// the household has had a successful apply (the morning glance is the dominant
	// use, and a home-screen icon makes it one tap). Dismissed per browser in the
	// template; hidden by the template when already running standalone.
	ShowInstallHint bool
	// OfferedCount is how many live, schedulable (visitor) permits the picker is
	// offering. The picker tailors its guidance on it: more than one means the
	// "this is usually your visitor permit" (singular) line would contradict the
	// two-or-more shown, so a "you can set up both" line is used instead.
	OfferedCount int
	// MoreToSetUp puts a one-time nudge on the Schedule page right after a permit is
	// added, when the council list still holds another schedulable visitor permit
	// this account hasn't set up — surfacing the "add the other whenever you like"
	// offer at the moment it is most relevant. Detected free in addPermit (it already
	// read the list); passed via ?more=1 so it rides the post-add landing, not every
	// later visit (a manual refresh of that URL re-shows it, like the added=1 flash).
	MoreToSetUp bool
	// ShowGuestHint points a household at guest passes once its behaviour proves
	// the need: several one-off bookings and no guest activity means someone is
	// manually doing exactly what a guest link automates. Server-gated on the
	// change log, dismissed per-browser in the template like the other hints.
	ShowGuestHint bool
	// Share page (State "share" / "share-card").
	ShareEmailAvailable bool         // the invite form only makes sense with SMTP configured
	ShareQR             template.URL // data URI of the QR for the printable card (typed: html/template neuters a data: src otherwise)
	ShareURL            string       // the human-readable address printed under the QR
	// GuestActive gates the page-level "add your plates first" banner: a
	// household already using guest QRs (which need no saved cars) shouldn't be
	// told to add plates — the roster and one-off surfaces explain their own
	// prerequisite at the moment of use instead.
	GuestActive bool
	// dashboard state
	Vehicles []vehicleView
	// Regions are the registration jurisdictions the tenant offers for a vehicle's
	// state, home state first. Empty means no chooser is shown (the provider has no
	// such concept, or the tenant is not resolvable yet).
	Regions []provider.Region
	// LegendVehicles is the Schedule page's colour key: only the cars whose colour
	// is actually on the page (see legendVehicles). LegendMore counts those left
	// out, surfaced as a link to the full list.
	LegendVehicles []vehicleView
	LegendMore     int
	Permits        []permitView
	ExpiredPermits []expiredPermitView // collapsed: expired/cancelled permits kept as copy sources
	Log            []store.ApplyRecord
	Changes        []changeView // who changed the setup (account_log), newest first
	// Activity paging: whether older rows exist beyond what is shown, and whether
	// we are already showing the expanded list.
	LogMore       bool
	ChangesMore   bool
	ShowingAll    bool
	RelinkBy      string     // human date the session must be re-authorised by ("" if unknown)
	TenantLinked  bool       // settings: an active tenant session exists
	AutoReconnect bool       // settings: a saved password lets p.stonn auto-reconnect
	LastReconnect string     // settings: when the saved password last signed back in ("" = never)
	Notify        notifyView // settings: notification channels
	Terms         termsView  // terms state + settings display
	// picker state
	HasManaged bool // the account already manages a permit: the picker is "manage another", so it can offer a way back
	Pick       []pickView
	// HasPermits distinguishes the two empty-picker cases: the tenant account
	// holds permits but none is schedulable (so explain why), versus it holds no
	// permits at all (so explain that one must be applied for with the tenant).
	HasPermits bool

	// PermitsUnknown means the tenant gave us only part of the list, so an empty
	// picker proves nothing. Without it, a partial response holding zero rows told the
	// household flatly "your council account doesn't have any permits on it yet" —
	// about an account that may well hold several.
	PermitsUnknown bool
	// guest passes
	Guests          []guestGrantView   // management page: existing grants
	GuestsEnabled   bool               // kill-switch state (default on)
	PermitOpts      []permitOpt        // create-grant permit choices
	NewGuestLinks   []guestLinkView    // links shown once, right after a grant is created
	Edit            *editGrantView     // non-nil puts the pass form in edit mode
	QR              *qrShowView        // non-nil shows the on-screen visitor QR
	DoorQR          *doorQRView        // non-nil renders the printable door-QR poster (State "doorqr")
	DoorGrants      []doorGrantView    // durable door QRs in the management list
	PendingRequests []guestReqView     // printed-QR requests awaiting the holder's decision
	RecentRequests  []guestDecidedView // recently decided printed-QR requests, so every member sees how they were resolved
	Guest           guestActView       // public activation menu (State "guest")
	Wait            *guestWaitView     // public "waiting for approval" page (State "guest-wait")
	Admin           *adminView         // admin dashboard (State "admin")
	Unsub           *unsubView         // public unsubscribe confirm/result (State "unsubscribe")
	Message         *messageView       // styled message/error page (State "message")
	Decide          *decideView        // public no-sign-in guest-request decide page (State "guestdecide")
	Confirm         *confirmView       // public renewal-confirm page (State "confirm")
}

// messageView drives the styled message/error page (State "message"): the
// terminal notice every guard and failure path lands on. LinkLabel/LinkHref
// render an optional inline action (href pre-validated by messageWithLink;
// html/template's URL filter backstops it), After is trailing text.
type messageView struct {
	Text      string
	LinkLabel string
	LinkHref  string
	After     string
}

// decideView drives the no-sign-in approve/decline page reached from the
// guest-request email. Status is the request as stored (pending | approved |
// denied | expired); Outcome is what a just-performed POST did ("" on a plain
// view): applied | approving | declined | revoked.
type decideView struct {
	Plate       string
	PermitLabel string // "" if the permit has since been removed
	Requested   string // human local time of the scan
	Path        string // POST target (the same signed path)
	Status      string
	DecidedBy   string
	Until       string // human "until ..." phrase on an approval
	Viewer      string // the recipient this link authorises (shown for audit clarity)
	Outcome     string
}

// unsubView drives the public unsubscribe page. Address is the one address the
// signed link authorises; Done marks the post-action confirmation.
type unsubView struct {
	Address string
	Path    string // POST target (the same signed path)
	Done    bool
}

// confirmView drives the public "keep my scheduler running" page. The emailed
// link only GETs this; the button POSTs, so a mail scanner following links can no
// longer silently satisfy the human-liveness check this flow exists to make.
type confirmView struct {
	Token string
	Until string // when the session would otherwise lapse ("" if unknown)
	Done  bool
	Stale bool // token unknown/used/expired — reassure rather than alarm
}

// Tenant is the tenant this page speaks for (see tenantView).
func (d dashboardData) Tenant() tenantView {
	if d.tenant != nil {
		return *d.tenant
	}
	return defaultTenantView
}

// linkedAnywhere reports whether the account holds a session with ANY tenant:
// the gate for the app pages. Tenant-specific flows (the picker, adding a
// permit) check the current tenant themselves.
func (s *Server) linkedAnywhere(ctx context.Context, owner string) bool {
	if s.store == nil {
		return false
	}
	sessions, err := s.store.ListTenantSessionsFor(ctx, owner)
	if err != nil {
		return false
	}
	for _, cs := range sessions {
		if cs.Cookie != "" {
			return true
		}
	}
	return false
}

// tenantOption is one option in the sign-up tenant picker.
type tenantOption struct {
	ID       string
	Name     string
	Selected bool
}

// tenantChoice is one entry in the user menu's area switcher.
type tenantChoice struct {
	ID      string
	Name    string
	Current bool // the selected tenant
	Linked  bool // a session exists with it
}

// tenantsFor lists the enabled tenants for the menu, marking the current one and
// which are linked. Empty unless more than one tenant is enabled, so a
// single-tenant deployment renders no switcher.
func (s *Server) tenantsFor(ctx context.Context, owner string) []tenantChoice {
	if s.registry == nil || s.store == nil {
		return nil
	}
	enabled := s.registry.Enabled()
	if len(enabled) < 2 {
		return nil
	}
	current, _ := s.store.TenantIDFor(ctx, owner)
	linked := s.linkedAreaSet(ctx, owner)
	// Only areas the account has LINKED appear in the switcher: it is the working
	// set to move BETWEEN, and it stays short no matter how many areas the registry
	// serves. An area not yet linked is reached via "Connect another area…", not by
	// listing every council here (which would grow the menu with the registry).
	out := make([]tenantChoice, 0, len(enabled))
	for _, c := range enabled {
		if linked[c.ID] {
			out = append(out, tenantChoice{ID: c.ID, Name: c.Name, Current: c.ID == current, Linked: true})
		}
	}
	return out
}

// linkedAreaSet is the set of area ids the account holds a live session with.
func (s *Server) linkedAreaSet(ctx context.Context, owner string) map[string]bool {
	linked := map[string]bool{}
	if sessions, err := s.store.ListTenantSessionsFor(ctx, owner); err == nil {
		for _, cs := range sessions {
			if cs.Cookie != "" {
				linked[cs.TenantID] = true
			}
		}
	}
	return linked
}

// canConnectArea reports whether a multi-area deployment still has an enabled area
// the account has not linked, so the menu can offer "Connect another area…".
func (s *Server) canConnectArea(ctx context.Context, owner string) bool {
	return len(s.unlinkedAreas(ctx, owner)) > 0
}

// unlinkedAreas lists the enabled areas the account has NOT linked yet, for the
// connect-another-area picker. Empty for a single-area deployment or once every
// area is linked.
func (s *Server) unlinkedAreas(ctx context.Context, owner string) []tenantChoice {
	if s.registry == nil || s.store == nil {
		return nil
	}
	enabled := s.registry.Enabled()
	if len(enabled) < 2 {
		return nil
	}
	linked := s.linkedAreaSet(ctx, owner)
	out := make([]tenantChoice, 0, len(enabled))
	for _, c := range enabled {
		if !linked[c.ID] {
			out = append(out, tenantChoice{ID: c.ID, Name: c.Name})
		}
	}
	return out
}

// tenantOfPermit is the descriptor of the tenant a permit belongs to (the
// owner's current tenant when the permit carries none).
func (s *Server) tenantOfPermit(ctx context.Context, p model.Permit) *tenant.Tenant {
	if s.registry != nil && p.TenantID != "" {
		if c, ok := s.registry.ByID(p.TenantID); ok {
			return c
		}
	}
	return s.tenantFor(ctx, p.Owner)
}

// locForPermit is the timezone a permit's days are reckoned in: its tenant's.
func (s *Server) locForPermit(ctx context.Context, p model.Permit) *time.Location {
	if s.registry != nil {
		return s.tenantOfPermit(ctx, p).Location()
	}
	return s.cfg.DisplayLocation
}

// changeView is one row of the account change log, rendered on Activity.
type changeView struct {
	Actor string // who did it ("" = the system)
	Text  string // already-rendered sentence (see changeText)
	At    time.Time
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
	FailuresOnly   bool   // only notify when something needs attention
	Status         string // transient confirmation after auto-save
	Error          string // transient error (e.g. tried to turn everything off)
	// NtfyConfirmed: a test push to the current topic was tapped on a device — the
	// precondition for turning email off. NtfyConfirmedOn is that day, for display.
	NtfyConfirmed   bool
	NtfyConfirmedOn string
	// PushSent: a test has just gone to the phone and the tap is what's awaited.
	// The box shows "sent" and polls for the confirmation so the page turns green
	// by itself when the phone is tapped (render-only; never stored).
	PushSent bool
	// Suppressed surfaces the mail-suppression list in Settings. Without it the
	// page showed "Email me" happily ticked while every message was being dropped
	// — an unsubscribe (which a mail scanner can trigger via the one-click POST)
	// was invisible right where the user would look to check their email works.
	Suppressed     bool
	SuppressedWhy  string // store.SuppressUnsubscribed / SuppressBounce / SuppressComplaint
	SuppressedInfo bool   // an IsSuppressed lookup succeeded (distinguishes "no" from "unknown")
}

// notifyViewOf builds the settings view of a member's notification preferences.
func (s *Server) notifyViewOf(ctx context.Context, user string, pref store.NotifyPref) notifyView {
	nv := notifyView{
		EmailAvailable: s.notify.EmailAvailable(), NtfyAvailable: s.notify.NtfyAvailable(),
		EmailEnabled: pref.EmailEnabled, NtfyEnabled: pref.NtfyEnabled,
		NtfyTopic: pref.NtfyTopic, NtfyBase: s.notify.NtfyBase(), UserEmail: user,
		QuietEnabled: pref.QuietFrom != pref.QuietUntil, QuietFrom: pref.QuietFrom, QuietUntil: pref.QuietUntil,
		FailuresOnly:  pref.FailuresOnly,
		NtfyConfirmed: pref.NtfyConfirmed(),
	}
	// Shown in the account's own zone like every other date on Settings; the
	// process zone (time.Local) is UTC in the container, which put the day out by
	// one for a confirmation tapped in a Melbourne morning.
	if t, err := time.Parse(time.RFC3339, pref.NtfyConfirmedAt); err == nil {
		_, owner, _ := s.resolveAccount(ctx)
		nv.NtfyConfirmedOn = t.In(s.locFor(ctx, owner)).Format("2 Jan 2006")
	}
	if bad, why, err := s.store.IsSuppressed(ctx, user); err == nil {
		nv.SuppressedInfo = true
		nv.Suppressed, nv.SuppressedWhy = bad, why
	} else {
		log.Printf("settings: suppression lookup for %s: %v", notify.RedactEmail(user), err)
	}
	return nv
}

// legendVehicles narrows the colour key at the top of the Schedule page to the
// cars whose colour actually appears on it, and reports how many were left out.
//
// The key used to list every car. That reads fine for three or four, but this app
// is for households with a nanny, a carer, grandparents, a neighbour — ten cars
// took four rows and pushed the permit card itself below the fold on a phone,
// spending the most valuable space on screen explaining colours that were mostly
// not on it. A key should explain what you can see, so this shows exactly the
// colours the page renders and nothing else. It shrinks itself: sixteen cars with
// four in the roster gives four chips.
//
// Keyed on colour rather than vehicle id because not every place that renders a
// colour carries an id — and if two cars ever did share one (possible only past
// sixteen, where the palette wraps), listing both is right, since the key could
// not otherwise tell them apart. Input order is preserved so it is stable between
// renders.
func legendVehicles(vehicles []vehicleView, used map[string]bool) (shown []vehicleView, more int) {
	for _, v := range vehicles {
		if v.Color != "" && used[v.Color] {
			shown = append(shown, v)
		}
	}
	return shown, len(vehicles) - len(shown)
}

type vehicleView struct {
	NotifyDriver bool
	ID           int64
	Label        string
	Registration string
	Color        string
	Email        string // optional driver email (shown on the Vehicles page)
	State        string // registration state code ("" = tenant home state; shown as a chip)
}

type memberView struct {
	Email string
	Added string // human date the access was granted
	// Pending means they have been invited but have not accepted, so they currently
	// have no access. Shown so an unanswered invite is visible to the owner rather
	// than looking like access that silently failed.
	Pending bool
}

// inviteView is an invitation waiting on the signed-in person's own answer. Held in
// its own field rather than folded into Members, because this is the one case where
// the viewer is the subject of the row rather than its owner.
type inviteView struct {
	Owner string // the account inviting them
	// Blocked names why this person cannot accept right now: "own" (they manage
	// their own permits) or "shared" (they share their own account with someone).
	// The card then offers only Decline, instead of an Accept that can only fail.
	Blocked string
}

// capsView is the page-facing shape of provider.Capabilities for one tenant:
// what the portal can do, resolved for the permit (or, on account-wide pages,
// the account's current tenant). Templates branch on these fields only.
type capsView struct {
	// CanClear: the portal can leave a permit with no vehicle at all. False hides
	// the "take the car off" action and the handler refuses it.
	CanClear bool
	// Expiry: the portal reports a meaningful end date. False leaves the card's
	// expiry labels empty ("expiry unknown") rather than showing a placeholder.
	Expiry bool
	// Regions: the portal has a registration-jurisdiction concept (non-empty
	// Regions list on the view). False hides the state chooser.
	Regions bool
}

func capsOf(c provider.Capabilities) capsView {
	return capsView{CanClear: c.CanClearVehicle, Expiry: c.SupportsExpiry, Regions: len(c.Regions) > 0}
}

type permitView struct {
	// Tenant names the permit's tenant when the account holds permits with more
	// than one; "" otherwise (nothing to distinguish).
	Tenant        string
	Permit        model.Permit
	DesiredReg    string
	DesiredSource string
	// ActiveColor is the stored colour of whichever saved car is on the permit
	// right now, or "" when the plate is not one of the household's cars (a
	// visitor's ad-hoc plate). Empty is meaningful, not missing: it renders the
	// plate neutral, so colour reads as "one of ours" and its absence as "someone
	// else's" — which is the question this badge exists to answer.
	ActiveColor string
	Days        []dayView
	Cal         []calView
	Overrides   []overrideView
	Vehicles    []vehicleView
	// Regions are the tenant's registration jurisdictions (home first) for the
	// one-off plate's state selector; empty hides it.
	Regions []provider.Region
	// Unnamed: the permit still carries the picker's default name (its number, or
	// blank), so a subtle "Name this permit" nudge is offered.
	Unnamed bool
	Loc     *time.Location
	// Expiry surfacing (empty ExpiryLabel = expiry unknown).
	ExpiryLabel string // "3 Aug 2026"
	ExpiryIn    string // "in 12 days" / "tomorrow" / "today" / "3 days ago"
	ExpiresSoon bool   // within the UI lead window (approaching)
	Expired     bool   // already past the end date
	Detail      string // tenant identifier line: "VPP24714 · 1st Visitor Permit"
	// Copy-schedule affordance (for a renewed/replacement permit).
	RosterEmpty bool // no weekly rules yet — a fresh permit
	// Notice is the outcome of an action the viewer just took on this permit
	// (a schedule copy), rendered at the top of the card fragment. The household
	// change notice deliberately skips the actor, so without this the person who
	// ran the copy was the only one never told what moved — or that their old
	// door poster had just stopped working.
	Notice string
	// CopyPitch leads with the "renewed this permit?" copy card (open form, note).
	// False renders the quiet copy button instead. Only meaningful when CopyFrom
	// is non-empty; shown once per added permit until dismissed, copied, or a
	// roster day is set (Permit.CopyOfferDone).
	CopyPitch bool
	// CanClear offers the "take the car off" action: the permit shows a plate but
	// nothing is scheduled for right now, so the plate is lingering (a departed
	// guest, an ended booking) and the scheduler won't touch it. When a schedule
	// covers now, clearing would just be re-applied, so the button is hidden. It
	// is also false whenever the permit's portal cannot leave a permit empty at
	// all (Caps.CanClear) — the action then does not exist for this council.
	CanClear bool
	// Caps is what the permit's own portal supports, from the provider's declared
	// capabilities. Every capability-dependent control in the card branches on it,
	// never on a council name: a new tenant whose portal differs gets the right UI
	// by declaring so in its connector.
	Caps capsView
	// ShowSetupNudge gates the "nothing scheduled yet" banner: an empty roster with
	// no one-off bookings AND no history of using the guest/QR path. A QR-only
	// household is using the permit as intended, so the nudge is suppressed for them.
	ShowSetupNudge bool
	CopyFrom       []permitOpt // this owner's OTHER permits, to copy a schedule from
	// IsPrimary gates the owner-only "stop managing this permit" action. Carried on
	// the permit view (not just the page) because the card renders as a standalone
	// htmx fragment, where the dashboard's own IsPrimary is out of scope.
	IsPrimary bool
	// PlateRefreshing: "on permit now" was served from a stale (or absent) cache
	// while a background tenant refresh runs. Renders a subtle "checking" spinner —
	// unless PlateRecent says the shown plate was council-confirmed recently
	// enough to lead with.
	PlateRefreshing bool
	// PlateRecent: the refresh is outstanding, but the shown plate was confirmed
	// by the council within plateRecentWindow (a persisted stamp, or an agreeing
	// cached reading). The badge shows the tick at once, with PlateCheckedAgo as a
	// quiet age hint, instead of a spinner on every cold visit; the poll still
	// runs and swaps the badge if the refresh finds something different.
	PlateRecent bool
	// PlateCheckedAgo is the hint text for PlateRecent ("checked 2 hr ago"); ""
	// otherwise. Composed in Go so the golden renders pin it at a fixed clock.
	PlateCheckedAgo string
	// Applying: the schedule's desired plate for right now is not yet the plate the
	// tenant confirms is on the permit — a change is in flight (a booking just made,
	// a roster edit affecting today). Renders an "applying" spinner. Crucially this
	// is NOT the same as showing the new plate: "on permit now" keeps displaying the
	// tenant-confirmed plate until the tenant itself confirms the change, so the
	// badge never claims a change that hasn't landed.
	Applying bool
	// PollNext, when > 0, is the attempt number for a bounded self-refresh: the card
	// re-fetches itself (/permits/{id}/card?n=PollNext) to swap in the settled plate
	// without a manual reload, while a refresh or an apply is still outstanding.
	// Bounded (see armPlatePoll) so a tenant outage or a rejected change can't turn
	// the card into a permanent poll — the concern that used to force fragments to
	// arm no follow-up at all, which is why a just-made change never refreshed.
	PollNext int
	// PollDelay is how many seconds to wait before that next poll. It backs off across
	// attempts (see platePollDelays) so a quick apply swaps in fast while a slow COLD
	// tenant read still gets minutes of gentle retries instead of freezing the spinner.
	PollDelay int
	// PlateUnconfirmed is set when the self-refresh ran out of attempts with a read or
	// apply still outstanding. The pill then shows an honest "couldn't confirm" mark
	// (not a spinner frozen mid-check): the plate displayed is the last tenant-confirmed
	// value, and the scheduler goes on retrying out of band.
	PlateUnconfirmed bool
	// pollSeed floors the attempt number armPlatePoll works from, derived from how
	// long the shown tenant reading has been stale — so a reload during an outage
	// resumes the poll budget where the outage left it instead of restarting the
	// spinner from zero. Never rendered; template access is impossible (unexported)
	// and unneeded.
	pollSeed int
}

// expiredPermitView is the compact row shown for a permit p.stonn no longer acts
// on (expired or cancelled). It's kept so its schedule can still be copied onto a
// renewed permit, and offers a one-click remove.
type expiredPermitView struct {
	ID         int64
	Label      string
	Detail     string // "VPP24714 · 1st Visitor Permit" (tenant identifiers)
	StatusText string // "Expired 1 Jul 2026" / "Cancelled"
}

// buildExpiredView makes the compact row for an inactive permit (no tenant call).
func buildExpiredView(p model.Permit, now time.Time, loc *time.Location) expiredPermitView {
	label := p.Label
	if label == "" {
		label = "Permit " + p.CouncilPermitID
	}
	var st string
	switch {
	// Through ExpiryDeadline like every other "has this finished?" question: the
	// bare EndDate instant is UTC midnight on the LAST valid day, so comparing
	// against it directly called a permit expired from mid-morning of a day it was
	// still good for — the row is only reachable once Inactive agrees, but the
	// wording must not rest on a different clock from the one that put it here.
	case !p.EndDate.IsZero() && !now.Before(model.ExpiryDeadline(p.EndDate, loc)):
		st = "Expired " + p.EndDate.In(loc).Format("2 Jan 2006")
	case p.Status != "":
		st = p.Status
	default:
		st = "Inactive"
	}
	return expiredPermitView{ID: p.ID, Label: label, Detail: permitDetail(p), StatusText: st}
}

// permitDetail is the tenant identifier line — permit number and/or type — shown
// under a permit's name. Empty if the tenant hasn't reported either yet.
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
	Adhoc     bool   // covered by an override with a typed plate — no saved colour to show
	Usual     string // the roster plate an override displaced, "" when not displaced
	Source    string // "roster" | "override" | ""
	HasOneoff bool
	IsToday   bool
	Past      bool // earlier this week; shown dimmed for context
	// Today-only confirmation state, mirroring the status pill (see armPlatePoll).
	// The calendar renders INTENT — for future days the only truth there is — but
	// today's cell must not paint a plate the tenant hasn't confirmed with the
	// same solid bar as a confirmed one.
	Applying    bool // a change is in flight; the bar's plate isn't on the permit yet
	Unconfirmed bool // polls exhausted with the change/read still outstanding
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
	// Warn flags a permit that is addable but already expired or cancelled, so the
	// picker doesn't silently invite someone to schedule a permit that will never
	// be reconciled. Text explains which.
	Warn string
	// Dead: the tenant says this permit is over (cancelled, expired, rejected).
	// Listed after the live ones, under their own heading, with Status as a pill
	// and a different button — a dead permit is addable only to copy its old
	// schedule, and residents shown an identical "Manage" card added dead permits
	// believing they were the working one (2026-08, three households).
	Dead   bool
	Status string // tenant status label for the pill, e.g. "Cancelled"
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
		views[i] = vehicleView{ID: v.ID, Label: v.Label, Registration: v.Registration, Color: c, Email: v.Email, State: v.State, NotifyDriver: v.NotifyDriver}
		colorByID[v.ID] = c
		regByID[v.ID] = v.Registration
		labelByID[v.ID] = v.Label
	}
	return views, colorByID, regByID, labelByID
}

func (s *Server) render(w http.ResponseWriter, data dashboardData) {
	buf, err := s.renderBuf(w, data)
	if err != nil {
		log.Printf("render dashboard: %v", err)
		// The BARE page, deliberately: the styled message page renders through
		// this same template set, so a broken template must land somewhere that
		// depends on nothing.
		s.bareMessage(w, http.StatusInternalServerError, messageView{Text: "Something went wrong rendering this page. Please try again."})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// renderBuf executes the page into a buffer: writing straight to w means a
// mid-render failure (a nil pointer in a view model) ships a truncated page
// with a 200 that looks like success. Pages are small; the copy is negligible.
// The nonce comes from the response's own CSP header rather than the caller —
// anything a handler had to remember would eventually be forgotten on one
// page, and a missing nonce means every inline script silently stops running.
// SEO fields derive centrally from State; non-indexable states get an empty
// CanonicalPath, which the head turns into a noindex.
func (s *Server) renderBuf(w http.ResponseWriter, data dashboardData) (*bytes.Buffer, error) {
	data.Nonce = scriptNonce(w)
	if data.tenant == nil {
		cv := s.tenantViewFor(context.Background(), data.Owner)
		data.tenant = &cv
	}
	data.BaseURL = s.cfg.PublicBaseURL
	data.Title, data.Description, data.CanonicalPath = seoFor(data.State, data.Tenant())
	data.JSONLD = jsonLDFor(data.State, data.BaseURL, data.Tenant())
	if data.Guide != nil {
		data.Title, data.Description, data.CanonicalPath = data.Guide.Title, data.Guide.Desc, "/guide/"+data.Guide.Slug
		data.JSONLD = guideJSONLD(data.Guide)
	}
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, "dashboard", data); err != nil {
		return nil, err
	}
	return &buf, nil
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
	base := dashboardData{User: u, Owner: owner, IsPrimary: isPrimary, OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(), Loc: s.locFor(ctx, owner), Page: page, Contact: s.cfg.ContactEnabled(),
		Tenants: s.tenantsFor(ctx, owner), CanConnectArea: s.canConnectArea(ctx, owner)}
	if !isPrimary {
		base.SharedWith = owner
	}
	if r.URL.Query().Get("linked") == "1" {
		base.Flash = "Council account linked."
	}
	// Terms gate: before anything else (and before we ever store a tenant login),
	// each user must accept the current terms individually, and re-accept if they
	// change. Consent is per person (the raw signed-in email), not per account.
	if ok, updated := s.consentStatus(ctx, user); !ok {
		base.State = "terms"
		base.Terms = termsView{Version: s.terms.Version, Intro: s.terms.Intro, Clauses: s.terms.Clauses, Updated: updated, OIDC: s.auth != nil}
		s.render(w, base)
		return dashboardData{}, false
	}
	if !s.linkedAnywhere(ctx, owner) {
		// The tenant account belongs to the primary; a secondary can only wait
		// for them to connect it (the template shows the right message per role).
		base.State = "onboarding"
		// Several registry to choose from: the form asks. One: nothing to ask.
		if s.registry != nil {
			if enabled := s.registry.Enabled(); len(enabled) > 1 {
				current := s.tenantFor(ctx, owner)
				for _, c := range enabled {
					base.TenantOptions = append(base.TenantOptions, tenantOption{ID: c.ID, Name: c.Name, Selected: current != nil && current.ID == c.ID})
				}
			}
		}
		base.InAppBrowser = inAppBrowser(r.UserAgent())
		base.AutoReconnect = s.hasSavedPassword(ctx, owner) // drives the save-password default
		// An unanswered invitation is the most likely reason a person with no
		// tenant link is here at all; this page is the only one they can reach.
		if from, ok, err := s.store.PendingInvite(ctx, user); err == nil && ok {
			base.Invite = &inviteView{Owner: from}
		}
		// The landing after a REJECTED tenant login (see tenantLink): name both
		// causes and offer the remedy as a button. Takes precedence over the
		// relink/capacity banners — this person is mid-attempt, and the next step
		// matters more than account status. The banner's content lives in the
		// template (it needs structure: lead line, button row, fallback link),
		// not in this prose field.
		if r.URL.Query().Get("link") == "rejected" {
			base.LinkHelp = true
		} else if r.URL.Query().Get("link") == "throttled" {
			base.LinkThrottled = true
		} else
		// A RETURNING household is not a signup. The paths that end a session
		// (idle retirement, a rejected saved password, a manual disconnect)
		// delete the row, so without this a household whose schedule has STOPPED
		// RUNNING saw the same fresh "Link your council account" page as a
		// newcomer — with their permits, cars and roster all still here and no
		// hint that nothing is being applied meanwhile. Errors fall through to
		// the plain signup rendering: wrongly quiet beats wrongly alarming.
		if known, err := s.store.HasOwnData(ctx, owner); err == nil && known {
			base.Relink = true
			base.Warn = "Your permit schedule is paused: p.stonn is not connected to the council, so no plate changes are being made. Reconnect below to resume it."
		} else if err == nil && s.cfg.MaxAccounts > 0 {
			// A genuinely new household gets the capacity refusal HERE, before
			// terms and a typed password — tenantLink re-checks under the
			// admission lock, so this read needs no locking and may be stale.
			if n, cerr := s.store.CountLinkedAccounts(ctx); cerr == nil && n >= s.cfg.MaxAccounts {
				base.CapacityFull = true
			}
		}
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

// inAppBrowser reports whether the user agent is a social app's built-in
// webview. Deliberately narrow: only the Meta family, which is where the
// observed signups actually come from and whose markers are documented and
// stable (FBAN/FBAV for Facebook and Messenger on iOS, FB_IAB for Android,
// "Instagram" for Instagram's). A generic Android ("; wv)") match would also
// catch benign embedded views where the advice is noise. False negatives are
// fine — the person just sees the normal page — while a false positive tells
// someone in a real browser their password manager won't work, which is both
// wrong and worrying.
func inAppBrowser(ua string) bool {
	return strings.Contains(ua, "FBAN/") ||
		strings.Contains(ua, "FBAV/") ||
		strings.Contains(ua, "FB_IAB") ||
		strings.Contains(ua, "Instagram") ||
		strings.Contains(ua, "GSA/") // the Google app's webview (a rejected signup arrived this way, 2026-08-24)
}
