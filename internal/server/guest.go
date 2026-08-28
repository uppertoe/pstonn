package server

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
	"rsc.io/qr"
)

// qrTTL is how long a visitor QR stays valid after the resident shows it. Kept
// short: it's an in-person, show-it-now flow, so a tight window limits exposure.
const qrTTL = 15 * time.Minute

// qrDataURI renders text as a QR code PNG in a data: URI (CSP allows img data:).
// Level Q (~25% error correction) is a robust choice for a code scanned off a
// screen at an angle or with glare, without making it much denser for a short URL.
func qrDataURI(text string) (string, error) {
	c, err := qr.Encode(text, qr.Q)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()), nil
}

// ---- guest-pass view types ----

// guestActView drives the public activation menu (State "guest").
type guestActView struct {
	Token          string         // raw token, echoed into the POST form
	OwnerEmail     string         // account holder, shown for trust
	PermitLabel    string         // which permit this affects
	CurrentReg     string         // what is on the permit right now ("" if unknown)
	CheckedAgo     string         // how long ago CurrentReg was confirmed with the council; "" while fresh ("4 hr ago" turns "on now" into "last known")
	Cars           []vehicleView  // the cars this link may activate
	AllowOvernight bool           // whether the overnight checkbox is offered
	AllowPlate     bool           // whether the visitor may type an arbitrary plate
	RequestOnly    bool           // printed QR: entering a plate only requests approval
	RevertPlate    string         // pre-existing plate the guest may put back ("" = no revert offered)
	PendingReg     string         // plate the schedule targets but the council doesn't show yet ("" = settled)
	Stalled        bool           // the pending change has taken suspiciously long; stop polling
	SelectedReg    string         // the schedule's target plate: highlights the chosen car IMMEDIATELY, while "on now" tracks the actual record
	UntilText      string         // when the winning booking ends ("until the end of today"), "" when open-ended/roster-driven
	KeepForm       bool           // poll responses only: render hx-preserve so a half-filled form survives the swap; activation responses omit it so the form resets
	FP             string         // fingerprint of the visible state; polls echo it so an unchanged page is a 204, not a re-render
	Req            *guestWaitView // printed door QR only: this browser's own remembered request (from the greq cookie), so a re-scan shows its fate instead of a blank form
}

// guestWaitView drives the visitor's "waiting for approval" page (State
// "guest-wait"), which polls the status endpoint.
type guestWaitView struct {
	OwnerEmail string
	Plate      string
	ReqID      int64
	Nonce      string
	Status     string // template-ready state: "pending" | "approved" | "applied" | "stalled" | "denied" | "expired" | "superseded" | "ended"
	Until      string // set when approved
}

// guestReqView is one pending request in the holder's approvals queue.
type guestReqView struct {
	ID          int64
	Plate       string
	PermitLabel string
	Ago         string // "2 min ago"
}

// guestDecidedView is one recently decided printed-QR request on the guests
// page. It exists for the member who DIDN'T decide: everyone on the account got
// the "approve this?" nudge, so everyone can come back later and see how it was
// resolved — and where the approved plate stands now.
type guestDecidedView struct {
	Plate       string
	PermitLabel string
	Outcome     string // "Approved" | "Declined" | "Not answered"
	DecidedBy   string // deciding member ("" for expired-unanswered)
	Ago         string // "2 hr ago" (since the decision)
	Live        string // approved rows: where the plate stands now ("" = nothing to add)
	Warn        bool   // amber the live note (superseded / stalled)
}

// qrShowView drives the on-screen visitor QR the resident shows in person (instant,
// short-lived). The durable printed door QR uses doorQRView / the poster instead.
type qrShowView struct {
	PermitLabel string
	ImageURI    template.URL // the QR as a data: URI (trusted: server-generated)
	URL         string       // the activation URL (also printed under the QR)
	// StopsAt is when this CODE stops working, as a plain clock time. Deliberately
	// not called "expires": next to a parking permit that word reads as the PERMIT
	// expiring, which would be alarming and wrong. The copy says "this code stops
	// working at …" for the same reason.
	StopsAt string
}

// doorQRView drives the styled, printable door-QR poster (State "doorqr"). It is a
// durable artifact: the same code reprints because the token is kept sealed.
type doorQRView struct {
	GrantID     int64
	PermitLabel string
	OwnerEmail  string
	ImageURI    template.URL
	URL         string
	CreatedAt   string // "20 Jul 2026"
}

// doorGrantView is one durable door QR in the holder's management list.
type doorGrantView struct {
	GrantID     int64
	PermitLabel string
	CreatedAt   string
}

// guestGrantView + guestRecipientView drive the account holder's management page.
type guestGrantView struct {
	ID             int64
	Label          string
	PermitLabel    string
	PermitDead     bool // the permit is over: the pass's links refuse visitors until it is copied onto a live permit
	AllowOvernight bool
	Cars           []vehicleView
	Recipients     []guestRecipientView
}

// editGrantView drives the create/edit form when editing an existing grant (nil
// on the dashboardData means "create mode").
type editGrantView struct {
	ID             int64
	Label          string
	PermitLabel    string
	AllowOvernight bool
	Selected       map[int64]bool // vehicle ids currently on the grant (pre-checked)
	Recipients     []guestRecipientView
}

type guestRecipientView struct {
	TokenID int64
	Email   string
	Revoked bool
	// Undeliverable explains why mail to this address is being skipped (a bounce
	// or a spam complaint reported by the mail provider). Without surfacing it,
	// the owner sees "has a link" for someone who never received one and never
	// will — the typo'd-address case that is otherwise completely invisible.
	Undeliverable string
}

type permitOpt struct {
	ID    int64
	Label string
}

// guestLinkView is a freshly-minted link shown once, right after grant creation
// (the raw token is never stored, so this is the only chance to copy it).
type guestLinkView struct {
	Email string
	URL   string
}

// ---- token helpers ----

// newGuestToken returns a random URL token and its storage hash. Only the hash is
// ever persisted; the raw token lives in the emailed link.
func newGuestToken() (raw, hash string) {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		// Fail closed: never mint a predictable (e.g. all-zero) token. A crypto/rand
		// failure is catastrophic and effectively never happens; the panic is
		// recovered by net/http into a 500, so no weak token is issued.
		panic("guest token: crypto/rand failed: " + err.Error())
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashGuestToken(raw)
}

func hashGuestToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Server) guestLink(raw string) string {
	return s.cfg.PublicBaseURL + "/g/" + raw
}

func permitLabel(p model.Permit) string {
	if p.Label != "" {
		return p.Label
	}
	return "Permit " + p.CouncilPermitID
}

// errApplyBusy stands in for a council write this process deliberately did NOT
// make, because another plate change for the same permit was still in flight when
// the apply budget ran out (see the AcquireApply calls below). Classified
// transient: the booking is already saved, so the scheduler converges on it — the
// page must show the honest "still applying" state rather than telling the
// household their council login needs reconnecting.
var errApplyBusy = &parking.CouncilError{
	Kind: parking.FailTransient,
	Op:   "change the vehicle on your permit",
	Err:  errors.New("another plate change for this permit is still in flight"),
}

// dayEndLocal is midnight at the start of the day `extraDays` after t's day, in
// t's location: extraDays=0 → end of today, extraDays=1 → end of tomorrow.
func dayEndLocal(t time.Time, extraDays int) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d+1+extraDays, 0, 0, 0, 0, t.Location())
}

func untilPhrase(now time.Time, overnight bool) string {
	if overnight {
		return "the end of tomorrow (" + now.AddDate(0, 0, 1).Weekday().String() + ")"
	}
	return "the end of today"
}

// noStore keeps the token link and its page out of caches and referrers.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// ---- bounds on the public guest surface ----
//
// These are process-wide rather than fields on Server because the door QR is the
// one capability handed to strangers, and every one of these bounds has to hold
// across every request that reaches it — the same reasoning (and the same
// in-memory, restart-resettable mechanism) as the invite and guest-link throttles
// the Server already carries.
var (
	// guestScanner records that we have heard from a scanner from one IP. It is only
	// ENFORCED once a grant's pending queue reaches its reserved tail (see
	// PendingGuestRequestsInReserve), but it is consulted on every request so the
	// slots a scanner already took are counted against it: that is what makes the
	// reserved slots reachable by someone at a DIFFERENT address. The window covers the
	// hour-plus a pending row can live, because a bound shorter than the thing it
	// bounds lets the same phone refill the queue as it drains. It is a per-IP signal,
	// so it bounds one phone but not several — see the honest limit noted at the gate.
	guestScanner = newRateLimiter(1, 90*time.Minute)

	// guestNudge bounds the "approve this?" nudge PER ACCOUNT. The nudge
	// deliberately bypasses quiet hours at high priority and fans out to every
	// member, and notify dedups on the plate — so cycling plates through a public
	// poster turned one phone into roughly two 3am pushes a minute for every member
	// of the household, and DENYING made room for more. Suppressing the push does
	// not suppress the request: it still queues on the guests page, so a real
	// visitor arriving during a flood is still answerable, just not by alarm.
	guestNudge = newRateLimiter(4, 30*time.Minute)

	// guestApplyNotify bounds the per-account "a guest put their car on your
	// permit" fanout. notify's dedup key includes the plate, so a visitor-QR holder
	// cycling plates produced an email plus a push per attempt with nothing
	// suppressing any of it — the one notification path on this surface that had no
	// per-account cap, unlike invites (1/day) and guest links (5/day). Sized well
	// above a household's real use: a guest link switching between cars several
	// times an afternoon is ordinary; a hundred plates an hour is not.
	guestApplyNotify = newRateLimiter(10, time.Hour)

	// guestStalls is the stall clock behind the visitor page's "taking longer than
	// usual". See stallClock.
	guestStalls = &stallClock{seen: map[stallKey]time.Time{}}
)

type stallKey struct {
	permitID int64
	want     string
}

// stallClock remembers when this process FIRST saw a permit's target plate go
// unconfirmed on the council record.
//
// The pending banner used the winning override's creation time, which only exists
// for a booked change: a roster-driven target had no clock at all, so `stalled`
// could never become true and a visitor whose household had a broken council
// session watched "Changing to X…" poll every 2.5 seconds for as long as the tab
// stayed open, while the honest message telling them to check with the resident
// was unreachable. Observation time is the clock that works for both: it starts
// when someone first looks, it restarts when the target changes (the key includes
// the plate), and it needs no schema and no per-browser state. Losing it on
// restart only means the page spins for another guestApplyTimeout.
type stallClock struct {
	mu   sync.Mutex
	seen map[stallKey]time.Time
}

// maxStallKeys bounds the map. A guest can mint keys (each activation resolves to
// a new target plate), so on overflow it is cleared outright: the cost is a page
// that spins for another guestApplyTimeout, never unbounded memory.
const maxStallKeys = 4096

// since returns the first time this process saw (permitID, want) outstanding,
// recording now if this is the first sighting.
func (c *stallClock) since(permitID int64, want string, now time.Time) time.Time {
	k := stallKey{permitID: permitID, want: model.NormPlate(want)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) > maxStallKeys {
		c.seen = map[stallKey]time.Time{}
	}
	if t, ok := c.seen[k]; ok {
		return t
	}
	c.seen[k] = now
	return now
}

// forget drops a target's clock once it has settled, so the next time the same
// plate is being applied it is timed afresh rather than judged stalled instantly.
func (c *stallClock) forget(permitID int64, want string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.seen, stallKey{permitID: permitID, want: model.NormPlate(want)})
}

// ================= PUBLIC ACTIVATION (no login) =================

// guestPage renders the activation menu for a token. It has NO side effects, so
// email scanners and link-preview bots that fetch the URL can't trigger anything.
func (s *Server) guestPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if permit.Inactive(time.Now(), s.cfg.DisplayLocation) {
		s.renderGuestInactive(w, r)
		return
	}
	s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "")
}

// guestCurrentPlate is the plate to show as "on the permit now": the council's
// own (cached) record when reachable, else our stored belief. Never an error —
// a council hiccup must not fail the page.
func (s *Server) guestCurrentPlate(ctx context.Context, gc guestCtx, permit model.Permit) string {
	if gc.Grant.RequestOnly {
		return "" // a printed door QR must not disclose the current plate
	}
	current := permit.ActiveRegistration
	if s.council != nil { // a council hiccup (or, in tests, no client at all) must not fail the page
		if actual, _, _, err := s.council.CurrentVehicleCached(ctx, permit.Owner,
			model.Permit{CouncilPermitID: permit.CouncilPermitID, PermitTypeID: permit.PermitTypeID}, 5*time.Minute); err == nil {
			// This read just showed the council holding a different plate than our
			// stored belief — the one state where the scheduler could wrongly skip a
			// due change as "already correct". Don't wait out the ~6h drift cadence
			// with a guest at the kerb: ask for the owner's drift read on the next
			// warm pass (≤3 min), which verifies and adopts through the normal
			// external-change path. Divergence-gated, so an open guest page polling
			// a healthy permit requests nothing.
			if !model.SamePlate(actual, permit.ActiveRegistration) && s.sched != nil {
				s.sched.RequestDriftSoon(permit.Owner)
			}
			current = actual
		}
	}
	return current
}

// guestPlateCheckedAgo reports how long ago the plate shown to a guest was
// actually confirmed with the council, as display text — "" while the reading is
// fresh (or unknown). The guest page's "On the permit now" line is the single
// most load-bearing sentence in the app for a visitor about to walk away from
// their car, and it used to state a cached value as present-tense fact with no
// age bound: during a council outage "now" could be days old.
func (s *Server) guestPlateCheckedAgo(ctx context.Context, permit model.Permit) string {
	if s.council == nil {
		return ""
	}
	_, age, fresh, err := s.council.CurrentVehicleCached(ctx, permit.Owner,
		model.Permit{CouncilPermitID: permit.CouncilPermitID, PermitTypeID: permit.PermitTypeID}, 5*time.Minute)
	if err != nil || fresh {
		return ""
	}
	now := time.Now()
	return agoText(now, now.Add(-age))
}

// revertPlate decides whether a guest may revert, and to what: the captured
// baseline, only while its window lasts, only when it isn't already on the
// permit, and only when it is NOT one of the link's own cars (those they can
// simply tap; the revert exists to restore a plate they could not pick).
func revertPlate(baseline string, until time.Time, current string, cars []model.Vehicle, now time.Time) string {
	if baseline == "" || !now.Before(until) || model.SamePlate(baseline, current) {
		return ""
	}
	for _, v := range cars {
		if model.SamePlate(v.Registration, baseline) {
			return ""
		}
	}
	return baseline
}

// guestDesired returns the plate the schedule is currently steering the permit
// toward ("" when nothing is scheduled), when that decision was made, and when
// its booking ends (both zero when roster-driven/open-ended). It is the same
// resolution the scheduler acts on, so the page's "still applying" state can
// never disagree with what will be applied.
func (s *Server) guestDesired(ctx context.Context, permit model.Permit) (want string, decidedAt, until time.Time) {
	now := time.Now().In(s.cfg.DisplayLocation)
	rules, err := s.store.ListRules(ctx, permit.ID)
	if err != nil {
		return "", time.Time{}, time.Time{}
	}
	overrides, err := s.store.ListOverrides(ctx, permit.ID, now)
	if err != nil {
		return "", time.Time{}, time.Time{}
	}
	res := model.Resolve(now, rules, overrides)
	if res.Source == model.SourceNone {
		return "", time.Time{}, time.Time{}
	}
	if res.Registration != "" {
		want = res.Registration
	} else {
		vehicles, verr := s.store.ListVehiclesFor(ctx, permit.Owner)
		if verr != nil {
			return "", time.Time{}, time.Time{}
		}
		for _, v := range vehicles {
			if v.ID == res.VehicleID {
				want = v.Registration
				break
			}
		}
	}
	if res.Source == model.SourceOverride {
		// Re-find the winner with Resolve's own tie-break (freshest CreatedAt, then
		// highest ID): its creation time is when the pending change was asked for
		// (the stall clock) and its end is when the booking lapses (the "until").
		var best *model.Override
		for i := range overrides {
			o := &overrides[i]
			if o.StartsAt.After(now) || (o.EndsAt != nil && !now.Before(*o.EndsAt)) {
				continue
			}
			if best == nil || o.CreatedAt.After(best.CreatedAt) ||
				(o.CreatedAt.Equal(best.CreatedAt) && o.ID > best.ID) {
				best = o
			}
		}
		if best != nil {
			decidedAt = best.CreatedAt
			if best.EndsAt != nil {
				until = *best.EndsAt
			}
		}
	}
	return want, decidedAt, until
}

// untilText phrases when the winning booking ends, or "" when there is nothing
// to phrase (no end, open-ended). now and end must be in the display location.
func untilText(now, end time.Time) string {
	if end.IsZero() {
		return ""
	}
	switch {
	case !end.After(dayEndLocal(now, 0)):
		return "until the end of today"
	case !end.After(dayEndLocal(now, 1)):
		return "until the end of tomorrow (" + now.AddDate(0, 0, 1).Weekday().String() + ")"
	default:
		return "until " + end.Format("Mon 2 Jan")
	}
}

// revertPinEnd bounds the revert pin: never past the end of today. The guest's
// own overrides are already swept, so tomorrow belongs to the owner's schedule —
// an overnight mistake must not pin yesterday's plate over tomorrow's roster.
func revertPinEnd(now, baselineUntil time.Time) time.Time {
	if today := dayEndLocal(now, 0); baselineUntil.After(today) {
		return today
	}
	return baselineUntil
}

// pendingState reports whether the council record has caught up to the
// schedule's target: a non-empty pendingReg means "still applying"; stalled
// means it has been outstanding past guestApplyTimeout and polling should stop.
//
// since is when the change was asked for: the winning booking's creation time
// when there is one, otherwise when this process first saw the target go
// unconfirmed (see stallClock). A zero since still means "never stalled", so a
// caller with no clock at all understates rather than accusing a healthy apply.
func pendingState(actual, want string, since, now time.Time) (pendingReg string, stalled bool) {
	if want == "" || model.SamePlate(actual, want) {
		return "", false
	}
	return want, !since.IsZero() && now.Sub(since) > guestApplyTimeout
}

// stallSince picks the clock pendingState should judge a target by: the booking's
// own creation time when the schedule resolved to a deliberate booking, else the
// first time we saw this target outstanding. Roster-driven targets have no
// creation time, which is why they could never stall.
func stallSince(permitID int64, current, want string, decidedAt, now time.Time) time.Time {
	if !decidedAt.IsZero() {
		return decidedAt
	}
	if want == "" || model.SamePlate(current, want) {
		guestStalls.forget(permitID, want)
		return time.Time{}
	}
	return guestStalls.since(permitID, want, now)
}

// buildGuestView assembles the activation-menu view model from actual state:
// the council-side current plate, the revert offer, and the pending/stalled
// status against the schedule's resolved target.
func (s *Server) buildGuestView(r *http.Request, gc guestCtx, permit model.Permit, current string) guestActView {
	ctx := r.Context()
	cars, _, _, _ := vehicleViews(gc.Vehicles)
	view := guestActView{
		Token: gc.rawToken, PermitLabel: permitLabel(permit),
		Cars: cars, AllowOvernight: gc.Grant.AllowOvernight,
		AllowPlate: gc.Grant.AllowPlate, RequestOnly: gc.Grant.RequestOnly,
	}
	// The label is the owner's own free text (or, failing that, the council permit
	// id) and it headlines the page. On a printed door QR — left on a wall for
	// anyone to scan — that leaks whatever the owner typed, typically an address
	// or apartment number, so use a generic heading there. Completes the same
	// redaction set as the owner email and current plate below.
	if gc.Grant.RequestOnly {
		view.PermitLabel = "Visitor parking permit"
	}
	// A door-QR re-scan should answer "what happened to my request?", not present
	// a blank form as if nothing ever happened. The visitor's own request (and
	// only theirs — the cookie carries the request's poll nonce) is shown with
	// its live fate: pending, on the permit, superseded, ended, or denied.
	if gc.Grant.RequestOnly {
		if req, nonce, ok := s.guestReqFromCookie(r, gc); ok {
			status, _ := s.requestLiveState(ctx, permit, req)
			view.Req = &guestWaitView{Plate: req.Plate, ReqID: req.ID, Nonce: nonce, Status: status, Until: req.Until}
		}
	}
	// A printed door QR is meant to be left out in public, so the page must not
	// disclose the holder's email or the plate currently on the permit to anyone
	// who scans it. For emailed links / on-screen QR (a known or present visitor)
	// the current plate and "managed by" address are useful trust signals.
	if !gc.Grant.RequestOnly {
		view.OwnerEmail = permit.Owner
		view.CurrentReg = current
		view.CheckedAgo = s.guestPlateCheckedAgo(ctx, permit)
		want, decidedAt, until := s.guestDesired(ctx, permit)
		// Offer "put it back" only while THIS link's activation is still the winning
		// plate. If the owner (or their schedule) has since booked over it, the guest
		// has nothing to undo — and reverting would wrongly displace that deliberate
		// booking. Requiring the link's own live override to match the resolved
		// winner keeps the offer honest and prevents the clobber.
		if gp, ok := s.store.ActiveGuestOverridePlate(ctx, permit.ID, gc.TokenID, time.Now()); ok && model.SamePlate(gp, want) {
			view.RevertPlate = revertPlate(gc.BaselinePlate, gc.BaselineUntil, current, gc.Vehicles, time.Now())
		}
		now := time.Now()
		view.PendingReg, view.Stalled = pendingState(current, want, stallSince(permit.ID, current, want, decidedAt, now), now)
		if !until.IsZero() {
			now := now.In(s.cfg.DisplayLocation)
			view.UntilText = untilText(now, until.In(s.cfg.DisplayLocation))
		}
		// The highlight follows the guest's choice the moment it is saved; the
		// "on now" pill follows the council's actual record as it catches up.
		view.SelectedReg = current
		if view.PendingReg != "" {
			view.SelectedReg = view.PendingReg
		}
	}
	view.FP = guestFP(view)
	return view
}

// guestFP fingerprints the state a poll could change. Everything else on the
// page is static per token, so an unchanged fingerprint means an identical body.
func guestFP(v guestActView) string {
	stalled := "0"
	if v.Stalled {
		stalled = "1"
	}
	sum := sha256.Sum256([]byte(v.CurrentReg + "|" + v.PendingReg + "|" + stalled + "|" + v.RevertPlate + "|" + v.UntilText + "|" + v.CheckedAgo))
	return hex.EncodeToString(sum[:6])
}

// renderGuestMenu renders the activation menu with optional feedback. An htmx
// request gets just the live-updating body fragment (no navigation); anything
// else gets the full page. While a change is still applying, the fragment
// carries a poller so the page keeps showing the council's ACTUAL record until
// it matches the schedule's target — never just the intended result.
func (s *Server) renderGuestMenu(w http.ResponseWriter, r *http.Request, gc guestCtx, permit model.Permit, current, flash, warn string) {
	s.renderGuestMenuOpts(w, r, gc, permit, current, flash, warn, false)
}

// renderGuestMenuOpts: keepForm=true (poll responses) renders hx-preserve on the
// form inputs so an in-progress tick/typed plate survives the swap; activation
// responses use false so the overnight box resets — overnight is a deliberate
// per-booking choice, never sticky state.
func (s *Server) renderGuestMenuOpts(w http.ResponseWriter, r *http.Request, gc guestCtx, permit model.Permit, current, flash, warn string, keepForm bool) {
	noStore(w)
	view := s.buildGuestView(r, gc, permit, current)
	view.KeepForm = keepForm
	data := dashboardData{State: "guest", Loc: s.cfg.DisplayLocation, Guest: view, Flash: flash, Warn: warn}
	// The in-page activation swaps (hx-post car/plate, the live poll) want just the
	// #gbody fragment; a boosted link navigation wants the whole page (else it
	// swaps the fragment into <body> and drops the card wrapper/padding).
	if isHX(r) && !isBoosted(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "guest-body", data); err != nil {
			log.Printf("render guest-body: %v", err)
		}
		return
	}
	s.render(w, data)
}

// guestLive is the poll endpoint behind the "still applying" state: public,
// token-gated, side-effect-free. The poll echoes the fingerprint of the state
// it is showing; an unchanged state answers 204 (htmx swaps nothing), so the
// page only repaints — and only replays banner animations — on a REAL change.
// Only pages that rendered a pending banner poll here, so a settled answer
// means the awaited change (or a superseding one) has landed — announce the
// ACTUAL plate now on the council record.
func (s *Server) guestLive(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if permit.Inactive(time.Now(), s.cfg.DisplayLocation) {
		s.renderGuestInactive(w, r)
		return
	}
	if gc.Grant.RequestOnly {
		s.renderGuestGone(w, r)
		return
	}
	current := s.guestCurrentPlate(r.Context(), gc, permit)
	view := s.buildGuestView(r, gc, permit, current)
	if r.URL.Query().Get("fp") == view.FP {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	flash := ""
	if view.PendingReg == "" && !view.Stalled {
		if want, _, _ := s.guestDesired(r.Context(), permit); want != "" && model.SamePlate(current, want) {
			flash = current + " is now on the permit."
		}
	}
	s.renderGuestMenuOpts(w, r, gc, permit, current, flash, "", true)
}

func isHX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// isBoosted reports an hx-boost navigation (a clicked link/form the app turned
// into an AJAX page load). These want a WHOLE page, not an in-page fragment: a
// boosted request still carries HX-Request, so a fragment-or-page check must
// exclude it or a boosted link to a standalone page (the guest menu) swaps in
// only the inner fragment and loses its wrapper — and its padding.
func isBoosted(r *http.Request) bool { return r.Header.Get("HX-Boosted") == "true" }

// guestActivate performs an activation: it creates a fresh override for the chosen
// car (end of today, or tomorrow if overnight) and applies it to the council for
// instant feedback, leaving the scheduler to guarantee eventual consistency. The
// response is the same menu with the result inlined (htmx swaps it in place), so
// a guest can tap one car, then another, then revert, without navigating.
func (s *Server) guestActivate(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		s.guestFail(w, r, "This request could not be verified. Please reopen your link and try again.")
		return
	}
	if !s.guest.allow(rateLimitKey(r)) {
		s.guestFail(w, r, "Too many attempts. Please wait a little while and try again.")
		return
	}
	limitBody(r)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	// A link outlives its permit: a poster stays on the door after the council
	// cancels or expires the permit behind it. Without this gate the activation
	// below would put a real plate on the dead permit and tell the visitor they
	// are covered — the exact fine this app exists to prevent. (The scheduler
	// already refuses to reconcile inactive permits, so the override would also
	// never be corrected.)
	if permit.Inactive(time.Now(), s.cfg.DisplayLocation) {
		s.renderGuestInactive(w, r)
		return
	}

	// A printed QR is inert: a scan only REQUESTS the permit. Nothing goes on the
	// permit until the account holder approves it live.
	if gc.Grant.RequestOnly {
		s.guestRequest(w, r, gc, permit)
		return
	}

	now := time.Now().In(s.cfg.DisplayLocation)
	overnight := gc.Grant.AllowOvernight && r.FormValue("overnight") != ""
	end := dayEndLocal(now, 0)
	if overnight {
		end = dayEndLocal(now, 1)
	}
	current := s.guestCurrentPlate(r.Context(), gc, permit)

	// The target is either an arbitrary plate (when the grant allows it, e.g. a
	// visitor QR) or one of the grant's saved cars. Each becomes a fresh override,
	// created now, so it wins the resolution tie-break for its window.
	var reg, name, createdBy string
	var overrideID int64
	if plate := normalizeReg(r.FormValue("plate")); plate != "" && gc.Grant.AllowPlate {
		if !validRego(plate) {
			s.renderGuestMenu(w, r, gc, permit, current, "", plateFormatMsg)
			return
		}
		reg = plate
		createdBy = gc.Recipient
		if createdBy == "" {
			createdBy = "visitor (QR)"
		}
		id, err := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, plate, now, &end, createdBy, gc.TokenID)
		if err != nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", guestCreateMessage(err, "Something went wrong saving your plate. Please try again."))
			return
		}
		overrideID = id
	} else {
		vid := atoi64(r.FormValue("vehicle_id"))
		var chosen *model.Vehicle
		for i := range gc.Vehicles {
			if gc.Vehicles[i].ID == vid {
				chosen = &gc.Vehicles[i]
				break
			}
		}
		if chosen == nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", "Please choose one of the cars on your link.")
			return
		}
		reg, name, createdBy = chosen.Registration, chosen.Label, gc.Recipient
		id, err := s.store.CreateGuestOverride(r.Context(), permit.ID, chosen.ID, now, &end, gc.Recipient, gc.TokenID)
		if err != nil {
			s.renderGuestMenu(w, r, gc, permit, current, "", guestCreateMessage(err, "Something went wrong saving your choice. Please try again."))
			return
		}
		overrideID = id
	}

	// Capture (or extend) the revert baseline: the plate that was on the permit
	// when this run of activations began. A later tap within the window must NOT
	// re-capture — that would make "revert" restore the guest's own earlier pick
	// instead of the true pre-existing plate. The window is marked even when the
	// pre-existing plate is unknown ('' baseline: no revert offered), so a mid-run
	// tap can't mistake the guest's own plate for the baseline. Done atomically
	// in SQL: two near-simultaneous activations (a double-tap, or two family
	// members on one shared link) must not both "capture" and record the first
	// activation's own plate as the pre-existing one.
	if bp, bu, err := s.store.CaptureOrExtendGuestBaseline(r.Context(), gc.TokenID, current, end, now); err == nil {
		gc.BaselinePlate, gc.BaselineUntil = bp, bu
	}

	until := untilPhrase(now, overnight)
	// Best-effort synchronous apply so the visitor gets a real result; the
	// scheduler (kicked below) owns retries and eventual consistency regardless.
	// Detached from the request context: a closed tab mid-apply must not cancel
	// the council write halfway, nor silently drop the audit row and the
	// displaced-driver notice after the change has already landed. Capped below
	// the server's 20s WriteTimeout so a slow apply still leaves room to write
	// the response.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	// Serialise with the reconcile loop for the duration of the write AND the
	// active_registration write that records it. Without this the loop could be
	// mid-apply of the roster plate, and whichever of us reached the council last
	// would decide the plate while whichever wrote the database last decided our
	// belief about it — leaving the council holding one car and the row naming
	// another. Every later tick then compares its target against that wrong belief,
	// finds nothing to do, and leaves a car uncovered until the next drift check.
	// Bounded by applyCtx, so a stuck claim cannot hold the request open. Held over
	// the council write and the row that records it — those two are the one decision
	// — and released immediately after, so the audit row, the notices and rendering
	// the page never hold up a reconcile pass.
	release, claimed := s.sched.AcquireApply(applyCtx, permit.ID)
	err := error(errApplyBusy)
	if claimed {
		// Re-check authorisation HERE, under the claim and immediately before the
		// council write. The guarded insert proved the link was live at insert time,
		// but a revocation landing in the gap since then deletes the override and tells
		// the owner the pass has stopped working — this stops us then putting the
		// revoked guest's plate on the real permit anyway.
		if d := s.authoriseGuestApply(applyCtx, gc.TokenID, overrideID); d != guestApplyAllowed {
			release()
			s.kickScheduler() // let reconcile restore the correct target
			s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(bg, gc, permit), "", d.message())
			return
		}
		if err = s.council.SetVehicle(applyCtx, permit.Owner, permit, reg); err == nil {
			if e := s.store.SetPermitActive(bg, permit.ID, reg); e != nil {
				// Council confirmed the change; only the local record failed. The Kick
				// below drives a reconcile that re-records it (and alerts if it persists).
				log.Printf("guest: applied %q at council for permit %d but local commit failed: %v", reg, permit.ID, e)
			}
		}
	}
	release()
	// Plain Kick, deliberately: this handler already attempted the council write
	// itself, so clearing the permit's failure backoff would add council pressure
	// without adding a chance of success — and this path is unauthenticated.
	s.sched.Kick()
	if err == nil {
		_ = s.store.RecordApply(bg, permit.ID, reg, "guest", "success", "activated by "+createdBy)
		d, told := s.displacedDriver(bg, permit, current, reg, gc.Recipient)
		s.notifyGuestApply(bg, permit, reg, name, createdBy, d, told)
		s.renderGuestMenu(w, r, gc, permit, reg, reg+" is now on the permit until "+until+".", "")
		return
	}
	// The activity log is user-facing: record a plain-English detail and keep the
	// raw council error in the server log only.
	log.Printf("guest activate %s on permit %d: %v", reg, permit.ID, err)
	_ = s.store.RecordApply(bg, permit.ID, reg, "guest", "error", guestApplyDetail(err))
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The override is saved and the scheduler will apply it shortly; the pending
		// banner + poller (from renderGuestMenu) track the ACTUAL result — no claim.
		s.renderGuestMenu(w, r, gc, permit, current, "", "")
		return
	}
	s.renderGuestMenu(w, r, gc, permit, current, "", "Couldn't update the permit right now. The account holder may need to reconnect their council login. Please try again shortly.")
}

// guestRevert restores the plate that was on the permit before this link's run
// of activations: it sweeps the link's own overrides, re-pins the baseline for
// the rest of the window, and applies it. Always the ORIGINAL pre-existing
// plate — tapping between several cars first doesn't change what revert restores.
func (s *Server) guestRevert(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sameOrigin(r) {
		s.guestFail(w, r, "This request could not be verified. Please reopen your link and try again.")
		return
	}
	if !s.guest.allow(rateLimitKey(r)) {
		s.guestFail(w, r, "Too many attempts. Please wait a little while and try again.")
		return
	}
	limitBody(r)
	gc, permit, ok := s.resolveGuest(r, r.PathValue("token"))
	if !ok {
		s.renderGuestGone(w, r)
		return
	}
	if permit.Inactive(time.Now(), s.cfg.DisplayLocation) {
		s.renderGuestInactive(w, r)
		return
	}
	if gc.Grant.RequestOnly {
		s.renderGuestGone(w, r) // printed QRs never change the permit directly, so there is nothing to revert
		return
	}
	now := time.Now().In(s.cfg.DisplayLocation)
	baseline := normalizeReg(gc.BaselinePlate)
	if baseline == "" || !now.Before(gc.BaselineUntil) || !validRego(baseline) {
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Nothing to put back right now.")
		return
	}

	// Sweep this link's overrides first.
	if err := s.store.DeleteGuestOverrides(r.Context(), permit.ID, gc.TokenID); err != nil {
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Something went wrong. Please try again.")
		return
	}
	createdBy := gc.Recipient
	if createdBy == "" {
		createdBy = "visitor (QR)"
	}

	// Decide what to put back. With the guest's overrides gone, if a deliberate
	// owner booking or the weekly schedule already covers this moment, THAT wins —
	// re-pinning the stale baseline would let a fresh pin leapfrog a booking the
	// owner made after the guest activated. Only when nothing else covers now do we
	// re-pin the pre-existing baseline (capped at end of today; see revertPinEnd).
	target := baseline
	if want, _, _ := s.guestDesired(r.Context(), permit); want != "" {
		target = want
	} else {
		end := revertPinEnd(now, gc.BaselineUntil)
		if _, err := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, baseline, now, &end, createdBy+" (undo)", gc.TokenID); err != nil {
			// The sweep above ALREADY committed, so "the permit wasn't changed" would be
			// false. Say what actually happened and let reconcile settle the target.
			log.Printf("guest: revert re-pin for permit %d failed after the sweep: %v", permit.ID, err)
			s.kickScheduler()
			s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "",
				"Your car was taken off the permit, but we couldn't put the previous one back automatically — it will be restored shortly.")
			return
		}
	}
	// Forget the baseline: the revert consumed it, and hiding the button beats
	// offering a second no-op undo. The next activation captures a fresh one.
	_ = s.store.ClearGuestBaseline(r.Context(), gc.TokenID)
	gc.BaselinePlate, gc.BaselineUntil = "", time.Time{}

	// Detached from the request (see guestActivate): a disconnect mid-apply must
	// not drop the bookkeeping, and the budget stays under the WriteTimeout.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	// Exclusive for this permit over the write and the row that records it (see
	// guestActivate): a revert racing the reconcile loop is the same lost update, and
	// here the plate left behind would be the one the guest just asked us to remove.
	release, claimed := s.sched.AcquireApply(applyCtx, permit.ID)
	err := error(errApplyBusy)
	if claimed {
		// The same gate activation uses. A revert is still a council write on a guest's
		// authority: if the link was revoked while we were deciding the target, it must
		// not reach the portal (overrideID 0 — a revert restores the pre-guest plate
		// rather than exercising a vehicle/plate capability).
		if d := s.authoriseGuestApply(applyCtx, gc.TokenID, 0); d != guestApplyAllowed {
			release()
			s.kickScheduler()
			s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(bg, gc, permit), "", d.message())
			return
		}
		if err = s.council.SetVehicle(applyCtx, permit.Owner, permit, target); err == nil {
			if e := s.store.SetPermitActive(bg, permit.ID, target); e != nil {
				log.Printf("guest: reverted permit %d to %q at council but local commit failed: %v", permit.ID, target, e)
			}
		}
	}
	release()
	s.sched.Kick()
	if err == nil {
		_ = s.store.RecordApply(bg, permit.ID, target, "guest", "success", "put back by "+createdBy)
		// A revert can't displace a third party: the guest's own overrides were
		// just swept, and the baseline is only re-pinned when nothing else covers
		// now — so there is no displaced booking to chase.
		s.notifyGuestApply(bg, permit, target, "", createdBy+" (undo)", model.DisplacedBooking{}, false)
		s.renderGuestMenu(w, r, gc, permit, target, target+" is back on the permit.", "")
		return
	}
	log.Printf("guest revert to %s on permit %d: %v", target, permit.ID, err)
	_ = s.store.RecordApply(bg, permit.ID, target, "guest", "error", guestApplyDetail(err))
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		// The restore is saved; the pending banner + poller track the actual result.
		s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "")
		return
	}
	s.renderGuestMenu(w, r, gc, permit, s.guestCurrentPlate(r.Context(), gc, permit), "", "Couldn't update the permit right now. The account holder may need to reconnect their council login. Please try again shortly.")
}

// guestFail reports a pre-resolution failure (bad origin, rate limit). For a
// true htmx fragment request the whole body is swapped for the notice — the
// page's reload link restores the menu; for a boosted (plain-form) post or a
// non-htmx post it falls back to the full result page, since swapping a bare
// fragment into a boosted <body> loses the card wrapper (the same bug class
// renderGuestMenuOpts/renderGuestGone already guard against).
func (s *Server) guestFail(w http.ResponseWriter, r *http.Request, msg string) {
	if isHX(r) && !isBoosted(r) {
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="banner warn" style="margin-top:14px"><span>%s</span></div><p class="empty-note" style="margin-top:12px"><a href="">Reload this page</a> to try again.</p>`,
			template.HTMLEscapeString(msg))
		return
	}
	s.renderGuestResult(w, "", false, msg)
}

// guestCtx bundles a resolved token with the raw token string (for echoing back).
type guestCtx struct {
	store.GuestContext
	rawToken string
}

// resolveGuest validates a raw token and loads its grant + permit. ok=false means
// the link is invalid/revoked/disabled or its permit is gone (caller shows the
// neutral "no longer active" page).
func (s *Server) resolveGuest(r *http.Request, raw string) (guestCtx, model.Permit, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return guestCtx{}, model.Permit{}, false
	}
	gc, err := s.store.GuestContextByTokenHash(r.Context(), hashGuestToken(raw))
	if err != nil {
		return guestCtx{}, model.Permit{}, false
	}
	permit, err := s.store.GetPermit(r.Context(), gc.Grant.PermitID)
	if err != nil || permit.Owner != gc.Grant.Owner {
		return guestCtx{}, model.Permit{}, false
	}
	// A guest presenting a valid token IS household activity: someone the owner
	// gave access to is using the service right now, which is exactly the
	// evidence the 90-day idle bound wants. Resolving is the one funnel every
	// guest surface (menu, poll, activate, revert, printed-QR request) passes
	// through, so the touch lives here rather than in each handler. Hourly
	// throttled inside.
	s.touchGuestActivity(r.Context(), permit.Owner)
	return guestCtx{GuestContext: gc, rawToken: raw}, permit, true
}

// undeliverableText turns a suppression reason into something an account holder
// can act on. A bounce is usually a typo they can fix; a complaint means the
// person marked our mail as spam, which is theirs to undo, not the owner's.
func undeliverableText(reason string) string {
	switch reason {
	case store.SuppressBounce:
		return "email bounced — check the address, or share the link another way"
	case store.SuppressComplaint:
		return "they marked our email as spam, so we've stopped emailing them"
	case store.SuppressUnsubscribed:
		// Added after this switch was written, and without a case here an
		// unsubscribed recipient rendered as a normal "has a link" row — the silent
		// suppression this page exists to expose. The owner needs to know the link
		// never arrived and that re-sending will not help.
		return "they unsubscribed, so we can't email them — share the link another way"
	case store.SuppressManual:
		return "email disabled for this address"
	default:
		return ""
	}
}

// guestApplyDetail is the user-facing activity-log detail for a failed guest
// apply: the Activity page renders it verbatim, so it must be a plain sentence,
// not a raw council error (which goes to the server log instead).
func guestApplyDetail(err error) string {
	if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
		return "Couldn't reach the council; p.stonn will keep trying."
	}
	return "The council did not accept the change."
}

func (s *Server) notifyGuestApply(ctx context.Context, permit model.Permit, reg, name, by string, d model.DisplacedBooking, told bool) {
	if s.notify == nil {
		return
	}
	// Bounded per account (see guestApplyNotify). The change itself is never
	// dropped — it is on the permit, in the activity log, and on the schedule — but
	// the notification is the only part of this path a link holder can trigger at
	// will, and notify's dedup key includes the plate, so cycling plates meant one
	// email and one push per attempt with nothing in the way.
	if !guestApplyNotify.allow("ga:" + permit.Owner) {
		log.Printf("guest apply notify for %s throttled", redact.Email(permit.Owner))
		return
	}
	// Enqueue durably (a fast insert): unlike the scheduler's apply-notify, this
	// path has no reconcile-loop retry behind it, so a fire-and-forget send could
	// silently drop the "a guest put their car on your permit" notice.
	outcome := notify.ApplyOutcome{
		Owner: permit.Owner, PermitLabel: permitLabel(permit), Reg: reg, Name: name, By: by, Source: "guest", OK: true,
		DisplacedReg: d.Reg, DisplacedTold: told,
	}
	if err := s.notify.EnqueueApply(ctx, outcome); err != nil {
		log.Printf("guest apply notify enqueue for %s: %v", redact.Email(permit.Owner), err)
	}
}

// displacedDriver resolves who should be warned that prev was just taken off a
// permit by actor's change, and notifies them when reachable: the shared
// model.FindDisplaced policy fed the permit's live overrides, the owner's saved
// vehicles, and the account members. Returns what it found so sync-apply paths
// can annotate the account notification (Reg set + no Contact = a booking was
// displaced but its driver couldn't be told). Best-effort: on any store error it
// stays quiet — a missed heads-up is low-harm, the account fanout still fires.
// Returns the displaced booking and whether its driver will genuinely be warned. The
// second value decides between "we've emailed them" and "please tell them yourself", so
// it must reflect what happened — a suppressed address (previous bounce/unsubscribe) is
// guaranteed never to be delivered, and claiming otherwise stands BOTH people down.
func (s *Server) displacedDriver(ctx context.Context, permit model.Permit, prev, next, actor string) (model.DisplacedBooking, bool) {
	if prev == "" || model.SamePlate(prev, next) {
		return model.DisplacedBooking{}, false
	}
	now := time.Now()
	overrides, err := s.store.ListOverrides(ctx, permit.ID, now)
	if err != nil {
		return model.DisplacedBooking{}, false
	}
	saved, err := s.store.ListVehiclesFor(ctx, permit.Owner)
	if err != nil {
		return model.DisplacedBooking{}, false
	}
	vehicles := make(map[int64]model.VehicleInfo, len(saved))
	for _, v := range saved {
		vehicles[v.ID] = model.VehicleInfo{Registration: v.Registration, Label: v.Label, Email: v.Email}
	}
	members, err := s.store.AccountEmails(ctx, permit.Owner)
	if err != nil {
		return model.DisplacedBooking{}, false
	}
	d := model.FindDisplaced(overrides, vehicles, prev, actor, members, now)
	if d.Contact == "" || s.notify == nil {
		return d, false
	}
	if sup, serr := s.store.SuppressedAmong(ctx, []string{d.Contact}); serr != nil || len(sup) > 0 {
		if serr != nil {
			log.Printf("suppression check for %s: %v", notify.RedactEmail(d.Contact), serr)
		}
		return d, false // undeliverable (or unknown): ask the account to pass it on
	}
	if err := s.notify.NotifyDriverDisplaced(ctx, permit.Owner, d.Contact, permitLabel(permit), prev, next); err != nil {
		log.Printf("enqueue driver-displaced for %s: %v", notify.RedactEmail(d.Contact), err)
		return d, false
	}
	return d, true
}

func (s *Server) renderGuestGone(w http.ResponseWriter, r *http.Request) {
	const msg = "This link is no longer active. Ask the account holder for a new one."
	if isHX(r) && !isBoosted(r) {
		// The link died mid-session (revoked, disabled): swap the menu for the notice.
		// A boosted link click, though, is a navigation and wants the whole page.
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="banner warn" style="margin-top:14px"><span>%s</span></div>`, msg)
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusNotFound)
	s.render(w, dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation, Warn: msg})
}

// renderGuestInactive is the notice for a link whose token is still valid but
// whose PERMIT has been cancelled or has expired. Deliberately distinct from
// renderGuestGone: "ask for a new link" would send this guest chasing a link
// that would be exactly as dead. What they need to hear is that the permit
// itself is finished — parking on its say-so no longer protects anyone.
func (s *Server) renderGuestInactive(w http.ResponseWriter, r *http.Request) {
	const msg = "This permit is no longer active, so this code can't put cars on it right now. Please check with your host before parking."
	if isHX(r) && !isBoosted(r) {
		// The permit died mid-session: swap the menu for the notice in place.
		noStore(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<div class="banner warn" style="margin-top:14px"><span>%s</span></div>`, msg)
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusGone)
	s.render(w, dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation, Warn: msg})
}

func (s *Server) renderGuestResult(w http.ResponseWriter, ownerEmail string, ok bool, msg string) {
	noStore(w)
	d := dashboardData{State: "guest-result", Loc: s.cfg.DisplayLocation,
		Guest: guestActView{OwnerEmail: ownerEmail}}
	if ok {
		d.Flash = msg
	} else {
		d.Warn = msg
	}
	s.render(w, d)
}

// ================= ACCOUNT-HOLDER MANAGEMENT (login required) =================

// guestsPage lists the owner's guest passes and the create form.
func (s *Server) guestsPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	// Success feedback after deciding a printed-QR request. These values land in the
	// green success banner — the most trusted element on a page whose whole premise is
	// custody of a council password — and although our own redirects write them, nothing
	// stops someone handing a signed-in user a crafted /guests?resent=… link. So each is
	// VALIDATED on the read path (not just the write path, which the old comment here
	// described): a plate must parse as a rego, a recipient as an email, or it is dropped.
	// This mirrors settings.go, which was hardened for exactly this (H3); /guests was the
	// untouched half.
	switch q := r.URL.Query(); {
	case validRego(normalizeReg(q.Get("applied"))):
		base.Flash = normalizeReg(q.Get("applied")) + " is now on the permit."
	case validRego(normalizeReg(q.Get("approving"))):
		base.Flash = "Approved — " + normalizeReg(q.Get("approving")) + " is being put on the permit."
	case q.Get("declined") != "":
		base.Flash = "Request declined."
	case looksLikeEmail(q.Get("resent")):
		base.Flash = "A fresh link has been sent to " + q.Get("resent") + ". Their previous link has been replaced."
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, base)
}

// editGuestGrant renders the guests page with the pass form pre-filled for the
// grant to edit.
func (s *Server) editGuestGrant(w http.ResponseWriter, r *http.Request) {
	// Gated before the page shell: the form this renders posts to
	// updateGuestGrant, which refuses a dead permit — say so up front instead of
	// letting the edit be filled in for nothing.
	_, owner, _ := s.resolveAccount(r.Context())
	if s.refuseDeadGrantPermit(w, r, owner, pathInt(r, "id"), permitInactivePassFrozen) {
		return
	}
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, pathInt(r, "id")); err != nil {
		s.serverError(w, err)
		return
	}
	if base.Edit == nil { // no such grant for this owner
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	s.render(w, base)
}

// loadGuests fills the guest-management fields (grants, permit/vehicle choices,
// kill-switch state) on base. When editID > 0 and matches one of the owner's
// grants, it also populates base.Edit so the form renders in edit mode.
func (s *Server) loadGuests(ctx context.Context, base *dashboardData, editID int64) error {
	owner := base.Owner
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return err
	}
	labelByPermit := map[int64]string{}
	deadPermit := map[int64]bool{}
	now := time.Now()
	for _, p := range permits {
		if p.Inactive(now, s.cfg.DisplayLocation) {
			// Existing passes and request history still name the permit, but say
			// plainly that it's finished — and never offer it for NEW links. The
			// pass card itself carries a pill and the way out (see PermitDead): a
			// suffix on a bare permit number was not read as "your guests' links
			// are dead" by the one household this happened to (2026-08-22).
			labelByPermit[p.ID] = permitLabel(p) + " — no longer active"
			deadPermit[p.ID] = true
			continue
		}
		labelByPermit[p.ID] = permitLabel(p)
		base.PermitOpts = append(base.PermitOpts, permitOpt{ID: p.ID, Label: permitLabel(p)})
	}
	vehicles, err := s.store.ListVehiclesFor(ctx, owner)
	if err != nil {
		return err
	}
	base.Vehicles, _, _, _ = vehicleViews(vehicles)

	details, err := s.store.ListGuestGrants(ctx, owner)
	if err != nil {
		return err
	}
	// Annotate recipients whose address the mail provider has told us is dead.
	// One query for the whole page rather than one per recipient.
	var allRecipients []string
	for _, d := range details {
		for _, t := range d.Tokens {
			allRecipients = append(allRecipients, t.RecipientEmail)
		}
	}
	undeliverable, err := s.store.SuppressedAmong(ctx, allRecipients)
	if err != nil {
		// Best-effort annotation: never fail the page over it.
		log.Printf("guests: suppression lookup for %s: %v", redact.Email(owner), err)
		undeliverable = map[string]string{}
	}
	for _, d := range details {
		cars, _, _, _ := vehicleViews(d.Vehicles)
		var recips []guestRecipientView
		for _, t := range d.Tokens {
			recips = append(recips, guestRecipientView{
				TokenID: t.ID, Email: t.RecipientEmail, Revoked: t.Revoked,
				Undeliverable: undeliverableText(undeliverable[t.RecipientEmail]),
			})
		}
		base.Guests = append(base.Guests, guestGrantView{
			ID: d.Grant.ID, Label: d.Grant.Label, PermitLabel: labelByPermit[d.Grant.PermitID],
			PermitDead:     deadPermit[d.Grant.PermitID],
			AllowOvernight: d.Grant.AllowOvernight, Cars: cars, Recipients: recips,
		})
		if editID > 0 && d.Grant.ID == editID {
			sel := map[int64]bool{}
			for _, v := range d.Vehicles {
				sel[v.ID] = true
			}
			base.Edit = &editGrantView{
				ID: d.Grant.ID, Label: d.Grant.Label, PermitLabel: labelByPermit[d.Grant.PermitID],
				AllowOvernight: d.Grant.AllowOvernight, Selected: sel, Recipients: recips,
			}
		}
	}
	if reqs, rerr := s.store.ListPendingRequests(ctx, owner); rerr == nil {
		now := time.Now()
		for _, rq := range reqs {
			base.PendingRequests = append(base.PendingRequests, guestReqView{
				ID: rq.ID, Plate: rq.Plate, PermitLabel: labelByPermit[rq.PermitID], Ago: agoText(now, rq.RequestedAt),
			})
		}
	}
	// Recently decided printed-QR requests: every member got the "approve this?"
	// nudge, so every member can see how it was resolved — including the live
	// fate of an approved plate (on the permit / superseded / ended). Best-effort
	// like the queue above: an error just hides the section.
	if recent, rerr := s.store.ListRecentDecidedRequests(ctx, owner, time.Now().Add(-guestReqCookieTTL)); rerr == nil {
		now := time.Now()
		permitByID := map[int64]model.Permit{}
		for _, p := range permits {
			permitByID[p.ID] = p
		}
		for _, rq := range recent {
			v := guestDecidedView{
				Plate: rq.Plate, PermitLabel: labelByPermit[rq.PermitID],
				DecidedBy: rq.DecidedBy, Ago: agoText(now, rq.DecidedAt),
			}
			switch rq.Status {
			case "approved":
				v.Outcome = "Approved"
				if p, ok := permitByID[rq.PermitID]; ok {
					switch st, replacedBy := s.requestLiveState(ctx, p, rq); st {
					case "applied":
						v.Live = "On the permit until " + rq.Until + "."
					case "approved":
						v.Live = "Being put on the permit…"
					case "stalled":
						v.Live, v.Warn = "Not yet confirmed on the permit — check the permit's schedule.", true
					case "superseded":
						// Members may see the superseding plate (unlike the public door-QR
						// pages, which never disclose the permit's current plate).
						v.Live, v.Warn = "No longer on the permit — since replaced.", true
						if replacedBy != "" {
							v.Live = "No longer on the permit — since replaced by " + replacedBy + "."
						}
					case "ended":
						v.Live = "The pass has ended."
					}
				}
			case "denied":
				v.Outcome = "Declined"
			default: // "expired": aged out with nobody answering
				v.Outcome = "Not answered"
			}
			base.RecentRequests = append(base.RecentRequests, v)
		}
	}
	if doors, derr := s.store.ListPrintedGrants(ctx, owner); derr == nil {
		for _, d := range doors {
			base.DoorGrants = append(base.DoorGrants, doorGrantView{
				GrantID: d.GrantID, PermitLabel: d.PermitLabel,
				CreatedAt: d.CreatedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006"),
			})
		}
	}
	base.GuestsEnabled, err = s.store.GuestsEnabled(ctx, owner)
	return err
}

// agoText is a coarse "how long ago" for the approvals queue.
func agoText(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hr ago", int(d.Hours()))
	default:
		// The stale-plate caption can be days old (a cached reading has no upper
		// age bound during a council outage); "78 hr ago" hides that.
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// createGuestGrant creates a grant + a per-recipient token, emails each link, and
// re-renders the page showing the links once (the only time we hold the raw token).
func (s *Server) createGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	permitID := atoi64(r.FormValue("permit_id"))
	label := guestGrantLabel(r.FormValue("label"))
	allowOvernight := r.FormValue("allow_overnight") != ""
	var vehicleIDs []int64
	for _, v := range r.Form["vehicle_id"] {
		if id := atoi64(v); id > 0 {
			vehicleIDs = append(vehicleIDs, id)
		}
	}
	recipients, droppedEmails := parseEmails(r.FormValue("recipients"))
	if len(vehicleIDs) == 0 {
		s.formError(w, r, "Choose at least one car this link may activate.")
		return
	}
	if len(recipients) == 0 {
		if len(droppedEmails) > 0 {
			s.formError(w, r, "None of those recipient emails look valid. Check them and try again.")
			return
		}
		s.formError(w, r, "Add at least one recipient email.")
		return
	}
	if len(recipients) > maxGuestRecipients {
		s.formError(w, r, tooManyRecipients)
		return
	}

	// Refuse a dead target before minting anything, and FAIL CLOSED on a store
	// error — a gate that shrugs on error would mint and email a link for a
	// permit it couldn't check. Unknown permits fall through: CreateGuestGrant's
	// atomic ownership check answers those with a clean 403.
	switch permit, perr := s.store.GetPermit(r.Context(), permitID); {
	case errors.Is(perr, store.ErrNotFound):
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Owner == owner && permit.Inactive(time.Now(), s.cfg.DisplayLocation):
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
		return
	}

	recs, links := s.mintLinks(recipients)
	if _, err := s.store.CreateGuestGrant(r.Context(), owner, user, permitID, label, allowOvernight, vehicleIDs, recs); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit or car isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	sent := s.emailLinks(r.Context(), owner, permitLabel(permit), links)

	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.NewGuestLinks = links
	switch {
	case sent == len(links):
		base.Flash = "Guest pass created and links emailed."
	case sent > 0:
		base.Flash = "Guest pass created. Some links couldn't be emailed — copy the links below to be sure everyone gets theirs."
	default:
		base.Flash = "Guest pass created. Copy the links below to share them."
	}
	base.Flash += skippedNote(droppedEmails)
	s.logChange(r.Context(), owner, user, store.ActionGuestCreate, strings.Join(recipients, ", "), label)
	s.render(w, base)
}

// tokenShape matches the SHAPE of a token this app mints: base64url, and long
// enough to be one. The bound is loose on purpose — this is not an existence check
// (see guestManifest) and a token that is merely an unfamiliar length must still
// be allowed to work.
var tokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// guestManifest serves a per-recipient web app manifest, so a guest can install
// their link to the home screen (Android/Chrome "Install") and have the icon open
// straight to THEIR menu (start_url is their own link). Public and token-scoped;
// icons are the app's static PNGs. Existence is deliberately not checked: a
// manifest for a dead link is harmless (the page it points to just shows "no
// longer active"), and checking would put a DB query on an anonymous route.
func (s *Server) guestManifest(w http.ResponseWriter, r *http.Request) {
	// The shape gate keeps anything that isn't a token out of the document, and
	// json.Marshal — not %q, which is Go quoting and emits \x01 for a decoded
	// control byte — makes what does get in valid JSON. With %q a single such byte
	// broke the whole manifest, so "Install" silently stopped working.
	token := r.PathValue("token")
	if !tokenShape.MatchString(token) {
		http.NotFound(w, r)
		return
	}
	start, err := json.Marshal("/g/" + token)
	if err != nil {
		s.serverError(w, err)
		return
	}
	startURL := string(start)
	w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, `{
  "name": "p.stonn parking permit",
  "short_name": "p.stonn",
  "start_url": `+startURL+`,
  "scope": "/g/",
  "display": "standalone",
  "theme_color": "#0d9488",
  "background_color": "#eceff5",
  "icons": [
    {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
    {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}
  ]
}`)
}

// resendGuestLink emails a recipient a FRESH link for a guest pass they already
// have. The original link can't be re-sent (only its hash is stored), so this
// mints a new token and supersedes the old one. Owner-only.
func (s *Server) resendGuestLink(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	recipient := strings.TrimSpace(r.FormValue("recipient"))
	if recipient == "" {
		s.formError(w, r, "No recipient to re-send to.")
		return
	}
	// Don't rotate the token when the permit is dead: the guest's link 410ing is
	// the very symptom that prompts a re-send, and rotating would trade their
	// token — which comes back to life after a renewal copy — for a fresh one
	// that is just as dead.
	if s.refuseDeadGrantPermit(w, r, owner, pathInt(r, "id"), permitInactivePassFrozen) {
		return
	}
	// Nor when we can't deliver the replacement — that would break the
	// recipient's current link with nothing to replace it.
	if !s.notify.EmailAvailable() {
		s.formError(w, r, "Email isn't set up, so links can't be re-sent.")
		return
	}
	raw, hash := newGuestToken()
	permitID, err := s.store.ResetGuestToken(r.Context(), owner, pathInt(r, "id"), recipient, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That guest pass or recipient isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	// Logged because this ROTATES the token: the recipient's old link is now dead.
	// A member silently re-keying someone else's access is exactly the kind of
	// change the household should be able to see after the fact.
	s.logChange(r.Context(), owner, user, store.ActionGuestResend, recipient, "")
	permit, _ := s.store.GetPermit(r.Context(), permitID)
	links := []guestLinkView{{Email: recipient, URL: s.guestLink(raw)}}
	if s.emailLinks(r.Context(), owner, permitLabel(permit), links) == 0 {
		// The send failed at runtime (SMTP up-check passed, delivery didn't). The
		// old token is already superseded, so claiming success would leave the
		// recipient with a dead link and nothing delivered. Show the fresh link
		// once on-page instead, like create/update do, so the owner can pass it on.
		base, ok := s.appShell(w, r, "guests")
		if !ok {
			return
		}
		if err := s.loadGuests(r.Context(), &base, 0); err != nil {
			s.serverError(w, err)
			return
		}
		base.NewGuestLinks = links
		base.Flash = "The email could not be sent. Copy the fresh link below and share it yourself — the old link no longer works."
		s.render(w, base)
		return
	}
	http.Redirect(w, r, "/guests?resent="+url.QueryEscape(recipient), http.StatusSeeOther)
}

// updateGuestGrant edits a grant's label, cars, and overnight option, and adds
// any new recipients (each getting a fresh emailed link). The permit is fixed.
func (s *Server) updateGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	id := pathInt(r, "id")
	// An edit can add recipients — minting by another door — so it shares the
	// dead-permit refusal with the create surfaces.
	if s.refuseDeadGrantPermit(w, r, owner, id, permitInactivePassFrozen) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	label := guestGrantLabel(r.FormValue("label"))
	allowOvernight := r.FormValue("allow_overnight") != ""
	var vehicleIDs []int64
	for _, v := range r.Form["vehicle_id"] {
		if vid := atoi64(v); vid > 0 {
			vehicleIDs = append(vehicleIDs, vid)
		}
	}
	if len(vehicleIDs) == 0 {
		s.formError(w, r, "Choose at least one car this pass may activate.")
		return
	}
	// Parse and validate the recipients BEFORE mutating anything: returning an error
	// after the label/cars were already committed left the pass changed while telling
	// the user it failed.
	emails, droppedEmails := parseEmails(r.FormValue("recipients"))
	if len(emails) > maxGuestRecipients {
		s.formError(w, r, tooManyRecipients)
		return
	}
	swept, err := s.store.UpdateGuestGrant(r.Context(), owner, id, label, allowOvernight, vehicleIDs)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That pass or car isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	if swept > 0 {
		// A car was unticked mid-booking: its live overrides were just removed, so ask
		// reconcile to take it off the permit now rather than at the next tick.
		s.kickScheduler()
	}

	// New recipients (if any) each get a fresh token + link.
	var newLinks []guestLinkView
	if len(emails) > 0 {
		recs, links := s.mintLinks(emails)
		// NOTE: the grant update above has already committed. These errors must not claim
		// the whole edit failed.
		added, err := s.store.AddGuestTokens(r.Context(), owner, id, recs)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			// A 500 here would tell the user the whole edit failed when the label/cars
			// are already committed. Send them back to the pass, which shows its real
			// current state and lets them add the recipients again.
			log.Printf("guest: pass %d updated but adding recipients failed: %v", id, err)
			http.Redirect(w, r, "/guests", http.StatusSeeOther)
			return
		}
		addedSet := map[string]bool{}
		for _, e := range added {
			addedSet[e] = true
		}
		for _, l := range links {
			if addedSet[l.Email] {
				newLinks = append(newLinks, l)
			}
		}
	}

	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		// By here the grant is updated AND any new tokens are live. A 500 would strand
		// them: this render is the only place the links are shown, and emailLinks below
		// never runs. Redirect instead — the pass and its recipients are listed on the
		// guests page, so the household can re-send a link rather than being left with
		// live tokens they never saw.
		log.Printf("guest: pass %d updated but the guests page could not be rendered: %v", id, err)
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	if len(newLinks) > 0 {
		plabel := ""
		for _, g := range base.Guests {
			if g.ID == id {
				plabel = g.PermitLabel
			}
		}
		sent := s.emailLinks(r.Context(), owner, plabel, newLinks)
		base.NewGuestLinks = newLinks
		switch {
		case sent == len(newLinks):
			base.Flash = "Guest pass updated and new links emailed."
		case sent > 0:
			base.Flash = "Guest pass updated. Some links couldn't be emailed — copy the links below to be sure everyone gets theirs."
		default:
			base.Flash = "Guest pass updated. Copy the new links below to share them."
		}
	} else {
		base.Flash = "Guest pass updated."
	}
	base.Flash += skippedNote(droppedEmails)
	s.logChange(r.Context(), owner, user, store.ActionGuestUpdate, label, "")
	s.render(w, base)
}

// maxGuestRecipients bounds one submission's recipient list. Every address on it
// becomes a LIVE token over the household's permit and an outbound email, and the
// list is free text inside a 64 KB body — which is room for roughly four thousand
// of them, each costing token rows, a mail attempt and a management row on the
// guests page. Far above any real household's list; far below anything that turns
// one form post into a bulk mailer.
const maxGuestRecipients = 20

const tooManyRecipients = "That's too many recipients for one pass. Add up to 20 at a time."

// maxGuestGrantLabel matches the permit-label cap, for the same reasons: the label
// headlines the guest's page and rides into the email that carries their link, so
// an unbounded one inflates every stored notification along the way.
const maxGuestGrantLabel = 40

// guestGrantLabel cleans and caps a pass name the same way a permit's is (control
// characters stripped, trimmed, truncated by runes so a multi-byte name can't be
// cut in half).
func guestGrantLabel(s string) string {
	label := cleanLabel(s)
	if rs := []rune(label); len(rs) > maxGuestGrantLabel {
		label = string(rs[:maxGuestGrantLabel])
	}
	return label
}

// mintLinks generates a fresh token per email: the store records to persist (only
// the hash) and the display links to email or show once.
func (s *Server) mintLinks(emails []string) ([]store.GuestRecipient, []guestLinkView) {
	recs := make([]store.GuestRecipient, 0, len(emails))
	links := make([]guestLinkView, 0, len(emails))
	for _, e := range emails {
		raw, hash := newGuestToken()
		recs = append(recs, store.GuestRecipient{Email: e, TokenHash: hash})
		links = append(links, guestLinkView{Email: e, URL: s.guestLink(raw)})
	}
	return recs, links
}

// emailLinks sends each link best-effort (no-op without SMTP) and returns how
// many were accepted. Failures are logged so a guest who never received their
// link can be traced; the caller's flash + the shown-once links panel are the
// user-facing fallback.
//
// Throttled two ways, like the member invite: these mails go to arbitrary
// addresses the user types, and each one carries a live capability over their
// permit — so an account must not be able to mail-bomb a stranger (per-recipient)
// or burn the SMTP reputation everyone shares (per-owner). A throttled link is
// not lost: the caller always shows it on screen to copy.
func (s *Server) emailLinks(ctx context.Context, owner, permitLabel string, links []guestLinkView) int {
	sent := 0
	for _, l := range links {
		if !s.guestLinkOut.allow("o:"+owner) || !s.guestLinkTo.allow("t:"+l.Email) {
			log.Printf("guest link email to %s for %s throttled", notify.RedactEmail(l.Email), notify.RedactEmail(owner))
			continue
		}
		if err := s.notify.SendGuestLink(ctx, l.Email, owner, permitLabel, l.URL); err == nil {
			sent++
		} else {
			log.Printf("guest link email to %s for %s: %v", notify.RedactEmail(l.Email), notify.RedactEmail(owner), err)
		}
	}
	return sent
}

// visitorQR returns the permit's on-screen visitor QR, reusing the current one if
// it is still working and minting a fresh one otherwise.
//
// Reuse is what lets this be a one-tap action from the schedule page. A resident
// whose visitor mis-scans will simply tap again; minting each time would leave
// several working codes for one doorstep, invalidate nothing, and make the stated
// stop-working time true of only the newest. It also means re-opening the modal
// cannot race a scan already in progress.
func (s *Server) visitorQR(ctx context.Context, owner, user string, permit model.Permit) (*qrShowView, error) {
	raw, expires, err := s.reuseVisitorQR(ctx, owner, permit.ID)
	switch {
	case err == nil: // still live: same code, its own original deadline
	case errors.Is(err, store.ErrNotFound):
		raw, expires, err = s.mintVisitorQR(ctx, owner, user, permit)
		if err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	img, err := qrDataURI(s.guestLink(raw))
	if err != nil {
		return nil, err
	}
	return &qrShowView{
		PermitLabel: permitLabel(permit),
		ImageURI:    template.URL(img),
		URL:         s.guestLink(raw),
		StopsAt:     expires.In(s.cfg.DisplayLocation).Format("3:04pm"),
	}, nil
}

// reuseVisitorQR opens the sealed token of a still-working QR for this permit.
// A token we cannot unseal is treated as absent, so a key problem yields a fresh
// code rather than a dead end at the door.
func (s *Server) reuseVisitorQR(ctx context.Context, owner string, permitID int64) (string, time.Time, error) {
	sealed, expires, err := s.store.LiveQRGrant(ctx, owner, permitID, time.Now())
	if err != nil {
		return "", time.Time{}, err
	}
	raw, _, err := s.box.OpenCtx(secretbox.GuestToken(owner), sealed)
	if err != nil {
		log.Printf("visitor QR: could not open a live token for permit %d (%v); minting a fresh one", permitID, err)
		return "", time.Time{}, store.ErrNotFound
	}
	return raw, expires, nil
}

// mintVisitorQR creates a new short-lived plate-entry grant and logs it.
func (s *Server) mintVisitorQR(ctx context.Context, owner, user string, permit model.Permit) (string, time.Time, error) {
	raw, hash := newGuestToken()
	sealed, err := s.box.SealCtx(secretbox.GuestToken(owner), raw)
	if err != nil {
		return "", time.Time{}, err
	}
	if _, err := s.store.CreateQRGrant(ctx, owner, user, permit.ID, hash, sealed, qrTTL); err != nil {
		return "", time.Time{}, err
	}
	// This mints a live, if short-lived, capability: whoever scans the screen can
	// put a plate on the permit without further approval. Every other way of
	// handing out permit access is logged, so this one is too. Only a genuinely NEW
	// code is logged — re-opening the same one is not a new grant of access.
	s.logChange(ctx, owner, user, store.ActionDoorQRShow, permitLabel(permit), "")
	return raw, time.Now().Add(qrTTL), nil
}

// showVisitorQR renders the on-screen visitor QR for a permit. A visitor scans it,
// types their plate, and it goes on the permit until the end of the day.
//
// Serves a bare card to htmx (the schedule page's modal) and a full page otherwise,
// so the same action works from the permit card and from the guests page.
func (s *Server) showVisitorQR(w http.ResponseWriter, r *http.Request) {
	noStore(w) // the response embeds a live activation token; keep it out of caches
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	permit, err := s.store.GetPermit(r.Context(), atoi64(r.FormValue("permit_id")))
	if err != nil || permit.Owner != owner {
		s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
		return
	}
	if permit.Inactive(time.Now(), s.cfg.DisplayLocation) {
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
		return
	}
	qr, err := s.visitorQR(r.Context(), owner, user, permit)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	// A boosted link is a navigation and wants the whole page; a plain hx-post from
	// the permit card's button wants just the card to drop into its modal.
	if isHX(r) && !isBoosted(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "qr-card", dashboardData{QR: qr, Loc: s.cfg.DisplayLocation}); err != nil {
			log.Printf("render qr-card: %v", err)
		}
		return
	}
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	base.QR = qr
	s.render(w, base)
}

func (s *Server) deleteGuestGrant(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Name it before deleting, so the log and the notice can say which pass died.
	label := s.grantLabel(r.Context(), owner, pathInt(r, "id"))
	// A missing row is tolerated (a double-submitted form, a stale page) but must
	// not be announced: logging it and emailing the household "a guest pass was
	// deleted, those links have stopped working" for an id that never existed
	// invents an event, and the dedup key only suppresses identical repeats.
	// Take the permit's apply claim BEFORE revoking, so an in-flight guest activation
	// either completes first (and its override is then swept) or cannot start — a
	// revocation must not be overtaken by a council write on the authority it removed.
	pid, _ := s.store.GuestGrantPermit(r.Context(), owner, pathInt(r, "id"))
	releaseClaims := s.claimPermitApplies(r.Context(), []int64{pid})
	err := s.store.DeleteGuestGrant(r.Context(), owner, pathInt(r, "id"))
	releaseClaims()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionGuestDelete, label, "")
		s.notifyDestructive(r.Context(), owner, user,
			user+" deleted a guest pass"+optional(label, " (")+closeParen(label)+" on your p.stonn account. Anyone holding those links can no longer use your permit, and p.stonn is taking any car they had put on it back off now — check the permit directly if this is urgent.")
		// The sweep changed what the schedule resolves to, so the permit is now out of
		// date. Without a kick it stays that way until the next pass — and the point of
		// revoking was that the guest's plate comes off NOW.
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) revokeGuestToken(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Name the recipient before their link dies, so the audit row says whose access
	// was taken away rather than merely that some access was.
	recipient, _ := s.store.GuestTokenRecipient(r.Context(), owner, pathInt(r, "tid"))
	// Tolerate a missing row, but don't log an action that didn't happen.
	pid, _ := s.store.GuestTokenPermit(r.Context(), owner, pathInt(r, "tid"))
	releaseClaims := s.claimPermitApplies(r.Context(), []int64{pid}) // see deleteGuestGrant
	err := s.store.RevokeGuestToken(r.Context(), owner, pathInt(r, "tid"))
	releaseClaims()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionGuestRevoke, recipient, "")
		// Told to the household like every other withdrawal of access (deleting a pass,
		// removing a door QR): one member cutting off a person the others invited is
		// exactly the change silence hides.
		s.notifyDestructive(r.Context(), owner, user,
			user+" revoked a guest link"+optional(recipient, " (")+closeParen(recipient)+" on your p.stonn account. That link no longer works, and p.stonn is taking any car it had put on your permit back off now — check the permit directly if this is urgent.")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

// kickScheduler asks the reconcile loop to run now. Tolerates a Server built
// without one (tests construct one directly): a revocation must still take the
// guest's authority away even when nothing is running to re-apply the schedule.
func (s *Server) kickScheduler() {
	if s.sched != nil {
		s.sched.Kick()
	}
}

func (s *Server) toggleGuests(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	enabled := r.FormValue("enabled") != ""
	// Pausing is a revocation across every permit on the account: claim them all (in a
	// stable order) so no guest apply can be in flight as the switch flips.
	var releaseClaims = func() {}
	if !enabled {
		var ids []int64
		if ps, perr := s.store.ListPermitsFor(r.Context(), owner); perr == nil {
			for _, p := range ps {
				ids = append(ids, p.ID)
			}
		}
		releaseClaims = s.claimPermitApplies(r.Context(), ids)
	}
	err := s.store.SetGuestsEnabled(r.Context(), owner, enabled)
	releaseClaims()
	if err != nil {
		s.serverError(w, err)
		return
	}
	state := "on"
	if !enabled {
		state = "off"
	}
	s.logChange(r.Context(), owner, user, store.ActionGuestToggle, "", state)
	if !enabled {
		// Pausing kills every guest link at once — a visitor at the kerb just sees
		// "no longer active", so the household should know it was deliberate.
		s.notifyDestructive(r.Context(), owner, user,
			user+" paused all guest passes on your p.stonn account. Existing guest links and printed QR codes will not work until they are resumed, and p.stonn is taking any car a guest had put on a permit back off now — check the permit directly if this is urgent.")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) setVehicleEmail(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email != "" && !looksLikeEmail(email) {
		s.formError(w, r, "Enter a valid email address, or leave it blank.")
		return
	}
	if err := s.store.SetVehicleEmail(r.Context(), owner, pathInt(r, "id"), email); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	// Worth logging precisely because of what it is: the one action that adds
	// ANOTHER PERSON's email address to the account. It was the only change
	// missing from the Activity page.
	detail := "removed"
	if email != "" {
		detail = "set"
	}
	s.logChange(r.Context(), owner, user, store.ActionVehicleEmail,
		s.plateOf(r.Context(), owner, pathInt(r, "id")), detail)
	http.Redirect(w, r, "/vehicles?saved=1", http.StatusSeeOther)
}

// parseEmails splits a free-text recipient list (comma/space/semicolon/newline
// separated), lower-cases, validates, and de-duplicates. Invalid tokens are
// dropped so one typo doesn't discard the rest, and returned separately so the
// caller can tell the user who was skipped.
func parseEmails(s string) (out, dropped []string) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'
	})
	seen := map[string]bool{}
	for _, f := range fields {
		e := strings.ToLower(strings.TrimSpace(f))
		if e == "" || seen[e] {
			continue
		}
		if !looksLikeEmail(e) {
			dropped = append(dropped, e)
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out, dropped
}

// skippedNote turns parseEmails' dropped tokens into a flash suffix, so a
// typo'd recipient doesn't vanish without a trace.
func skippedNote(dropped []string) string {
	if len(dropped) == 0 {
		return ""
	}
	return " Skipped (not a valid email): " + strings.Join(dropped, ", ") + "."
}

// ================= PRINTED QR: REQUEST + APPROVE =================

func randNonce() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		panic("guest request nonce: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// requestLiveState classifies where a printed-QR request stands RIGHT NOW, in
// the template's own status terms, so every surface that shows a request (the
// wait page's poll, a door-QR re-scan, the guests page's recent list) derives
// the same answer from the same resolution the scheduler acts on:
//
//	pending    — awaiting the holder's decision
//	denied     — declined by the holder
//	expired    — aged out unanswered (distinct from an actual "no")
//	ended      — approved, but the granted window has since lapsed
//	superseded — approved, but the schedule now resolves to a different plate
//	             (or to nothing): the pass was overridden, not merely slow
//	applied    — approved AND the council's own record shows the plate
//	stalled    — approved but unconfirmed past guestApplyTimeout
//	approved   — approved, council catching up (keep polling)
//
// replacedBy is the plate now steering the permit, only for "superseded" ("" =
// nothing scheduled). Owner-facing surfaces may show it; the PUBLIC door-QR
// pages must not — a poster scan must never disclose the permit's current plate.
func (s *Server) requestLiveState(ctx context.Context, permit model.Permit, req store.GuestRequest) (status, replacedBy string) {
	switch req.Status {
	case "pending":
		return "pending", ""
	case "denied":
		return "denied", ""
	case "expired":
		// Aged out unanswered — distinct from an actual "no" on every surface.
		return "expired", ""
	}
	// Approved. Ended is checked first: after the window lapses the schedule
	// naturally resolves elsewhere, which must read as "ended", not "superseded".
	now := time.Now().In(s.cfg.DisplayLocation)
	end := req.UntilTS
	if end.IsZero() && !req.DecidedAt.IsZero() {
		// Rows approved before until_ts existed: reproduce the approval's window
		// (printed-QR approvals always ran to the end of the approval's day).
		end = dayEndLocal(req.DecidedAt.In(s.cfg.DisplayLocation), 0)
	}
	if !end.IsZero() && !now.Before(end) {
		return "ended", ""
	}
	want, _, _ := s.guestDesired(ctx, permit)
	if !model.SamePlate(want, req.Plate) {
		return "superseded", want
	}
	if model.SamePlate(permit.ActiveRegistration, req.Plate) {
		return "applied", ""
	}
	if !req.DecidedAt.IsZero() && time.Since(req.DecidedAt) > guestApplyTimeout {
		return "stalled", ""
	}
	return "approved", ""
}

// guestReqCookie remembers the visitor's own printed-QR request in their
// browser: "reqID.nonce", where the nonce is the same per-request secret the
// wait page's poll URL already carries — the cookie only persists it client-
// side, introducing no new secret class. Scoped to /g/ (the public guest
// routes) and long enough to outlive the granted window, so the morning-after
// re-scan can still say "your pass has ended".
const guestReqCookie = "greq"

const guestReqCookieTTL = 48 * time.Hour

func (s *Server) setGuestReqCookie(w http.ResponseWriter, reqID int64, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name:     guestReqCookie,
		Value:    fmt.Sprintf("%d.%s", reqID, nonce),
		Path:     "/g/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.cfg.PublicBaseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(guestReqCookieTTL.Seconds()),
	})
}

// guestReqFromCookie resolves the browser's remembered request. It is gated on
// the nonce (a stale, purged, or tampered cookie simply resolves to nothing)
// and pinned to THIS grant, so a request made at one door never surfaces at
// another. Returns the nonce too, for the status fragment's poll URL.
func (s *Server) guestReqFromCookie(r *http.Request, gc guestCtx) (store.GuestRequest, string, bool) {
	c, err := r.Cookie(guestReqCookie)
	if err != nil {
		return store.GuestRequest{}, "", false
	}
	idStr, nonce, ok := strings.Cut(c.Value, ".")
	if !ok || nonce == "" {
		return store.GuestRequest{}, "", false
	}
	id := atoi64(idStr)
	if id <= 0 {
		return store.GuestRequest{}, "", false
	}
	req, err := s.store.GuestRequestForPoll(r.Context(), id, nonce)
	if err != nil || req.GrantID != gc.Grant.ID {
		return store.GuestRequest{}, "", false
	}
	return req, nonce, true
}

// guestRequest handles a printed-QR scan: it records a pending request for the
// plate the visitor typed, notifies the account holder, and shows a page that
// polls until the holder decides. Nothing is put on the permit here — the
// approval is the security boundary.
func (s *Server) guestRequest(w http.ResponseWriter, r *http.Request, gc guestCtx, permit model.Permit) {
	// A printed door QR is public, so the visitor-facing pages here never show the
	// holder's email (unlike the emailed/on-screen flows, where the recipient is known).
	plate := normalizeReg(r.FormValue("plate"))
	if !validRego(plate) {
		// Re-rendered through the shared view builder, which is where the request-only
		// redaction lives. Assembling the view here instead put the permit's LABEL on a
		// page anyone who scans a poster can reach — the owner's own text, typically an
		// address or apartment number — and this branch is not even adversarial:
		// normalizeReg now absorbs the ordinary-visitor spellings ("ABC-123", a pasted
		// non-breaking space), but a mistyped length or a stray symbol still lands here.
		s.renderGuestMenu(w, r, gc, permit, "", "", plateFormatMsg)
		return
	}
	// This browser's own remembered request, resolved before anything is created: it
	// is the only evidence that the person asking is the one who asked before.
	mine, myNonce, haveMine := s.guestReqFromCookie(r, gc)
	ownRepeat := haveMine && mine.Status == "pending" && model.SamePlate(mine.Plate, plate)
	// A re-submission of one's own pending plate consumes no slot, so it is never
	// throttled. Anything else is refused once the queue has grown into the reserved
	// tail IF we have already heard from this requester — either their rate-limit key has
	// spent its scanner token, or their browser already carries a still-pending request
	// for this grant (the greq cookie). Counting the cookie too means a returning browser
	// that hops to a fresh IP is still recognised, where the per-IP signal alone would
	// not. The key is rateLimitKey, so an IPv6 caller is bucketed by its whole /64 — one
	// delegated allocation can no longer masquerade as an unlimited supply of scanners.
	//
	// HONEST LIMIT: this bounds one phone, one persistent browser, and one IPv6 /64 to
	// maxPendingGuestRequests-guestReqReserved slots, so a genuine visitor elsewhere still
	// lands. It does NOT stop a flood from several genuinely distinct addresses (distinct
	// IPv4s, or distinct /64s): each looks like a real newcomer, and a public door QR
	// cannot tell them apart from real visitors without turning legitimate newcomers away.
	// That residual is why approval, not the request, is the security boundary here.
	heardFrom := !guestScanner.allow("greq:"+rateLimitKey(r)) || (haveMine && mine.Status == "pending")
	if !ownRepeat && heardFrom {
		if reserved, err := s.store.PendingGuestRequestsInReserve(r.Context(), gc.Grant.ID); err == nil && reserved {
			s.renderGuestResult(w, "", false, "There are already several requests waiting for the resident. Please knock or contact them directly.")
			return
		}
	}
	reqID, nonce, created, err := s.store.CreateGuestRequest(r.Context(), gc.Grant.ID, permit.ID, permit.Owner, plate, randNonce())
	if errors.Is(err, store.ErrGuestRequestLimit) {
		s.renderGuestResult(w, "", false, "There are already several requests waiting for the resident. Please knock or contact them directly.")
		return
	}
	if err != nil {
		s.renderGuestResult(w, "", false, "Something went wrong sending your request. Please try again.")
		return
	}
	if !created {
		// The plate already has a pending request, so this scan reused it — and the
		// nonce that came back is THAT request's poll secret. Two visitors can type the
		// same plate (a shared work ute, a plate typed wrong the same way twice), and
		// the store cannot tell them apart, so it is only handed over to a browser that
		// can already present it. Anyone else is told the truth about the plate they
		// typed and given no way to read a stranger's request.
		if haveMine && mine.ID == reqID {
			s.setGuestReqCookie(w, mine.ID, myNonce)
			s.render(w, dashboardData{State: "guest-wait", Loc: s.cfg.DisplayLocation,
				Wait: &guestWaitView{Plate: mine.Plate, ReqID: mine.ID, Nonce: myNonce, Status: mine.Status}})
			return
		}
		s.renderGuestResult(w, "", true, "A request for "+plate+" is already waiting for the resident to approve. There's nothing more to do here — if it isn't approved shortly, try knocking.")
		return
	}
	s.notifyGuestRequest(r.Context(), permit, plate, reqID)
	// Remember the request in this browser (the one that made it), so a later
	// re-scan of the same door code shows its fate instead of a blank form.
	s.setGuestReqCookie(w, reqID, nonce)
	s.render(w, dashboardData{State: "guest-wait", Loc: s.cfg.DisplayLocation,
		Wait: &guestWaitView{Plate: plate, ReqID: reqID, Nonce: nonce, Status: "pending"}})
}

// guestRequestStatus is the visitor's poll endpoint: public and nonce-gated so a
// request id can't be enumerated. While pending it re-renders a polling fragment;
// once decided it renders a static result.
func (s *Server) guestRequestStatus(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	id, nonce := pathInt(r, "id"), r.URL.Query().Get("n")
	req, err := s.store.GuestRequestForPoll(r.Context(), id, nonce)
	var v guestWaitView
	switch {
	case err == nil:
		// Status passes through as-is: "expired" (aged out unanswered) renders its
		// own message, distinct from an actual "denied".
		v = guestWaitView{Plate: req.Plate, ReqID: req.ID, Nonce: nonce, Status: req.Status, Until: req.Until}
		// "approved" means the resident said yes; requestLiveState only reports it
		// as ON the permit once the council's own record actually shows the plate
		// ("applied"), flags a long-unconfirmed apply ("stalled"), and — the states
		// this endpoint couldn't see before — notices when the pass has since been
		// overridden ("superseded") or its window has lapsed ("ended"), instead of
		// misreading either as a stall.
		if req.Status == "approved" {
			if permit, perr := s.store.GetPermit(r.Context(), req.PermitID); perr == nil {
				v.Status, _ = s.requestLiveState(r.Context(), permit, req)
			}
			// A permit lookup error keeps Status "approved": transient — keep polling.
		}
	case errors.Is(err, store.ErrNotFound):
		v = guestWaitView{Status: "denied"} // wrong nonce / unknown id — a real terminal
	default:
		// A transient DB error must NOT strand the visitor on a false "Not approved":
		// keep polling.
		log.Printf("guest poll %d: %v", id, err)
		v = guestWaitView{ReqID: id, Nonce: nonce, Status: "pending"}
	}
	if !isHX(r) {
		// A direct navigation (bookmark, or a browser that landed here after a
		// network hiccup) gets the full wait page — with styling and the poller —
		// not the bare fragment.
		s.render(w, dashboardData{State: "guest-wait", Loc: s.cfg.DisplayLocation, Wait: &v})
		return
	}
	if e := templates.ExecuteTemplate(w, "guest-req-status", v); e != nil {
		log.Printf("render guest-req-status: %v", e)
	}
}

// guestApplyTimeout is how long an approved printed-QR request may sit unconfirmed
// on the council before the visitor's page stops spinning and suggests checking
// with the resident (the scheduler keeps retrying regardless).
const guestApplyTimeout = 8 * time.Minute

func (s *Server) notifyGuestRequest(ctx context.Context, permit model.Permit, plate string, reqID int64) {
	if s.notify == nil {
		return
	}
	// Throttled per ACCOUNT, not per plate (see guestNudge): the request itself is
	// always recorded and always visible in the approvals queue — only the alarm is
	// rationed, because the alarm is the part a stranger with a poster can aim at a
	// household at 3am.
	if !guestNudge.allow("n:" + permit.Owner) {
		log.Printf("guest request nudge for %s throttled", redact.Email(permit.Owner))
		return
	}
	// Enqueue durably (a fast DB insert) so the holder's "approve this?" nudge
	// survives a restart and is retried — the printed-QR flow depends on it.
	url := s.cfg.PublicBaseURL + "/guests"
	if err := s.notify.NotifyGuestRequest(ctx, permit.Owner, permitLabel(permit), plate, url, reqID); err != nil {
		log.Printf("guest request notify enqueue for %s: %v", redact.Email(permit.Owner), err)
	}
}

// showPrintedQR mints a durable request-only grant and renders a QR to print and
// leave out (e.g. at the door). A scan of it only requests the permit; the holder
// approves live. It replaces any existing printed QR for the permit.
// mintPrintedGrant creates (or replaces) a permit's door QR, sealing the raw token
// at rest so the same code can be reprinted later. Returns the new grant id.
func (s *Server) mintPrintedGrant(ctx context.Context, owner, createdBy string, permitID int64) (int64, error) {
	raw, hash := newGuestToken()
	sealed, err := s.box.SealCtx(secretbox.GuestToken(owner), raw)
	if err != nil {
		return 0, err
	}
	return s.store.CreatePrintedGrant(ctx, owner, createdBy, permitID, hash, sealed)
}

// showPrintedQR handles "Print a door QR" for a permit. It is idempotent: if the
// permit already has a door QR it reopens that (same code) rather than rotating the
// token, so a copy already on the fridge keeps working.
func (s *Server) showPrintedQR(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	permitID := atoi64(r.FormValue("permit_id"))
	// Checked before the idempotent reopen too: reprinting a poster for a dead
	// permit is as misleading as minting a fresh one. Fails closed on a store
	// error, for the same reason as createGuestGrant's gate.
	switch permit, perr := s.store.GetPermit(r.Context(), permitID); {
	case errors.Is(perr, store.ErrNotFound):
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Owner == owner && permit.Inactive(time.Now(), s.cfg.DisplayLocation):
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
		return
	}
	if g, err := s.store.PrintedGrantForPermit(r.Context(), owner, permitID); err == nil {
		http.Redirect(w, r, fmt.Sprintf("/guests/door/%d/view", g.GrantID), http.StatusSeeOther)
		return
	}
	grantID, err := s.mintPrintedGrant(r.Context(), owner, user, permitID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That permit isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionDoorQRCreate, s.permitLabelByID(r.Context(), owner, permitID), "")
	http.Redirect(w, r, fmt.Sprintf("/guests/door/%d/view", grantID), http.StatusSeeOther)
}

// viewDoorQR renders the durable, printable poster for an existing door QR. It never
// rotates the token, so it can be reopened and reprinted as often as needed.
func (s *Server) viewDoorQR(w http.ResponseWriter, r *http.Request) {
	noStore(w) // the poster embeds the durable door-QR token; keep it out of caches
	_, owner, _ := s.resolveAccount(r.Context())
	g, err := s.store.PrintedGrantByID(r.Context(), owner, atoi64(r.PathValue("id")))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusNotFound, "That door QR is no longer available.")
			return
		}
		s.serverError(w, err)
		return
	}
	// The POST mint gate calls reprinting a dead permit's poster "as misleading
	// as minting a fresh one" — and this view page IS the printable poster, so
	// it carries the same gate. Fails closed like the mint gates.
	switch permit, perr := s.store.GetPermit(r.Context(), g.PermitID); {
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Inactive(time.Now(), s.cfg.DisplayLocation):
		s.message(w, http.StatusConflict, permitInactiveNoPoster)
		return
	}
	raw, _, err := s.box.OpenCtx(secretbox.GuestToken(owner), g.TokenSealed)
	if err != nil {
		// The at-rest key changed, so we can't reproduce the printed code. Ask the
		// holder to replace it (which mints a fresh one they can reprint).
		s.message(w, http.StatusConflict, "This code can't be shown again on this server. Remove it on the Guests page, then create a new printed QR for this permit.")
		return
	}
	url := s.guestLink(raw)
	img, err := qrDataURI(url)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	base.State = "doorqr"
	base.DoorQR = &doorQRView{
		GrantID: g.GrantID, PermitLabel: g.PermitLabel, OwnerEmail: owner,
		ImageURI: template.URL(img), URL: url,
		CreatedAt: g.CreatedAt.In(s.cfg.DisplayLocation).Format("2 Jan 2006"),
	}
	s.render(w, base)
}

// revokeDoorQR retires a door QR for good (its code stops working).
func (s *Server) revokeDoorQR(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Claim the permit first, exactly as deleteGuestGrant/revokeGuestToken/toggleGuests
	// do. Without it an in-flight door-QR approval could write the visitor's plate to
	// the council AFTER the household was told the code had stopped working.
	if pid, perr := s.store.GuestGrantPermit(r.Context(), owner, atoi64(r.PathValue("id"))); perr == nil {
		defer s.claimPermitApplies(r.Context(), []int64{pid})()
	}
	label := s.grantLabel(r.Context(), owner, atoi64(r.PathValue("id")))
	// As in deleteGuestGrant: a no-op must not announce itself to the household.
	err := s.store.RevokePrintedGrant(r.Context(), owner, atoi64(r.PathValue("id")))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionDoorQRRevoke, label, "")
		s.notifyDestructive(r.Context(), owner, user,
			user+" removed a printed QR code on your p.stonn account. Any copy already printed and put up has stopped working, and p.stonn is taking any car approved through it back off the permit now — check the permit directly if this is urgent.")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests", http.StatusSeeOther)
}

func (s *Server) approveGuestRequest(w http.ResponseWriter, r *http.Request) {
	s.decideRequest(w, r, true)
}
func (s *Server) denyGuestRequest(w http.ResponseWriter, r *http.Request) {
	s.decideRequest(w, r, false)
}

// decideOutcome is what running a decision produced, so the two front doors —
// the signed-in approvals page and the signed email link — can each respond in
// their own idiom (redirects with query flags versus a rendered outcome page)
// while sharing one implementation of the delicate approve path.
type decideOutcome struct {
	kind  decideKind
	plate string
	err   error
}

type decideKind int

const (
	decideErr            decideKind = iota // err holds the cause
	decideAlreadyDecided                   // decline raced: no longer pending
	decideDeclined
	decideGone           // approve: request/permit gone, not ours, or raced
	decideCapFull        // permit at its guest-booking sub-cap
	decidePermitInactive // approve: the permit itself is cancelled or expired
	decideRevoked        // door QR revoked between approval and apply
	decideApplied        // approved and the council confirmed the plate
	decideApproving
)

// decideCapFullMessage is shown when an approval hits the guest-booking
// sub-cap; shared by both front doors so the wording can never drift.
const decideCapFullMessage = "This permit already has the maximum number of active guest bookings. Remove one before approving another."

// decidePermitInactiveMessage: approving a request against a permit the council
// has since cancelled (or that has expired) must refuse loudly. Silently
// "approving" would strand the visitor on a permit that protects nobody.
const decidePermitInactiveMessage = "This permit is no longer active (cancelled or expired), so nothing can go on it. The visitor has not been approved — let them know."

// permitInactiveNoNewLinks refuses minting any guest surface (pass, visitor QR,
// door QR) for a permit that is cancelled or expired: every link would promise
// parking cover the permit can no longer give.
const permitInactiveNoNewLinks = "That permit is no longer active, so guest links and QR codes can't be created for it."

// permitInactivePassFrozen refuses re-sending or editing a pass whose permit has
// died — a re-send would rotate away the recipient's token (the very thing that
// starts working again after a renewal copy) and email a born-dead link in its
// place; an edit can add recipients, which is minting by another door.
const permitInactivePassFrozen = "That pass's permit is no longer active, so its links can't be re-sent or offered to new people. Renewed the permit? Use “Copy schedule from another permit” — the pass moves across and its links start working again."

// permitInactiveNoPoster refuses showing the printable poster for a dead
// permit's door QR: the POST mint gate calls reprinting one "as misleading as
// minting a fresh one", and the view page is the same artifact one click later.
const permitInactiveNoPoster = "That permit is no longer active, so its printed QR can't be shown or reprinted. Renewed the permit? Use “Copy schedule from another permit” — the door QR moves across and the printed poster keeps working."

// refuseDeadGrantPermit answers the request with msg when the grant's permit is
// cancelled or expired, reporting whether it wrote a response. An unknown grant
// returns false so the handler's own ownership path can give its usual answer;
// a store error fails closed (these gates guard link-minting surfaces).
func (s *Server) refuseDeadGrantPermit(w http.ResponseWriter, r *http.Request, owner string, grantID int64, msg string) bool {
	pid, err := s.store.GuestGrantPermit(r.Context(), owner, grantID)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		s.serverError(w, err)
		return true
	}
	switch permit, err := s.store.GetPermit(r.Context(), pid); {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		s.serverError(w, err)
		return true
	case permit.Inactive(time.Now(), s.cfg.DisplayLocation):
		s.message(w, http.StatusConflict, msg)
		return true
	}
	return false
}

// decideRequest approves or denies a pending printed-QR request. On approval it
// puts the plate on the permit (end of day) and applies it best-effort.
func (s *Server) decideRequest(w http.ResponseWriter, r *http.Request, approve bool) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	out := s.runDecideRequest(r, owner, user, pathInt(r, "id"), approve)
	switch out.kind {
	case decideErr:
		s.serverError(w, out.err)
	case decideAlreadyDecided:
		http.Redirect(w, r, "/guests?alreadydecided=1", http.StatusSeeOther)
	case decideDeclined:
		http.Redirect(w, r, "/guests?declined=1", http.StatusSeeOther)
	case decideGone:
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
	case decideCapFull:
		s.message(w, http.StatusConflict, decideCapFullMessage)
	case decidePermitInactive:
		s.message(w, http.StatusConflict, decidePermitInactiveMessage)
	case decideRevoked:
		http.Redirect(w, r, "/guests?revoked=1", http.StatusSeeOther)
	default: // decideApplied / decideApproving
		q := url.Values{}
		if out.kind == decideApplied {
			q.Set("applied", out.plate)
		} else {
			q.Set("approving", out.plate)
		}
		http.Redirect(w, r, "/guests?"+q.Encode(), http.StatusSeeOther)
	}
}

// runDecideRequest is the shared decision core: owner scopes the request, user
// is recorded as the decider in the change log. Callers have already
// authenticated user as a member of owner's account (session or signed link).
func (s *Server) runDecideRequest(r *http.Request, owner, user string, id int64, approve bool) decideOutcome {
	now := time.Now().In(s.cfg.DisplayLocation)

	if !approve {
		switch _, err := s.store.DecideGuestRequest(r.Context(), owner, id, false, "", user, time.Time{}); {
		case errors.Is(err, store.ErrNotFound):
			// The row is no longer pending — another member approved (or it expired)
			// first. Record NOTHING: the change log is the household's account of who
			// authorised a plate change, so logging a decline that never happened would
			// misattribute a plate that is in fact going ON the permit.
			return decideOutcome{kind: decideAlreadyDecided}
		case err != nil:
			return decideOutcome{kind: decideErr, err: err}
		}
		s.logChange(r.Context(), owner, user, store.ActionRequestNo, "", "")
		return decideOutcome{kind: decideDeclined}
	}

	// Approve: set up the plate override BEFORE finalising the approval, so we can
	// never leave a request marked "approved" that the scheduler has nothing to act
	// on (which would strand the visitor and mislead the holder).
	req, rerr := s.store.GuestRequestByID(r.Context(), id)
	if rerr != nil || req.Status != "pending" {
		return decideOutcome{kind: decideGone} // gone / already decided
	}
	permit, perr := s.store.GetPermit(r.Context(), req.PermitID)
	if perr != nil || permit.Owner != owner {
		return decideOutcome{kind: decideGone} // not ours / permit removed
	}
	// The request may have been made (and the approval email sent) while the
	// permit was still alive. Approving now would create an override the
	// scheduler refuses to act on — a visitor told "approved" with nothing
	// behind it.
	if permit.Inactive(now, s.cfg.DisplayLocation) {
		return decideOutcome{kind: decidePermitInactive}
	}
	end := dayEndLocal(now, 0)
	// Tagged with the door QR's own token, so removing the poster (or pausing guest
	// passes) can take this plate back off the permit. Untagged, the row was
	// indistinguishable from a booking the household made itself, and "that code has
	// stopped working" left the visitor parked on the permit for the rest of the day.
	// A token we cannot resolve tags nothing (0) rather than blocking the approval.
	doorToken, terr := s.store.GrantTokenID(r.Context(), req.GrantID)
	if terr != nil {
		log.Printf("doorqr approve: no token for grant %d: %v", req.GrantID, terr)
	}
	ovID, cerr := s.store.CreateGuestPlateOverride(r.Context(), permit.ID, req.Plate, now, &end, "visitor (printed QR)", doorToken)
	if errors.Is(cerr, store.ErrGuestOverrideRefused) {
		// The permit is at its guest-booking sub-cap. Tell the owner plainly instead of
		// returning a 500 — approving a door-QR request must not look like the app is
		// broken.
		return decideOutcome{kind: decideCapFull}
	}
	if cerr != nil {
		return decideOutcome{kind: decideErr, err: cerr} // don't approve if we couldn't set up the change
	}
	if _, err := s.store.DecideGuestRequest(r.Context(), owner, id, true, untilPhrase(now, false), user, end); err != nil {
		// The approval didn't land — raced with a concurrent deny (ErrNotFound: the
		// row is no longer pending) or a DB error. Roll back the override we
		// optimistically created, so a denied or undecided request can never leave a
		// live plate the scheduler would put on the permit.
		_ = s.store.DeleteOverride(r.Context(), owner, ovID)
		if errors.Is(err, store.ErrNotFound) {
			return decideOutcome{kind: decideGone}
		}
		return decideOutcome{kind: decideErr, err: err}
	}
	// Best-effort synchronous apply for instant feedback; the scheduler converges
	// otherwise. SetVehicle returns nil only once the council confirms the plate.
	confirmed := false
	prev := permit.ActiveRegistration
	// Detached from the request (see guestActivate): a disconnect mid-apply must
	// not drop the bookkeeping, and the budget stays under the WriteTimeout.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	// Exclusive for this permit while we write (see guestActivate): an approval
	// racing the reconcile loop could otherwise leave the council holding the roster
	// plate while the row claims the visitor's, and the visitor is standing at the
	// door believing they are covered. A claim we cannot get means we simply don't
	// apply here — the override is saved, so the scheduler applies it, and both
	// front doors have a wording for "approving" versus "applied".
	release, claimed := s.sched.AcquireApply(applyCtx, permit.ID)
	applyErr := error(errApplyBusy)
	if claimed {
		// The same gate guestActivate and guestRevert use. This was the one guest path
		// that wrote to the council without re-checking authorisation under the claim:
		// a door QR revoked between the approval and here would otherwise still have its
		// visitor's plate applied, after the household was told the code had stopped.
		if d := s.authoriseGuestApply(applyCtx, doorToken, ovID); d != guestApplyAllowed {
			release()
			cancel()                                    // this path returns early; don't leak the apply context
			_ = s.store.DeleteOverride(bg, owner, ovID) // don't leave it for the scheduler
			s.kickScheduler()
			return decideOutcome{kind: decideRevoked}
		}
		if applyErr = s.council.SetVehicle(applyCtx, permit.Owner, permit, req.Plate); applyErr == nil {
			if e := s.store.SetPermitActive(bg, permit.ID, req.Plate); e != nil {
				log.Printf("guest: approved plate %q for permit %d at council but local commit failed: %v", req.Plate, permit.ID, e)
			}
		}
	}
	release()
	if applyErr == nil {
		_ = s.store.RecordApply(bg, permit.ID, req.Plate, "guest", "success", "approved a printed-QR request")
		confirmed = true
		// The approved plate may have bumped a still-live booking's car off the
		// permit; warn that driver if they're reachable. The approving member saw
		// the change happen, but the OTHER members didn't — fan the confirmation
		// out like every other plate change (the guest-link path does the same).
		d, told := s.displacedDriver(bg, permit, prev, req.Plate, user)
		outcome := notify.ApplyOutcome{
			Owner: permit.Owner, PermitLabel: permitLabel(permit), Reg: req.Plate, By: user, Source: "doorqr", OK: true,
			DisplacedReg: d.Reg, DisplacedTold: told,
		}
		if err := s.notify.EnqueueApply(bg, outcome); err != nil {
			log.Printf("doorqr apply notify enqueue for %s: %v", redact.Email(permit.Owner), err)
		}
	} else {
		log.Printf("doorqr approve %s on permit %d: %v", req.Plate, permit.ID, applyErr)
	}
	cancel()
	s.sched.Kick()

	s.logChange(bg, owner, user, store.ActionRequestOK, req.Plate, "")
	if confirmed {
		return decideOutcome{kind: decideApplied, plate: req.Plate}
	}
	return decideOutcome{kind: decideApproving, plate: req.Plate}
}

// guestCreateMessage turns a refused guest-override insert into something true for the
// visitor. A refusal means the link was revoked or disabled between opening the page
// and submitting (or the permit is at its booking cap) — "please try again" would have
// them retrying a link that will never work again.
func guestCreateMessage(err error, fallback string) string {
	if errors.Is(err, store.ErrGuestOverrideRefused) {
		return "This link is no longer active, so the permit wasn't changed. Please ask the household for a new one."
	}
	return fallback
}

// guestApplyDenial says why a guest council write must not proceed: revoked (the
// owner withdrew the authority) or unverifiable (we could not check). They are
// different things to tell a visitor — calling a database blip "the owner turned your
// link off" starts an argument at the kerb over something that did not happen.
type guestApplyDenial int

const (
	guestApplyAllowed guestApplyDenial = iota
	guestApplyRevoked
	guestApplyUnverified
)

// authoriseGuestApply is the single gate EVERY public guest path must pass immediately
// before writing to the council, while holding that permit's apply claim.
//
// It exists as one helper on purpose: activation was fixed first and revert was left
// behind, which is the recurring shape of bugs here — a capability check added to one
// path and not its sibling. Anything that writes to the council on a guest's behalf
// goes through this.
//
// overrideID != 0 checks the FULL capability of that specific override (token, grant,
// permit, account switch, and the vehicle/plate permission it exercised). overrideID 0
// checks only that the link still carries authority at all — the revert case, which
// restores the pre-guest plate rather than exercising a capability.
func (s *Server) authoriseGuestApply(ctx context.Context, tokenID, overrideID int64) guestApplyDenial {
	var ok bool
	var err error
	if overrideID != 0 {
		ok, err = s.store.GuestOverrideStillAuthorised(ctx, overrideID, tokenID)
	} else {
		ok, err = s.store.GuestTokenStillLive(ctx, tokenID)
	}
	switch {
	case err != nil:
		log.Printf("guest: could not verify authorisation for token %d (override %d): %v", tokenID, overrideID, err)
		return guestApplyUnverified
	case !ok:
		return guestApplyRevoked
	}
	return guestApplyAllowed
}

func (d guestApplyDenial) message() string {
	if d == guestApplyRevoked {
		return "This link was turned off just now, so the permit wasn't changed."
	}
	return "We couldn't check your link just now, so the permit wasn't changed. Please try again."
}

// claimPermitApplies takes the per-permit apply claim for every id before a revocation
// mutates guest authority, and returns a release for all of them.
//
// Holding the claim is what gives revocation a real linearization point: an activation
// that already holds it completes (it WAS authorised), and the sweep then removes its
// override; an activation that has not started yet blocks, and its re-check afterwards
// fails. Without this, "revoked" could still be overtaken by a council write. ids are
// claimed in a stable order so two multi-permit revocations cannot deadlock, and a
// claim we cannot get is logged and skipped — a revocation must never fail to revoke.
func (s *Server) claimPermitApplies(ctx context.Context, ids []int64) func() {
	if s.sched == nil {
		return func() {}
	}
	sorted := append([]int64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var releases []func()
	for _, id := range sorted {
		if id == 0 {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		release, ok := s.sched.AcquireApply(cctx, id)
		cancel()
		if !ok {
			log.Printf("guest: revoking without the apply claim for permit %d (busy); a guest write in flight may still land and be reconciled away", id)
			release()
			continue
		}
		releases = append(releases, release)
	}
	return func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
}
