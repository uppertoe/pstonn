package server

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
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
	Token          string            // raw token, echoed into the POST form
	OwnerEmail     string            // account holder, shown for trust
	PermitLabel    string            // which permit this affects
	CurrentReg     string            // what is on the permit right now ("" if unknown)
	CheckedAgo     string            // how long ago CurrentReg was confirmed with the tenant; "" while fresh ("4 hr ago" turns "on now" into "last known")
	Cars           []vehicleView     // the cars this link may activate
	AllowOvernight bool              // whether the overnight checkbox is offered
	AllowPlate     bool              // whether the visitor may type an arbitrary plate
	Regions        []provider.Region // registration-state options for a typed plate (empty hides the chooser)
	RequestOnly    bool              // printed QR: entering a plate only requests approval
	RevertPlate    string            // pre-existing plate the guest may put back ("" = no revert offered)
	PendingReg     string            // plate the schedule targets but the tenant doesn't show yet ("" = settled)
	Stalled        bool              // the pending change has taken suspiciously long; stop polling
	PendingOutage  bool              // the pending change can't land because the council is down (auth circuit / breaker) — say so honestly instead of the optimistic "Changing to…" spinner. Computed on every render (POST and poll) so the message is consistent.
	SelectedReg    string            // the schedule's target plate: highlights the chosen car IMMEDIATELY, while "on now" tracks the actual record
	UntilText      string            // when the winning booking ends ("until the end of today"), "" when open-ended/roster-driven
	KeepForm       bool              // poll responses only: render hx-preserve so a half-filled form survives the swap; activation responses omit it so the form resets
	FP             string            // fingerprint of the visible state; polls echo it so an unchanged page is a 204, not a re-render
	Req            *guestWaitView    // printed door QR only: this browser's own remembered request (from the greq cookie), so a re-scan shows its fate instead of a blank form
}

// guestWaitView drives the visitor's "waiting for approval" page (State
// "guest-wait"), which polls the status endpoint.
type guestWaitView struct {
	tenant     *tenantView // the permit owner's tenant, for the referral line
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
// Tenant is the tenant a wait fragment speaks for (the default when unknown).
func (v guestWaitView) Tenant() tenantView {
	if v.tenant != nil {
		return *v.tenant
	}
	return defaultTenantView
}

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
	Dead  bool // no longer active at the tenant; copying FROM it moves its guest passes
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

// errApplyBusy stands in for a tenant write this process deliberately did NOT
// make, because another plate change for the same permit was still in flight when
// the apply budget ran out (see the AcquireApply calls below). Classified
// transient: the booking is already saved, so the scheduler converges on it — the
// page must show the honest "still applying" state rather than telling the
// household their tenant login needs reconnecting.
var errApplyBusy = &parking.TenantError{
	Kind: parking.FailTransient,
	Op:   provider.OpSetVehicle,
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
// unconfirmed on the tenant record.
//
// The pending banner used the winning override's creation time, which only exists
// for a booked change: a roster-driven target had no clock at all, so `stalled`
// could never become true and a visitor whose household had a broken tenant
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
