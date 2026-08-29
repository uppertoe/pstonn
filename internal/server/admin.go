package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// schedulerStaleAfter is how long without a completed reconcile pass counts as a
// wedged work loop (the reconcile loop ticks every minute, so this is generous).
const schedulerStaleAfter = 10 * time.Minute

// ---- CDN-proxy detection ----
//
// The app is served DNS-only: Caddy faces clients directly, so clientIP sees the
// real peer and every per-IP throttle in the app keys on one visitor. Putting a
// CDN proxy in front of that hostname breaks all of them at once and silently —
// requests then arrive from a small pool of edge addresses, so the guest-pass,
// contact-form, confirm and /status limiters collapse onto a handful of buckets
// and stop limiting individuals at all. That exact regression shipped once and
// went unnoticed for weeks, because nothing looked wrong from the outside.
//
// These headers are the tell: a CDN adds them on the way through and nothing else
// does. Observing one is proof the deployment has changed shape underneath the
// app, so latch it and say so — once in the log, and on every /status poll, which
// is the one thing an operator is already watching.
var edgeProxyHeaders = []string{"CF-Connecting-IP", "CF-Ray", "CF-IPCountry"}

var (
	edgeProxyWarn sync.Once
	edgeProxySeen atomic.Value // string: the header name that gave it away
)

// noteEdgeProxy records and returns the CDN forwarding header seen on this
// request, or the one seen on any earlier request in this process. It is
// deliberately sticky: the check runs only on the handlers in this file, and a
// single proxied request is enough to prove the misconfiguration, so a later
// unproxied poll must not clear the finding.
func noteEdgeProxy(r *http.Request) string {
	for _, h := range edgeProxyHeaders {
		if r.Header.Get(h) == "" {
			continue
		}
		edgeProxySeen.Store(h)
		edgeProxyWarn.Do(func() {
			log.Printf("WARNING: request carried %s, so a CDN proxy now sits in front of this app. "+
				"Every per-IP rate limit is keyed on the address the app sees, which is now an edge address shared by "+
				"all visitors, so the throttles no longer limit anyone. Set the DNS record back to DNS-only (grey cloud).", h)
		})
		return h
	}
	seen, _ := edgeProxySeen.Load().(string)
	return seen
}

// ---- admin dashboard (human, admin-gated) ----

type adminView struct {
	Rows    []adminRow
	Total   int
	Linked  int
	WarmOK  int
	Failing int // linked accounts whose keep-warm looks stale or whose last apply errored
	// service health
	SchedulerLast  string
	SchedulerStale bool
	StatusEnabled  bool // whether the machine /status endpoint is configured
	SESHook        bool // whether the SES bounce/complaint webhook is wired up
	// Suppressed lists addresses the mail provider rejected. Operator-facing: a
	// growing list is the early warning that the sending domain's reputation is
	// being damaged, which on SES ends in a sending pause.
	Suppressed []suppressionRow
}

type suppressionRow struct {
	Address string
	Reason  string
	Detail  string
	Ago     string
	Hits    int
}

type adminRow struct {
	Email        string
	MemberOf     string // shares another account (accepted)
	InvitedBy    string // has an unanswered invitation to another account
	Status       string // ok | stale | relink | unlinked
	StatusLabel  string
	Warmed       string // relative time of last keep-warm
	RelinkBy     string // re-authorise deadline (date)
	EmailOn      bool
	NtfyTopic    string
	Consent      string // accepted terms version, or ""
	Permits      int
	Plates       string // active plates, joined
	Members      int
	LastApply    string // e.g. "success · 2 hr ago" / "error · 5 min ago"
	LastApplyBad bool   // most recent apply was not a success
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	u, ok := s.user(w, r)
	if !ok {
		return
	}
	// An admin loading this page is a request that came the whole way through the
	// proxy chain, so it is a free chance to notice a CDN in front of the app. The
	// finding is latched and reported on /status; the dashboard is not the place to
	// explain it.
	noteEdgeProxy(r)
	accounts, err := s.store.AdminAccounts(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	warmed, err := s.store.OwnersWithPermit(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	now := time.Now()
	loc := s.cfg.DisplayLocation
	maxAge := s.cfg.Council.SessionMaxAge
	// A keep-warm is "stale" only once a warmed session is genuinely near lapsing:
	// keep-warm renews every WarmInterval and must succeed before IdleWindow, so the
	// safety margin before the idle window is the real deadline. The old fixed 6h
	// predated WARM_INTERVAL=8h and flagged every healthy session in the 6–8h gap
	// after each renew. Owners with no permit are not kept warm at all, so their
	// ageing is expected and never attention-worthy — mirror the /status counts.
	warmStaleAfter := s.cfg.Council.IdleWindow - s.cfg.Council.WarmSafetyMargin
	if warmStaleAfter <= 0 {
		warmStaleAfter = s.cfg.Council.WarmInterval
	}

	v := &adminView{Total: len(accounts), StatusEnabled: s.cfg.StatusToken != ""}
	last := s.sched.LastReconcile()
	if last.IsZero() {
		v.SchedulerLast = "never"
		v.SchedulerStale = true
	} else {
		v.SchedulerLast = agoText(now, last)
		v.SchedulerStale = now.Sub(last) > schedulerStaleAfter
	}

	for _, a := range accounts {
		row := adminRow{
			Email: a.Owner, MemberOf: a.MemberOf, InvitedBy: a.InvitedBy, EmailOn: a.EmailEnabled,
			Consent: a.ConsentVersion, Permits: a.PermitCount, Members: a.MemberCount,
			Plates: strings.Join(a.Plates, ", "),
		}
		if a.NtfyEnabled {
			row.NtfyTopic = a.NtfyTopic
		}
		// Tenant / keep-warm status.
		_, keptWarm := warmed[a.Owner]
		var needsAttention bool
		row.Status, row.StatusLabel, needsAttention = tenantRowStatus(a, keptWarm, now, maxAge, warmStaleAfter)
		if row.Status == "ok" {
			v.WarmOK++
		}
		if a.Linked {
			v.Linked++
			if !a.WarmedAt.IsZero() {
				row.Warmed = agoText(now, a.WarmedAt)
			}
			if maxAge > 0 && !idleSince(a).IsZero() {
				row.RelinkBy = idleSince(a).Add(maxAge).In(loc).Format("2 Jan 2006")
			}
		}
		if a.LastApplyStatus != "" {
			label := a.LastApplyStatus
			bad, cleared := applyFailureState(a.LastApplyStatus, a.MaxFailStreak)
			if cleared {
				label += " (cleared)"
			}
			if !a.LastApplyAt.IsZero() {
				label += " · " + agoText(now, a.LastApplyAt)
			}
			row.LastApply = label
			if bad {
				row.LastApplyBad = true
				needsAttention = true
			}
		}
		if needsAttention { // count each account at most once
			v.Failing++
		}
		v.Rows = append(v.Rows, row)
	}
	v.SESHook = s.cfg.SESHookEnabled()
	if sups, err := s.store.ListSuppressions(r.Context()); err == nil {
		for _, sp := range sups {
			v.Suppressed = append(v.Suppressed, suppressionRow{
				Address: sp.Address, Reason: sp.Reason, Detail: sp.Detail,
				Ago: agoText(now, sp.LastSeen), Hits: sp.Hits,
			})
		}
	} else {
		log.Printf("admin: list suppressions: %v", err)
	}
	s.render(w, dashboardData{
		State: "admin", User: u, LogoutURL: s.logoutURL(), Loc: loc, Admin: v,
	})
}

// ---- machine status endpoint (outage watchdog, bearer-token gated) ----

type statusResponse struct {
	Time      string          `json:"time"`
	Scheduler schedulerStatus `json:"scheduler"`
	Sessions  sessionCounts   `json:"sessions"`
	// Tenant reports the outbound-traffic health the watchdog needs to alert on a
	// developing edge block: the real request rate, pushback count/diagnostics, the
	// fleet circuit state, and whether restart-protection persistence is intact.
	Tenant tenantStatus `json:"council"` // the watchdog reads this key; rename together with it
	// TenantOptions is the same health per tenant, and how many linked sessions each
	// holds, for a process serving more than one (an edge block is per portal).
	TenantOptions map[string]tenantBreakdown `json:"councils,omitempty"`
	// Client reports what the app believes about the caller of this very request.
	// It is here so the watchdog's ordinary poll doubles as an assertion about the
	// deployment's shape: the throttles that protect every public route key on this
	// address, and if it stops being a real client address nothing else notices.
	Client clientObservation `json:"client"`
	// RosterSealed is the roster as AES-256-GCM ciphertext (base64, 12-byte nonce
	// prefix — the same construction as internal/secretbox), under ROSTER_KEY. The
	// watchdog holds that key; a leaked STATUS_TOKEN alone yields only this. There
	// is no plaintext counterpart field on purpose: a struct with nowhere to put an
	// unsealed roster cannot regress into serving one.
	RosterSealed string `json:"roster_sealed,omitempty"`
}

type clientObservation struct {
	IP string `json:"ip"` // what every per-IP throttle keys on for this request
	// EdgeProxy names a CDN forwarding header seen on this or an earlier request.
	// Non-empty means the per-IP throttles are no longer per-client; the watchdog
	// should treat it as an alert, not a note.
	EdgeProxy string `json:"edge_proxy,omitempty"`
}

type schedulerStatus struct {
	LastReconcile string `json:"last_reconcile,omitempty"` // RFC3339 UTC of the last COMPLETED pass, "" if never
	// LastAttempt is when the most recent pass STARTED. If it is recent but
	// LastReconcile is stale, a pass is running but bailing (e.g. a failing database
	// read) — which the completion clock alone hides.
	LastAttempt string `json:"last_attempt,omitempty"`
	Stale       bool   `json:"stale"`
}

type sessionCounts struct {
	Linked int `json:"linked"`
	// Warm counts MAINTAINED sessions still within their warm interval (recently
	// touched, renew not yet due). Defined off the same interval as OverdueWarm so
	// the two never overlap: warm = not yet due, overdue = past due.
	Warm int `json:"warm"`
	// Warm-margin health, so the watchdog can catch a reconnect-backlog forming
	// (e.g. a tenant outage stalling warms near the idle cliff) BEFORE sessions
	// lapse en masse. OverdueWarm: past their warm deadline. NearExpiry: within
	// expiryWarningMargin of the estimated idle cliff — 0 in healthy operation.
	// MinMargin: the worst session's remaining seconds to the cliff (negative =
	// already past the estimate; omitted when no sessions). All four cover only
	// warmed owners (those with a permit) — an un-warmed session's expected lapse is
	// not a fault.
	OverdueWarm      int  `json:"overdue_warm"`
	NearExpiry       int  `json:"near_expiry"`
	MinMarginSeconds *int `json:"min_margin_seconds,omitempty"`
	// Session-lifecycle churn over the last hour, scheduler-observed. A healthy fleet
	// re-authenticates almost never, so a nonzero — and especially a rising — value is
	// the canary for a tenant-side DEFAULT change (a shortened idle window, cookie
	// rotation, or silent-renew disabled): none of those alter response shape, so no
	// other metric would surface them. ExpiredOwners1h is the DISTINCT-owner count,
	// the systemic signal the operator alert also fires on.
	Expiries1h      int `json:"expiries_1h"`
	Reconnects1h    int `json:"reconnects_1h"`
	ExpiredOwners1h int `json:"expired_owners_1h"`
	// Reconnect-queue backlog, so the watchdog can tell healthy draining from a
	// growing recovery backlog (a login-shape outage or repeated transient failures):
	// how many owners are queued for auto-reconnect, how many are due now, and the age
	// of the oldest queued item in seconds.
	ReconnectQueued        int `json:"reconnect_queued"`
	ReconnectDue           int `json:"reconnect_due"`
	ReconnectOldestSeconds int `json:"reconnect_oldest_seconds"`
}

// tenantSessionCounts aggregates warm/expiry-margin health from the live sessions.
// estimated_expiry = updated_at + idleWindow, so margin = idleWindow - age. A
// healthy fleet keeps min-margin near (idleWindow - warmInterval) and NearExpiry at
// zero; a stalled warm loop makes margins shrink and NearExpiry climb.
//
// Only sessions whose owner is in warmed — the ones keep-warm actually
// maintains — contribute to the warm-risk figures. A linked owner with no permit
// is deliberately left to lapse, so its (expected) shrinking margin must not read
// as a perpetual alarm. NearExpiry uses expiryWarningMargin,
// kept independent of warmInterval so raising the warm interval does not flag healthy
// sessions hours before their renew is even due.
func tenantSessionCounts(sessions []store.TenantSession, now time.Time, warmInterval, idleWindow, expiryWarningMargin time.Duration, warmed map[string]struct{}) sessionCounts {
	sc := sessionCounts{}
	haveMargin := false
	var minMargin time.Duration
	for _, cs := range sessions {
		if cs.Cookie == "" {
			continue
		}
		sc.Linked++
		if _, ok := warmed[cs.Owner]; !ok {
			continue // not kept warm (no permit): its lapse is expected, not a fault
		}
		if cs.UpdatedAt.IsZero() {
			continue
		}
		age := now.Sub(cs.UpdatedAt)
		if warmInterval > 0 {
			if age < warmInterval {
				sc.Warm++
			} else {
				sc.OverdueWarm++
			}
		}
		if idleWindow > 0 {
			margin := idleWindow - age
			if expiryWarningMargin > 0 && margin < expiryWarningMargin {
				sc.NearExpiry++
			}
			if !haveMargin || margin < minMargin {
				minMargin, haveMargin = margin, true
			}
		}
	}
	if haveMargin {
		secs := int(minMargin / time.Second)
		sc.MinMarginSeconds = &secs
	}
	return sc
}

// tenantStatus is the outbound-tenant health for the watchdog. The rate windows
// answer "what rate was the council seeing when it began refusing us"; the pushback
// fields say WHICH control fired; the breaker fields say whether we are paused; and
// persist_ok says whether a restart would still honour that pause.
type tenantStatus struct {
	Requests1m         int    `json:"requests_1m"`
	Requests5m         int    `json:"requests_5m"`
	PushbacksTotal     uint64 `json:"pushbacks_total"`
	BreakerOpen        bool   `json:"breaker_open"`
	BreakerRemainingS  int    `json:"breaker_remaining_seconds,omitempty"`
	LastPushbackAt     string `json:"last_pushback_at,omitempty"`
	LastPushbackStatus int    `json:"last_pushback_status,omitempty"`
	LastPushbackRef    string `json:"last_pushback_ref,omitempty"`
	PersistOK          bool   `json:"breaker_persist_ok"`
	PersistError       string `json:"breaker_persist_error,omitempty"`
	// LastPushbackSurface says whether the refusal hit login, auth or API traffic —
	// the difference between "our credentials are being throttled" and "our reads are".
	LastPushbackSurface string `json:"last_pushback_surface,omitempty"`
	// TruncatedGrid* report the last time the tenant returned fewer permits than it
	// said it had. That means it has started paging and we are acting on partial lists,
	// which the watchdog must be able to alert on: the app log alone loses the evidence
	// on restart, and a stable first page would hide missing permits indefinitely.
	TruncatedGridAt   string `json:"truncated_grid_at,omitempty"`
	TruncatedGridGot  int    `json:"truncated_grid_got,omitempty"`
	TruncatedGridWant int    `json:"truncated_grid_want,omitempty"`
}

// statusJSON is the read-only status the external outage watchdog polls. It is
// gated by a bearer token (a machine can't do the interactive login), and returns
// nothing without STATUS_TOKEN configured. A successful poll doubles as the
// watchdog's roster refresh and health/heartbeat check.
func (s *Server) statusJSON(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusToken == "" {
		http.NotFound(w, r)
		return
	}
	// Throttle before comparing: the token is the only gate on the roster, and an
	// unthrottled endpoint is an offline-speed guessing oracle. A watchdog polls
	// every few minutes, so this is far above any legitimate use.
	if !s.statusLimit.allow(rateLimitKey(r)) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	presented, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok || !secretEqual(presented, s.cfg.StatusToken) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// The roster — every permit-managing account's email, push topic and next due
	// write — is the sensitive half of this endpoint. The watchdog needs it only to
	// reach users during an outage, and needs it rarely, so it is served ONLY when
	// asked for, and only sealed. The frequent health poll then carries nothing
	// worth stealing.
	//
	// Asking is the whole condition. This used to also serve the roster whenever no
	// ROSTER_KEY was configured, which inverted the intent: the deployment with no
	// key was the one shipping every user's address in the clear on every poll, and
	// there was no way — not even ?roster=0 — to stop it. STATUS_TOKEN without
	// ROSTER_KEY is now a startup error, so the key is always present here.
	wantRoster := r.URL.Query().Get("roster") == "1"
	var roster []store.RosterEntry
	if wantRoster {
		var rerr error
		roster, rerr = s.store.NotifyRoster(r.Context())
		if rerr != nil {
			s.serverError(w, rerr)
			return
		}
		roster = s.enrichRoster(r.Context(), roster)
	}
	sessions, err := s.store.ListTenantSessions(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	warmed, err := s.store.OwnersWithPermit(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	now := time.Now()
	counts := tenantSessionCounts(sessions, now, s.cfg.Council.WarmInterval, s.cfg.Council.IdleWindow, s.cfg.Council.ExpiryWarningMargin, warmed)
	counts.Expiries1h, counts.Reconnects1h, counts.ExpiredOwners1h = s.sched.SessionChurn()
	counts.ReconnectQueued, counts.ReconnectDue, counts.ReconnectOldestSeconds = s.sched.ReconnectBacklog()
	last := s.sched.LastReconcile()
	resp := statusResponse{
		Time: now.UTC().Format(time.RFC3339),
		Scheduler: schedulerStatus{
			Stale: last.IsZero() || now.Sub(last) > schedulerStaleAfter,
		},
		Sessions: counts,
		Client: clientObservation{
			IP:        clientIP(r),
			EdgeProxy: noteEdgeProxy(r),
		},
		Tenant:        s.tenantSnapshot(),
		TenantOptions: s.tenantBreakdowns(sessions),
	}
	if wantRoster {
		// A missing or malformed ROSTER_KEY makes this fail, which is the correct
		// outcome: the watchdog gets a 500 it will report rather than a roster it
		// should never receive unsealed. Startup already refuses that combination.
		sealed, serr := sealRoster(s.cfg.RosterKey, roster)
		if serr != nil {
			s.serverError(w, serr)
			return
		}
		resp.RosterSealed = sealed
	}
	if !last.IsZero() {
		resp.Scheduler.LastReconcile = last.UTC().Format(time.RFC3339)
	}
	if att := s.sched.LastReconcileAttempt(); !att.IsZero() {
		resp.Scheduler.LastAttempt = att.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// tenantBreakdown is one tenant's slice of the status page.
type tenantBreakdown struct {
	Linked int          `json:"linked"`
	Health tenantStatus `json:"health"`
}

// perTenant is what a multi-tenant client exposes for the breakdown.
type perTenant interface {
	IDs() []string
	Client(id string) (*parking.Client, bool)
}

// tenantBreakdowns builds the per-tenant section when the client is a mux.
func (s *Server) tenantBreakdowns(sessions []store.TenantSession) map[string]tenantBreakdown {
	pc, ok := s.tenant.(perTenant)
	if !ok {
		return nil
	}
	out := map[string]tenantBreakdown{}
	for _, id := range pc.IDs() {
		c, _ := pc.Client(id)
		b := tenantBreakdown{Health: tenantStatusFrom(c.Stats())}
		for _, cs := range sessions {
			if cs.TenantID == id && cs.Cookie != "" {
				b.Linked++
			}
		}
		out[id] = b
	}
	return out
}

// tenantSnapshot returns the tenant-health section, nil-safe for tests that
// construct a Server without a tenant client (production always has one).
func (s *Server) tenantSnapshot() tenantStatus {
	if s.tenant == nil {
		return tenantStatus{PersistOK: true}
	}
	return tenantStatusFrom(s.tenant.Stats())
}

// tenantStatusFrom maps the tenant client's Stats snapshot onto the /status
// shape, converting the breaker's remaining pause to whole seconds and rendering
// timestamps as RFC3339.
func tenantStatusFrom(st parking.Stats) tenantStatus {
	cs := tenantStatus{
		Requests1m:          st.LastMinute,
		Requests5m:          st.Last5Min,
		PushbacksTotal:      st.Pushback,
		BreakerOpen:         st.BreakerOpen,
		BreakerRemainingS:   int(st.BreakerFor.Round(time.Second) / time.Second),
		LastPushbackStatus:  st.LastPushbackStatus,
		LastPushbackRef:     st.LastPushbackRef,
		PersistOK:           st.PersistOK,
		PersistError:        st.PersistError,
		LastPushbackSurface: st.LastPushbackSurface,
		TruncatedGridGot:    st.TruncatedGridGot,
		TruncatedGridWant:   st.TruncatedGridWant,
	}
	if !st.TruncatedGridAt.IsZero() {
		cs.TruncatedGridAt = st.TruncatedGridAt.UTC().Format(time.RFC3339)
	}
	if !st.LastPushbackAt.IsZero() {
		cs.LastPushbackAt = st.LastPushbackAt.UTC().Format(time.RFC3339)
	}
	return cs
}

// bearerToken extracts the credential from an Authorization header, requiring the
// Bearer scheme that deploy/.env.example documents.
//
// The previous TrimPrefix accepted a bare `Authorization: <token>` as well, which
// is laxer than the documented contract for no benefit: nothing legitimate sends
// it, and a gate that quietly accepts more shapes than its documentation is a gate
// nobody can reason about. The scheme name is compared case-insensitively because
// RFC 7235 defines it that way, and refusing `bearer` would be a self-inflicted
// outage of the watchdog rather than a security property.
func bearerToken(header string) (string, bool) {
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	return strings.TrimSpace(header[len(scheme):]), true
}

// secretEqual compares a presented credential against the expected one without
// leaking either through timing.
//
// It digests both sides first because subtle.ConstantTimeCompare is only constant
// time for equal-length inputs — on a length mismatch it returns immediately, so
// comparing the raw strings tells an attacker the length of STATUS_TOKEN, which is
// the first thing you would want to know before guessing it. Hashing makes every
// comparison the same fixed width regardless of what was sent.
func secretEqual(presented, want string) bool {
	a := sha256.Sum256([]byte(presented))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// rosterChangeHorizon is how far ahead each roster entry's NextChangeAt looks.
// It bounds what the watchdog can target during an outage: past this, its
// long-outage backstop (which emails every managed household) has taken over
// anyway, so a wider horizon would add schedule detail to the sealed payload
// that nothing reads.
const rosterChangeHorizon = 48 * time.Hour

// enrichRoster applies the model-level half of the roster policy: drop owners
// whose permits are ALL dead (a cancelled permit is nothing an outage can
// break), and stamp each survivor with when their schedule next requires a
// tenant write, so the watchdog can warn exactly the households whose change
// an outage has actually cost.
//
// Read errors fail OPEN on membership — an entry we cannot evaluate stays in,
// un-stamped, because this list exists for a moment when things are already
// going wrong, and a database blip must not quietly shrink who gets warned.
func (s *Server) enrichRoster(ctx context.Context, roster []store.RosterEntry) []store.RosterEntry {
	loc := s.cfg.DisplayLocation
	now := time.Now().In(loc)
	out := make([]store.RosterEntry, 0, len(roster))
	for _, e := range roster {
		permits, err := s.store.ListPermitsFor(ctx, e.Email)
		if err != nil {
			log.Printf("roster: permits for %s: %v (kept, unstamped)", redact.Email(e.Email), err)
			out = append(out, e)
			continue
		}
		var next *time.Time
		alive := false
		for _, p := range permits {
			if p.Inactive(now, loc) {
				continue
			}
			alive = true
			rules, rerr := s.store.ListRules(ctx, p.ID)
			if rerr != nil {
				log.Printf("roster: rules for permit %d: %v", p.ID, rerr)
				continue
			}
			overrides, oerr := s.store.ListOverrides(ctx, p.ID, now)
			if oerr != nil {
				log.Printf("roster: overrides for permit %d: %v", p.ID, oerr)
				continue
			}
			if c := model.NextChange(now, rosterChangeHorizon, rules, overrides); c != nil && (next == nil || c.Before(*next)) {
				next = c
			}
		}
		if !alive && err == nil && len(permits) > 0 {
			continue // permits exist but every one is dead; nothing to protect
		}
		if !alive {
			// No permit rows at all shouldn't reach here (NotifyRoster's SQL cut),
			// but keep the entry if it somehow does — fail open, as above.
			out = append(out, e)
			continue
		}
		if next != nil {
			e.NextChangeAt = next.UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}
	return out
}

// sealRoster encrypts the roster for transport to the outage watchdog, using the
// same AES-256-GCM construction as internal/secretbox (random 12-byte nonce
// prefixed to the ciphertext, base64). The watchdog holds ROSTER_KEY and reverses
// it; nothing else can read the payload even with a valid STATUS_TOKEN.
func sealRoster(key []byte, roster []store.RosterEntry) (string, error) {
	plain, err := json.Marshal(roster)
	if err != nil {
		return "", err
	}
	box, err := secretbox.New(key)
	if err != nil {
		return "", err
	}
	return box.Seal(string(plain))
}

// tenantRowStatus classifies one account's tenant connection for the admin table,
// returning the status key, its label, and whether it warrants operator attention.
// keptWarm is whether the owner manages a permit: only those sessions are kept
// warm, so only they can be "stale" — an owner with no permit ages as expected,
// not a fault (this mirrors what tenantSessionCounts reports on /status). The re-link
// bound is idle-based (see idleSince); warmStaleAfter is the keep-warm renew deadline,
// derived from the configured idle window and interval rather than a fixed constant so
// it tracks WARM_INTERVAL instead of flagging healthy sessions between renews.
func tenantRowStatus(a store.AdminAccount, keptWarm bool, now time.Time, maxAge, warmStaleAfter time.Duration) (status, label string, attention bool) {
	switch {
	case !a.Linked:
		return "unlinked", "Not linked", false
	case maxAge > 0 && !idleSince(a).IsZero() && now.Sub(idleSince(a)) >= maxAge:
		return "relink", "Re-link due", true
	case keptWarm && (a.WarmedAt.IsZero() || now.Sub(a.WarmedAt) > warmStaleAfter):
		return "stale", "Keep-warm stale", true
	default:
		return "ok", "OK", false
	}
}

// applyFailureState classifies an account's newest apply-log outcome for the admin
// table. A non-success row is a LIVE fault only while the permit is still in a failure
// streak; once the streak clears (a later pass found the scheduled plate back in
// place) the row is stale audit history — the "error" simply stays the newest apply_log
// row for up to 90 days. Reporting that as "needs attention" turns a resolved transient
// blip into a permanent alarm, so gate the red flag on the live streak and label a
// settled former failure "cleared". Only "error" is a fault: "changed" records an
// external edit at the portal and is informational, never attention-worthy.
func applyFailureState(status string, maxFailStreak int) (bad, cleared bool) {
	if status != "error" {
		return false, false
	}
	if maxFailStreak > 0 {
		return true, false
	}
	return false, true
}

// idleSince is the clock the re-authorise bound is measured against, mirroring
// scheduler.decideWarm: last activity, falling back to the link time for sessions
// that predate the idle column. Kept in step with that function — if they diverge,
// /admin reports a deadline the scheduler does not act on.
func idleSince(a store.AdminAccount) time.Time {
	if !a.LastActive.IsZero() {
		return a.LastActive
	}
	return a.LinkedAt
}
