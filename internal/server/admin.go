package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
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
	MemberOf     string // shares another account
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
	now := time.Now()
	loc := s.cfg.DisplayLocation
	maxAge := s.cfg.Council.SessionMaxAge

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
			Email: a.Owner, MemberOf: a.MemberOf, EmailOn: a.EmailEnabled,
			Consent: a.ConsentVersion, Permits: a.PermitCount, Members: a.MemberCount,
			Plates: strings.Join(a.Plates, ", "),
		}
		if a.NtfyEnabled {
			row.NtfyTopic = a.NtfyTopic
		}
		// Council / keep-warm status. The re-authorise deadline is IDLE-based, so it
		// must be read off the same clock decideWarm retires on — using linked_at
		// showed a false "Re-link due", and a date months in the past, for any active
		// household that happened to link more than maxAge ago.
		needsAttention := false
		switch {
		case !a.Linked:
			row.Status, row.StatusLabel = "unlinked", "Not linked"
		case maxAge > 0 && !idleSince(a).IsZero() && now.Sub(idleSince(a)) >= maxAge:
			row.Status, row.StatusLabel = "relink", "Re-link due"
			needsAttention = true
		case a.WarmedAt.IsZero() || now.Sub(a.WarmedAt) > 6*time.Hour:
			row.Status, row.StatusLabel = "stale", "Keep-warm stale"
			needsAttention = true
		default:
			row.Status, row.StatusLabel = "ok", "OK"
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
			row.LastApply = a.LastApplyStatus
			if !a.LastApplyAt.IsZero() {
				row.LastApply += " · " + agoText(now, a.LastApplyAt)
			}
			if a.LastApplyStatus != "success" {
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
	// Council reports the outbound-traffic health the watchdog needs to alert on a
	// developing edge block: the real request rate, pushback count/diagnostics, the
	// fleet circuit state, and whether restart-protection persistence is intact.
	Council councilStatus `json:"council"`
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
	LastReconcile string `json:"last_reconcile,omitempty"` // RFC3339 UTC, "" if never
	Stale         bool   `json:"stale"`
}

type sessionCounts struct {
	Linked int `json:"linked"`
	Warm   int `json:"warm"`
}

// councilStatus is the outbound-council health for the watchdog. The rate windows
// answer "what rate was the council seeing when it began refusing us"; the pushback
// fields say WHICH control fired; the breaker fields say whether we are paused; and
// persist_ok says whether a restart would still honour that pause.
type councilStatus struct {
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
	if !s.statusLimit.allow(clientIP(r)) {
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
	// The roster — every consented account's email plus their push topic — is the
	// sensitive half of this endpoint. The watchdog needs it only to reach users
	// during an outage, and needs it rarely, so it is served ONLY when asked for,
	// and only sealed. The frequent health poll then carries nothing worth stealing.
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
	}
	sessions, err := s.store.ListCouncilSessions(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	now := time.Now()
	var linked, warm int
	for _, cs := range sessions {
		if cs.Cookie == "" {
			continue
		}
		linked++
		if !cs.UpdatedAt.IsZero() && now.Sub(cs.UpdatedAt) < 6*time.Hour {
			warm++
		}
	}
	last := s.sched.LastReconcile()
	resp := statusResponse{
		Time: now.UTC().Format(time.RFC3339),
		Scheduler: schedulerStatus{
			Stale: last.IsZero() || now.Sub(last) > schedulerStaleAfter,
		},
		Sessions: sessionCounts{Linked: linked, Warm: warm},
		Client: clientObservation{
			IP:        clientIP(r),
			EdgeProxy: noteEdgeProxy(r),
		},
		Council: s.councilSnapshot(),
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
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

// councilSnapshot returns the council-health section, nil-safe for tests that
// construct a Server without a council client (production always has one).
func (s *Server) councilSnapshot() councilStatus {
	if s.council == nil {
		return councilStatus{PersistOK: true}
	}
	return councilStatusFrom(s.council.Stats())
}

// councilStatusFrom maps the council client's Stats snapshot onto the /status
// shape, converting the breaker's remaining pause to whole seconds and rendering
// timestamps as RFC3339.
func councilStatusFrom(st parking.Stats) councilStatus {
	cs := councilStatus{
		Requests1m:         st.LastMinute,
		Requests5m:         st.Last5Min,
		PushbacksTotal:     st.Pushback,
		BreakerOpen:        st.BreakerOpen,
		BreakerRemainingS:  int(st.BreakerFor.Round(time.Second) / time.Second),
		LastPushbackStatus: st.LastPushbackStatus,
		LastPushbackRef:    st.LastPushbackRef,
		PersistOK:          st.PersistOK,
		PersistError:       st.PersistError,
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
