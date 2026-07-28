package server

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// schedulerStaleAfter is how long without a completed reconcile pass counts as a
// wedged work loop (the reconcile loop ticks every minute, so this is generous).
const schedulerStaleAfter = 10 * time.Minute

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
	Time      string              `json:"time"`
	Scheduler schedulerStatus     `json:"scheduler"`
	Sessions  sessionCounts       `json:"sessions"`
	Roster    []store.RosterEntry `json:"roster,omitempty"`
	// RosterSealed is the roster as AES-256-GCM ciphertext (base64, 12-byte nonce
	// prefix — the same construction as internal/secretbox), under ROSTER_KEY. The
	// watchdog holds that key; a leaked STATUS_TOKEN alone yields only this.
	RosterSealed string `json:"roster_sealed,omitempty"`
}

type schedulerStatus struct {
	LastReconcile string `json:"last_reconcile,omitempty"` // RFC3339 UTC, "" if never
	Stale         bool   `json:"stale"`
}

type sessionCounts struct {
	Linked int `json:"linked"`
	Warm   int `json:"warm"`
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
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.StatusToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// The roster — every consented account's email plus their push topic — is the
	// sensitive half of this endpoint. The watchdog needs it only to reach users
	// during an outage, and needs it rarely, so it is served ONLY when asked for
	// and encrypted when a key is configured. The frequent health poll then carries
	// nothing worth stealing.
	wantRoster := r.URL.Query().Get("roster") == "1" || len(s.cfg.RosterKey) == 0
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
	}
	switch {
	case !wantRoster:
		// Health-only poll: nothing sensitive in the response at all.
	case len(s.cfg.RosterKey) > 0:
		sealed, serr := sealRoster(s.cfg.RosterKey, roster)
		if serr != nil {
			s.serverError(w, serr)
			return
		}
		resp.RosterSealed = sealed
	default:
		// No key configured: keep the historical plaintext shape so an existing
		// watchdog keeps working until it is updated (main warns at startup).
		resp.Roster = roster
	}
	if !last.IsZero() {
		resp.Scheduler.LastReconcile = last.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
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
