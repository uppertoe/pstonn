package server

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

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
		// Council / keep-warm status.
		needsAttention := false
		switch {
		case !a.Linked:
			row.Status, row.StatusLabel = "unlinked", "Not linked"
		case maxAge > 0 && !a.LinkedAt.IsZero() && now.Sub(a.LinkedAt) >= maxAge:
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
			if maxAge > 0 && !a.LinkedAt.IsZero() {
				row.RelinkBy = a.LinkedAt.Add(maxAge).In(loc).Format("2 Jan 2006")
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
	Roster    []store.RosterEntry `json:"roster"`
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
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.cfg.StatusToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	roster, err := s.store.NotifyRoster(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
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
		Roster:   roster,
	}
	if !last.IsZero() {
		resp.Scheduler.LastReconcile = last.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
