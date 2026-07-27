package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// pickerPage renders the permit picker on its own route (for "manage another
// permit" from the dashboard). It goes through appShell so it gets the same
// gating (terms, council link) and chrome (sign-out, contact) as every other
// signed-in page; appShell already renders the picker itself for a user with
// no managed permits, so this handler only adds the "manage another" case.
func (s *Server) pickerPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "")
	if !ok {
		return
	}
	s.renderPicker(w, r, base)
}

// renderPicker lists the user's council permits (excluding already-managed ones)
// for them to nominate. A dead session cookie routes back to onboarding.
// The live council read is inherent to this page, so it gets a deadline well
// inside the server's 20s WriteTimeout: a slow portal yields the error branch
// (a rendered page), not a dropped connection.
func (s *Server) renderPicker(w http.ResponseWriter, r *http.Request, base dashboardData) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	owner := base.Owner
	permits, err := s.council.ListPermits(ctx, owner)
	if err != nil {
		base.State = "onboarding"
		base.AutoReconnect = s.hasSavedPassword(ctx, owner)
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

// isVisitorPermit reports whether a council permit type is a visitor permit, the
// only kind p.stonn schedules. The council names them like "(A) 1st Visitor
// Permit", so a case-insensitive "visitor" match is the reliable signal.
func isVisitorPermit(permitType string) bool {
	return strings.Contains(strings.ToLower(permitType), "visitor")
}

func (s *Server) addPermit(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	// Bounded well inside the server's 20s WriteTimeout: the council authorization
	// read below must fail with a rendered error, not a dropped connection.
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cpid := strings.TrimSpace(r.FormValue("council_permit_id"))
	if cpid == "" {
		s.formError(w, r, "Council permit ID is required.")
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
		cleanLabel(r.FormValue("label")))
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			// Raced the pre-check above: another account claimed it in between.
			s.message(w, http.StatusConflict, "That permit is already being managed by another account.")
			return
		}
		s.serverError(w, err)
		return
	}
	// Seed "on permit now" from the plate the council record already reports, so
	// it shows immediately instead of "unknown" until the first live refresh.
	if match.CurrentRego != "" {
		_ = s.store.SetPermitActive(ctx, pid, match.CurrentRego)
	}
	// Seed expiry + status + identifiers so the schedule shows them straight away;
	// the scheduler keeps them fresh on the keep-warm cadence thereafter.
	_ = s.store.UpdatePermitMeta(ctx, owner, cpid, match.Status, match.PermitNumber, match.PermitType, match.EndDate)
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

// copySchedule clones the weekly roster and active/upcoming one-offs from another
// of the account's permits onto this one — the "I renewed my permit, put my
// schedule back" flow. Any account member may do it (it's schedule management).
func (s *Server) copySchedule(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	dst, ok := s.ownedPermit(w, r, owner) // target = permit in the path
	if !ok {
		return
	}
	src := atoi64(r.FormValue("source"))
	if src == 0 || src == dst.ID {
		s.formError(w, r, "Choose which permit to copy the schedule from.")
		return
	}
	// Confirm the source is also this account's (CopySchedule re-checks, but this
	// gives a clean 404 rather than a generic error).
	if sp, err := s.store.GetPermit(r.Context(), src); err != nil || sp.Owner != owner {
		s.message(w, http.StatusNotFound, "That permit isn't one of yours.")
		return
	}
	n, err := s.store.CopySchedule(r.Context(), owner, src, dst.ID, time.Now())
	if err != nil {
		s.serverError(w, err)
		return
	}
	if n == 0 {
		s.formError(w, r, "That permit has no schedule to copy.")
		return
	}
	s.sched.Kick()
	s.respondPermit(w, r, owner, dst)
}

// cleanLabel trims a user-supplied name and strips control characters (including
// CR/LF), so a label can't smuggle newlines into an email header (defence in depth
// alongside the mailer's own sanitisation) or odd control bytes into the UI.
func cleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// renamePermit gives a permit a friendly name the user chooses (e.g. "Nanny"),
// shown everywhere it appears — schedule, guest passes, door QRs. It's purely a
// display label; the council record is untouched.
func (s *Server) renamePermit(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	label := cleanLabel(r.FormValue("label"))
	if label == "" {
		s.formError(w, r, "Give the permit a name.")
		return
	}
	if rs := []rune(label); len(rs) > 40 {
		label = string(rs[:40])
	}
	if err := s.store.SetPermitLabel(r.Context(), owner, p.ID, label); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}
