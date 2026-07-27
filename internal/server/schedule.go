package server

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

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
	var expired []expiredPermitView
	for _, p := range managed {
		// Expired/cancelled permits collapse into a compact section — no full card,
		// no council call — but stay available as a copy-schedule source.
		if p.Inactive(now, s.cfg.DisplayLocation) {
			expired = append(expired, buildExpiredView(p, now, s.cfg.DisplayLocation))
			continue
		}
		pv, err := s.buildPermitView(ctx, p, vviews, colorByID, regByID, labelByID, now)
		if err != nil {
			s.serverError(w, err)
			return
		}
		pv.IsPrimary = base.IsPrimary
		pvs = append(pvs, pv)
	}
	base.Vehicles = vviews
	base.Permits = pvs
	base.ExpiredPermits = expired
	s.render(w, base)
}

// buildPermitView assembles one permit's roster grid, 14-day at-a-glance
// calendar (resolved per day), and upcoming one-offs.
func (s *Server) buildPermitView(ctx context.Context, p model.Permit, vviews []vehicleView, colorByID, regByID, labelByID map[int64]string, now time.Time) (permitView, error) {
	// Refresh "on permit now" from the council (cached ≤5 min, refreshed in the
	// background — never a synchronous council call), so the display is truthful
	// and external portal changes are caught. With nothing cached yet, keep the
	// stored belief. A non-fresh value marks the view PlateRefreshing, which
	// renders a one-shot htmx follow-up so the refreshed plate swaps in without
	// a manual reload.
	plateRefreshing := false
	if actual, fresh, err := s.council.CurrentVehicleCached(ctx, p.Owner,
		model.Permit{CouncilPermitID: p.CouncilPermitID, PermitTypeID: p.PermitTypeID}, 5*time.Minute); err == nil {
		plateRefreshing = !fresh
		if actual != p.ActiveRegistration {
			p.ActiveRegistration = actual
			_ = s.store.SetPermitActive(ctx, p.ID, actual)
		}
	} else {
		plateRefreshing = true // nothing cached yet; a background fetch is running
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
	pv := permitView{
		Permit: p, DesiredReg: desiredReg, DesiredSource: source,
		Days: days, Cal: cal, Overrides: ovs, Vehicles: vviews, Loc: loc,
		RosterEmpty:     len(rules) == 0,
		Detail:          permitDetail(p),
		PlateRefreshing: plateRefreshing,
	}
	fillExpiry(&pv, now)
	// Offer to copy a schedule from the owner's other permits (e.g. after a
	// renewal creates a fresh permit under a new council id).
	if siblings, err := s.store.ListPermitsFor(ctx, p.Owner); err == nil {
		for _, sp := range siblings {
			if sp.ID != p.ID {
				label := sp.Label
				if label == "" {
					label = "Permit " + sp.CouncilPermitID
				}
				if sp.Inactive(now, loc) {
					label += " (expired)"
				}
				pv.CopyFrom = append(pv.CopyFrom, permitOpt{ID: sp.ID, Label: label})
			}
		}
	}
	return pv, nil
}

// expirySoonLead is how close to a permit's end date the schedule starts flagging
// it (a little wider than the email reminder lead, so the UI hints first).
const expirySoonLead = 21 * 24 * time.Hour

// fillExpiry derives the human expiry labels on a permit view from its end date.
func fillExpiry(pv *permitView, now time.Time) {
	end := pv.Permit.EndDate
	if end.IsZero() {
		return
	}
	loc := pv.Loc
	if loc == nil {
		loc = time.Local
	}
	end = end.In(loc)
	pv.ExpiryLabel = end.Format("2 Jan 2006")
	// Whole calendar-day difference in local time. Anchor both dates at noon and
	// round, so a DST transition (a 23- or 25-hour day) between them doesn't shift
	// the count by one.
	startDay := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, loc)
	endDay := time.Date(end.Year(), end.Month(), end.Day(), 12, 0, 0, 0, loc)
	days := int(math.Round(endDay.Sub(startDay).Hours() / 24))
	switch {
	case days < 0:
		pv.Expired = true
		if days == -1 {
			pv.ExpiryIn = "yesterday"
		} else {
			pv.ExpiryIn = fmt.Sprintf("%d days ago", -days)
		}
	case days == 0:
		pv.ExpiresSoon = true
		pv.ExpiryIn = "today"
	case days == 1:
		pv.ExpiresSoon = true
		pv.ExpiryIn = "tomorrow"
	default:
		pv.ExpiryIn = fmt.Sprintf("in %d days", days)
		pv.ExpiresSoon = end.Sub(now) <= expirySoonLead
	}
}

func (s *Server) setRule(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	// Strict parse: atoi would map garbage to 0 (= Sunday), silently setting the
	// wrong day; an out-of-range value would persist as an invisible row Resolve
	// never matches.
	wd, werr := strconv.Atoi(strings.TrimSpace(r.FormValue("weekday")))
	if werr != nil || wd < 0 || wd > 6 {
		s.formError(w, r, "That day isn't valid. Please reload the page and try again.")
		return
	}
	weekday := time.Weekday(wd)
	vehicleID := atoi64(r.FormValue("vehicle_id"))
	var err error
	var plate string
	if vehicleID == 0 {
		err = s.store.ClearRule(r.Context(), p.ID, weekday)
	} else {
		if !s.ownsVehicle(w, r, owner, vehicleID) {
			return
		}
		err = s.store.SetRule(r.Context(), p.ID, weekday, vehicleID)
		plate = s.plateOf(r.Context(), owner, vehicleID)
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Roster edits are the change most likely to matter and least likely to be
	// noticed: clearing a day produces no apply at all, so the scheduler does
	// nothing and says nothing.
	if vehicleID == 0 {
		s.logChange(r.Context(), owner, user, store.ActionRosterClear,
			weekday.String()+" on "+permitLabel(p), "")
	} else {
		s.logChange(r.Context(), owner, user, store.ActionRosterSet,
			weekday.String()+" on "+permitLabel(p), plate)
	}
	s.sched.KickPermit(p.ID)
	s.respondPermit(w, r, owner, p)
}

// combineDateTime joins a native date input (YYYY-MM-DD) and time input (HH:MM)
// into the "2006-01-02T15:04" form the parser expects. It returns "" when no date
// was given (the field is unset); a date with an empty time uses defaultTime.
func combineDateTime(date, timeStr, defaultTime string) string {
	date = strings.TrimSpace(date)
	if date == "" {
		return ""
	}
	t := strings.TrimSpace(timeStr)
	if t == "" {
		t = defaultTime
	}
	return date + "T" + t
}

func (s *Server) addOverride(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	// The form posts separate date + time inputs (datetime-local has no time
	// picker in some mobile browsers). A blank date means "unset"; a date with no
	// time defaults to the start of that day for "from" and the end of the day for
	// "until", so choosing only a day still makes a sensible booking.
	startsAt := time.Now()
	if raw := combineDateTime(r.FormValue("from_date"), r.FormValue("from_time"), "00:00"); raw != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, s.cfg.DisplayLocation)
		if err != nil {
			s.formError(w, r, "Couldn't read the start time.")
			return
		}
		startsAt = t
	}
	var endsAt *time.Time
	if raw := combineDateTime(r.FormValue("until_date"), r.FormValue("until_time"), "23:59"); raw != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, s.cfg.DisplayLocation)
		if err != nil {
			s.formError(w, r, "Couldn't read the end time.")
			return
		}
		endsAt = &t
	}
	if endsAt != nil && !endsAt.After(startsAt) {
		s.formError(w, r, "The end time must be after the start time.")
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
			s.formError(w, r, "Enter a valid number plate (letters and numbers, e.g. ABC123).")
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
		s.formError(w, r, "Choose a saved car or enter a one-off plate.")
		return
	}
	// Record the window too: an open-ended booking beats the roster indefinitely,
	// which is worth being able to see and attribute.
	reg := plate
	if reg == "" {
		reg = s.plateOf(r.Context(), owner, vehicleID)
	}
	window := "from " + startsAt.In(s.cfg.DisplayLocation).Format("2 Jan 3:04pm")
	if endsAt == nil {
		window += ", open-ended"
	} else {
		window += " until " + endsAt.In(s.cfg.DisplayLocation).Format("2 Jan 3:04pm")
	}
	s.logChange(r.Context(), owner, user, store.ActionOverrideAdd, reg, window)
	s.sched.KickPermit(p.ID)
	s.respondPermit(w, r, owner, p)
}

func (s *Server) deleteOverride(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	// Read the booking before deleting it, so the log can name what went.
	var gone string
	if ovs, err := s.store.ListOverrides(r.Context(), p.ID, time.Time{}); err == nil {
		oid := pathInt(r, "oid")
		for _, o := range ovs {
			if o.ID == oid {
				gone = o.Registration
				if gone == "" {
					gone = s.plateOf(r.Context(), owner, o.VehicleID)
				}
			}
		}
	}
	if err := s.store.DeleteOverride(r.Context(), owner, pathInt(r, "oid")); err != nil {
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionOverrideDelete, gone, "")
	s.sched.KickPermit(p.ID)
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
	// Fragments are one-shot: never embed another follow-up fetch, so a council
	// outage can't turn the page into a persistent polling loop.
	pv.PlateRefreshing = false
	_, _, pv.IsPrimary = s.resolveAccount(ctx)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "permit-body", pv); err != nil {
		log.Printf("render permit-body: %v", err)
	}
}

// permitCard re-renders one permit's card fragment. It is the target of the
// one-shot follow-up fetch a page render emits when it served a stale plate:
// by the time this fires the background council refresh has usually landed, so
// the swap shows the verified plate without a manual reload.
func (s *Server) permitCard(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	s.respondPermit(w, r, owner, p)
}
