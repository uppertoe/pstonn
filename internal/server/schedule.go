package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// schedule is the primary day-to-day page: permit status, weekly roster, 14-day
// calendar, and the chronological one-offs.
func (s *Server) schedule(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "schedule")
	if !ok {
		return
	}
	// The post-addPermit landing (see addPermit): say what just happened, because
	// an expired permit's card is inside the collapsed section below and an
	// active one's next step (set a roster) is not self-evident to a newcomer.
	switch r.URL.Query().Get("added") {
	case "1":
		base.Flash = "Permit added. Pick a car for each day of the week below, or make a one-off booking."
	case "expired":
		base.Warn = s.say(r.Context(), base.Owner, "schedule.added_expired")
	}
	ctx := r.Context()
	owner := base.Owner
	now := time.Now().In(s.locFor(ctx, owner))
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
		if p.Inactive(now, s.locFor(ctx, owner)) {
			expired = append(expired, buildExpiredView(p, now, s.locFor(ctx, owner)))
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
	// Only consulted when the garage is empty (the banner's only trigger), so
	// the extra query is skipped for every set-up household.
	if len(vviews) == 0 {
		if ga, gerr := s.store.HasGuestActivity(ctx, owner); gerr == nil {
			base.GuestActive = ga
		}
	}
	if used, lerr := s.legendColors(ctx, owner, vviews, now); lerr == nil {
		base.LegendVehicles, base.LegendMore = legendVehicles(vviews, used)
	} else {
		log.Printf("legend colours for %s: %v", redact.Email(owner), lerr)
	}
	base.Permits = pvs
	base.ExpiredPermits = expired
	// Shared-access hint: only for a primary far enough along to have a live
	// permit card on screen, with no members yet. A pending invite counts as a
	// member here — that household has already found the feature.
	if base.IsPrimary && len(pvs) > 0 {
		if n, cerr := s.store.CountMembers(ctx, owner); cerr == nil && n == 0 {
			base.ShowShareHint = true
		}
	}
	// The home-screen tip waits for the first successful apply: the household has
	// something worth glancing at, and the tip lands as a reward rather than a chore.
	if len(pvs) > 0 {
		if n, cerr := s.store.CountSuccessfulApplies(ctx, owner); cerr == nil && n > 0 {
			base.ShowInstallHint = true
		}
	}
	s.render(w, base)
}

// legendFragment serves just the Schedule page's colour key, re-fetched by the
// page whenever a permit changes (see the schedule-changed trigger).
func (s *Server) legendFragment(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	vehicles, err := s.store.ListVehiclesFor(r.Context(), owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	vviews, _, _, _ := vehicleViews(vehicles)
	used, err := s.legendColors(r.Context(), owner, vviews, time.Now().In(s.locFor(r.Context(), owner)))
	if err != nil {
		s.serverError(w, err)
		return
	}
	var d dashboardData
	d.LegendVehicles, d.LegendMore = legendVehicles(vviews, used)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "legend", d); err != nil {
		log.Printf("render legend: %v", err)
	}
}

// buildPermitView assembles one permit's roster grid, 14-day at-a-glance
// calendar (resolved per day), and upcoming one-offs.
// endOfDay closes a one-off booking at the END of t's calendar day in loc —
// midnight at the start of the following day, which is what "until the end of the
// day" means to the person booking it. Same convention as dayEndLocal, which
// guest activations use.
//
// It must be the day boundary, not 23:59: model.Resolve treats a booking's end as
// EXCLUSIVE, so a 23:59 end left the last minute of the day uncovered by the
// booking. The weekly roster reasserted itself for that minute — a real council
// write and a "your permit was updated" notification at 23:59, then the next day's
// booking or roster writing again at 00:00, where one change was intended.
func endOfDay(t time.Time, loc *time.Location) time.Time {
	l := t.In(loc)
	return time.Date(l.Year(), l.Month(), l.Day()+1, 0, 0, 0, 0, loc)
}

// legendColors is the set of car colours the Schedule page will render, across
// every permit on it: whatever each roster day and each live one-off points at,
// plus whatever is on each permit right now.
//
// Read from the store rather than from the built permitViews so the htmx fragment
// path can recompute it as cheaply as the full page — it is local SQLite only, no
// council call. That matters because it runs on every roster tap. The day strip
// adds nothing here: it resolves from those same rules and overrides, so its
// colours are always a subset.
func (s *Server) legendColors(ctx context.Context, owner string, vviews []vehicleView, now time.Time) (map[string]bool, error) {
	colorByReg := map[string]string{}
	colorByID := map[int64]string{}
	for _, v := range vviews {
		colorByID[v.ID] = v.Color
		colorByReg[normPlate(v.Registration)] = v.Color
	}
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	mark := func(c string) {
		if c != "" {
			used[c] = true
		}
	}
	for _, p := range permits {
		// Expired permits collapse into their own section and render no colours.
		if p.Inactive(now, s.locFor(ctx, owner)) {
			continue
		}
		mark(colorByReg[normPlate(p.ActiveRegistration)])
		rules, err := s.store.ListRules(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		for _, ru := range rules {
			mark(colorByID[ru.VehicleID])
		}
		ovs, err := s.store.ListOverrides(ctx, p.ID, now)
		if err != nil {
			return nil, err
		}
		for _, o := range ovs {
			mark(colorByID[o.VehicleID]) // an ad-hoc plate has no vehicle, so no colour
		}
	}
	return used, nil
}

// normPlate canonicalises a registration for comparison: the council echoes
// plates back in whatever case and spacing they were entered with. Delegated to
// model so that "are these the same plate?" has exactly one answer across the
// app — the display layer's idea of it and the scheduler's must not diverge.
func normPlate(s string) string {
	return model.NormPlate(s)
}

// colorOfPlate finds the household's colour for a plate that is on the permit.
//
// Matched on the PLATE rather than a vehicle id because "what is on the permit
// now" comes back from the council as a bare registration — it may be a saved
// car, or a visitor's one-off plate that belongs to no vehicle row at all.
// Returns "" for the latter, which renders neutral: colour means "one of your
// cars", and its absence means "not one of yours", which is worth knowing at a
// glance. Case- and space-insensitive, since the council echoes plates back in
// whatever form they were entered.
func colorOfPlate(vs []vehicleView, plate string) string {
	want := normPlate(plate)
	if want == "" {
		return ""
	}
	for _, v := range vs {
		if normPlate(v.Registration) == want {
			return v.Color
		}
	}
	return ""
}

func (s *Server) buildPermitView(ctx context.Context, p model.Permit, vviews []vehicleView, colorByID, regByID, labelByID map[int64]string, now time.Time) (permitView, error) {
	// Refresh "on permit now" from the council (cached ≤5 min, refreshed in the
	// background — never a synchronous council call), so the display is truthful
	// and external portal changes are caught. With nothing cached yet, keep the
	// stored belief. A non-fresh value marks the view PlateRefreshing, which
	// renders a one-shot htmx follow-up so the refreshed plate swaps in without
	// a manual reload.
	plateRefreshing := false
	if actual, _, fresh, err := s.council.CurrentVehicleCached(ctx, p.Owner,
		model.Permit{CouncilPermitID: p.CouncilPermitID, PermitTypeID: p.PermitTypeID}, plateMaxAge); err == nil {
		plateRefreshing = !fresh
		// model.SamePlate, not a plain !=: the portal echoes plates back in whatever
		// case they were entered with, and overwriting our belief with a case variant
		// makes the scheduler's next tick see a plate that differs from its target —
		// so it performs a real council write and tells the household their permit was
		// updated (and emails a displaced driver) for a change that changes nothing.
		//
		// Adopt only a FRESH reading. The maxAge reasoning below assumed the reading
		// was at most a few minutes old, but a stale entry has no upper bound (the
		// refresh path keeps it through failures), and other writers touch the stored
		// plate without touching this cache — so with the council down, a days-old
		// cached plate could win the CAS against a NEWER stored plate and rewrite the
		// record backwards. The refresh already running will adopt on the next render.
		if fresh && !model.SamePlate(actual, p.ActiveRegistration) {
			// Compare-and-swap: this reading may be up to maxAge old, and an apply can
			// commit a newer plate while a render is in flight (the card self-polls
			// exactly while applies settle). A blind write would regress the record to a
			// plate the council no longer holds. Only adopt our belief locally if the
			// stored one is still what we based the comparison on.
			ok, err := s.store.SetPermitActiveIfUnchanged(ctx, p.ID, p.ActiveRegistration, actual)
			if err != nil {
				// Don't swallow it: a persistent write failure here would otherwise be
				// invisible, the page just quietly showing a stale plate.
				log.Printf("dashboard: adopt council plate for permit %d: %v", p.ID, err)
			}
			if ok {
				p.ActiveRegistration = actual
			}
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

	loc := s.locFor(ctx, p.Owner)
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
		// A day taken by a typed-plate override has no saved colour, which used to
		// leave the neutral bar — a covered day that read as "nothing scheduled".
		// The flag gives it a distinct bar instead. Usual names the roster plate the
		// override displaced (popover/aria only), skipped when the override IS the
		// rostered car so it never says "ABC123 · usually ABC123".
		adhoc := r.Source == model.SourceOverride && r.Registration != ""
		usual := ""
		if r.Source == model.SourceOverride {
			if reg := regByID[ruleByWeekday[day.Weekday()]]; reg != "" && !model.SamePlate(reg, calReg) {
				usual = reg
			}
		}
		cal = append(cal, calView{
			DayLabel: day.Format("Mon 2"), Reg: calReg, Color: calColor,
			Adhoc: adhoc, Usual: usual,
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
	// A change is in flight when the schedule wants a plate right now that the
	// council's confirmed record does not yet show. desiredReg != "" excludes an
	// unresolvable schedule (a deleted vehicle), which the scheduler reports rather
	// than applies, so it is not "applying". SamePlate, not !=, for the same reason
	// the drift check uses it: the council echoes case/spacing variants.
	applying := res.Source != model.SourceNone && desiredReg != "" &&
		!model.SamePlate(desiredReg, p.ActiveRegistration)
	// The "nothing scheduled yet" nudge is for a NEW household that hasn't set up a
	// roster and might mistake the empty card for "working". A household that hands
	// visitors a QR code is using the permit exactly as intended, so once they've
	// touched the guest/QR path the nudge would just nag — drop it for them.
	hasGuests, err := s.store.HasGuestActivity(ctx, p.Owner)
	if err != nil {
		return permitView{}, err
	}
	// Siblings serve two features below: the copy-from options, and deciding which
	// card carries the account's single setup nudge. Errors are tolerated the way
	// CopyFrom always tolerated them — both features quietly degrade.
	siblings, _ := s.store.ListPermitsFor(ctx, p.Owner)
	// The nudge teaches a concept, not a permit, so it appears ONCE per account:
	// only while NOTHING on the account is scheduled (a household that has set up
	// any permit knows the mechanics), and then only on the first live card — a
	// two-permit signup used to read the same banner twice in a row. Computed here
	// rather than at page level because htmx card re-renders rebuild one view in
	// isolation and must reach the same answer.
	nudge := len(rules) == 0 && len(ovs) == 0 && !hasGuests
	if nudge {
		if scheduled, err := s.store.OwnerHasSchedule(ctx, p.Owner, now); err == nil && scheduled {
			nudge = false
		}
		for _, sp := range siblings {
			if sp.Inactive(now, loc) {
				continue
			}
			nudge = sp.ID == p.ID
			break
		}
	}
	pv := permitView{
		Permit: p, DesiredReg: desiredReg, DesiredSource: source,
		Days: days, Cal: cal, Overrides: ovs, Vehicles: vviews, Loc: loc,
		ActiveColor: colorOfPlate(vviews, p.ActiveRegistration),
		RosterEmpty: len(rules) == 0,
		CopyPitch:   len(rules) == 0 && !p.CopyOfferDone,
		// Offer "take the car off" only in the lingering-plate state: a plate is on
		// the permit but nothing is scheduled for now, so the scheduler won't clear
		// or replace it. With a schedule covering now, a clear would be re-applied.
		CanClear:        res.Source == model.SourceNone && p.ActiveRegistration != "",
		ShowSetupNudge:  nudge,
		Detail:          permitDetail(p),
		PlateRefreshing: plateRefreshing,
		Applying:        applying,
		// The honesty clock must survive a reload: PlateUnconfirmed used to be
		// reachable only by leaving the tab open for the whole poll budget, because
		// every full render restarted at attempt 0 — so during a council outage a
		// reloading user saw a spinner forever and never the "couldn't confirm"
		// mark. Seeded from the REFRESH-FAILURE streak, not the cache entry's age:
		// on a healthy system the first visit of the day serves an hours-old
		// reading while a refresh lands within seconds, and age-based seeding
		// declared that visit unconfirmable instantly — with no polls, so the
		// fresh answer never even swapped in (shipped 2026-08-10, caught the same
		// evening as "couldn't check" on every cold dashboard visit).
		pollSeed: attemptForStaleness(s.council.RefreshFailingFor(p.Owner,
			model.Permit{CouncilPermitID: p.CouncilPermitID, PermitTypeID: p.PermitTypeID})),
	}
	// Default to a first-attempt poll; a fragment response refines this with the
	// real attempt count (see respondPermit). A full page render keeps attempt 0
	// (floored at pollSeed either way).
	pv.armPlatePoll(0)
	fillExpiry(&pv, now)
	// Offer to copy a schedule from the owner's other permits (e.g. after a
	// renewal creates a fresh permit under a new council id).
	for _, sp := range siblings {
		if sp.ID != p.ID {
			label := sp.Label
			if label == "" {
				label = "Permit " + sp.CouncilPermitID
			}
			dead := sp.Inactive(now, loc)
			if dead {
				label += " (no longer active)"
			}
			pv.CopyFrom = append(pv.CopyFrom, permitOpt{ID: sp.ID, Label: label, Dead: dead})
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
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
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
	// A first roster day answers the "renewed this permit?" copy pitch: they are
	// building a schedule by hand, so the pitch must not lead again. p is a local
	// copy, so mirror the flag for the respondPermit render below.
	if vehicleID != 0 && !p.CopyOfferDone {
		if err := s.store.MarkCopyOfferDone(r.Context(), p.ID); err == nil {
			p.CopyOfferDone = true
		}
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
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
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
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, s.locFor(r.Context(), owner))
		if err != nil {
			s.formError(w, r, "Couldn't read the start time.")
			return
		}
		startsAt = t
	}
	// When it ENDS is an explicit choice, defaulting to the end of the day it
	// starts. It used to be "blank means run forever", which made the open-ended
	// booking the thing you got by not deciding — the opposite of what it should
	// be. An indefinite booking quietly holds the permit against the household's
	// own roster until somebody notices, so it now takes a deliberate selection.
	//
	// Measured from the START day rather than literally "today", so booking a car
	// for next Tuesday ends at the end of next Tuesday rather than in the past.
	//
	// An unrecognised or absent value falls back to the safe default, so a stale
	// cached page or a client that drops the field cannot resurrect the old
	// forever-by-accident behaviour.
	var endsAt *time.Time
	switch r.FormValue("ends") {
	case "open":
		endsAt = nil // deliberate: runs until someone changes it
	case "custom":
		raw := combineDateTime(r.FormValue("until_date"), r.FormValue("until_time"), "00:00")
		if raw == "" {
			s.formError(w, r, "Pick the date this booking should end, or choose one of the other options.")
			return
		}
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, s.locFor(r.Context(), owner))
		if err != nil {
			s.formError(w, r, "Couldn't read the end time.")
			return
		}
		// A chosen date with no time means the whole of that day, so it closes at the
		// day boundary. It used to default to 23:59, which left the last minute of the
		// day to the weekly roster for exactly the reason endOfDay explains.
		if strings.TrimSpace(r.FormValue("until_time")) == "" {
			t = endOfDay(t, s.locFor(r.Context(), owner))
		}
		endsAt = &t
	case "nextday":
		t := endOfDay(startsAt.AddDate(0, 0, 1), s.locFor(r.Context(), owner))
		endsAt = &t
	default: // "day", and anything unexpected
		t := endOfDay(startsAt, s.locFor(r.Context(), owner))
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
	// Cap simultaneously-live bookings per permit, atomically (count+insert in one tx),
	// so the never-pruned, hot-path override table can't grow without bound — walked on
	// every dashboard render and reconcile pass. A ceiling a real household never hits.
	overLimit := func(err error) bool {
		if errors.Is(err, store.ErrOverrideLimit) {
			s.formError(w, r, "This permit already has the maximum number of active bookings. Remove one before adding another.")
			return true
		}
		return false
	}
	switch {
	case plate != "":
		if !validRego(plate) {
			s.formError(w, r, plateFormatMsg)
			return
		}
		if _, err := s.store.CreateOverrideCapped(r.Context(), p.ID, 0, plate, startsAt, endsAt, user, store.MaxLiveOverridesPerPermit); err != nil {
			if !overLimit(err) {
				s.serverError(w, err)
			}
			return
		}
	case vehicleID != 0:
		if !s.ownsVehicle(w, r, owner, vehicleID) {
			return
		}
		if _, err := s.store.CreateOverrideCapped(r.Context(), p.ID, vehicleID, "", startsAt, endsAt, user, store.MaxLiveOverridesPerPermit); err != nil {
			if !overLimit(err) {
				s.serverError(w, err)
			}
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
	window := "from " + startsAt.In(s.locFor(r.Context(), owner)).Format("2 Jan 3:04pm")
	if endsAt == nil {
		window += ", open-ended"
	} else {
		window += " until " + windowEndText(*endsAt, s.locFor(r.Context(), owner))
	}
	s.logChange(r.Context(), owner, user, store.ActionOverrideAdd, reg, window)
	s.sched.KickPermit(p.ID)
	s.respondPermit(w, r, owner, p)
}

func (s *Server) deleteOverride(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
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
	// Scoped to this permit as well as this owner, and reporting whether anything
	// went, so a booking on another of the account's permits cannot be deleted
	// through this permit's URL and a miss stays silent.
	deleted, err := s.store.DeleteOverrideOnPermit(r.Context(), owner, p.ID, pathInt(r, "oid"))
	if err != nil {
		s.serverError(w, err)
		return
	}
	if deleted {
		s.logChange(r.Context(), owner, user, store.ActionOverrideDelete, gone, "")
		s.sched.KickPermit(p.ID)
	}
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
//
// platePollDelays is the self-refresh cadence: the delay in SECONDS before each
// successive poll, indexed by how many polls have already been served. It caps how
// many times a card re-fetches itself to catch a plate still settling at the council
// (its length is the bound), AND how long it waits between tries.
//
// It BACKS OFF on purpose. The old cadence was a flat 5s×10 (~50s), which barely
// fitted two council attempts — so an idle-day dashboard load, which finds an empty
// plate cache AND an expired access token and therefore must silent-renew before it
// can even read (each attempt up to ~25s, and the council's edge occasionally makes
// that slow), routinely outlasted the window and froze the "checking" spinner until a
// reload. A few quick polls still swap in a normal apply fast; then it stretches to a
// gentle ~30-60s heartbeat so a slow cold read gets several minutes of retries and
// lands, while the bound still stops a genuine council outage from polling forever.
// Past the cap the card keeps showing the last council-confirmed plate; the scheduler
// goes on retrying and notifies out of band.
var platePollDelays = []int{5, 5, 5, 10, 10, 15, 20, 30, 45, 60, 60, 60}

// plateMaxAge is how old a cached council reading may be before the dashboard
// treats it as stale: shows the checking spinner and declines to adopt it into
// the stored record.
const plateMaxAge = 5 * time.Minute

// attemptForStaleness maps how long refreshes have been FAILING consecutively
// (parking.RefreshFailingFor — not the cache entry's age, which merely says
// nobody looked lately) onto the poll attempt to resume from: the attempt a tab
// left open would have reached in that time. Past the whole budget it returns
// the cap, which renders the honest "couldn't confirm" mark immediately instead
// of a fresh spinner.
func attemptForStaleness(failingFor time.Duration) int {
	if failingFor <= 0 {
		return 0
	}
	elapsed := time.Duration(0)
	for i, d := range platePollDelays {
		if elapsed >= failingFor {
			return i
		}
		elapsed += time.Duration(d) * time.Second
	}
	return len(platePollDelays)
}

// armPlatePoll sets PollNext (whether this card re-fetches itself, and the next
// attempt number) and PollDelay (seconds to wait first). It arms while a background
// refresh is running (stale cache) OR a change is in flight (Applying), never past the
// cap. attempt is how many polls have already been served — 0 on a full page render or
// the fragment a user action returns, higher on a self-refresh follow-up — and is
// floored at pollSeed, so a reload during an outage resumes the honesty clock at the
// reading's real age rather than resetting it to a fresh spinner.
func (pv *permitView) armPlatePoll(attempt int) {
	if pv.pollSeed > attempt {
		attempt = pv.pollSeed
	}
	outstanding := pv.PlateRefreshing || pv.Applying
	if attempt < len(platePollDelays) && outstanding {
		pv.PollNext = attempt + 1
		pv.PollDelay = platePollDelays[attempt]
	} else {
		pv.PollNext = 0
		pv.PollDelay = 0
		// Out of polls with a read or apply STILL outstanding: surface an honest
		// "couldn't confirm" mark rather than leaving a spinner frozen mid-check. A settled
		// card (nothing outstanding) falls through with this false and shows the tick.
		pv.PlateUnconfirmed = outstanding
	}
	// Today's calendar cell mirrors the pill. The calendar renders INTENT (what
	// the schedule wants), which for future days is the only truth there is — but
	// today it sat pixel-identical to a confirmed day even when the apply had been
	// failing for days, and the only contradicting signal was a 13px icon in the
	// pill above. Stamped here because this is the one place that knows the final
	// Applying/PlateUnconfirmed state for the render.
	for i := range pv.Cal {
		if pv.Cal[i].IsToday {
			pv.Cal[i].Applying = pv.Applying && !pv.PlateUnconfirmed
			pv.Cal[i].Unconfirmed = pv.PlateUnconfirmed
		}
	}
}

func (s *Server) respondPermit(w http.ResponseWriter, r *http.Request, owner string, p model.Permit) {
	s.respondPermitNotice(w, r, owner, p, "")
}

// respondPermitNotice is respondPermit with an outcome line at the top of the
// card, for the person whose action just changed this permit.
func (s *Server) respondPermitNotice(w http.ResponseWriter, r *http.Request, owner string, p model.Permit, notice string) {
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
	pv, err := s.buildPermitView(ctx, p, vviews, colorByID, regByID, labelByID, time.Now().In(s.locFor(r.Context(), owner)))
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Re-arm the self-refresh against the attempt count this fetch carried, so the
	// card keeps swapping in the settling plate — a bounded poll (armPlatePoll caps
	// it), which is what lets a just-made change refresh without a manual reload
	// while still preventing a council outage from looping forever.
	attempt, _ := strconv.Atoi(r.URL.Query().Get("n"))
	pv.armPlatePoll(attempt)
	pv.Notice = notice
	_, _, pv.IsPrimary = s.resolveAccount(ctx)
	// The colour key lives ABOVE the permit cards, outside this fragment's target,
	// so a roster change would otherwise leave it stale until the next full load —
	// a car could vanish from the schedule while its chip stayed in the key. Tell
	// the page instead of pushing the key here: the key re-fetches itself, so the
	// newest state comes from the newest request rather than from whichever
	// overlapping response happened to land last.
	w.Header().Set("HX-Trigger", "schedule-changed")
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

// windowEndText renders a booking's end for a human.
//
// A booking that runs "to the end of a day" ends at the following midnight, because
// model.Resolve treats the end as exclusive — a 23:59 end left the last minute of the
// day uncovered and let the weekly roster reassert itself for sixty seconds. Correct,
// but formatting that instant literally produces "5 Aug 12:00am" for a booking the
// user made for the 4th, which reads as a whole day longer than they asked for.
//
// So a midnight end is described by the day it completes, not the day it touches.
func windowEndText(end time.Time, loc *time.Location) string {
	if loc == nil {
		loc = time.Local
	}
	l := end.In(loc)
	if l.Hour() == 0 && l.Minute() == 0 && l.Second() == 0 {
		return "the end of " + l.AddDate(0, 0, -1).Format("2 Jan")
	}
	return l.Format("2 Jan 3:04pm")
}
