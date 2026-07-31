package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/uppertoe/pstonn/internal/store"
)

// maxLabelRunes caps a user-chosen display label. Same number as the permit-label
// cap in renamePermit: both are nicknames shown in the UI and pasted into email
// subjects and bodies, so they want the same bound.
const maxLabelRunes = 40

// vehiclesPage manages the owner's plates.
func (s *Server) vehiclesPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "vehicles")
	if !ok {
		return
	}
	vehicles, err := s.store.ListVehiclesFor(r.Context(), base.Owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base.Vehicles, _, _, _ = vehicleViews(vehicles)
	if r.URL.Query().Get("saved") == "1" {
		// Saving a driver email otherwise changes nothing visible on the page.
		base.Flash = "Driver email saved."
	}
	// Every value here is validated before it is composed into the banner: the plate
	// against the same rego rule the rest of the app uses, the two figures as plain
	// counts. Nothing the caller writes reaches the page verbatim.
	if plate := r.URL.Query().Get("deleted"); validRego(plate) {
		base.Flash = deletedVehicleFlash(plate,
			atoi(r.URL.Query().Get("days")), atoi(r.URL.Query().Get("bookings")))
	}
	s.render(w, base)
}

func (s *Server) addVehicle(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	reg := normalizeReg(r.FormValue("registration"))
	// Cap the nickname by rune, exactly as renamePermit caps a permit label. The
	// form's maxlength is a client-side courtesy, not a limit: a crafted POST can
	// carry the whole body, and this label is copied into every apply notification
	// and stored again in each outbox row, so an unbounded one inflates mail and
	// the DB for as long as the car exists. 40 runes (not bytes) so an emoji or an
	// accented name is not cut mid-character.
	label := cleanLabel(r.FormValue("label"))
	if rs := []rune(label); len(rs) > maxLabelRunes {
		label = string(rs[:maxLabelRunes])
	}
	if !validRego(reg) {
		s.formError(w, r, "Enter a valid number plate (letters and numbers, e.g. ABC123).")
		return
	}
	if _, err := s.store.CreateVehicle(r.Context(), owner, reg, label); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			s.message(w, http.StatusConflict, "You already have a vehicle with that plate.")
			return
		}
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionVehicleAdd, reg, label)
	http.Redirect(w, r, "/vehicles", http.StatusSeeOther)
}

func (s *Server) deleteVehicle(w http.ResponseWriter, r *http.Request) {
	user, owner, _ := s.resolveAccount(r.Context())
	// Name the car before it goes, and warn the household: deleting a vehicle
	// cascade-deletes every roster day and booking that used it, which is silent
	// otherwise (a cleared day produces no apply, so nothing is notified).
	plate := s.plateOf(r.Context(), owner, pathInt(r, "id"))
	// Read what the delete is about to take with it, BEFORE it goes. Afterwards the
	// rows are gone and the household could only be told that "some days" changed,
	// which is not enough to act on — the point of the notice is that somebody can
	// reassign the emptied days before a car parks on an unscheduled one.
	usage, uerr := s.store.VehicleUsageFor(r.Context(), owner, pathInt(r, "id"))
	if uerr != nil {
		log.Printf("vehicle usage for %s before delete: %v", owner, uerr)
	}
	if err := s.store.DeleteVehicle(r.Context(), owner, pathInt(r, "id")); err != nil {
		s.serverError(w, err)
		return
	}
	// The delete happened either way, so the household hears about it either way.
	// Gating this on a resolved plate meant a transient read error turned a
	// cascading delete of roster days and bookings into a silent one — the exact
	// invisible change the notice exists to surface.
	named := "a car"
	if plate != "" {
		named = "the car " + plate
	}
	// The full detail — which weekdays on which permit — goes into the durable places:
	// the account's change log (visible on Activity) and the notification. It is
	// deliberately NOT carried in the redirect URL: free text from a query parameter
	// lands in the green success banner, which is the most trusted element on the
	// page, and anyone can hand a signed-in user a crafted link. The flash therefore
	// gets counts only, rebuilt server-side from validated integers.
	s.logChange(r.Context(), owner, user, store.ActionVehicleDelete, plate, usageSentence(usage))
	s.notifyDestructive(r.Context(), owner, user,
		user+" deleted "+named+" from your p.stonn account. "+usageSentence(usage))
	q := url.Values{
		"deleted":  {plate},
		"days":     {strconv.Itoa(len(usage.Rules))},
		"bookings": {strconv.Itoa(usage.LiveOverrides)},
	}
	http.Redirect(w, r, "/vehicles?"+q.Encode(), http.StatusSeeOther)
}

// usageSentence describes what a vehicle deletion took with it, naming the roster
// days rather than gesturing at them.
//
// "Some days now fall back to whatever else is scheduled" is true but unactionable:
// the household cannot fix what they cannot identify, and an unscheduled day is only
// discovered when a car parks on it. Deleting a car cascades its roster days and
// bookings away silently (a cleared day produces no apply, so nothing else notices),
// which makes this sentence the only warning there is.
func usageSentence(u store.VehicleUsage) string {
	if len(u.Rules) == 0 && u.LiveOverrides == 0 {
		return "It was not on any roster day or booking, so nothing else has changed."
	}
	var parts []string
	if len(u.Rules) > 0 {
		byPermit := map[string][]string{}
		var order []string
		for _, r := range u.Rules {
			label := r.PermitLabel
			if label == "" {
				label = "your permit"
			}
			if _, seen := byPermit[label]; !seen {
				order = append(order, label)
			}
			byPermit[label] = append(byPermit[label], r.Weekday.String())
		}
		for _, label := range order {
			parts = append(parts, joinWords(byPermit[label])+" on "+label)
		}
	}
	out := ""
	if len(parts) > 0 {
		out = joinWords(parts) + " now have nothing scheduled. Those days will keep whatever registration is currently on the permit until you set them again."
	}
	if u.LiveOverrides > 0 {
		booking := "booking"
		if u.LiveOverrides > 1 {
			booking = "bookings"
		}
		if out != "" {
			out += " "
		}
		out += fmt.Sprintf("%d current one-off %s using it %s also removed.", u.LiveOverrides, booking, wasWere(u.LiveOverrides))
	}
	return out
}

// deletedVehicleFlash is the on-screen confirmation for the person who just pressed
// delete — the one best placed to fix an emptied day right now. It is built from
// counts rather than the full sentence because the full sentence would have to travel
// through the URL to get here, and free text in the URL is free text in the banner.
// The named detail is on Activity and in the notification.
func deletedVehicleFlash(plate string, days, bookings int) string {
	out := "Deleted " + plate + "."
	switch {
	case days == 1:
		out += " One roster day now has nothing scheduled. Activity shows which day. Until you set it again, the permit will keep its current registration."
	case days > 1:
		out += fmt.Sprintf(" %d roster days now have nothing scheduled. Activity shows which days. Until you set them again, the permit will keep its current registration.", days)
	}
	switch {
	case bookings == 1:
		out += " One current one-off booking using it was also removed."
	case bookings > 1:
		out += fmt.Sprintf(" %d current one-off bookings using it were also removed.", bookings)
	}
	if days == 0 && bookings == 0 {
		out += " It was not on any roster day or booking, so nothing else has changed."
	}
	return out
}

func wasWere(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

// joinWords renders a list the way a person would say it.
func joinWords(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
	}
}
