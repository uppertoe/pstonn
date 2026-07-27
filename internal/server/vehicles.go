package server

import (
	"errors"
	"net/http"

	"github.com/uppertoe/pstonn/internal/store"
)

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
	s.render(w, base)
}

func (s *Server) addVehicle(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	reg := normalizeReg(r.FormValue("registration"))
	label := cleanLabel(r.FormValue("label"))
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
	http.Redirect(w, r, "/vehicles", http.StatusSeeOther)
}

func (s *Server) deleteVehicle(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	if err := s.store.DeleteVehicle(r.Context(), owner, pathInt(r, "id")); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/vehicles", http.StatusSeeOther)
}
