package server

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// The household's own quick picker: a guest grant the account keeps for itself,
// so a phone's home screen can carry one button per rego with no sign-in. It is
// created, changed, re-linked and deleted from the Guests tab; the page it opens
// is the public activation page with Grant.Picker set (see buildGuestView).

// loadPicker fills the Guests tab's picker card: the grant, its regos, and the
// QR and link rebuilt from the sealed token. A token that cannot be opened is
// logged and the card falls back to offering a new link — never a 500 on the
// whole tab over one sealed value.
func (s *Server) loadPicker(ctx context.Context, base *dashboardData) error {
	pg, err := s.store.PickerGrant(ctx, base.Owner)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	cars, _, _, _ := vehicleViews(pg.Vehicles)
	names := make([]string, 0, len(cars))
	for _, c := range cars {
		names = append(names, c.Label)
	}
	v := &pickerView{
		GrantID: pg.GrantID, PermitLabel: s.permitLabelByID(ctx, base.Owner, pg.PermitID),
		Cars: cars, Names: andList(names), AllowOvernight: pg.AllowOvernight,
	}
	if raw, _, err := s.box.OpenCtx(secretbox.GuestToken(base.Owner), pg.TokenSealed); err == nil {
		v.URL = s.guestLink(raw)
		if img, err := qrDataURI(v.URL); err == nil {
			v.ImageURI = template.URL(img)
		}
	} else {
		alog.Warnf("quick picker: could not open the sealed token for %s: %v", redact.Email(base.Owner), err)
	}
	base.GuestMgmt.Picker = v
	return nil
}

// andList joins names the way a sentence does: "Nana", "Nana and Baba",
// "Nana, Baba and X-Trail".
func andList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// pickerForm reads the regos and overnight option common to create and update.
func pickerForm(r *http.Request) (vehicleIDs []int64, allowOvernight bool) {
	for _, v := range r.Form["vehicle_id"] {
		if id := atoi64(v); id > 0 {
			vehicleIDs = append(vehicleIDs, id)
		}
	}
	return vehicleIDs, r.FormValue("allow_overnight") != ""
}

// editPicker renders the Guests tab with the picker card open on its form,
// pre-filled with the current regos and overnight option.
func (s *Server) editPicker(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	if base.GuestMgmt.Picker == nil {
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	sel := map[int64]bool{}
	for _, c := range base.GuestMgmt.Picker.Cars {
		sel[c.ID] = true
	}
	base.GuestMgmt.PickerEdit = &pickerEditView{AllowOvernight: base.GuestMgmt.Picker.AllowOvernight, Selected: sel}
	base.GuestMgmt.PickerOpen = true
	s.render(w, base)
}

// createPicker mints the account's quick picker: a grant over the ticked regos
// and one sealed token, then lands back on the Guests tab with the card open on
// its QR. A second submission finds the first and shows it rather than minting
// another link.
func (s *Server) createPicker(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	permitID := atoi64(r.FormValue("permit_id"))
	vehicleIDs, allowOvernight := pickerForm(r)
	if len(vehicleIDs) == 0 {
		s.formError(w, r, "Tick at least one rego for the picker to offer.")
		return
	}
	// Refuse a dead permit before minting anything, failing closed on a store
	// error, as every other link-minting surface does.
	switch permit, perr := s.store.GetPermit(r.Context(), permitID); {
	case errors.Is(perr, store.ErrNotFound):
	case perr != nil:
		s.serverError(w, perr)
		return
	case permit.Owner == owner && permit.Inactive(time.Now(), s.locFor(r.Context(), owner)):
		s.message(w, http.StatusConflict, permitInactiveNoNewLinks)
		return
	}
	raw, hash := newGuestToken()
	sealed, err := s.box.SealCtx(secretbox.GuestToken(owner), raw)
	if err != nil {
		s.serverError(w, err)
		return
	}
	switch _, err := s.store.CreatePickerGrant(r.Context(), owner, user, permitID, allowOvernight, vehicleIDs, hash, sealed); {
	case errors.Is(err, store.ErrDuplicate):
		http.Redirect(w, r, "/guests?picker=made#picker", http.StatusSeeOther)
		return
	case errors.Is(err, store.ErrNotFound):
		s.message(w, http.StatusForbidden, "That permit or rego isn't one you manage.")
		return
	case err != nil:
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionPickerCreate, s.permitLabelByID(r.Context(), owner, permitID), "")
	http.Redirect(w, r, "/guests?picker=made#picker", http.StatusSeeOther)
}

// updatePicker changes which regos the picker offers and whether it has the
// overnight option. Unticking a rego that is on the permit through the picker
// takes it off now, as editing a guest pass does.
func (s *Server) updatePicker(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "Could not read the form. Please try again.")
		return
	}
	vehicleIDs, allowOvernight := pickerForm(r)
	if len(vehicleIDs) == 0 {
		s.formError(w, r, "Tick at least one rego for the picker to offer.")
		return
	}
	pg, err := s.store.PickerGrant(r.Context(), owner)
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	swept, err := s.store.UpdateGuestGrant(r.Context(), owner, pg.GrantID, "Quick picker", allowOvernight, vehicleIDs)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.message(w, http.StatusForbidden, "That rego isn't one you manage.")
			return
		}
		s.serverError(w, err)
		return
	}
	if swept > 0 {
		s.kickScheduler()
	}
	s.logChange(r.Context(), owner, user, store.ActionPickerUpdate, "", "")
	http.Redirect(w, r, "/guests?picker=updated#picker", http.StatusSeeOther)
}

// rotatePicker gives the picker a fresh link, for a lost or replaced phone. The
// old link stops working; a booking it already made runs to its end.
func (s *Server) rotatePicker(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	raw, hash := newGuestToken()
	sealed, err := s.box.SealCtx(secretbox.GuestToken(owner), raw)
	if err != nil {
		s.serverError(w, err)
		return
	}
	switch err := s.store.RotatePickerToken(r.Context(), owner, hash, sealed); {
	case errors.Is(err, store.ErrNotFound):
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	case err != nil:
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionPickerRotate, "", "")
	http.Redirect(w, r, "/guests?picker=newlink#picker", http.StatusSeeOther)
}

// deletePicker removes the picker. Like deleting a guest pass, it takes off any
// rego the picker put on the permit: the confirm says so, and the same sweep
// keeps the link's authority and the permit's state in step.
func (s *Server) deletePicker(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	pg, err := s.store.PickerGrant(r.Context(), owner)
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Claim the permit's applies first, as deleteGuestGrant does, so an in-flight
	// tap cannot land after its link was withdrawn.
	releaseClaims := s.claimPermitApplies(r.Context(), []int64{pg.PermitID})
	err = s.store.DeleteGuestGrant(r.Context(), owner, pg.GrantID)
	releaseClaims()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, err)
		return
	}
	if err == nil {
		s.logChange(r.Context(), owner, user, store.ActionPickerDelete, "", "")
		s.kickScheduler()
	}
	http.Redirect(w, r, "/guests?picker=deleted", http.StatusSeeOther)
}
