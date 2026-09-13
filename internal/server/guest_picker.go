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
//
// The card on the Guests tab is a fragment. Each action here answers an htmx
// request by re-rendering the card in place, open, with the outcome as its
// notice — the same shape as the schedule's permit card — so nothing else on
// the tab moves and the page does not scroll. A request without htmx (scripting
// off) falls back to the post-redirect-get the rest of the tab uses.

// pickerCard builds the card view: nil when the tab cannot offer one (no live
// permit, or no regos yet and no picker to show). The QR and link are rebuilt
// from the sealed token; one that cannot be opened is logged and the card
// offers a new link instead of failing the whole tab.
func (s *Server) pickerCard(ctx context.Context, owner string, permits []permitOpt, vehicles []vehicleView, edit bool) (*pickerCardView, error) {
	if len(permits) == 0 {
		return nil, nil
	}
	card := &pickerCardView{Vehicles: vehicles, PermitOpts: permits}
	pg, err := s.store.PickerGrant(ctx, owner)
	if errors.Is(err, store.ErrNotFound) {
		if len(vehicles) == 0 {
			return nil, nil
		}
		return card, nil
	}
	if err != nil {
		return nil, err
	}
	cars, _, _, _ := vehicleViews(pg.Vehicles)
	names := make([]string, 0, len(cars))
	for _, c := range cars {
		names = append(names, c.Label)
	}
	v := &pickerView{
		GrantID: pg.GrantID, PermitLabel: s.permitLabelByID(ctx, owner, pg.PermitID),
		Cars: cars, Names: andList(names), AllowOvernight: pg.AllowOvernight,
	}
	if raw, _, err := s.box.OpenCtx(secretbox.GuestToken(owner), pg.TokenSealed); err == nil {
		v.URL = s.guestLink(raw)
		if img, err := qrDataURI(v.URL); err == nil {
			v.ImageURI = template.URL(img)
		}
	} else {
		alog.Warnf("quick picker: could not open the sealed token for %s: %v", redact.Email(owner), err)
	}
	card.Picker = v
	if edit {
		sel := map[int64]bool{}
		for _, c := range cars {
			sel[c.ID] = true
		}
		card.Edit = &pickerEditView{AllowOvernight: pg.AllowOvernight, Selected: sel}
		card.Open = true
	}
	return card, nil
}

// livePermitOpts is the permit choice the card's create form offers: the
// account's permits that are still active, labelled as the Guests tab does.
func (s *Server) livePermitOpts(ctx context.Context, owner string) ([]permitOpt, error) {
	permits, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		return nil, err
	}
	var opts []permitOpt
	now := time.Now()
	for _, p := range permits {
		if p.Inactive(now, s.locFor(ctx, owner)) {
			continue
		}
		opts = append(opts, permitOpt{ID: p.ID, Label: permitLabel(p)})
	}
	return opts, nil
}

// respondPickerCard is every picker action's reply. An htmx request gets the
// card fragment re-rendered, open, carrying notice; anything else is sent back
// to the Guests tab with the flag that produces the same message there.
func (s *Server) respondPickerCard(w http.ResponseWriter, r *http.Request, owner string, edit bool, notice, flag string) {
	if r.Header.Get("HX-Request") == "" {
		if flag == "" {
			http.Redirect(w, r, "/guests#picker", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/guests?picker="+flag+"#picker", http.StatusSeeOther)
		return
	}
	ctx := r.Context()
	permits, err := s.livePermitOpts(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	vs, err := s.store.ListVehiclesFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	vehicles, _, _, _ := vehicleViews(vs)
	card, err := s.pickerCard(ctx, owner, permits, vehicles, edit)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if card == nil {
		// Nothing left to offer (the last rego was removed): an empty fragment
		// takes the card off the tab, as a full load would.
		w.WriteHeader(http.StatusOK)
		return
	}
	card.Open = true
	card.Notice = notice
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.ExecuteTemplate(w, "picker-card", card); err != nil {
		alog.Infof("render picker-card: %v", err)
	}
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

// showPicker returns the card as it stands: the reply to Cancel on the edit
// form. Without htmx it is the Guests tab, scrolled to the card.
func (s *Server) showPicker(w http.ResponseWriter, r *http.Request) {
	_, owner, _ := s.resolveAccount(r.Context())
	s.respondPickerCard(w, r, owner, false, "", "")
}

// editPicker renders the card open on its form, pre-filled with the current
// regos and overnight option: the fragment for htmx, the whole tab otherwise.
func (s *Server) editPicker(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") != "" {
		_, owner, _ := s.resolveAccount(r.Context())
		s.respondPickerCard(w, r, owner, true, "", "")
		return
	}
	base, ok := s.appShell(w, r, "guests")
	if !ok {
		return
	}
	if err := s.loadGuests(r.Context(), &base, 0); err != nil {
		s.serverError(w, err)
		return
	}
	card := base.GuestMgmt.PickerCard
	if card == nil || card.Picker == nil {
		http.Redirect(w, r, "/guests", http.StatusSeeOther)
		return
	}
	sel := map[int64]bool{}
	for _, c := range card.Picker.Cars {
		sel[c.ID] = true
	}
	card.Edit = &pickerEditView{AllowOvernight: card.Picker.AllowOvernight, Selected: sel}
	card.Open = true
	s.render(w, base)
}

// createPicker mints the account's quick picker: a grant over the ticked regos
// and one sealed token. A second submission finds the first and shows it
// rather than minting another link.
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
	const made = "Your quick picker is ready. Open it on your phone and add it to the home screen."
	switch _, err := s.store.CreatePickerGrant(r.Context(), owner, user, permitID, allowOvernight, vehicleIDs, hash, sealed); {
	case errors.Is(err, store.ErrDuplicate):
		s.respondPickerCard(w, r, owner, false, made, "made")
		return
	case errors.Is(err, store.ErrNotFound):
		s.message(w, http.StatusForbidden, "That permit or rego isn't one you manage.")
		return
	case err != nil:
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionPickerCreate, s.permitLabelByID(r.Context(), owner, permitID), "")
	s.respondPickerCard(w, r, owner, false, made, "made")
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
		s.respondPickerCard(w, r, owner, false, "", "")
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
	s.respondPickerCard(w, r, owner, false, "Quick picker updated.", "updated")
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
		s.respondPickerCard(w, r, owner, false, "", "")
		return
	case err != nil:
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionPickerRotate, "", "")
	s.respondPickerCard(w, r, owner, false, "The quick picker has a new link. The one on your phone has stopped working, so open this one and save it again.", "newlink")
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
		s.respondPickerCard(w, r, owner, false, "", "")
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
	s.respondPickerCard(w, r, owner, false, "Quick picker deleted. Its link has stopped working.", "deleted")
}
