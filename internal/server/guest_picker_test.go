package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestQuickPickerManagement drives the Guests tab's picker card through the
// real router: create, the card and its link, edit, a new link, delete. The
// public page it opens is checked as the household would see it — the permit's
// name, every rego in full, and the picker's own prompt.
func TestQuickPickerManagement(t *testing.T) {
	// A linked household with consent recorded, so the Guests tab renders rather
	// than the onboarding page.
	s, _ := newApplyRig(t)
	const owner = "owner@example.com"
	const origin = "http://app.example.com"
	ctx := context.Background()
	if err := s.store.RecordConsent(ctx, owner, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	if err := s.tenant.Link(ctx, owner, "", owner, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
	pid, err := s.store.UpsertPermit(ctx, owner, "90001", "14", "Home permit")
	if err != nil {
		t.Fatal(err)
	}
	nana, err := s.store.CreateVehicle(ctx, owner, "ABC123", "Nana", "")
	if err != nil {
		t.Fatal(err)
	}
	baba, err := s.store.CreateVehicle(ctx, owner, "XYZ789", "Baba", "")
	if err != nil {
		t.Fatal(err)
	}
	rawLink := func(t *testing.T) string {
		t.Helper()
		pg, err := s.store.PickerGrant(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		raw, _, err := s.box.OpenCtx(secretbox.GuestToken(owner), pg.TokenSealed)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// Before: the card offers to create one, and the checklist line is open.
	page := s.doReq("GET", "/guests", owner, "", nil).Body.String()
	if !strings.Contains(page, "Your own quick picker") || !strings.Contains(page, "Create the picker") || strings.Contains(page, "Your quick picker") {
		t.Fatalf("guests page before creating:\n%s", page)
	}
	if v := s.checklistFor(ctx, owner, owner, true, "guests"); v == nil || v.Items[3].Done {
		t.Fatalf("checklist before creating = %+v", v)
	}

	// No regos ticked: refused, nothing minted.
	if w := s.doReq("POST", "/guests/picker", owner, origin, url.Values{"permit_id": {itoa64(pid)}}); w.Code != http.StatusBadRequest && w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("create with no regos = %d %s", w.Code, w.Body.String())
	}
	if _, err := s.store.PickerGrant(ctx, owner); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused create minted a picker: %v", err)
	}
	w := s.doReq("POST", "/guests/picker", owner, origin, url.Values{
		"permit_id": {itoa64(pid)}, "vehicle_id": {itoa64(nana), itoa64(baba)}, "allow_overnight": {"1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?picker=made#picker" {
		t.Fatalf("create = %d %q", w.Code, w.Header().Get("Location"))
	}
	// A second submit finds the first rather than minting a second link.
	if w := s.doReq("POST", "/guests/picker", owner, origin, url.Values{"permit_id": {itoa64(pid)}, "vehicle_id": {itoa64(nana)}}); w.Header().Get("Location") != "/guests?picker=made#picker" {
		t.Fatalf("second create = %d %q", w.Code, w.Header().Get("Location"))
	}
	raw := rawLink(t)
	page = s.doReq("GET", "/guests?picker=made", owner, "", nil).Body.String()
	for _, want := range []string{"Your quick picker", "It offers Baba and Nana, with the overnight option on.", "/g/" + raw, "data:image/png;base64,", "Your quick picker is ready", "New link", "/guests/picker/edit"} {
		if !strings.Contains(page, want) {
			t.Fatalf("guests page after creating lacks %q:\n%s", want, page)
		}
	}
	ms, err := s.store.Milestones(ctx, owner)
	if err != nil || !ms[store.MilestonePicker] {
		t.Fatalf("milestone after creating = %v %v", ms, err)
	}
	if v := s.checklistFor(ctx, owner, owner, true, "guests"); v == nil || !v.Items[3].Done {
		t.Fatalf("checklist after creating = %+v", v)
	}

	// The picker page: the permit's name headlines, regos are in full, and the
	// prompt is the household's, not a visitor's.
	menu := s.getGuest("/g/" + raw)
	if menu.Code != 200 {
		t.Fatalf("picker page = %d", menu.Code)
	}
	body := menu.Body.String()
	for _, want := range []string{"<h1>Home permit</h1>", "Tap a rego to put it on the permit", "ABC123", "XYZ789", "Open p.stonn", "Overnight<br>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("picker page lacks %q:\n%s", want, body)
		}
	}
	for _, leak := range []string{"visitor permit", "The account holder is told", "bookmark this page", "Share p.stonn"} {
		if strings.Contains(body, leak) {
			t.Fatalf("picker page carries visitor copy %q", leak)
		}
	}

	// Edit: the form is pre-filled; saving with one rego narrows the picker.
	page = s.doReq("GET", "/guests/picker/edit", owner, "", nil).Body.String()
	if !strings.Contains(page, "Save changes") || !strings.Contains(page, `value="`+itoa64(baba)+`" checked`) {
		t.Fatalf("edit page:\n%s", page)
	}
	w = s.doReq("POST", "/guests/picker/update", owner, origin, url.Values{"vehicle_id": {itoa64(baba)}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?picker=updated#picker" {
		t.Fatalf("update = %d %q", w.Code, w.Header().Get("Location"))
	}
	if pg, _ := s.store.PickerGrant(ctx, owner); pg.AllowOvernight || len(pg.Vehicles) != 1 || pg.Vehicles[0].ID != baba {
		t.Fatalf("after update = %+v", pg)
	}
	if page = s.doReq("GET", "/guests", owner, "", nil).Body.String(); !strings.Contains(page, "It offers Baba, with the overnight option off.") {
		t.Fatalf("summary after update:\n%s", page)
	}

	// New link: the old one stops resolving; the new one works.
	w = s.doReq("POST", "/guests/picker/rotate", owner, origin, url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?picker=newlink#picker" {
		t.Fatalf("rotate = %d %q", w.Code, w.Header().Get("Location"))
	}
	if old := s.getGuest("/g/" + raw); old.Code == 200 && strings.Contains(old.Body.String(), "Tap a rego") {
		t.Fatal("the old picker link still opens the picker after a new link was made")
	}
	raw2 := rawLink(t)
	if raw2 == raw {
		t.Fatal("rotate kept the same link")
	}
	if fresh := s.getGuest("/g/" + raw2); fresh.Code != 200 || !strings.Contains(fresh.Body.String(), "Tap a rego to put it on the permit") {
		t.Fatalf("new picker link = %d", fresh.Code)
	}

	// Delete: gone from the store and the page, and the link is dead.
	w = s.doReq("POST", "/guests/picker/delete", owner, origin, url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?picker=deleted#picker" {
		t.Fatalf("delete = %d %q", w.Code, w.Header().Get("Location"))
	}
	if _, err := s.store.PickerGrant(ctx, owner); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if gone := s.getGuest("/g/" + raw2); gone.Code == 200 && strings.Contains(gone.Body.String(), "Tap a rego") {
		t.Fatal("a deleted picker's link still opens the picker")
	}
	// Every step is in the household's change log.
	changes, err := s.store.ListChanges(ctx, owner, 20)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range changes {
		seen[c.Action] = true
	}
	for _, a := range []string{store.ActionPickerCreate, store.ActionPickerUpdate, store.ActionPickerRotate, store.ActionPickerDelete} {
		if !seen[a] {
			t.Fatalf("change log lacks %s: %+v", a, changes)
		}
	}
	// With htmx, every action answers with just the card, open, carrying its
	// outcome, so the tab swaps the card in place rather than reloading.
	hx := func(method, target string, form url.Values) *httptest.ResponseRecorder {
		var body io.Reader = strings.NewReader("")
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, target, body)
		req.Host = "app.example.com"
		req.RemoteAddr = "10.0.0.2:41000"
		req.Header.Set("Remote-Email", owner)
		req.Header.Set("Remote-Groups", "user")
		req.Header.Set("HX-Request", "true")
		req.Header.Set("Origin", origin)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	w = hx("POST", "/guests/picker", url.Values{"permit_id": {itoa64(pid)}, "vehicle_id": {itoa64(nana)}})
	frag := w.Body.String()
	if w.Code != 200 || !strings.HasPrefix(strings.TrimSpace(frag), `<section class="card fold" id="picker"`) || strings.Contains(frag, "<html") {
		t.Fatalf("htmx create = %d, not the card fragment:\n%s", w.Code, frag)
	}
	for _, want := range []string{"x-data=\"{open: true}\"", "Your quick picker is ready", "It offers Nana, with the overnight option off.", "New link"} {
		if !strings.Contains(frag, want) {
			t.Fatalf("htmx create reply lacks %q:\n%s", want, frag)
		}
	}
	if frag = hx("GET", "/guests/picker/edit", nil).Body.String(); !strings.Contains(frag, "Save changes") || strings.Contains(frag, "<html") {
		t.Fatalf("htmx edit = not the card's form:\n%s", frag)
	}
	if frag = hx("GET", "/guests/picker", nil).Body.String(); strings.Contains(frag, "Save changes") || !strings.Contains(frag, "New link") {
		t.Fatalf("htmx cancel = not the card at rest:\n%s", frag)
	}
	if frag = hx("POST", "/guests/picker/delete", url.Values{}).Body.String(); !strings.Contains(frag, "Quick picker deleted") || !strings.Contains(frag, "Create the picker") {
		t.Fatalf("htmx delete = not the create card with its notice:\n%s", frag)
	}
	if w := hx("POST", "/guests/picker", url.Values{"permit_id": {itoa64(pid)}}); w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), "<") {
		t.Fatalf("htmx validation = %d %q, want a bare 422 for the toast", w.Code, w.Body.String())
	}

	// The picker's gates: anonymous and cross-site posts never reach it.
	if w := s.doReq("POST", "/guests/picker", "", origin, url.Values{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous create = %d", w.Code)
	}
	if w := s.doReq("POST", "/guests/picker/rotate", owner, "", url.Values{}); w.Code != http.StatusForbidden {
		t.Fatalf("rotate without Origin = %d", w.Code)
	}
}

// TestQuickPickerActivation: a tap on the picker books the household's own rego
// exactly as a guest link would, but the booking is attributed to the picker
// and the page shows the plate in full rather than masked.
func TestQuickPickerActivation(t *testing.T) {
	s, rp := newApplyRig(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "primary@example.com"
	if err := s.tenant.Link(ctx, owner, "", owner, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
	pid, err := s.store.UpsertPermit(ctx, owner, "90001", "14", "Home permit")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetPermitActive(ctx, pid, "SBX1AB"); err != nil {
		t.Fatal(err)
	}
	baba, err := s.store.CreateVehicle(ctx, owner, "XYZ789", "Baba", "")
	if err != nil {
		t.Fatal(err)
	}
	const raw = "picker-token-for-activation-test-01"
	if _, err := s.store.CreatePickerGrant(ctx, owner, owner, pid, true, []int64{baba}, hashGuestToken(raw), "sealed"); err != nil {
		t.Fatal(err)
	}
	// The pre-existing plate is someone else's: the household's page still shows
	// it in full, since it is their permit.
	if body := s.getGuest("/g/" + raw).Body.String(); !strings.Contains(body, `<span class="plate">SBX1AB</span>`) || strings.Contains(body, "masked") {
		t.Fatalf("picker page masks the household's own permit:\n%s", body)
	}

	w := s.postGuest("/g/"+raw, "203.0.113.9", "", url.Values{"vehicle_id": {itoa64(baba)}})
	if w.Code != 200 {
		t.Fatalf("tap = %d %s", w.Code, w.Body.String())
	}
	if got := rp.last(t); got.Registration != "XYZ789" {
		t.Fatalf("provider was handed %+v", got)
	}
	overrides, err := s.store.ListOverrides(ctx, pid, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range overrides {
		// A saved rego's booking references the vehicle, not a typed plate.
		if o.VehicleID == baba {
			found = true
			if o.CreatedBy != "the quick picker" {
				t.Fatalf("booking attributed to %q, want the quick picker", o.CreatedBy)
			}
		}
	}
	if !found {
		t.Fatalf("no booking for the tapped rego: %+v", overrides)
	}
	// The put-back offer names the displaced plate in full, and taking it
	// restores it.
	if body := w.Body.String(); !strings.Contains(body, "Put <span class=\"plate\" style=\"margin:0 4px\">SBX1AB</span> back") {
		t.Fatalf("no full-plate put-back on the picker page:\n%s", body)
	}
	if w := s.postGuest("/g/"+raw+"/revert", "203.0.113.9", "", url.Values{}); w.Code != 200 {
		t.Fatalf("put back = %d", w.Code)
	}
	if got := rp.last(t); got.Registration != "SBX1AB" {
		t.Fatalf("put back handed the provider %+v", got)
	}
}
