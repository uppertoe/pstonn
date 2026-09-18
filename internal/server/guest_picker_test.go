package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/notify"
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
		"permit_id": {itoa64(pid)}, "all_vehicles": {"1"}, "allow_overnight": {"1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?picker=made#picker" {
		t.Fatalf("create = %d %q", w.Code, w.Header().Get("Location"))
	}
	// A second submit finds the first rather than minting a second link.
	if w := s.doReq("POST", "/guests/picker", owner, origin, url.Values{"permit_id": {itoa64(pid)}, "vehicle_id": {itoa64(nana)}}); w.Header().Get("Location") != "/guests?picker=made#picker" {
		t.Fatalf("second create = %d %q", w.Code, w.Header().Get("Location"))
	}
	raw := rawLink(t)
	page = s.doReq("GET", "/guests?picker=made", owner, "", nil).Body.String()
	for _, want := range []string{"Your quick picker", "It offers every rego, including any you add later, with the overnight option on.", "/g/" + raw, "data:image/png;base64,", "Your quick picker is ready", "New link", "/guests/picker/edit"} {
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
	// A rego added after the picker was made is on it without an edit.
	if _, err := s.store.CreateVehicle(ctx, owner, "NEW111", "Later", ""); err != nil {
		t.Fatal(err)
	}
	// With mail configured, the page carries the confirm dialog's audience line
	// (who on the account is emailed) and each tile the rego it stands for.
	s.notify = notify.New(s.store, &mailer.Mailer{SendHook: func(string, string, string, mailer.Options) error { return nil }},
		"", "", "https://app.example.com", "", "", time.UTC, nil, nil)
	// Quiet hours off, so the line reads the same whatever the clock says.
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, EmailEnabled: true}); err != nil {
		t.Fatal(err)
	}
	menu = s.getGuest("/g/" + raw)
	body := menu.Body.String()
	for _, want := range []string{"<h1>Home permit</h1>", "Tap a rego to put it on the permit", "ABC123", "XYZ789", "NEW111", "Open p.stonn", "Overnight<br>",
		`data-plate="XYZ789" data-label="Baba" data-color="`, `data-audience="The following people will be notified of the change:` + "\n" + owner + ` — by email"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("picker page lacks %q:\n%s", want, body)
		}
	}
	for _, leak := range []string{"visitor permit", "The account holder is told", "bookmark this page", "Share p.stonn"} {
		if strings.Contains(body, leak) {
			t.Fatalf("picker page carries visitor copy %q", leak)
		}
	}
	// A rego with a driver who is told carries that driver on ITS tile only,
	// the way the scheduler emails them; a suppressed address is left off.
	if err := s.store.SetVehicleEmail(ctx, owner, nana, "nanny@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetVehicleEmail(ctx, owner, baba, "gone@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SuppressAddress(ctx, "gone@example.com", store.SuppressBounce, "test"); err != nil {
		t.Fatal(err)
	}
	body = s.getGuest("/g/" + raw).Body.String()
	members := `data-audience="The following people will be notified of the change:` + "\n" + owner + ` — by email`
	if want := regexp.MustCompile(`data-label="Nana" data-color="#[0-9a-f]{6}" ` + regexp.QuoteMeta(members+"\n"+`nanny@example.com — by email, as the driver of ABC123"`)); !want.MatchString(body) {
		t.Fatalf("Nana's tile lacks its driver %q:\n%s", want, body)
	}
	if want := regexp.MustCompile(`data-label="Baba" data-color="#[0-9a-f]{6}" ` + regexp.QuoteMeta(members+`"`)); !want.MatchString(body) {
		t.Fatalf("Baba's tile should list the members only %q:\n%s", want, body)
	}

	// Edit: the form is pre-filled with every-rego on; saving with one rego
	// ticked and every-rego off narrows the picker.
	page = s.doReq("GET", "/guests/picker/edit", owner, "", nil).Body.String()
	if !strings.Contains(page, "Save changes") || !strings.Contains(page, `x-data="{all: true}"`) {
		t.Fatalf("edit page:\n%s", page)
	}
	w = s.doReq("POST", "/guests/picker/update", owner, origin, url.Values{"vehicle_id": {itoa64(baba)}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?picker=updated#picker" {
		t.Fatalf("update = %d %q", w.Code, w.Header().Get("Location"))
	}
	if pg, _ := s.store.PickerGrant(ctx, owner); pg.AllowOvernight || pg.AllVehicles || len(pg.Vehicles) != 1 || pg.Vehicles[0].ID != baba {
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
	_ = nana
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
	if _, err := s.store.CreatePickerGrant(ctx, owner, owner, pid, true, false, []int64{baba}, hashGuestToken(raw), "sealed"); err != nil {
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

	// Taking the rego off: offered on the schedule's own terms. With the roster
	// covering today the offer is withheld and a hand-built request is refused
	// before anything changes; with nothing scheduled, the picker's own booking
	// is ended and the council's record cleared.
	w = s.postGuest("/g/"+raw, "203.0.113.9", "", url.Values{"vehicle_id": {itoa64(baba)}})
	if !strings.Contains(w.Body.String(), "off the permit</button>") {
		t.Fatalf("no take-off offer after the tap:\n%s", w.Body.String())
	}
	// Today in the permit's own zone: the rig's council is in Melbourne while
	// its display default is UTC.
	permit, _ := s.store.GetPermit(ctx, pid)
	today := time.Now().In(s.locForPermit(ctx, permit)).Weekday()
	if err := s.store.SetRule(ctx, owner, pid, 0, today, baba); err != nil {
		t.Fatal(err)
	}
	if body := s.getGuest("/g/" + raw).Body.String(); strings.Contains(body, "off the permit</button>") {
		t.Fatalf("take-off offered while the roster covers today:\n%s", body)
	}
	w = s.postGuest("/g/"+raw+"/clear", "203.0.113.9", "", url.Values{})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "The roster has a rego scheduled for now") {
		t.Fatalf("clear under a roster day = %d:\n%s", w.Code, w.Body.String())
	}
	if p, _ := s.store.GetPermit(ctx, pid); p.ActiveRegistration != "XYZ789" {
		t.Fatalf("refused clear changed the permit to %q", p.ActiveRegistration)
	}
	if err := s.store.ClearRule(ctx, owner, pid, 0, today); err != nil {
		t.Fatal(err)
	}
	w = s.postGuest("/g/"+raw+"/clear", "203.0.113.9", "", url.Values{})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "XYZ789 is off the permit.") {
		t.Fatalf("clear = %d:\n%s", w.Code, w.Body.String())
	}
	if p, _ := s.store.GetPermit(ctx, pid); p.ActiveRegistration != "" {
		t.Fatalf("permit still shows %q after the clear", p.ActiveRegistration)
	}
	if cur, ok := rp.Current("90001"); !ok || cur != "" {
		t.Fatalf("council still holds %q", cur)
	}
	if ovs, _ := s.store.ListOverrides(ctx, pid, time.Now()); len(ovs) != 0 {
		t.Fatalf("the picker's booking survived the clear: %+v", ovs)
	}
	if body := w.Body.String(); strings.Contains(body, "off the permit</button>") || strings.Contains(body, "back on the permit") {
		t.Fatalf("an empty permit still offers take-off or put-back:\n%s", body)
	}
	// A visitor's pass may never leave the permit empty.
	const visitor = "visitor-token-for-clear-test-000001"
	if _, err := s.store.CreateGuestGrant(ctx, owner, owner, pid, "Nanny", false, []int64{baba}, []store.GuestRecipient{{Email: "v@example.com", TokenHash: hashGuestToken(visitor)}}); err != nil {
		t.Fatal(err)
	}
	if w := s.postGuest("/g/"+visitor+"/clear", "203.0.113.9", "", url.Values{}); strings.Contains(w.Body.String(), "off the permit") {
		t.Fatalf("a visitor pass could clear the permit:\n%s", w.Body.String())
	}
}

// The confirm dialog on the quick picker lists who is told, from the same
// per-member decision the notice makes: by email, by push, or both, held until
// quiet hours end where they are; the rego's own driver comes last when the
// scheduler would email them; nobody at all is said plainly.
func TestAudienceLines(t *testing.T) {
	loc, _ := time.LoadLocation("Australia/Melbourne")
	six := time.Date(2026, 9, 18, 6, 0, 0, 0, loc)
	const head = "The following people will be notified of the change:"
	driver := audienceDriver{Email: "nanny@example.com", Reg: "NAN123"}
	cases := []struct {
		name   string
		in     []notify.Recipient
		driver audienceDriver
		want   []string
	}{
		{"nobody", nil, audienceDriver{}, []string{"No one is notified of this change, the way notifications are set on the account."}},
		{"one email", []notify.Recipient{{Email: "jo@example.com", ByEmail: true}}, audienceDriver{}, []string{head, "jo@example.com — by email"}},
		{"email and push", []notify.Recipient{{Email: "sam@example.com", ByEmail: true, ByPush: true}}, audienceDriver{}, []string{head, "sam@example.com — by email and push notification"}},
		{"quiet hours", []notify.Recipient{{Email: "sam@example.com", ByEmail: true, NotBefore: six}}, audienceDriver{},
			[]string{head, "sam@example.com — by email at 6:00am, after their quiet hours"}},
		{"push only", []notify.Recipient{{Email: "jo@example.com", ByEmail: true}, {Email: "alex@example.com", ByPush: true}}, audienceDriver{},
			[]string{head, "jo@example.com — by email", "alex@example.com — by push notification"}},
		{"driver", []notify.Recipient{{Email: "jo@example.com", ByEmail: true}}, driver,
			[]string{head, "jo@example.com — by email", "nanny@example.com — by email, as the driver of NAN123"}},
		{"driver alone", nil, driver, []string{head, "nanny@example.com — by email, as the driver of NAN123"}},
		{"driver who is a member is listed once", []notify.Recipient{{Email: "Nanny@example.com", ByPush: true}}, driver,
			[]string{head, "Nanny@example.com — by push notification"}},
	}
	for _, c := range cases {
		got := audienceLines(c.in, loc, c.driver)
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
