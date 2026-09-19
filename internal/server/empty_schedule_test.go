package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// "Empty the permit" as a schedule value: a roster day and a booking can each
// say the permit is to have no rego. Both are refused where the council's
// permit cannot be left empty; otherwise they are stored as empty, and the card
// draws the day with the no-rego mark and lists the booking as no rego.
func TestEmptyRosterDayAndBooking(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "empty@example.com"
	const origin = "https://app.example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "EMPTY-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.CreateVehicle(ctx, user, "XYZ789", "Mum", ""); err != nil {
		t.Fatal(err)
	}
	rules := "/permits/" + itoa64(id) + "/rules"
	book := "/permits/" + itoa64(id) + "/override"

	// The council allows an empty permit: the roster day is stored as empty and
	// the card shows it as such, with the option offered and marked selected.
	w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {"empty"}})
	if w.Code != http.StatusOK {
		t.Fatalf("empty Monday = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	rs, _ := r.st.ListRules(ctx, id)
	if len(rs) != 1 || !rs[0].Empty || rs[0].Weekday != time.Monday {
		t.Fatalf("rules = %+v", rs)
	}
	body := w.Body.String()
	for _, want := range []string{`class="chip noreg"`, `vopt vempty sel`, "Leave the permit empty", "Nothing scheduled on Mon"} {
		if !strings.Contains(body, want) {
			t.Fatalf("card after an empty day lacks %q:\n%s", want, excerpt(body))
		}
	}
	// A rego over it replaces the empty day.
	vs, _ := r.st.ListVehiclesFor(ctx, user)
	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"1"}, "vehicle_id": {itoa64(vs[0].ID)}}); w.Code != http.StatusOK {
		t.Fatalf("rego over the empty day = %d", w.Code)
	}
	if rs, _ := r.st.ListRules(ctx, id); len(rs) != 1 || rs[0].Empty || rs[0].VehicleID != vs[0].ID {
		t.Fatalf("rules after the rego = %+v", rs)
	}

	// A booking of no rego, confirmed by the form, stored as empty and listed.
	w = r.s.doHX(http.MethodPost, book, user, origin, url.Values{"vehicle_id": {"empty"}, "ends": {"day"}})
	if w.Code != http.StatusOK {
		t.Fatalf("book no rego = %d: %s", w.Code, excerpt(w.Body.String()))
	}
	ovs, _ := r.st.ListOverrides(ctx, id, time.Now())
	if len(ovs) != 1 || !ovs[0].Empty {
		t.Fatalf("overrides = %+v", ovs)
	}
	if body := w.Body.String(); !strings.Contains(body, `<span class="veh"><span class="noplate">no rego</span></span>`) {
		t.Fatalf("the booking list does not show the no-rego booking:\n%s", excerpt(body))
	}
	if cs, _ := r.st.ListChanges(ctx, user, 5); len(cs) == 0 || changeText(cs[0]) != "added a one-off booking for no rego ("+cs[0].Detail+")" {
		t.Fatalf("change log after the no-rego booking = %+v", cs)
	}

	// A council that cannot leave a permit empty: neither write is accepted,
	// and the card offers neither option.
	r.fake.NoClear = true
	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"2"}, "vehicle_id": {"empty"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty day on a no-clear council = %d, want 422", w.Code)
	}
	if w := r.s.doHX(http.MethodPost, book, user, origin, url.Values{"vehicle_id": {"empty"}, "ends": {"day"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no-rego booking on a no-clear council = %d, want 422", w.Code)
	}
	if body := r.s.doReq("GET", "/schedule", user, "", nil).Body.String(); strings.Contains(body, "vopt vempty") || strings.Contains(body, "segempty") {
		t.Fatalf("a no-clear council still offers the empty options:\n%s", excerpt(body))
	}
}
