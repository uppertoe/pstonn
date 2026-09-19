package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// "Clear the permit" as a roster value: a day can say the permit is to have
// no rego. It is refused where the council's permit cannot be left empty;
// otherwise the day is stored as empty and the card draws it with the no-rego
// mark. (The model and store take an empty booking too, for the loop's sake,
// but the booking form does not offer one.)
func TestEmptyRosterDay(t *testing.T) {
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
	for _, want := range []string{`class="chip noreg"`, `vopt vclear sel`, `<span class="lab">Clear</span><span class="hint">the rego is removed</span>`, `<span class="lab">None</span><span class="hint">no change</span>`} {
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
	// A "vehicle_id=empty" booking is not a form the app offers: it is read as
	// no rego chosen and refused, never stored as a clearing booking.
	book := "/permits/" + itoa64(id) + "/override"
	if w := r.s.doHX(http.MethodPost, book, user, origin, url.Values{"vehicle_id": {"empty"}, "ends": {"day"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty booking = %d, want 422", w.Code)
	}
	if ovs, _ := r.st.ListOverrides(ctx, id, time.Now()); len(ovs) != 0 {
		t.Fatalf("overrides = %+v", ovs)
	}

	// A council that cannot leave a permit empty: the write is refused, and
	// the cell menu does not offer the option.
	r.fake.NoClear = true
	if w := r.s.doHX(http.MethodPost, rules, user, origin, url.Values{"weekday": {"2"}, "vehicle_id": {"empty"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty day on a no-clear council = %d, want 422", w.Code)
	}
	if body := r.s.doReq("GET", "/schedule", user, "", nil).Body.String(); strings.Contains(body, "vopt vclear") {
		t.Fatalf("a no-clear council still offers the clear option:\n%s", excerpt(body))
	}
}
