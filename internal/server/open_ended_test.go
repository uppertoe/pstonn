package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Every booking has an end. An open-ended one outranked the household's own
// roster until someone cancelled it, and switched a whole roster off for weeks;
// the form no longer offers it, and a page cached from before is told why
// rather than quietly given a different booking.
func TestOpenEndedBookingRefused(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "open@example.com"
	const origin = "https://app.example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "OPEN-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	vid, err := r.st.CreateVehicle(ctx, user, "XYZ789", "Mum", "")
	if err != nil {
		t.Fatal(err)
	}
	book := "/permits/" + itoa64(id) + "/override"
	w := r.s.doHX(http.MethodPost, book, user, origin, url.Values{"vehicle_id": {itoa64(vid)}, "ends": {"open"}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("open-ended booking = %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "without an end") {
		t.Fatalf("refusal does not say why: %s", excerpt(w.Body.String()))
	}
	if ovs, _ := r.st.ListOverrides(ctx, id, time.Now()); len(ovs) != 0 {
		t.Fatalf("an open-ended booking was stored: %+v", ovs)
	}
	if body := r.s.doReq("GET", "/schedule", user, "", nil).Body.String(); strings.Contains(body, "ends='open'") {
		t.Fatal("the booking form still offers an open-ended booking")
	}
}
