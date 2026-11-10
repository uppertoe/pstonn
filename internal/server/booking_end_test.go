package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// One household was refused six times choosing "At a set time" for the end
// (2026-11-08/10): the form closed on each refusal and took the date boxes with
// it. A time with no date now means that time on the start day; with neither,
// the refusal still says what is missing, and the form has a slot to say it in.
func TestBookingEndAtASetTime(t *testing.T) {
	r := newTenantRig(t)
	ctx := context.Background()
	const user = "ends@example.com"
	const origin = "https://app.example.com"
	r.consent(t, user)
	id, err := r.st.UpsertPermit(ctx, user, "ENDS-1", "1", "Front")
	if err != nil {
		t.Fatal(err)
	}
	vid, err := r.st.CreateVehicle(ctx, user, "XYZ789", "Mum", "")
	if err != nil {
		t.Fatal(err)
	}
	book := "/permits/" + itoa64(id) + "/override"
	base := func() url.Values {
		return url.Values{"vehicle_id": {itoa64(vid)}, "from_date": {"2030-01-01"}, "from_time": {"09:00"}, "ends": {"custom"}}
	}

	t.Run("a time with no date ends that day", func(t *testing.T) {
		v := base()
		v.Set("until_time", "17:00")
		w := r.s.doHX(http.MethodPost, book, user, origin, v)
		if w.Code >= 400 {
			t.Fatalf("time-only end = %d: %s", w.Code, excerpt(w.Body.String()))
		}
		ovs, err := r.st.ListOverrides(ctx, id, time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC))
		if err != nil || len(ovs) != 1 || ovs[0].EndsAt == nil {
			t.Fatalf("booking not stored with an end: %+v %v", ovs, err)
		}
		if got := ovs[0].EndsAt.Sub(ovs[0].StartsAt); got != 8*time.Hour {
			t.Fatalf("booking runs %s, want 8h (09:00 to 17:00 on the start day)", got)
		}
	})
	t.Run("neither date nor time is refused with the reason", func(t *testing.T) {
		w := r.s.doHX(http.MethodPost, book, user, origin, base())
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "Pick the date this booking should end") {
			t.Fatalf("empty end = %d %q, want 422 naming the date", w.Code, w.Body.String())
		}
	})
	t.Run("the booking form carries an inline refusal slot and fills the end date", func(t *testing.T) {
		r.link(t, user)
		body := r.s.doReq("GET", "/schedule", user, "", nil).Body.String()
		for _, want := range []string{`class="form-error" data-form-error`, `x-model="untilDate"`, `untilDate=startDay()`} {
			if !strings.Contains(body, want) {
				t.Errorf("booking form missing %q", want)
			}
		}
	})
}
