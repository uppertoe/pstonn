package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestPortalThatCannotClearOverHTTP: a portal whose provider declares
// CanClearVehicle=false gets a card with no "take the car off" action, and the
// handler refuses the request outright — before any claim or council call — so
// a stale tab or hand-built POST changes nothing. The UI adapted to a declared
// capability, not to a council name.
func TestPortalThatCannotClearOverHTTP(t *testing.T) {
	r := newTenantRig(t)
	r.fake.NoClear = true
	r.consent(t, rigUser)
	r.link(t, rigUser)
	if rr := r.post("/permits", rigUser, url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, _ := r.st.ListPermitsFor(r.ctx, rigUser)
	pid := ps[0].ID
	clearPath := "/permits/" + strconv.FormatInt(pid, 10) + "/clear"

	// The lingering-plate state, where a clearing portal WOULD offer the action.
	page := r.get("/schedule", rigUser).Body.String()
	if strings.Contains(page, `action="`+clearPath+`"`) {
		t.Fatalf("the clear action is offered on a portal that cannot clear:\n%s", excerpt(page))
	}
	// The state chooser is still there (regions are a separate capability).
	if !strings.Contains(page, `name="plate_state"`) {
		t.Fatalf("the state chooser vanished with the clear action:\n%s", excerpt(page))
	}
	rr := r.post(clearPath, rigUser, nil)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "be left with no vehicle on it") {
		t.Fatalf("code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if reg, _ := r.fake.Current("90001"); reg != "SBX1AB" {
		t.Fatalf("the council record was changed anyway: %q", reg)
	}

	// Flip the capability: the same account, same permit, now offers and accepts it.
	r.fake.NoClear = false
	page = r.get("/schedule", rigUser).Body.String()
	if !strings.Contains(page, `action="`+clearPath+`"`) {
		t.Fatalf("the clear action is missing on a portal that can clear:\n%s", excerpt(page))
	}
	if rr := r.post(clearPath, rigUser, nil); rr.Code != http.StatusSeeOther {
		t.Fatalf("clear on a capable portal: code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if reg, _ := r.fake.Current("90001"); reg != "" {
		t.Fatalf("council record still shows %q", reg)
	}
}
