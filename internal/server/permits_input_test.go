package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/uppertoe/pstonn/internal/identity"
)

// TestPickerRendersWithoutRegistry: the picker's "which area?" branch guarded
// s.registry != nil in the same if-statement whose init clause had already called
// s.registry.Enabled() — the guard ran second. A deployment or rig with no
// registry must get the onboarding page, not a panic.
func TestPickerRendersWithoutRegistry(t *testing.T) {
	r := newTenantRig(t)
	r.s.registry = nil
	req := httptest.NewRequest("GET", "/permits/new", nil)
	w := httptest.NewRecorder()
	const user = "solo@example.com" // never linked, so the branch under test is the one taken
	r.s.renderPicker(w, req, dashboardData{User: identity.User{Email: user}, Owner: user, IsPrimary: true, Loc: time.UTC})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "portal_password") {
		t.Fatalf("picker without a registry = %d: %s", w.Code, excerpt(w.Body.String()))
	}
}

// TestAddPermitLabelIsCapped: renamePermit and addVehicle bound a label at 40
// runes; addPermit was the one label that reached the store unbounded.
func TestAddPermitLabelIsCapped(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	long := strings.Repeat("é", maxLabelRunes+5) // multi-byte, so a byte cap would cut mid-character
	if rr := r.post("/permits", rigUser, url.Values{"council_permit_id": {"90001"}, "label": {long}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add permit = %d: %s", rr.Code, excerpt(rr.Body.String()))
	}
	ps, err := r.st.ListPermitsFor(context.Background(), rigUser)
	if err != nil || len(ps) != 1 {
		t.Fatalf("permits = %v (%v), want one", ps, err)
	}
	if n := utf8.RuneCountInString(ps[0].Label); n != maxLabelRunes || !utf8.ValidString(ps[0].Label) {
		t.Fatalf("stored label is %d runes (valid=%v), want %d", n, utf8.ValidString(ps[0].Label), maxLabelRunes)
	}
}
