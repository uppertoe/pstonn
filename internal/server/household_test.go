package server

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/store"
)

func TestHouseholdHelpers(t *testing.T) {
	for in, want := range map[string]string{"SBX1AB": "••••AB", "ABC123": "••••23", "AB1": "•••", "1JA1JI": "••••JI"} {
		if got := maskRego(in); got != want {
			t.Errorf("maskRego(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"the Nguyens": "the Nguyens’", "Nana": "Nana’s", "x@y.com": "x@y.com’s"} {
		if got := possessive(in); got != want {
			t.Errorf("possessive(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sentenceCase("the Nguyens’"); got != "The Nguyens’" {
		t.Errorf("sentenceCase = %q", got)
	}
	for _, bad := range []string{"", strings.Repeat("a", 41), "<b>hi</b>", "line\nbreak"} {
		if validHouseholdName(bad) {
			t.Errorf("validHouseholdName(%q) = true, want false", bad)
		}
	}
	if !validHouseholdName("the O’Briens") {
		t.Error("a plain name with an apostrophe should be valid")
	}
}

// TestHouseholdNameSavedAndLogged: the owner sets the visitor-facing name, it
// is stored and appears in the change log; a blank clears it; junk is refused.
func TestHouseholdNameSavedAndLogged(t *testing.T) {
	s := newAuthzServer(t)
	const owner = "own@example.com"
	ctx := context.Background()
	if err := s.store.RecordConsent(ctx, owner, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	post := func(name string) *httptest.ResponseRecorder {
		return s.doReq("POST", "/account/household-name", owner, "http://app.example.com", url.Values{"household_name": {name}})
	}
	if w := post("  the   Nguyens "); w.Code != 303 || w.Header().Get("Location") != "/settings?named=1" {
		t.Fatalf("save = %d -> %q", w.Code, w.Header().Get("Location"))
	}
	if got, _ := s.store.HouseholdName(ctx, owner); got != "the Nguyens" {
		t.Fatalf("stored %q, want the collapsed name", got)
	}
	if w := post("<script>"); w.Code == 303 {
		t.Fatal("markup accepted as a household name")
	}
	if w := post(""); w.Code != 303 {
		t.Fatalf("clear = %d", w.Code)
	}
	if got, _ := s.store.HouseholdName(ctx, owner); got != "" {
		t.Fatalf("still %q after clearing", got)
	}
	changes, err := s.store.ListChanges(ctx, owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	var saw int
	for _, c := range changes {
		if c.Action == store.ActionHouseholdName {
			saw++
		}
	}
	if saw != 2 {
		t.Fatalf("household-name change entries = %d, want 2", saw)
	}
}
