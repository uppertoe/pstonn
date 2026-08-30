package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/uppertoe/pstonn/internal/store"
)

// Route-mapping tests for the signed-in guest-management POSTs: the approvals
// queue's approve/deny buttons and the pause-all toggle. They assert which
// handler each path reaches (by its distinctive redirect), that the CSRF and
// method gates wrap them, and that the toggle actually flips the kill-switch.

func newGuestRoutesServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := newAuthzServer(t)
	const owner = "owner@example.com"
	if err := s.store.RecordConsent(context.Background(), owner, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	return s, owner
}

func TestGuestRequestDecisionRoutes(t *testing.T) {
	s, owner := newGuestRoutesServer(t)
	const origin = "http://app.example.com"
	ctx := context.Background()
	pid, grantID, _ := seedDoorQR(t, s, owner, "Door")
	reqID, _, _, err := s.store.CreateGuestRequest(ctx, grantID, pid, owner, "TRD441", "", "nonce-route")
	if err != nil {
		t.Fatal(err)
	}
	approve := "/guests/requests/" + itoa64(reqID) + "/approve"
	deny := "/guests/requests/" + itoa64(reqID) + "/deny"

	// Gates first: anonymous, cross-site and wrong-method requests never reach the
	// handler (and so never decide anything).
	// (No OIDC is wired on this server, so "not signed in" is a 401 rather than a
	// redirect to the login; either way the handler is not reached.)
	if w := s.doReq("POST", deny, "", origin, url.Values{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous deny = %d, want 401", w.Code)
	}
	if w := s.doReq("POST", deny, owner, "", url.Values{}); w.Code != http.StatusForbidden {
		t.Fatalf("deny without Origin = %d, want 403 (CSRF)", w.Code)
	}
	// POST-only: a GET falls to the /guests/ prefix's own not-found (no GET pattern
	// exists for the mux to answer 405 with) and decides nothing.
	if w := s.doReq("GET", deny, owner, "", nil); w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
		t.Fatalf("GET deny = %d, want 405 or 404", w.Code)
	}
	if req, err := s.store.GuestRequestByID(ctx, reqID); err != nil || req.Status != "pending" {
		t.Fatalf("a refused request decided the row: %+v %v", req, err)
	}

	// deny reaches denyGuestRequest: the row flips and the redirect names it.
	w := s.doReq("POST", deny, owner, origin, url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests?declined=1" {
		t.Fatalf("deny = %d %q", w.Code, w.Header().Get("Location"))
	}
	if req, err := s.store.GuestRequestByID(ctx, reqID); err != nil || req.Status != "denied" || req.DecidedBy != owner {
		t.Fatalf("after deny = %+v %v", req, err)
	}
	// Denying again: no longer pending → the "already decided" answer, not an error.
	if w := s.doReq("POST", deny, owner, origin, url.Values{}); w.Header().Get("Location") != "/guests?alreadydecided=1" {
		t.Fatalf("second deny = %d %q", w.Code, w.Header().Get("Location"))
	}
	// approve reaches approveGuestRequest: a settled row is "gone" for approval,
	// which lands back on the queue with no flag.
	if w := s.doReq("POST", approve, owner, origin, url.Values{}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests" {
		t.Fatalf("approve of a settled row = %d %q", w.Code, w.Header().Get("Location"))
	}
	// A request id that is not this account's is equally "gone" — never a 500,
	// never a decision on someone else's row.
	otherID, _, _, err := s.store.CreateGuestRequest(ctx, grantID, pid, "someone@example.com", "OTH111", "", "nonce-other")
	if err != nil {
		t.Fatal(err)
	}
	if w := s.doReq("POST", "/guests/requests/"+itoa64(otherID)+"/approve", owner, origin, url.Values{}); w.Header().Get("Location") != "/guests" {
		t.Fatalf("approve of another account's request = %d %q", w.Code, w.Header().Get("Location"))
	}
	if req, err := s.store.GuestRequestByID(ctx, otherID); err != nil || req.Status != "pending" {
		t.Fatalf("another account's request was decided: %+v %v", req, err)
	}
	if w := s.doReq("POST", "/guests/requests/"+itoa64(otherID)+"/deny", owner, origin, url.Values{}); w.Header().Get("Location") != "/guests?alreadydecided=1" {
		t.Fatalf("deny of another account's request = %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestGuestToggleRoute(t *testing.T) {
	s, owner := newGuestRoutesServer(t)
	const origin = "http://app.example.com"
	ctx := context.Background()

	if w := s.doReq("POST", "/guests/toggle", owner, "", url.Values{}); w.Code != http.StatusForbidden {
		t.Fatalf("toggle without Origin = %d, want 403 (CSRF)", w.Code)
	}
	// The toggle is POST-only. A GET falls to the /guests/ prefix's own not-found
	// (the mux has no GET pattern to answer 405 with), and either way flips nothing.
	if w := s.doReq("GET", "/guests/toggle", owner, "", nil); w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
		t.Fatalf("GET toggle = %d, want 405 or 404", w.Code)
	}
	if on, _ := s.store.GuestsEnabled(ctx, owner); !on {
		t.Fatal("guest passes should default to enabled")
	}

	// Pause: no "enabled" field.
	w := s.doReq("POST", "/guests/toggle", owner, origin, url.Values{})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests" {
		t.Fatalf("pause = %d %q", w.Code, w.Header().Get("Location"))
	}
	if on, err := s.store.GuestsEnabled(ctx, owner); err != nil || on {
		t.Fatalf("after pause enabled=%v (%v), want false", on, err)
	}
	// Resume.
	w = s.doReq("POST", "/guests/toggle", owner, origin, url.Values{"enabled": {"1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/guests" {
		t.Fatalf("resume = %d %q", w.Code, w.Header().Get("Location"))
	}
	if on, err := s.store.GuestsEnabled(ctx, owner); err != nil || !on {
		t.Fatalf("after resume enabled=%v (%v), want true", on, err)
	}
	// Both flips are in the household's change log.
	changes, err := s.store.ListChanges(ctx, owner, 10)
	if err != nil {
		t.Fatal(err)
	}
	var toggles int
	for _, c := range changes {
		if c.Action == store.ActionGuestToggle {
			toggles++
		}
	}
	if toggles != 2 {
		t.Fatalf("change log has %d toggle entries, want 2: %+v", toggles, changes)
	}
}
