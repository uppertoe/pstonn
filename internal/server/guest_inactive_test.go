package server

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// These tests lock the inactive-permit gates on the guest surface. A guest link
// outlives its permit — a poster stays on the door after the council cancels or
// expires the permit behind it — so every path that could put a plate on (or
// promise one) has to check the permit is still alive, not just that the token
// is. The scheduler already refuses to reconcile inactive permits, which makes
// an ungated guest write doubly wrong: it would land AND never be corrected.

// cancelPermit marks an existing permit Cancelled with a still-future end date,
// so Inactive() is driven by status alone (the same shape as a council
// cancel-and-reissue, which is how this arises in practice).
func cancelPermit(t *testing.T, s *Server, owner, councilPermitID string) {
	t.Helper()
	future := time.Now().Add(365 * 24 * time.Hour)
	if err := s.store.UpdatePermitMeta(context.Background(), owner, councilPermitID,
		"Cancelled", "VPP-DEAD", "(B) 1st Visitor Permit", future); err != nil {
		t.Fatalf("cancel permit: %v", err)
	}
}

// A scan of a link whose permit has since been cancelled must refuse — on the
// GET (menu) and the POST (activation/request) alike — with the inactive notice
// (410), NOT the invalid-link notice (404), and must record nothing.
func TestGuestLinkOnInactivePermitRefuses(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	pid, _, raw := seedDoorQR(t, s, owner, "Door")
	cancelPermit(t, s, owner, "P-Door")

	get := s.getGuest("/g/" + raw)
	if get.Code != 410 {
		t.Fatalf("GET dead-permit link = %d, want 410", get.Code)
	}
	if !strings.Contains(get.Body.String(), "no longer active") {
		t.Fatalf("GET reply does not say the permit is inactive: %s", get.Body.String())
	}

	post := s.postGuest("/g/"+raw, "203.0.113.9", "", url.Values{"plate": {"TRD441"}})
	if post.Code != 410 {
		t.Fatalf("POST to dead-permit link = %d, want 410", post.Code)
	}
	if pending, err := s.store.ListPendingRequests(ctx, owner); err != nil || len(pending) != 0 {
		t.Fatalf("a scan of a dead permit's QR recorded a request: %v %v", pending, err)
	}
	if ovs, err := s.store.ListOverrides(ctx, pid, time.Now()); err != nil || len(ovs) != 0 {
		t.Fatalf("a scan of a dead permit's QR created an override: %v %v", ovs, err)
	}
}

// Approving a request that was made while the permit was still alive must
// refuse once the permit is dead: the approval would create an override the
// scheduler never acts on, telling the visitor "approved" with nothing behind
// it. The request stays pending (nobody decided it) and nothing is created.
func TestApproveRequestOnInactivePermitRefuses(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	pid, grantID, _ := seedDoorQR(t, s, owner, "Door")
	reqID, _, _, err := s.store.CreateGuestRequest(ctx, grantID, pid, owner, "TRD441", "nonce-dead")
	if err != nil {
		t.Fatal(err)
	}
	cancelPermit(t, s, owner, "P-Door")

	out := s.runDecideRequest(httptest.NewRequest("POST", "/", nil), owner, owner, reqID, true)
	if out.kind != decidePermitInactive {
		t.Fatalf("approve on dead permit = kind %d, want decidePermitInactive", out.kind)
	}
	if req, err := s.store.GuestRequestByID(ctx, reqID); err != nil || req.Status != "pending" {
		t.Fatalf("request after refused approval = %+v (%v), want still pending", req, err)
	}
	if ovs, err := s.store.ListOverrides(ctx, pid, time.Now()); err != nil || len(ovs) != 0 {
		t.Fatalf("refused approval left an override behind: %v %v", ovs, err)
	}
}

// The minting surfaces — visitor QR, printed door QR, guest pass — must refuse a
// dead permit at the handler even though the page no longer offers it, because
// the selector is only a UI hint.
func TestNoNewGuestLinksForInactivePermit(t *testing.T) {
	s := newAuthzServer(t)
	ctx := context.Background()
	const owner, origin = "owner@example.com", "http://app.example.com"
	if err := s.store.RecordConsent(ctx, owner, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	pid, err := s.store.UpsertPermit(ctx, owner, "CP-DEAD", "14", "Old permit")
	if err != nil {
		t.Fatal(err)
	}
	vehID, err := s.store.CreateVehicle(ctx, owner, "AAA111", "Car")
	if err != nil {
		t.Fatal(err)
	}
	cancelPermit(t, s, owner, "CP-DEAD")

	permitID := url.Values{"permit_id": {itoa64(pid)}}
	for _, target := range []string{"/guests/qr", "/guests/printed"} {
		w := s.doReq("POST", target, owner, origin, permitID)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "no longer active") {
			t.Fatalf("POST %s for dead permit = %d %q, want 409 + inactive notice", target, w.Code, w.Body.String())
		}
	}

	w := s.doReq("POST", "/guests", owner, origin, url.Values{
		"permit_id":  {itoa64(pid)},
		"label":      {"Nanny"},
		"vehicle_id": {itoa64(vehID)},
		"recipients": {"nanny@example.com"},
	})
	if w.Code != 409 || !strings.Contains(w.Body.String(), "no longer active") {
		t.Fatalf("create pass on dead permit = %d %q, want 409 + inactive notice", w.Code, w.Body.String())
	}
	if grants, err := s.store.ListGuestGrants(ctx, owner); err != nil || len(grants) != 0 {
		t.Fatalf("a pass was created for a dead permit: %v %v", grants, err)
	}
}

// The guests page must not offer a dead permit as a target for new links, while
// existing passes on it stay listed — labelled as no longer active.
func TestGuestsPageOffersOnlyActivePermits(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	activeID, err := s.store.UpsertPermit(ctx, owner, "CP-LIVE", "14", "Current")
	if err != nil {
		t.Fatal(err)
	}
	deadID, err := s.store.UpsertPermit(ctx, owner, "CP-DEAD", "14", "Old")
	if err != nil {
		t.Fatal(err)
	}
	vehID, err := s.store.CreateVehicle(ctx, owner, "AAA111", "Car")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateGuestGrant(ctx, owner, owner, deadID, "Nanny", false,
		[]int64{vehID}, []store.GuestRecipient{{Email: "nanny@example.com", TokenHash: "hash-dead"}}); err != nil {
		t.Fatal(err)
	}
	cancelPermit(t, s, owner, "CP-DEAD")

	base := dashboardData{Owner: owner}
	if err := s.loadGuests(ctx, &base, 0); err != nil {
		t.Fatal(err)
	}
	if len(base.PermitOpts) != 1 || base.PermitOpts[0].ID != activeID {
		t.Fatalf("PermitOpts = %+v, want only the live permit %d", base.PermitOpts, activeID)
	}
	if len(base.Guests) != 1 || !strings.Contains(base.Guests[0].PermitLabel, "no longer active") {
		t.Fatalf("existing pass on the dead permit = %+v, want listed with a 'no longer active' label", base.Guests)
	}
}
