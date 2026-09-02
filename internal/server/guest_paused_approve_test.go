package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// TestGuardedInsertHonoursGuestPause: the guest-override insert decides the link's
// liveness inside the statement, and it used to ask about the token and the grant
// but not the account's pause-all switch — the one thing GuestOverrideStillAuthorised
// does check. So a pause let the row in and only the apply refused it. The insert
// now refuses while passes are paused, and admits the same row once they resume.
func TestGuardedInsertHonoursGuestPause(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "paused@example.com"
	pid, grantID, _ := seedDoorQR(t, s, owner, "Door")
	tok, err := s.store.GrantTokenID(ctx, grantID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetGuestsEnabled(ctx, owner, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	end := now.Add(time.Hour)
	if _, err := s.store.CreateGuestPlateOverride(ctx, pid, "TRD441", "", now, &end, "visitor (printed QR)", tok); !errors.Is(err, store.ErrGuestOverrideRefused) {
		t.Fatalf("insert while passes are paused: err=%v, want ErrGuestOverrideRefused", err)
	}
	if err := s.store.SetGuestsEnabled(ctx, owner, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateGuestPlateOverride(ctx, pid, "TRD441", "", now, &end, "visitor (printed QR)", tok); err != nil {
		t.Fatalf("insert after resuming: %v", err)
	}
}

// TestApproveWhilePassesPausedRefuses: approving a printed-QR request while the
// household has paused guest passes must fail the way a revoked code does —
// before the request is marked approved, with nothing left for the scheduler —
// and must be told apart from "too many bookings", which is what the store's one
// refusal error used to be read as.
func TestApproveWhilePassesPausedRefuses(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	pid, grantID, _ := seedDoorQR(t, s, owner, "Door")
	reqID, _, _, err := s.store.CreateGuestRequest(ctx, grantID, pid, owner, "TRD441", "", "nonce-paused")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetGuestsEnabled(ctx, owner, false); err != nil {
		t.Fatal(err)
	}
	out := s.runDecideRequest(httptest.NewRequest("POST", "/", nil), owner, owner, reqID, true)
	if out.kind != decideRevoked {
		t.Fatalf("approve while paused = kind %d (err %v), want decideRevoked", out.kind, out.err)
	}
	if req, err := s.store.GuestRequestByID(ctx, reqID); err != nil || req.Status != "pending" {
		t.Fatalf("request after refused approval = %+v (%v), want still pending", req, err)
	}
	if ovs, err := s.store.ListOverrides(ctx, pid, time.Now()); err != nil || len(ovs) != 0 {
		t.Fatalf("refused approval left an override behind: %v %v", ovs, err)
	}

	// The other cause of the same store error — a permit at its guest sub-cap with
	// the code still live — keeps its own answer.
	if err := s.store.SetGuestsEnabled(ctx, owner, true); err != nil {
		t.Fatal(err)
	}
	tok, err := s.store.GrantTokenID(ctx, grantID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	end := now.Add(time.Hour)
	for i := 0; i < store.MaxLiveGuestOverridesPerPermit; i++ {
		if _, err := s.store.CreateGuestPlateOverride(ctx, pid, "FIL"+itoa64(int64(i)), "", now, &end, "fill", tok); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	if out := s.runDecideRequest(httptest.NewRequest("POST", "/", nil), owner, owner, reqID, true); out.kind != decideCapFull {
		t.Fatalf("approve at the sub-cap = kind %d, want decideCapFull", out.kind)
	}
}

// TestGuestsPageNamesDecideRefusals: decideRequest lands on /guests with
// ?alreadydecided=1 or ?revoked=1, and the page used to render neither — a member
// who pressed Approve saw the list again with no word on what happened.
func TestGuestsPageNamesDecideRefusals(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser)
	if rr := r.post("/permits", rigUser, url.Values{"council_permit_id": {"90001"}}); rr.Code != http.StatusSeeOther {
		t.Fatalf("add permit = %d: %s", rr.Code, excerpt(rr.Body.String()))
	}
	for flag, want := range map[string]string{
		"alreadydecided": "Someone else already answered that request.",
		"revoked":        "its printed QR code has been removed, or guest passes are paused.",
	} {
		rr := r.get("/guests?"+flag+"=1", rigUser)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("/guests?%s=1 = %d without %q: %s", flag, rr.Code, want, excerpt(rr.Body.String()))
		}
	}
}
