package server

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestGuestActivateOutageMessage: when a guest activates during a CONFIRMED council
// outage (the auth circuit open), the visitor is told honestly that the car may not
// be covered — not the optimistic "being applied" pending state that suits a brief
// blip. A blip (circuit closed) keeps the pending behaviour.
func TestGuestActivateOutageMessage(t *testing.T) {
	run := func(gateOpen bool) (int, string) {
		s, rp := newApplyRig(t)
		isolateGuestBounds(t)
		ctx := context.Background()
		const owner = "primary@example.com"
		if err := s.tenant.Link(ctx, owner, "", owner, "ok", false, true, 0); err != nil {
			t.Fatal(err)
		}
		pid, err := s.store.UpsertPermit(ctx, owner, "90001", "14", "Visitor")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.store.SetPermitActive(ctx, pid, "SBX1AB"); err != nil {
			t.Fatal(err)
		}
		van, err := s.store.CreateVehicle(ctx, owner, "NSW123", "Van", "NSW")
		if err != nil {
			t.Fatal(err)
		}
		const raw = "outage-token-000000000000000001"
		if _, err := s.store.CreateGuestGrant(ctx, owner, owner, pid, "Nanny", false, []int64{van},
			[]store.GuestRecipient{{Email: "nanny@example.com", TokenHash: hashGuestToken(raw)}}); err != nil {
			t.Fatal(err)
		}
		// The outage shape: the write fails transiently (as a council 500 does) AND the
		// auth circuit reads open.
		rp.mu.Lock()
		rp.applyErr = parking.ErrCouncilBusy
		rp.mu.Unlock()
		rp.AuthGateOpen = gateOpen

		w := s.postGuest("/g/"+raw, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(van)}})
		return w.Code, w.Body.String()
	}

	// Confirmed outage: an honest warning naming the plate, and NO success claim.
	code, body := run(true)
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	// Substrings without an apostrophe — html/template escapes ' to &#39;.
	if !strings.Contains(body, "system is down right now") || !strings.Contains(body, "may not be covered") || !strings.Contains(body, "NSW123") {
		t.Fatalf("outage: want the honest warning naming NSW123; got:\n%s", excerpt(body))
	}
	if strings.Contains(body, "is now on the permit") {
		t.Fatalf("outage: must not claim the car is on the permit; got:\n%s", excerpt(body))
	}

	// Brief blip (circuit closed): no outage warning — the optimistic pending stands.
	if _, body2 := run(false); strings.Contains(body2, "council's system is down") {
		t.Fatalf("a brief blip must not show the outage warning; got:\n%s", excerpt(body2))
	}
}

// TestDoorQROutagePollStatus: a printed-QR request approved during a CONFIRMED
// outage — the background apply fails, so it's approved-but-not-on-the-permit —
// must show the requester's poll the honest "council is down" status, not the
// optimistic "putting it on" spinner or a bare "stalled".
func TestDoorQROutagePollStatus(t *testing.T) {
	s, rp := newApplyRig(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "primary@example.com"
	if err := s.tenant.Link(ctx, owner, "", owner, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
	pid, err := s.store.UpsertPermit(ctx, owner, "90001", "14", "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetPermitActive(ctx, pid, "SBX1AB"); err != nil {
		t.Fatal(err)
	}
	const door = "door-outage-token-0000000000001"
	grantID, err := s.store.CreatePrintedGrant(ctx, owner, owner, pid, hashGuestToken(door), "sealed")
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "outage-poll-nonce-00000000000001"
	reqID, _, _, err := s.store.CreateGuestRequest(ctx, grantID, pid, owner, "ACT999", "ACT", nonce)
	if err != nil {
		t.Fatal(err)
	}
	// The apply fails (as a council 500) and the auth circuit reads open.
	rp.mu.Lock()
	rp.applyErr = parking.ErrCouncilBusy
	rp.mu.Unlock()
	rp.AuthGateOpen = true
	// Resident approves; the background apply fails → approved but not on the permit.
	if out := s.runDecideRequest(httptest.NewRequest("POST", "/guests/requests/x/approve", nil), owner, owner, reqID, true); out.kind == decideErr {
		t.Fatalf("approve errored: %v", out.err)
	}

	body := s.getGuest("/g/req/" + itoa64(reqID) + "?n=" + nonce).Body.String()
	if !strings.Contains(body, "system is down right now") || !strings.Contains(body, "may not be on the permit yet") {
		t.Fatalf("door-QR outage poll: want the honest outage copy; got:\n%s", excerpt(body))
	}
	if strings.Contains(body, "putting") {
		t.Fatalf("door-QR outage poll must not show the optimistic 'putting it on' spinner; got:\n%s", excerpt(body))
	}
}

// TestGuestActivateSessionExpiredMessage: when p.stonn's sign-in has lapsed (not a
// council outage), the visitor is told the resident must reconnect — not the
// misleading "try again shortly", which only the resident can act on.
func TestGuestActivateSessionExpiredMessage(t *testing.T) {
	s, rp := newApplyRig(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "primary@example.com"
	if err := s.tenant.Link(ctx, owner, "", owner, "ok", false, true, 0); err != nil {
		t.Fatal(err)
	}
	pid, err := s.store.UpsertPermit(ctx, owner, "90001", "14", "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetPermitActive(ctx, pid, "SBX1AB"); err != nil {
		t.Fatal(err)
	}
	van, err := s.store.CreateVehicle(ctx, owner, "NSW123", "Van", "NSW")
	if err != nil {
		t.Fatal(err)
	}
	const raw = "session-token-00000000000000001"
	if _, err := s.store.CreateGuestGrant(ctx, owner, owner, pid, "Nanny", false, []int64{van},
		[]store.GuestRecipient{{Email: "nanny@example.com", TokenHash: hashGuestToken(raw)}}); err != nil {
		t.Fatal(err)
	}
	// The sign-in has lapsed; the auth circuit is NOT open (this isn't a council outage).
	rp.mu.Lock()
	rp.applyErr = parking.ErrSessionExpired
	rp.mu.Unlock()
	rp.AuthGateOpen = false

	body := s.postGuest("/g/"+raw, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(van)}}).Body.String()
	if !strings.Contains(body, "sign-in to the council needs renewing") || !strings.Contains(body, "NSW123") {
		t.Fatalf("session-expired: want the 'resident must reconnect' copy naming NSW123; got:\n%s", excerpt(body))
	}
	if strings.Contains(body, "try again shortly") {
		t.Fatalf("session-expired: must not tell the visitor to try again; got:\n%s", excerpt(body))
	}
}
