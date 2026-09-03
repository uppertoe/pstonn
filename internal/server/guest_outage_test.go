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

// TestGuestActivateOutageMessage: activating during a CONFIRMED council outage, the
// guest's pending state reads honestly ("the council's system is down, may not be on
// yet") with NO optimistic "Changing to…" spinner — and it stays honest on the 2.5s
// poll, not just the initial POST (an earlier fix set a one-off banner the poll
// reverted). A brief blip (circuit closed) keeps the optimistic pending.
func TestGuestActivateOutageMessage(t *testing.T) {
	setup := func(gateOpen bool) (*Server, string, int64) {
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
		rp.mu.Lock()
		rp.applyErr = parking.ErrCouncilBusy
		rp.mu.Unlock()
		rp.AuthGateOpen = gateOpen
		return s, raw, van
	}

	// Confirmed outage: honest pending on the POST AND the poll; no optimistic spinner.
	s, raw, van := setup(true)
	post := s.postGuest("/g/"+raw, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(van)}})
	if post.Code != 200 {
		t.Fatalf("activate code = %d", post.Code)
	}
	poll := s.getGuest("/g/live/" + raw)
	for _, c := range []struct{ name, body string }{{"POST", post.Body.String()}, {"poll", poll.Body.String()}} {
		if !strings.Contains(c.body, "system is down") || !strings.Contains(c.body, "may not be on the permit yet") || !strings.Contains(c.body, "NSW123") {
			t.Fatalf("outage %s: want the honest 'council down' pending naming NSW123; got:\n%s", c.name, excerpt(c.body))
		}
		if strings.Contains(c.body, "Changing to") {
			t.Fatalf("outage %s: must not show the optimistic 'Changing to' spinner; got:\n%s", c.name, excerpt(c.body))
		}
		if strings.Contains(c.body, "is now on the permit") {
			t.Fatalf("outage %s: must not claim the car is on the permit; got:\n%s", c.name, excerpt(c.body))
		}
	}

	// Brief blip (circuit closed): the optimistic "Changing to NSW123" pending stands,
	// and the outage copy is absent.
	s2, raw2, van2 := setup(false)
	blip := s2.postGuest("/g/"+raw2, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(van2)}}).Body.String()
	if !strings.Contains(blip, "Changing to") || strings.Contains(blip, "system is down") {
		t.Fatalf("brief blip: want the optimistic pending, not the outage copy; got:\n%s", excerpt(blip))
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
	rp.mu.Lock()
	rp.applyErr = parking.ErrCouncilBusy
	rp.mu.Unlock()
	rp.AuthGateOpen = true
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
