package server

import (
	"context"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/store"
)

var guestPollFP = regexp.MustCompile(`/g/live/[^?"]+\?fp=([0-9a-f]+)`)

// TestGuestActivateOutageMessage: the guest pending state reads honestly during a
// council outage — no optimistic "Changing to…" spinner — on the POST AND, crucially,
// on the 2.5s poll carrying its fingerprint. The up→down transition is the case the
// earlier fix missed: PendingOutage wasn't in the fingerprint, so a poll 204'd and
// the visitor stayed on the stale optimistic message.
func TestGuestActivateOutageMessage(t *testing.T) {
	setup := func(gateOpen bool) (*Server, *recordingProvider, string, int64) {
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
		return s, rp, raw, van
	}

	// (1) Outage from the start: honest pending on the POST, no optimistic spinner.
	s, _, raw, van := setup(true)
	body := s.postGuest("/g/"+raw, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(van)}}).Body.String()
	if !strings.Contains(body, "system is down") || !strings.Contains(body, "may not be on the permit yet") || !strings.Contains(body, "NSW123") {
		t.Fatalf("outage POST: want the honest 'council down' pending naming NSW123; got:\n%s", excerpt(body))
	}
	if strings.Contains(body, "Changing to") {
		t.Fatalf("outage POST: must not show the optimistic 'Changing to' spinner; got:\n%s", excerpt(body))
	}
	if strings.Contains(body, "is now on the permit") {
		t.Fatalf("outage POST: must not claim the car is on the permit; got:\n%s", excerpt(body))
	}

	// (2) The up→down transition on the POLL carrying the UP fingerprint. Council up:
	// optimistic pending. Then it goes down; a poll with the stale fp must REPAINT to
	// the outage copy (not 204). This is exactly the case the fingerprint omission broke.
	s2, rp2, raw2, van2 := setup(false)
	up := s2.postGuest("/g/"+raw2, "203.0.113.5", "", url.Values{"vehicle_id": {itoa64(van2)}}).Body.String()
	if !strings.Contains(up, "Changing to") || strings.Contains(up, "system is down") {
		t.Fatalf("brief blip: want the optimistic pending, not the outage copy; got:\n%s", excerpt(up))
	}
	m := guestPollFP.FindStringSubmatch(up)
	if m == nil {
		t.Fatalf("no poll fingerprint in the up-state body:\n%s", excerpt(up))
	}
	rp2.AuthGateOpen = true // the council goes down mid-poll
	poll := s2.getGuest("/g/live/" + raw2 + "?fp=" + m[1])
	if poll.Code == 204 {
		t.Fatal("poll 204'd on the up→down transition — the outage flip was missed (fingerprint bug)")
	}
	pb := poll.Body.String()
	if !strings.Contains(pb, "system is down") || strings.Contains(pb, "Changing to") {
		t.Fatalf("poll must repaint to the outage copy on the transition; got:\n%s", excerpt(pb))
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
