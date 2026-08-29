package server

import (
	"bytes"
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// decideLinkFor mints the same signed path the notification email carries.
func decideLinkFor(t *testing.T, reqID int64, addr string) string {
	t.Helper()
	svc := notify.New(nil, nil, "", "", "https://app.example.com", "", "", time.UTC, nil,
		notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	link := svc.GuestDecideURL(reqID, addr)
	if link == "" {
		t.Fatal("minted no decide link")
	}
	return strings.TrimPrefix(link, "https://app.example.com")
}

// seedDecideRequest builds a household with a pending printed-QR request and a
// server able to render the decide pages and run the DECLINE path (the approve
// path needs the scheduler+tenant and is exercised elsewhere; the shared core
// is the same code either way).
func seedDecideRequest(t *testing.T) (*Server, store.GuestRequest, string) {
	t.Helper()
	s := newGuestTestServer(t)
	s.decideKey = notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32))
	ctx := context.Background()
	const owner = "owner@example.com"
	_, grantID, _ := seedDoorQR(t, s, owner, "Door")
	permitID, err := s.store.UpsertPermit(ctx, owner, "VPP1", "14", "Visitor permit")
	if err != nil {
		t.Fatal(err)
	}
	reqID, _, _, err := s.store.CreateGuestRequest(ctx, grantID, permitID, owner, "TRD441", "nonce-decide")
	if err != nil {
		t.Fatal(err)
	}
	req, err := s.store.GuestRequestByID(ctx, reqID)
	if err != nil {
		t.Fatal(err)
	}
	return s, req, owner
}

func (s *Server) decideDo(method, path string, form url.Values) *httptest.ResponseRecorder {
	var body string
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "app.example.com"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestDecideLinkShowsPendingRequest: a valid link renders the question with
// both buttons, and the GET alone must never decide anything (mail scanners
// prefetch links).
func TestDecideLinkShowsPendingRequest(t *testing.T) {
	s, req, owner := seedDecideRequest(t)
	w := s.decideDo("GET", decideLinkFor(t, req.ID, owner), nil)
	if w.Code != 200 {
		t.Fatalf("GET decide link = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"TRD441", "Approve", "Decline"} {
		if !strings.Contains(body, want) {
			t.Errorf("decide page missing %q", want)
		}
	}
	after, err := s.store.GuestRequestByID(context.Background(), req.ID)
	if err != nil || after.Status != "pending" {
		t.Fatalf("GET changed the request: status=%q err=%v — a prefetch must never decide", after.Status, err)
	}
}

// TestDecideLinkDecline: the POST declines the request and records the link's
// recipient as the decider, so the household's audit trail stays intact.
func TestDecideLinkDecline(t *testing.T) {
	s, req, owner := seedDecideRequest(t)
	path := decideLinkFor(t, req.ID, owner)
	w := s.decideDo("POST", path, url.Values{"decision": {"decline"}})
	if w.Code != 200 {
		t.Fatalf("POST decline = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Declined") {
		t.Error("decline outcome page missing confirmation")
	}
	after, err := s.store.GuestRequestByID(context.Background(), req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "denied" || after.DecidedBy != owner {
		t.Fatalf("request after decline: status=%q decidedBy=%q, want denied by %q", after.Status, after.DecidedBy, owner)
	}
	// The settled request now renders as a statement, not a question.
	w = s.decideDo("GET", path, nil)
	if !strings.Contains(w.Body.String(), "Already declined") {
		t.Error("revisiting the link after the decision does not show the settled state")
	}
}

// TestDecideLinkAuthz: forged and out-of-scope links all collapse into one
// neutral answer that leaks nothing and decides nothing.
func TestDecideLinkAuthz(t *testing.T) {
	s, req, owner := seedDecideRequest(t)
	good := decideLinkFor(t, req.ID, owner)
	parts := strings.Split(strings.TrimPrefix(good, "/r/"), "/") // id, addr, token

	stranger := decideLinkFor(t, req.ID, "stranger@example.com") // valid signature, not a member
	cases := map[string]string{
		"garbled token":     "/r/" + parts[0] + "/" + parts[1] + "/1.zzzz.forged",
		"other request id":  "/r/999/" + parts[1] + "/" + parts[2],
		"non-member holder": stranger,
	}
	for name, path := range cases {
		w := s.decideDo("POST", path, url.Values{"decision": {"decline"}})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "isn&#39;t valid or has expired") {
			t.Errorf("%s: got %d, want the neutral page", name, w.Code)
		}
	}
	after, _ := s.store.GuestRequestByID(context.Background(), req.ID)
	if after.Status != "pending" {
		t.Fatalf("a rejected link changed the request to %q", after.Status)
	}

	// A secondary member's own link DOES work: the household boundary, not the
	// owner identity, is the authorisation line.
	const secondary = "nanny@example.com"
	if err := s.store.AddMember(context.Background(), owner, secondary); err != nil {
		t.Fatal(err)
	}
	w := s.decideDo("POST", decideLinkFor(t, req.ID, secondary), url.Values{"decision": {"decline"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Declined") {
		t.Fatalf("secondary member's link refused: %d", w.Code)
	}
	after, _ = s.store.GuestRequestByID(context.Background(), req.ID)
	if after.DecidedBy != secondary {
		t.Fatalf("decidedBy=%q, want the secondary %q", after.DecidedBy, secondary)
	}
}

// TestDecideLinkExpiredRequest: once the request has expired unanswered, the
// link tells the truth and offers nothing to press.
func TestDecideLinkExpiredRequest(t *testing.T) {
	s, req, owner := seedDecideRequest(t)
	if _, err := s.store.ExpireGuestRequests(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	w := s.decideDo("GET", decideLinkFor(t, req.ID, owner), nil)
	body := w.Body.String()
	if !strings.Contains(body, "expired") {
		t.Error("expired request page does not say so")
	}
	if strings.Contains(body, "name=\"decision\"") {
		t.Error("expired request still renders decision buttons")
	}
}
