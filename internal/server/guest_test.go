package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

func TestHashGuestTokenStable(t *testing.T) {
	raw, hash := newGuestToken()
	if raw == "" || hash == "" || raw == hash {
		t.Fatalf("bad token/hash: %q %q", raw, hash)
	}
	if hashGuestToken(raw) != hash {
		t.Fatal("hashGuestToken is not stable for the same input")
	}
	if _, hash2 := newGuestToken(); hash2 == hash {
		t.Fatal("two tokens produced the same hash")
	}
}

func TestParseEmails(t *testing.T) {
	got, dropped := parseEmails("Dad@Example.com, mum@example.com\n dad@example.com ; bogus ,,")
	want := []string{"dad@example.com", "mum@example.com"} // lower-cased, de-duped, invalid dropped
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseEmails = %v, want %v", got, want)
	}
	if strings.Join(dropped, ",") != "bogus" {
		t.Fatalf("parseEmails dropped = %v, want [bogus]", dropped)
	}
	if out, _ := parseEmails(""); len(out) != 0 {
		t.Fatal("empty input should yield no emails")
	}
}

func TestDayEndAndUntilPhrase(t *testing.T) {
	loc, _ := time.LoadLocation("Australia/Melbourne")
	now := time.Date(2026, 7, 17, 14, 30, 0, 0, loc) // Friday afternoon

	if today := dayEndLocal(now, 0); today.Weekday() != time.Saturday || today.Hour() != 0 || today.Day() != 18 {
		t.Fatalf("end of today = %v, want Sat 18th 00:00", today)
	}
	if overnight := dayEndLocal(now, 1); overnight.Day() != 19 || overnight.Hour() != 0 {
		t.Fatalf("overnight end = %v, want 19th 00:00", overnight)
	}
	if got := untilPhrase(now, false); got != "the end of today" {
		t.Fatalf("untilPhrase(today) = %q", got)
	}
	if got := untilPhrase(now, true); !strings.Contains(got, "tomorrow") || !strings.Contains(got, "Saturday") {
		t.Fatalf("untilPhrase(overnight) = %q, want it to mention tomorrow/Saturday", got)
	}
}

func TestRevertPlate(t *testing.T) {
	now := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	until := now.Add(2 * time.Hour)
	cars := []model.Vehicle{{Registration: "AAA111"}, {Registration: "BBB222"}}

	if got := revertPlate("ZZZ999", until, "AAA111", cars, now); got != "ZZZ999" {
		t.Fatalf("external baseline should be revertable, got %q", got)
	}
	if got := revertPlate("", until, "AAA111", cars, now); got != "" {
		t.Fatal("unknown baseline must not offer revert")
	}
	if got := revertPlate("ZZZ999", now.Add(-time.Minute), "AAA111", cars, now); got != "" {
		t.Fatal("expired window must not offer revert")
	}
	if got := revertPlate("ZZZ999", until, "zzz999", cars, now); got != "" {
		t.Fatal("baseline already on the permit (case-insensitive) must not offer revert")
	}
	if got := revertPlate("bbb222", until, "AAA111", cars, now); got != "" {
		t.Fatal("baseline that is one of the link's own cars must not offer revert")
	}
}

func TestPendingState(t *testing.T) {
	now := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)

	if reg, stalled := pendingState("ABC123", "XYZ789", now.Add(-time.Minute), now); reg != "XYZ789" || stalled {
		t.Fatalf("fresh mismatch = (%q,%v), want pending XYZ789 not stalled", reg, stalled)
	}
	if reg, stalled := pendingState("ABC123", "XYZ789", now.Add(-10*time.Minute), now); reg != "XYZ789" || !stalled {
		t.Fatalf("old mismatch = (%q,%v), want XYZ789 stalled", reg, stalled)
	}
	if reg, stalled := pendingState("ABC123", "XYZ789", time.Time{}, now); reg != "XYZ789" || stalled {
		t.Fatalf("no clock at all = (%q,%v), want pending, never an accusation of stalling", reg, stalled)
	}
	if reg, _ := pendingState("xyz789", "XYZ789", now, now); reg != "" {
		t.Fatal("case-insensitive match must read as settled")
	}
	if reg, _ := pendingState("ABC123", "", now, now); reg != "" {
		t.Fatal("no schedule target must read as settled")
	}
}

func TestUntilText(t *testing.T) {
	loc, _ := time.LoadLocation("Australia/Melbourne")
	now := time.Date(2026, 7, 22, 14, 0, 0, 0, loc) // Wednesday afternoon

	if got := untilText(now, time.Time{}); got != "" {
		t.Fatalf("zero end = %q, want empty", got)
	}
	if got := untilText(now, dayEndLocal(now, 0)); got != "until the end of today" {
		t.Fatalf("end of today = %q", got)
	}
	if got := untilText(now, dayEndLocal(now, 1)); got != "until the end of tomorrow (Thursday)" {
		t.Fatalf("overnight end = %q", got)
	}
	if got := untilText(now, now.AddDate(0, 0, 5)); got != "until Mon 27 Jul" {
		t.Fatalf("far end = %q", got)
	}
}

func TestRevertPinEnd(t *testing.T) {
	loc, _ := time.LoadLocation("Australia/Melbourne")
	now := time.Date(2026, 7, 22, 14, 0, 0, 0, loc)
	today, tomorrow := dayEndLocal(now, 0), dayEndLocal(now, 1)

	// An overnight run must NOT pin the old plate over tomorrow's roster.
	if got := revertPinEnd(now, tomorrow); !got.Equal(today) {
		t.Fatalf("overnight window pin = %v, want capped at %v", got, today)
	}
	if got := revertPinEnd(now, today); !got.Equal(today) {
		t.Fatalf("same-day window pin = %v, want %v", got, today)
	}
	earlier := now.Add(2 * time.Hour)
	if got := revertPinEnd(now, earlier); !got.Equal(earlier) {
		t.Fatalf("shorter window pin = %v, want %v (never extended)", got, earlier)
	}
}

func TestValidRego(t *testing.T) {
	// validRego runs on already-normalised input (upper, no spaces).
	good := []string{"ABC123", "1QW4RT", "AB", "GOAT", "ABC1234", "12345678"}
	for _, r := range good {
		if !validRego(r) {
			t.Errorf("validRego(%q) = false, want true", r)
		}
	}
	bad := []string{"", "A", "ABC-123", "AB 12", "TOOLONGGG", "abc123", "AB.12"}
	for _, r := range bad {
		if validRego(r) {
			t.Errorf("validRego(%q) = true, want false", r)
		}
	}
}

// newGuestTestServer is the minimal Server for exercising store-backed guest
// logic (requestLiveState, the greq cookie): config + store, nothing else.
func newGuestTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "guest.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{cfg: &config.Config{DisplayLocation: time.UTC}, store: st}
}

// TestRequestLiveState locks the shared classification every request-status
// surface (wait-page poll, door-QR re-scan, guests-page recent list) renders.
func TestRequestLiveState(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "u@example.com"
	pid, err := s.store.UpsertPermit(ctx, owner, "P1", "14", "Visitor")
	if err != nil {
		t.Fatal(err)
	}
	permit, err := s.store.GetPermit(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	end := dayEndLocal(now, 0)
	base := store.GuestRequest{PermitID: pid, Plate: "GUEST1", Status: "approved", DecidedAt: now, UntilTS: end}

	// Undecided and refused states are terminal regardless of the schedule.
	for _, tc := range []struct{ status, want string }{
		{"pending", "pending"}, {"denied", "denied"}, {"expired", "expired"},
	} {
		r := base
		r.Status = tc.status
		if got, _ := s.requestLiveState(ctx, permit, r); got != tc.want {
			t.Errorf("status %q = %q, want %q", tc.status, got, tc.want)
		}
	}

	// Approved but nothing on the schedule steers to the plate (the override was
	// deleted, or never existed): superseded, with nothing steering the permit.
	if got, repl := s.requestLiveState(ctx, permit, base); got != "superseded" || repl != "" {
		t.Errorf("no-override = %q/%q, want superseded/\"\"", got, repl)
	}

	// With the approval's own override live, the state tracks the tenant record:
	// applying until it shows the plate, applied once it does.
	if _, err := s.store.CreatePlateOverride(ctx, pid, "GUEST1", now, &end, "visitor (printed QR)"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.requestLiveState(ctx, permit, base); got != "approved" {
		t.Errorf("applying = %q, want approved", got)
	}
	stale := base
	stale.DecidedAt = now.Add(-guestApplyTimeout - time.Minute)
	if got, _ := s.requestLiveState(ctx, permit, stale); got != "stalled" {
		t.Errorf("unconfirmed past timeout = %q, want stalled", got)
	}
	onPermit := permit
	onPermit.ActiveRegistration = "guest1" // case-insensitive match
	if got, _ := s.requestLiveState(ctx, onPermit, base); got != "applied" {
		t.Errorf("confirmed = %q, want applied", got)
	}

	// A later booking over the top supersedes the pass — and names the winner
	// (owner-facing surfaces may show it; public ones must not).
	time.Sleep(1100 * time.Millisecond) // the resolve tie-break is freshest CreatedAt (second granularity)
	if _, err := s.store.CreatePlateOverride(ctx, pid, "OWNER9", time.Now().UTC(), &end, owner); err != nil {
		t.Fatal(err)
	}
	if got, repl := s.requestLiveState(ctx, onPermit, base); got != "superseded" || repl != "OWNER9" {
		t.Errorf("overridden = %q/%q, want superseded/OWNER9", got, repl)
	}

	// Once the granted window lapses, the pass reads as ended — never superseded.
	lapsed := base
	lapsed.UntilTS = now.Add(-time.Minute)
	if got, _ := s.requestLiveState(ctx, onPermit, lapsed); got != "ended" {
		t.Errorf("lapsed window = %q, want ended", got)
	}
	// Legacy rows (approved before until_ts existed) fall back to the end of the
	// approval's day: a decision from yesterday reads as ended.
	legacy := base
	legacy.UntilTS = time.Time{}
	legacy.DecidedAt = now.AddDate(0, 0, -1)
	if got, _ := s.requestLiveState(ctx, onPermit, legacy); got != "ended" {
		t.Errorf("legacy yesterday = %q, want ended", got)
	}
}

// TestGuestReqFromCookie locks the cookie's gates: the nonce must match and the
// request must belong to THIS grant — a request made at one door never
// surfaces at another (and a tampered cookie resolves to nothing).
func TestGuestReqFromCookie(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "u@example.com"
	pidA, _ := s.store.UpsertPermit(ctx, owner, "P1", "14", "A")
	pidB, _ := s.store.UpsertPermit(ctx, owner, "P2", "14", "B")
	grantA, err := s.store.CreatePrintedGrant(ctx, owner, "", pidA, "hashA", "sealedA")
	if err != nil {
		t.Fatal(err)
	}
	grantB, err := s.store.CreatePrintedGrant(ctx, owner, "", pidB, "hashB", "sealedB")
	if err != nil {
		t.Fatal(err)
	}
	reqID, nonce, _, err := s.store.CreateGuestRequest(ctx, grantA, pidA, owner, "GUEST1", "secretnonce")
	if err != nil {
		t.Fatal(err)
	}

	get := func(cookie string, grantID int64) bool {
		r := httptest.NewRequest("GET", "/g/tok", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: guestReqCookie, Value: cookie})
		}
		gc := guestCtx{GuestContext: store.GuestContext{Grant: store.GuestGrant{ID: grantID}}}
		_, _, ok := s.guestReqFromCookie(r, gc)
		return ok
	}
	good := fmt.Sprintf("%d.%s", reqID, nonce)
	if !get(good, grantA) {
		t.Fatal("valid cookie on its own grant should resolve")
	}
	if get(good, grantB) {
		t.Fatal("a request must not surface at another grant's door")
	}
	if get(fmt.Sprintf("%d.wrong", reqID), grantA) {
		t.Fatal("wrong nonce must not resolve")
	}
	for _, v := range []string{"", "garbage", "9999." + nonce, "-1." + nonce} {
		if get(v, grantA) {
			t.Fatalf("cookie %q must not resolve", v)
		}
	}
}

// ================= SECURITY REGRESSIONS ON THE GUEST SURFACE =================
//
// Several of these drive store methods rather than handlers. They belong with the
// handler tests because the two halves are one guarantee: a revocation that
// sweeps nothing and a page that promises it did are the same defect seen from
// either end.

// postGuest drives a public /g/ route through the real router. ip and cookie are
// the two things this surface partitions on — "which phone is this?" — so they are
// what a test has to be able to vary.
func (s *Server) postGuest(target, ip, cookie string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	r.Host = "app.example.com"
	// A public, non-private peer: clientIP then uses the peer itself rather than any
	// forwarded header, which is what a direct scan looks like.
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://app.example.com")
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: guestReqCookie, Value: cookie})
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// getGuest is postGuest's read-only twin (the visitor's status poll).
func (s *Server) getGuest(target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	r.Host = "app.example.com"
	r.RemoteAddr = "203.0.113.77:40000"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// seedDoorQR creates an owner, a labelled permit and a printed door QR on it,
// returning the raw token a visitor would scan.
// seedTokenSeq keeps each seeded door token distinct (token_hash is UNIQUE) without
// deriving it from any value a test also greps the response for.
var seedTokenSeq int

func seedDoorQR(t *testing.T, s *Server, owner, label string) (permitID, grantID int64, raw string) {
	t.Helper()
	ctx := context.Background()
	permitID, err := s.store.UpsertPermit(ctx, owner, "P-"+label, "14", label)
	if err != nil {
		t.Fatalf("permit: %v", err)
	}
	// The token must share NO text with the label. It did (label was concatenated
	// into it), and since the page legitimately embeds the token in the manifest URL,
	// a "does the body contain the label?" redaction assertion matched the token and
	// reported a leak that was not there. Keep the two alphabets disjoint so such an
	// assertion can only ever fire on a real leak.
	seedTokenSeq++
	raw = "door" + strings.Repeat("x", 20) + strconv.Itoa(seedTokenSeq)
	grantID, err = s.store.CreatePrintedGrant(ctx, owner, owner, permitID, hashGuestToken(raw), "sealed-"+label)
	if err != nil {
		t.Fatalf("printed grant: %v", err)
	}
	return permitID, grantID, raw
}

// isolateGuestBounds swaps the process-wide guest throttles for fresh ones, so a
// test measures its own traffic and not the previous test's.
func isolateGuestBounds(t *testing.T) {
	t.Helper()
	scanner, nudge, apply := guestScanner, guestNudge, guestApplyNotify
	guestScanner = newRateLimiter(1, 90*time.Minute)
	guestNudge = newRateLimiter(4, 30*time.Minute)
	guestApplyNotify = newRateLimiter(10, time.Hour)
	t.Cleanup(func() { guestScanner, guestNudge, guestApplyNotify = scanner, nudge, apply })
}

// TestGuestRequestInvalidPlateStaysRedacted (E1): the rejected-plate reply is a
// PUBLIC page — a printed QR is on a wall — and it fires for an ordinary visitor
// mistyping their plate, not just for an attacker. It must carry the same
// redaction as every other request-only render: no permit label (the owner's own
// text, typically an address), no owner email. ("ABC-123" no longer triggers it:
// normalizeReg strips display separators, so the trigger here is a plate that is
// genuinely too long once normalised.)
func TestGuestRequestInvalidPlateStaysRedacted(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	const owner, label = "owner@example.com", "Flat3-12ExampleSt"
	_, _, raw := seedDoorQR(t, s, owner, label)

	body := s.postGuest("/g/"+raw, "203.0.113.5", "", url.Values{"plate": {"ABC1234567"}}).Body.String()
	if !strings.Contains(body, "Enter a valid number plate") {
		t.Fatalf("no plate-format guidance in the reply: %s", body)
	}
	if strings.Contains(body, label) {
		t.Fatal("the rejected-plate page leaked the permit label to whoever scanned the poster")
	}
	if strings.Contains(body, owner) {
		t.Fatal("the rejected-plate page leaked the owner's email")
	}
	if !strings.Contains(body, "Visitor parking permit") {
		t.Fatalf("expected the generic heading, got: %s", body)
	}
}

// TestGuestRequestKeepsSlotsForAnotherScanner (E2): the pending cap is a shared
// resource on a public surface. One phone must not be able to fill it — that
// bricked the door QR for the next visitor for the 60-75 minutes a pending row
// lives, repeatably.
func TestGuestRequestKeepsSlotsForAnotherScanner(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	_, _, raw := seedDoorQR(t, s, owner, "Door")
	const flood, visitor = "203.0.113.9", "198.51.100.4"

	for _, plate := range []string{"AAA111", "BBB222", "CCC333", "DDD444", "EEE555", "FFF666"} {
		s.postGuest("/g/"+raw, flood, "", url.Values{"plate": {plate}})
	}
	pending, err := s.store.ListPendingRequests(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	// The store caps a grant at 5 pending rows and holds 2 of them back, so one
	// scanner can reach 3 and no further.
	if len(pending) != 3 {
		t.Fatalf("one phone took %d of the grant's pending slots, want 3", len(pending))
	}
	// And the visitor those slots were held for still gets through.
	body := s.postGuest("/g/"+raw, visitor, "", url.Values{"plate": {"REAL111"}}).Body.String()
	if !strings.Contains(body, "Waiting for the resident") {
		t.Fatalf("a genuine second visitor at the same door was locked out: %s", body)
	}
	if pending, _ = s.store.ListPendingRequests(ctx, owner); len(pending) != 4 {
		t.Fatalf("pending rows after the real visitor = %d, want 4", len(pending))
	}
}

// TestGuestRequestNudgeThrottledPerAccount (E2): the approval nudge bypasses
// quiet hours at high priority, fans out to every member, and notify dedups on
// the PLATE — so cycling plates through a public poster was an unbounded 3am
// alarm. The requests still queue; only the alarm is rationed.
func TestGuestRequestNudgeThrottledPerAccount(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	permitID, _, _ := seedDoorQR(t, s, owner, "Door")
	permit, err := s.store.GetPermit(ctx, permitID)
	if err != nil {
		t.Fatal(err)
	}
	// Push-only, so a queued nudge is countable without an SMTP server.
	s.notify = notify.New(s.store, nil, "https://push.example", "", "http://app.example.com", "", "", time.UTC, nil, nil)
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, NtfyEnabled: true, NtfyTopic: "t", QuietFrom: 22, QuietUntil: 6}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		s.notifyGuestRequest(ctx, permit, fmt.Sprintf("PLT%03d", i), int64(i+1))
	}
	// Far-future "now" so a held (quiet-hours) row is counted too: the point is how
	// many notifications exist at all, not when they go out.
	queued, err := s.store.DueOutbox(ctx, time.Now().Add(72*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 4 {
		t.Fatalf("nine distinct plates queued %d nudges, want the per-account cap of 4", len(queued))
	}
}

// TestGuestApplyNotifyThrottledPerAccount (E3): a guest-link holder cycling
// plates generated an email plus a push per attempt, because notify's dedup key
// includes the plate and this was the only notification path on the guest surface
// with no per-account cap.
func TestGuestApplyNotifyThrottledPerAccount(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	permitID, _, _ := seedDoorQR(t, s, owner, "Door")
	permit, err := s.store.GetPermit(ctx, permitID)
	if err != nil {
		t.Fatal(err)
	}
	s.notify = notify.New(s.store, nil, "https://push.example", "", "http://app.example.com", "", "", time.UTC, nil, nil)
	if err := s.store.SetNotifyPref(ctx, store.NotifyPref{Owner: owner, NtfyEnabled: true, NtfyTopic: "t", QuietFrom: 22, QuietUntil: 6}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		s.notifyGuestApply(ctx, permit, fmt.Sprintf("CYC%03d", i), "", "visitor (QR)", model.DisplacedBooking{}, false)
	}
	queued, err := s.store.DueOutbox(ctx, time.Now().Add(72*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(queued) != 10 {
		t.Fatalf("fifteen plate changes queued %d notices, want the per-account cap of 10", len(queued))
	}
}

// TestGuestRequestDedupWithholdsAnotherVisitorsNonce (E8): two visitors can type
// the same plate. The second scan reuses the first's pending row, and the nonce
// that comes back is the FIRST visitor's poll secret — it may only go to a
// browser that can already present it.
func TestGuestRequestDedupWithholdsAnotherVisitorsNonce(t *testing.T) {
	s := newGuestTestServer(t)
	isolateGuestBounds(t)
	_, _, raw := seedDoorQR(t, s, "owner@example.com", "Door")

	first := s.postGuest("/g/"+raw, "203.0.113.11", "", url.Values{"plate": {"SHARED1"}})
	var remembered string
	for _, c := range first.Result().Cookies() {
		if c.Name == guestReqCookie {
			remembered = c.Value
		}
	}
	if remembered == "" {
		t.Fatalf("the first visitor got no request cookie: %s", first.Body.String())
	}
	idStr, nonce, _ := strings.Cut(remembered, ".")
	if nonce == "" {
		t.Fatalf("malformed request cookie %q", remembered)
	}

	// Visitor B: another phone, no cookie, same plate.
	second := s.postGuest("/g/"+raw, "198.51.100.12", "", url.Values{"plate": {"SHARED1"}})
	body := second.Body.String()
	if strings.Contains(body, nonce) {
		t.Fatal("the second visitor was handed the first visitor's poll nonce")
	}
	for _, c := range second.Result().Cookies() {
		if c.Name == guestReqCookie {
			t.Fatalf("the second visitor was given a cookie for someone else's request: %q", c.Value)
		}
	}
	if !strings.Contains(body, "already waiting for the resident") {
		t.Fatalf("the second visitor got no honest answer: %s", body)
	}
	// The first visitor's own poll still works — withholding the secret must not
	// have cost the person who owns it anything.
	own := s.getGuest("/g/req/" + idStr + "?n=" + nonce).Body.String()
	if !strings.Contains(own, "Waiting for the resident") {
		t.Fatalf("the first visitor's poll broke: %s", own)
	}
	// And a re-scan from the SAME browser is still shown its own request.
	again := s.postGuest("/g/"+raw, "203.0.113.11", remembered, url.Values{"plate": {"SHARED1"}}).Body.String()
	if !strings.Contains(again, nonce) {
		t.Fatalf("the original visitor's re-scan lost its own request: %s", again)
	}
}

// TestRevokeGuestTokenCannotKillAPrintedQR (E4): the per-recipient revoke route
// is for emailed links. A printed door QR is the one artifact a household has
// physically put on a wall, and retiring it through this route logged an empty
// target and told nobody — revokeDoorQR exists to do it loudly.
func TestRevokeGuestTokenCannotKillAPrintedQR(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	_, grantID, raw := seedDoorQR(t, s, owner, "Door")
	tokenID, err := s.store.GrantTokenID(ctx, grantID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.RevokeGuestToken(ctx, owner, tokenID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoking a printed grant's token = %v, want ErrNotFound", err)
	}
	if _, err := s.store.GuestContextByTokenHash(ctx, hashGuestToken(raw)); err != nil {
		t.Fatalf("the printed door QR stopped working through the per-recipient route: %v", err)
	}
	// The route it IS for still works.
	vehID, err := s.store.CreateVehicle(ctx, owner, "AAA111", "Mum")
	if err != nil {
		t.Fatal(err)
	}
	permitID, err := s.store.UpsertPermit(ctx, owner, "P-emailed", "14", "Emailed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.CreateGuestGrant(ctx, owner, owner, permitID, "Nanny", false, []int64{vehID},
		[]store.GuestRecipient{{Email: "nanny@example.com", TokenHash: hashGuestToken("nanny-token-aaaabbbb")}}); err != nil {
		t.Fatal(err)
	}
	details, err := s.store.ListGuestGrants(ctx, owner)
	if err != nil || len(details) != 1 || len(details[0].Tokens) != 1 {
		t.Fatalf("emailed grant not listed: %+v (%v)", details, err)
	}
	if err := s.store.RevokeGuestToken(ctx, owner, details[0].Tokens[0].ID); err != nil {
		t.Fatalf("revoking an emailed link: %v", err)
	}
	if _, err := s.store.GuestContextByTokenHash(ctx, hashGuestToken("nanny-token-aaaabbbb")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a revoked emailed link still resolves = %v", err)
	}
}

// TestUpdateGuestGrantCannotTouchAPrintedGrant (E5): the poster grant is public,
// so attaching household cars to it would turn "scan and ask the resident" into
// "scan and put their car on the permit".
func TestUpdateGuestGrantCannotTouchAPrintedGrant(t *testing.T) {
	s := newGuestTestServer(t)
	ctx := context.Background()
	const owner = "owner@example.com"
	_, grantID, raw := seedDoorQR(t, s, owner, "Door")
	vehID, err := s.store.CreateVehicle(ctx, owner, "AAA111", "Mum")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.UpdateGuestGrant(ctx, owner, grantID, "Mine now", true, []int64{vehID}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("updating a printed grant = %v, want ErrNotFound", err)
	}
	gc, err := s.store.GuestContextByTokenHash(ctx, hashGuestToken(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(gc.Vehicles) != 0 {
		t.Fatalf("a household car was attached to the public poster grant: %+v", gc.Vehicles)
	}
	if gc.Grant.AllowOvernight {
		t.Fatal("the poster grant was given overnight rights")
	}
}

// TestRevocationSweepsLiveGuestOverrides (E7): a guest link's real power is the
// override it leaves behind — it keeps steering the permit until the end of its
// window and every reconcile pass re-asserts it. Every path that says "this no
// longer works" must therefore take the plate off too, and must leave the
// household's own bookings (and already-ended history) alone.
func TestRevocationSweepsLiveGuestOverrides(t *testing.T) {
	ctx := context.Background()
	const owner = "owner@example.com"

	// seed returns a permit carrying one live guest override, one live owner
	// booking, and one guest override that has already ended.
	type seeded struct {
		permitID, grantID, tokenID int64
	}
	seed := func(t *testing.T, s *Server, name string, printed bool) seeded {
		t.Helper()
		permitID, err := s.store.UpsertPermit(ctx, owner, "P-"+name, "14", name)
		if err != nil {
			t.Fatal(err)
		}
		var grantID int64
		if printed {
			grantID, err = s.store.CreatePrintedGrant(ctx, owner, owner, permitID, hashGuestToken("tok-"+name), "sealed")
		} else {
			vehID, verr := s.store.CreateVehicle(ctx, owner, "OWN"+name, "Car "+name)
			if verr != nil {
				t.Fatal(verr)
			}
			grantID, err = s.store.CreateGuestGrant(ctx, owner, owner, permitID, name, false, []int64{vehID},
				[]store.GuestRecipient{{Email: name + "@example.com", TokenHash: hashGuestToken("tok-" + name)}})
		}
		if err != nil {
			t.Fatal(err)
		}
		tokenID, err := s.store.GrantTokenID(ctx, grantID)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		live := now.Add(20 * time.Hour)
		if _, err := s.store.CreateGuestPlateOverride(ctx, permitID, "GUEST1", now, &live, "visitor", tokenID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.store.CreatePlateOverride(ctx, permitID, "OWNER1", now, &live, owner); err != nil {
			t.Fatal(err)
		}
		past, ended := now.Add(-4*time.Hour), now.Add(-2*time.Hour)
		if _, err := s.store.CreateGuestPlateOverride(ctx, permitID, "OLDGST", past, &ended, "visitor", tokenID); err != nil {
			t.Fatal(err)
		}
		return seeded{permitID: permitID, grantID: grantID, tokenID: tokenID}
	}
	// plates reports which registrations still hold authority on the permit, plus
	// whether the ended guest row survived (history must not be rewritten).
	plates := func(t *testing.T, s *Server, permitID int64) (live map[string]bool, historyKept bool) {
		t.Helper()
		live = map[string]bool{}
		all, err := s.store.ListOverrides(ctx, permitID, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range all {
			if o.Registration == "OLDGST" {
				historyKept = true
				continue
			}
			if o.EndsAt == nil || o.EndsAt.After(time.Now()) {
				live[o.Registration] = true
			}
		}
		return live, historyKept
	}

	cases := []struct {
		name    string
		printed bool
		revoke  func(t *testing.T, s *Server, sd seeded)
	}{
		{"revoke one recipient's link", false, func(t *testing.T, s *Server, sd seeded) {
			if err := s.store.RevokeGuestToken(ctx, owner, sd.tokenID); err != nil {
				t.Fatal(err)
			}
		}},
		{"delete the whole pass", false, func(t *testing.T, s *Server, sd seeded) {
			if err := s.store.DeleteGuestGrant(ctx, owner, sd.grantID); err != nil {
				t.Fatal(err)
			}
		}},
		{"take down the door QR", true, func(t *testing.T, s *Server, sd seeded) {
			if err := s.store.RevokePrintedGrant(ctx, owner, sd.grantID); err != nil {
				t.Fatal(err)
			}
		}},
		{"pause all guest passes", false, func(t *testing.T, s *Server, sd seeded) {
			if err := s.store.SetGuestsEnabled(ctx, owner, false); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newGuestTestServer(t)
			sd := seed(t, s, "X", c.printed)
			if live, _ := plates(t, s, sd.permitID); !live["GUEST1"] {
				t.Fatal("the guest override was not live to begin with")
			}
			c.revoke(t, s, sd)
			live, historyKept := plates(t, s, sd.permitID)
			if live["GUEST1"] {
				t.Fatal("the guest's plate still holds the permit after their access was revoked")
			}
			if !live["OWNER1"] {
				t.Fatal("the household's own booking was swept away with the guest's")
			}
			if !historyKept {
				t.Fatal("an already-ended guest booking was deleted; revocation must not rewrite history")
			}
		})
	}
}

// TestStallClockCoversRosterTargets (H2): the pending banner used the winning
// override's creation time, which a roster-driven target does not have — so
// `stalled` could never be true, the visitor's page polled every 2.5s for as long
// as the tab stayed open, and the honest "taking longer than usual" message was
// unreachable.
func TestStallClockCoversRosterTargets(t *testing.T) {
	prev := guestStalls
	guestStalls = &stallClock{seen: map[stallKey]time.Time{}}
	t.Cleanup(func() { guestStalls = prev })

	t0 := time.Date(2026, 7, 22, 14, 0, 0, 0, time.UTC)
	const permitID = int64(7)

	if got := stallSince(permitID, "ABC123", "XYZ789", time.Time{}, t0); !got.Equal(t0) {
		t.Fatalf("first sighting = %v, want the clock to start at %v", got, t0)
	}
	// Case only differs: still the same car, so still the same clock.
	if got := stallSince(permitID, "abc123", "xyz789", time.Time{}, t0.Add(time.Minute)); !got.Equal(t0) {
		t.Fatalf("case-variant target restarted the clock: %v", got)
	}
	fresh := t0.Add(time.Minute)
	if reg, stalled := pendingState("ABC123", "XYZ789", stallSince(permitID, "ABC123", "XYZ789", time.Time{}, fresh), fresh); reg != "XYZ789" || stalled {
		t.Fatalf("a minute in = (%q,%v), want pending and not yet stalled", reg, stalled)
	}
	late := t0.Add(guestApplyTimeout + time.Minute)
	if reg, stalled := pendingState("ABC123", "XYZ789", stallSince(permitID, "ABC123", "XYZ789", time.Time{}, late), late); reg != "XYZ789" || !stalled {
		t.Fatalf("roster-driven target past the timeout = (%q,%v), want it to read as stalled", reg, stalled)
	}
	// A booked change keeps its own, truer clock: when it was asked for.
	asked := t0.Add(-time.Hour)
	if got := stallSince(permitID, "ABC123", "XYZ789", asked, late); !got.Equal(asked) {
		t.Fatalf("booked target clock = %v, want the booking's own time %v", got, asked)
	}
	// A different target is timed from scratch, not judged by the old one's clock.
	if got := stallSince(permitID, "ABC123", "OTHER1", time.Time{}, late); !got.Equal(late) {
		t.Fatalf("new target clock = %v, want %v", got, late)
	}
	// Settling forgets the clock, so the same plate applied again later spins
	// honestly instead of reading as stalled the instant it is asked for.
	settled := late.Add(time.Minute)
	if got := stallSince(permitID, "XYZ789", "XYZ789", time.Time{}, settled); !got.IsZero() {
		t.Fatalf("a settled target reported a stall clock: %v", got)
	}
	afresh := settled.Add(time.Hour)
	if got := stallSince(permitID, "ABC123", "XYZ789", time.Time{}, afresh); !got.Equal(afresh) {
		t.Fatalf("clock after settling = %v, want a fresh %v", got, afresh)
	}
}

// TestGuestManifestJSONAndShape (H5): the manifest was built with %q, which is Go
// quoting, not JSON — one decoded control byte in the path emitted \x01 and the
// whole document failed to parse, silently killing "Install".
func TestGuestManifestJSONAndShape(t *testing.T) {
	s := newGuestTestServer(t)
	good := "abcDEF0123456789_-xyz"
	w := s.getGuest("/g/manifest/" + good)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest for a well-shaped token = %d", w.Code)
	}
	var doc struct {
		StartURL string `json:"start_url"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, w.Body.String())
	}
	if doc.StartURL != "/g/"+good || doc.Scope != "/g/" {
		t.Fatalf("manifest points at %q (scope %q)", doc.StartURL, doc.Scope)
	}
	// Anything that isn't token-shaped never reaches the document at all.
	for _, bad := range []string{"short", "with\x01control", "has space", "slash/es", strings.Repeat("a", 65)} {
		w := s.getGuest("/g/manifest/" + url.PathEscape(bad))
		if w.Code == http.StatusOK {
			t.Fatalf("token %q was accepted into a manifest: %s", bad, w.Body.String())
		}
	}
}

// TestGuestGrantLabelCap (E6): the label headlines the guest's page and rides
// into the email carrying their link, so it is capped like a permit's — and
// truncated by runes, so a multi-byte name is never cut in half.
func TestGuestGrantLabelCap(t *testing.T) {
	if got := guestGrantLabel("  Nanny\x01  "); got != "Nanny" {
		t.Fatalf("guestGrantLabel = %q, want %q", got, "Nanny")
	}
	long := strings.Repeat("é", 100)
	got := guestGrantLabel(long)
	if rs := []rune(got); len(rs) != maxGuestGrantLabel {
		t.Fatalf("label kept %d runes, want %d", len(rs), maxGuestGrantLabel)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation split a multi-byte rune")
	}
}
