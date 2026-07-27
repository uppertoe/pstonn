package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/model"
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
	got := parseEmails("Dad@Example.com, mum@example.com\n dad@example.com ; bogus ,,")
	want := []string{"dad@example.com", "mum@example.com"} // lower-cased, de-duped, invalid dropped
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseEmails = %v, want %v", got, want)
	}
	if len(parseEmails("")) != 0 {
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
		t.Fatalf("roster-driven mismatch = (%q,%v), want pending, never stalled without a decision time", reg, stalled)
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
		{"pending", "pending"}, {"denied", "denied"}, {"expired", "denied"},
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

	// With the approval's own override live, the state tracks the council record:
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
	grantA, err := s.store.CreatePrintedGrant(ctx, owner, pidA, "hashA", "sealedA")
	if err != nil {
		t.Fatal(err)
	}
	grantB, err := s.store.CreatePrintedGrant(ctx, owner, pidB, "hashB", "sealedB")
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
