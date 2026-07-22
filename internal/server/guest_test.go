package server

import (
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
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
