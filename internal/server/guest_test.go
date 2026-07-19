package server

import (
	"strings"
	"testing"
	"time"
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
