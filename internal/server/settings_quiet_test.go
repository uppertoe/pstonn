package server

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/notify"
)

// TestSaveNotifyQuietHoursClamp drives POST /notifications through the real
// router and reads the saved preference back, so the two nudges saveNotify
// applies to quiet hours are locked at the store boundary: equal start and end
// (which would silently disable the window) are nudged an hour apart, and a
// window wider than notify.MaxQuietHours is capped at that many hours from the
// start — the hold covers failure notices too, so an over-wide window is a day
// of "your permit couldn't be updated" sitting unread. Absent or out-of-range
// hours fall back to the 22:00–06:00 defaults, and an unticked box stores the
// equal pair that means "off".
func TestSaveNotifyQuietHoursClamp(t *testing.T) {
	s := newAuthzServer(t)
	// A notify service with neither mail nor ntfy configured: the "keep one
	// channel on" guard is then moot, so the quiet-hours branch is reached with
	// every form. The decide key is required by the constructor, unused here.
	s.notify = notify.New(nil, nil, "", "", "https://app.example.com", "", "", time.UTC, nil,
		notify.DeriveDecideKey(bytes.Repeat([]byte{7}, 32)))
	const user, origin = "quiet@example.com", "http://app.example.com"
	ctx := context.Background()
	if err := s.store.RecordConsent(ctx, user, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		enabled     bool
		from, until string
		wantFrom    int
		wantUntil   int
	}{
		{"ordinary overnight window", true, "22", "6", 22, 6},
		{"equal hours are nudged apart", true, "8", "8", 8, 9},
		{"23:00 to 23:00 wraps the nudge past midnight", true, "23", "23", 23, 0},
		{"window wider than the cap is trimmed to the cap", true, "20", "18", 20, (20 + notify.MaxQuietHours) % 24},
		{"exactly the cap is left alone", true, "20", strconv.Itoa((20 + notify.MaxQuietHours) % 24), 20, (20 + notify.MaxQuietHours) % 24},
		{"wrap-around window under the cap is kept", true, "21", "5", 21, 5},
		{"blank hours fall back to the defaults", true, "", "", 22, 6},
		{"out-of-range hours fall back to the defaults", true, "25", "-1", 22, 6},
		{"junk hours fall back to the defaults", true, "ten", "6pm", 22, 6},
		{"unticked stores the disabled pair", false, "22", "6", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"email_enabled": {"1"}, "quiet_from": {tc.from}, "quiet_until": {tc.until}}
			if tc.enabled {
				form.Set("quiet_enabled", "1")
			}
			w := s.doReq("POST", "/notifications", user, origin, form)
			// A plain (non-htmx) save lands back on Settings; the nudge cases re-render
			// through the same redirect, so the status is the same either way.
			if w.Code != http.StatusSeeOther {
				t.Fatalf("POST /notifications = %d %s", w.Code, excerpt(w.Body.String()))
			}
			pref, err := s.store.GetNotifyPref(ctx, user)
			if err != nil {
				t.Fatal(err)
			}
			if pref.QuietFrom != tc.wantFrom || pref.QuietUntil != tc.wantUntil {
				t.Fatalf("saved quiet hours = %d→%d, want %d→%d", pref.QuietFrom, pref.QuietUntil, tc.wantFrom, tc.wantUntil)
			}
			if tc.enabled {
				if span := ((pref.QuietUntil - pref.QuietFrom) + 24) % 24; span == 0 || span > notify.MaxQuietHours {
					t.Fatalf("saved span %dh violates the 1..%d bound", span, notify.MaxQuietHours)
				}
			}
		})
	}
}
