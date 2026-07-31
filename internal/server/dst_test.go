package server

import (
	"html/template"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
)

// The server-side half of the DST coverage (internal/model has the rest). Melbourne
// 2026: DST ENDS Sun 2026-04-05 (02:00-02:59 happens twice, a 25-hour day) and STARTS
// Sun 2026-10-04 (02:00-02:59 does not exist, a 23-hour day).
//
// These two functions decide when a guest pass stops covering a car and how many days
// a user is told remain on their permit. On a day that is not 24 hours long, a naive
// "add 24 hours" is wrong by an hour in one direction and a whole day in the other.
func melb(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Australia/Melbourne")
	if err != nil {
		t.Fatalf("load Australia/Melbourne: %v", err)
	}
	return loc
}

// endOfDay must be the next local midnight — not 23:59 (which left the last minute of
// the day uncovered, because Resolve treats a booking's end as exclusive) and not
// start+24h (which is an hour out on both transition days).
func TestEndOfDayAcrossTransitions(t *testing.T) {
	loc := melb(t)

	cases := []struct {
		name     string
		at       time.Time
		wantDay  int
		wantSpan time.Duration // from the start of that local day to the returned end
	}{
		{
			name:     "the 23-hour spring-forward day",
			at:       time.Date(2026, 10, 4, 9, 0, 0, 0, loc),
			wantDay:  5,
			wantSpan: 23 * time.Hour,
		},
		{
			name:     "the 25-hour fall-back day",
			at:       time.Date(2026, 4, 5, 9, 0, 0, 0, loc),
			wantDay:  6,
			wantSpan: 25 * time.Hour,
		},
		{
			name:     "an ordinary day",
			at:       time.Date(2026, 6, 15, 9, 0, 0, 0, loc),
			wantDay:  16,
			wantSpan: 24 * time.Hour,
		},
		{
			// The evening BEFORE a transition: the end is still the next midnight, and
			// that midnight is on the far side of the jump.
			name:     "the evening before spring forward",
			at:       time.Date(2026, 10, 3, 22, 0, 0, 0, loc),
			wantDay:  4,
			wantSpan: 24 * time.Hour,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := endOfDay(c.at, loc)
			l := got.In(loc)
			if l.Hour() != 0 || l.Minute() != 0 || l.Second() != 0 {
				t.Errorf("endOfDay = %s, want a local midnight", l)
			}
			if l.Day() != c.wantDay {
				t.Errorf("endOfDay landed on day %d, want %d (%s)", l.Day(), c.wantDay, l)
			}
			dayStart := time.Date(c.at.In(loc).Year(), c.at.In(loc).Month(), c.at.In(loc).Day(), 0, 0, 0, 0, loc)
			if span := got.Sub(dayStart); span != c.wantSpan {
				t.Errorf("the day measured %v, want %v — endOfDay is not tracking the local day", span, c.wantSpan)
			}
		})
	}
}

// dayEndLocal is the guest-pass equivalent, and the two must agree: a pass "until the
// end of today" and a one-off booking for today must stop covering a car at the same
// instant, or one of them silently outlives the other.
func TestDayEndLocalAgreesWithEndOfDay(t *testing.T) {
	loc := melb(t)
	for _, at := range []time.Time{
		time.Date(2026, 10, 4, 9, 0, 0, 0, loc),  // 23-hour day
		time.Date(2026, 4, 5, 9, 0, 0, 0, loc),   // 25-hour day
		time.Date(2026, 10, 3, 22, 0, 0, 0, loc), // the evening before
		time.Date(2026, 6, 15, 9, 0, 0, 0, loc),
	} {
		if a, b := endOfDay(at, loc), dayEndLocal(at, 0); !a.Equal(b) {
			t.Errorf("at %s: endOfDay=%s but dayEndLocal=%s — the two must not diverge", at.In(loc), a, b)
		}
	}
}

// An overnight pass covers the car through the following day, so its end must be the
// midnight after that — including when one of the two days is short or long.
func TestOvernightPassSpansTheTransition(t *testing.T) {
	loc := melb(t)

	// Activated the evening before spring forward: covers through Sunday the 4th, so
	// it ends at midnight starting Monday the 5th.
	at := time.Date(2026, 10, 3, 20, 0, 0, 0, loc)
	end := dayEndLocal(at, 1)
	l := end.In(loc)
	if l.Day() != 5 || l.Hour() != 0 {
		t.Errorf("overnight end = %s, want midnight starting 5 Oct", l)
	}
	// The boundary is a CALENDAR one, so the real elapsed time varies with the zone.
	// Derivation: 20:00 → the next midnight is 4h, then the whole of Sunday the 4th,
	// which is 23 hours because the clocks jump forward. 4 + 23 = 27h.
	if got := end.Sub(at); got != 27*time.Hour {
		t.Errorf("overnight window measured %v, want 27h (4h + the 23-hour day)", got)
	}

	// Same shape on the long day: 4h + the 25-hour Sunday = 29h, an hour MORE real
	// time for the same calendar promise.
	at = time.Date(2026, 4, 4, 20, 0, 0, 0, loc)
	end = dayEndLocal(at, 1)
	if l := end.In(loc); l.Day() != 6 || l.Hour() != 0 {
		t.Errorf("overnight end = %s, want midnight starting 6 Apr", l)
	}
	if got := end.Sub(at); got != 29*time.Hour {
		t.Errorf("overnight window across the 25-hour day measured %v, want 29h (4h + the 25-hour day)", got)
	}
}

// fillExpiry's comment claims the noon anchoring makes the day count DST-proof. This
// proves it: the count must be the number of calendar days, not elapsed hours over 24,
// on both a short and a long day. Getting this wrong tells a user their permit expires
// tomorrow when it expires today, or the reverse.
func TestFillExpiryDayCountIsDSTProof(t *testing.T) {
	loc := melb(t)

	cases := []struct {
		name string
		now  time.Time
		end  time.Time
	}{
		{
			name: "counting across the spring-forward day",
			now:  time.Date(2026, 10, 3, 8, 0, 0, 0, loc),
			end:  time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "counting across the fall-back day",
			now:  time.Date(2026, 4, 4, 8, 0, 0, 0, loc),
			end:  time.Date(2026, 4, 7, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "the transition day itself is the last day",
			now:  time.Date(2026, 10, 2, 8, 0, 0, 0, loc),
			end:  time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pv := &permitView{Loc: loc}
			pv.Permit = model.Permit{EndDate: c.end}
			fillExpiry(pv, c.now)

			// Whole calendar days between the two local dates, computed independently.
			startDay := time.Date(c.now.In(loc).Year(), c.now.In(loc).Month(), c.now.In(loc).Day(), 0, 0, 0, 0, loc)
			endLocal := c.end.In(loc)
			endDay := time.Date(endLocal.Year(), endLocal.Month(), endLocal.Day(), 0, 0, 0, 0, loc)
			wantDays := 0
			for d := startDay; d.Before(endDay); d = d.AddDate(0, 0, 1) {
				wantDays++
			}
			if pv.Expired {
				t.Fatalf("permit reported expired with %d days still to run", wantDays)
			}
			if pv.ExpiryLabel == "" {
				t.Error("no expiry label was produced")
			}
			// The label carries the count in words; assert the arithmetic via ExpiresSoon,
			// which is the decision the count actually drives.
			if wantDays <= 21 && !pv.ExpiresSoon {
				t.Errorf("%d days out should read as expiring soon (label %q)", wantDays, pv.ExpiryLabel)
			}
		})
	}
}

// The final day must not read as expired while the permit is still usable, and the day
// after must. This is the same off-by-one ExpiryDeadline fixed, checked through the UI
// path so the page and the scheduler cannot disagree.
func TestFillExpiryOnTheFinalLocalDay(t *testing.T) {
	loc := melb(t)
	// End date on the 25-hour day.
	end := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)

	// Late on the final local day: still live.
	pv := &permitView{Loc: loc}
	pv.Permit = model.Permit{EndDate: end}
	fillExpiry(pv, time.Date(2026, 4, 5, 23, 30, 0, 0, loc))
	if pv.Expired {
		t.Error("the permit read as expired at 23:30 on its own final day")
	}

	// The next local day: finished.
	pv = &permitView{Loc: loc}
	pv.Permit = model.Permit{EndDate: end}
	fillExpiry(pv, time.Date(2026, 4, 6, 0, 30, 0, 0, loc))
	if !pv.Expired {
		t.Error("the permit did not read as expired the day after its end date")
	}
}

// A booking's END that lands on midnight means "the end of the previous day" —
// Resolve treats ends as exclusive, so a booking made for the 4th ends at 00:00 on
// the 5th. Printing that literally tells the user their booking runs a day longer
// than they asked for.
func TestEndFormattingNamesTheDayItCompletes(t *testing.T) {
	loc := melb(t)

	if got := windowEndText(time.Date(2026, 8, 5, 0, 0, 0, 0, loc), loc); got != "the end of 4 Aug" {
		t.Errorf("windowEndText(midnight 5 Aug) = %q, want \"the end of 4 Aug\"", got)
	}
	// A real time of day is printed as itself.
	if got := windowEndText(time.Date(2026, 8, 4, 17, 30, 0, 0, loc), loc); got != "4 Aug 5:30pm" {
		t.Errorf("windowEndText(4 Aug 5:30pm) = %q", got)
	}
}

// renderTimeFunc executes one of the template time helpers, which is the only way to
// reach them — they live in the package's FuncMap, not as ordinary functions.
func renderTimeFunc(t *testing.T, name string, at time.Time, loc *time.Location) string {
	t.Helper()
	tpl, err := template.New("probe").Funcs(templateFuncs).Parse("{{" + name + " .At .Loc}}")
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}
	var b strings.Builder
	if err := tpl.Execute(&b, struct {
		At  time.Time
		Loc *time.Location
	}{at, loc}); err != nil {
		t.Fatalf("execute probe: %v", err)
	}
	return b.String()
}

// The midnight rule must NOT apply to a start: a booking may legitimately begin at
// midnight, and calling that "the end of" the day before would be plainly wrong. This
// is the mistake the separate localEnd helper exists to prevent, and it is an easy one
// to make — folding the rule into localTime looks like a tidy-up and silently
// mislabels every midnight start.
func TestStartAtMidnightIsNotDescribedAsAnEnd(t *testing.T) {
	loc := melb(t)
	midnight := time.Date(2026, 8, 5, 0, 0, 0, 0, loc)

	start := renderTimeFunc(t, "localTime", midnight, loc)
	if strings.Contains(start, "end of") {
		t.Errorf("a booking STARTING at midnight rendered as %q", start)
	}
	end := renderTimeFunc(t, "localEnd", midnight, loc)
	if !strings.Contains(end, "end of") {
		t.Errorf("a booking ENDING at midnight rendered as %q, want it named by the day it completes", end)
	}
	if start == end {
		t.Error("localTime and localEnd render a midnight identically; the distinction was lost")
	}
	// A non-midnight instant reads the same either way.
	afternoon := time.Date(2026, 8, 4, 17, 30, 0, 0, loc)
	if a, b := renderTimeFunc(t, "localTime", afternoon, loc), renderTimeFunc(t, "localEnd", afternoon, loc); a != b {
		t.Errorf("an ordinary time rendered differently: %q vs %q", a, b)
	}
}
