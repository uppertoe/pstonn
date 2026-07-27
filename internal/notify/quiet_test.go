package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

func TestQuietDefer(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	svc := &Service{loc: loc}
	at := func(h, m int) time.Time { return time.Date(2026, 7, 21, h, m, 0, 0, loc) }
	day6 := time.Date(2026, 7, 21, 6, 0, 0, 0, loc)
	next6 := time.Date(2026, 7, 22, 6, 0, 0, 0, loc)

	cases := []struct {
		name       string
		from, till int
		now        time.Time
		want       time.Time // zero = immediate
	}{
		{"midnight roster change → 6am", 22, 6, at(0, 1), day6},
		{"2am → 6am", 22, 6, at(2, 0), day6},
		{"11pm → next 6am", 22, 6, at(23, 0), next6},
		{"exactly 22:00 → next 6am", 22, 6, at(22, 0), next6},
		{"noon → immediate", 22, 6, at(12, 0), time.Time{}},
		{"6am boundary → immediate (window is exclusive)", 22, 6, at(6, 0), time.Time{}},
		{"disabled (equal) → immediate even at 2am", 0, 0, at(2, 0), time.Time{}},
		{"non-wrap window 1..5, 3am → 5am", 1, 5, at(3, 0), time.Date(2026, 7, 21, 5, 0, 0, 0, loc)},
		{"non-wrap window 1..5, 6am → immediate", 1, 5, at(6, 0), time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := svc.quietDefer(store.NotifyPref{QuietFrom: c.from, QuietUntil: c.till}, c.now)
			if !got.Equal(c.want) {
				t.Fatalf("quietDefer = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDeferUntilActionNeeded covers the exemption: a hard "action needed"
// failure (a non-transient error the user must act on) bypasses the quiet-hours
// hold and sends immediately, while successes and transient failures still defer.
func TestDeferUntilActionNeeded(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	svc := &Service{loc: loc}
	pref := store.NotifyPref{QuietFrom: 22, QuietUntil: 6} // covers 02:00
	at2am := time.Date(2026, 7, 21, 2, 0, 0, 0, loc)
	day6 := time.Date(2026, 7, 21, 6, 0, 0, 0, loc)

	cases := []struct {
		name string
		o    ApplyOutcome
		want time.Time // zero = immediate
	}{
		{"success defers to 6am", ApplyOutcome{OK: true}, day6},
		{"transient failure defers to 6am", ApplyOutcome{OK: false, Transient: true}, day6},
		{"hard failure sends immediately", ApplyOutcome{OK: false, Transient: false}, time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := svc.deferUntil(pref, at2am, c.o); !got.Equal(c.want) {
				t.Fatalf("deferUntil = %v, want %v", got, c.want)
			}
		})
	}
}

func TestComposeApplyCopy(t *testing.T) {
	// Roster success: subject leads with the plate; body uses an em-dash (no nested
	// parens) and natural source wording (no trailing "(roster)").
	subj, body, _, _ := composeApply(ApplyOutcome{
		PermitLabel: "VPP24714", Reg: "1OF7MC", Name: "Anita's Car (Nanny)", Source: "roster", OK: true,
	})
	for _, want := range []string{"VPP24714 now shows 1OF7MC", "Anita's Car (Nanny) — 1OF7MC", "as scheduled by your weekly roster", "confirmation it went through"} {
		if !strings.Contains(subj+body, want) {
			t.Fatalf("roster copy missing %q; got subj=%q body=%q", want, subj, body)
		}
	}
	if strings.Contains(body, "(roster)") {
		t.Fatalf("body should not contain jargon %q: %q", "(roster)", body)
	}

	// Guest activation names the activator + guest-link behaviour.
	_, gb, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "guest", By: "dad@example.com", OK: true})
	if !strings.Contains(gb, "dad@example.com") || !strings.Contains(gb, "guest link") {
		t.Fatalf("guest copy missing activator/guest-link: %q", gb)
	}

	// A one-off booked by a household member names who booked it: on a shared
	// account that is the only thing distinguishing "the schedule ran" from
	// "someone booked over it". It must NOT be described as a guest link.
	_, ob, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "override", By: "partner@example.com", OK: true})
	if !strings.Contains(ob, "partner@example.com") || !strings.Contains(ob, "one-off booking") {
		t.Fatalf("override copy should name the booker: %q", ob)
	}
	if strings.Contains(ob, "guest link") {
		t.Fatalf("a member's one-off must not be described as a guest link: %q", ob)
	}
	// An unattributed one-off keeps the original second-person wording.
	_, ub, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "override", OK: true})
	if !strings.Contains(ub, "the one-off booking you made") {
		t.Fatalf("unattributed one-off copy changed: %q", ub)
	}

	// A printed-QR approval is attributed to the approving member, not to a link.
	_, db, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "doorqr", By: "mum@example.com", OK: true})
	if !strings.Contains(db, "mum@example.com") || !strings.Contains(db, "printed door QR") {
		t.Fatalf("door-QR copy missing approver/context: %q", db)
	}

	// Failure links the council portal and flags high priority for a hard refusal.
	_, fb, pri, tag := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Name: "Van", OK: false, CurrentReg: "Y", Reason: "The council refused.", Action: "Try again."})
	if !strings.Contains(fb, "Van — X") || !strings.Contains(fb, councilPortalURL) {
		t.Fatalf("failure copy missing car/portal: %q", fb)
	}
	if pri != "high" || tag != "warning" {
		t.Fatalf("hard failure should be high/warning, got %s/%s", pri, tag)
	}
}
