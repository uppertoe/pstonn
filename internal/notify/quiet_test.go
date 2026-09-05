package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
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
		// The span cap: a 07:00→06:00 window is 23 hours of hold, which for a
		// deferred failure notice is a full day of visitors on the wrong plate.
		// Clamped to MaxQuietHours, so 07:30 releases at 19:00 the same day...
		{"23h window is clamped to 12h", 7, 6, at(7, 30), time.Date(2026, 7, 21, 7+MaxQuietHours, 0, 0, 0, loc)},
		// ...and a time past the clamped end is outside the window entirely.
		{"past the clamped end → immediate", 7, 6, at(20, 0), time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := svc.quietDefer(store.NotifyPref{QuietFrom: c.from, QuietUntil: c.till}, c.now, nil)
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
			if got := svc.deferUntil(pref, at2am, nil, c.o); !got.Equal(c.want) {
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
	}, testPortal)
	for _, want := range []string{"VPP24714 now shows 1OF7MC", "Anita's Car (Nanny) — 1OF7MC", "as scheduled by your roster", "confirmation it went through"} {
		if !strings.Contains(subj+body, want) {
			t.Fatalf("roster copy missing %q; got subj=%q body=%q", want, subj, body)
		}
	}
	if strings.Contains(body, "(roster)") {
		t.Fatalf("body should not contain jargon %q: %q", "(roster)", body)
	}

	// Guest activation names the activator + guest-link behaviour.
	_, gb, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "guest", By: "dad@example.com", OK: true}, testPortal)
	if !strings.Contains(gb, "dad@example.com") || !strings.Contains(gb, "guest link") {
		t.Fatalf("guest copy missing activator/guest-link: %q", gb)
	}

	// A one-off booked by a household member names who booked it: on a shared
	// account that is the only thing distinguishing "the schedule ran" from
	// "someone booked over it". It must NOT be described as a guest link.
	_, ob, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "override", By: "partner@example.com", OK: true}, testPortal)
	if !strings.Contains(ob, "partner@example.com") || !strings.Contains(ob, "one-off booking") {
		t.Fatalf("override copy should name the booker: %q", ob)
	}
	if strings.Contains(ob, "guest link") {
		t.Fatalf("a member's one-off must not be described as a guest link: %q", ob)
	}
	// An unattributed one-off keeps the original second-person wording.
	_, ub, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "override", OK: true}, testPortal)
	if !strings.Contains(ub, "the one-off booking you made") {
		t.Fatalf("unattributed one-off copy changed: %q", ub)
	}

	// A printed-QR approval is attributed to the approving member, not to a link.
	_, db, _, _ := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Source: "doorqr", By: "mum@example.com", OK: true}, testPortal)
	if !strings.Contains(db, "mum@example.com") || !strings.Contains(db, "printed QR code") {
		t.Fatalf("door-QR copy missing approver/context: %q", db)
	}

	// Failure links the tenant portal and flags high priority for a hard refusal.
	_, fb, pri, tag := composeApply(ApplyOutcome{PermitLabel: "P", Reg: "X", Name: "Van", OK: false, CurrentReg: "Y", Reason: "The council refused.", Action: "Try again."}, testPortal)
	if !strings.Contains(fb, "Van — X") || !strings.Contains(fb, testPortal) {
		t.Fatalf("failure copy missing car/portal: %q", fb)
	}
	if pri != "high" || tag != "warning" {
		t.Fatalf("hard failure should be high/warning, got %s/%s", pri, tag)
	}

	// A plain transient hiccup softens: reassuring "still updating" subject, default
	// push priority (don't cry wolf on a blip that self-heals).
	ts, _, tp, _ := composeApply(ApplyOutcome{PermitLabel: "VPP1", CurrentReg: "OLD", OK: false, Transient: true, Reason: "trouble reaching the council", Action: "it will keep trying"}, testPortal)
	if !strings.Contains(ts, "Still updating") || strings.Contains(ts, "Action needed") {
		t.Fatalf("a transient blip should soften the subject, got %q", ts)
	}
	if tp != "default" {
		t.Fatalf("a transient blip should be default priority, got %s", tp)
	}

	// A CONFIRMED block is transient-but-urgent: the act-now subject and high-
	// priority push must fire even though Transient is set, so a household isn't
	// reassured while the change genuinely will not apply.
	us, ub2, up, _ := composeApply(ApplyOutcome{PermitLabel: "VPP1", CurrentReg: "OLD", OK: false, Transient: true, Urgent: true, Reason: "The council is refusing p.stonn's connection.", Action: "Change it yourself now to avoid a fine."}, testPortal)
	if !strings.Contains(us, "Action needed") || !strings.Contains(us, "still shows OLD") {
		t.Fatalf("an urgent block must use the act-now subject, got %q", us)
	}
	if up != "high" {
		t.Fatalf("an urgent block must be high priority, got %s", up)
	}
	if !strings.Contains(ub2, "avoid a fine") || !strings.Contains(ub2, testPortal) {
		t.Fatalf("urgent block body must carry the act-now action and portal: %q", ub2)
	}
}

// The "act now or risk a fine" notice must never be held by quiet hours. It is flagged
// Transient (a fleet block does clear) but Urgent, and the old actionNeeded() looked
// only at Transient — so the one message designed to break through DND was the one
// deferred until 06:00.
func TestUrgentOutcomeIsNotHeldByQuietHours(t *testing.T) {
	loc := time.FixedZone("AEST", 10*3600)
	s := &Service{loc: loc}
	pref := store.NotifyPref{QuietFrom: 22, QuietUntil: 6}
	at2330 := time.Date(2026, 8, 2, 23, 30, 0, 0, loc)
	urgent := ApplyOutcome{OK: false, Transient: true, Urgent: true}
	if got := s.deferUntil(pref, at2330, nil, urgent); !got.IsZero() {
		t.Fatalf("an urgent fine-risk notice was deferred to %v; it must send immediately", got)
	}
	// A soft transient failure is still allowed to wait for morning.
	soft := ApplyOutcome{OK: false, Transient: true}
	if got := s.deferUntil(pref, at2330, nil, soft); got.IsZero() {
		t.Fatal("a non-urgent transient failure should still respect quiet hours")
	}
}

// testPortal is the tenant portal link the composed notices point at.
const testPortal = "https://parkingpermits.stonnington.vic.gov.au/"

// Quiet hours are a household's NIGHT, and their night is where their permit is:
// a single service-wide zone reads "22:00" in the operator's city for every
// tenant. quietDefer takes the tenant's zone from the resolver, falling back to
// the service zone only when no tenant was resolved (the old behaviour).
func TestQuietHoursUseTheTenantZone(t *testing.T) {
	perth, err := time.LoadLocation("Australia/Perth")
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{loc: time.UTC}
	pref := store.NotifyPref{QuietFrom: 22, QuietUntil: 6}
	// 02:00 in Perth is 18:00 UTC the evening before: quiet in Perth, not in UTC.
	at := time.Date(2026, 7, 21, 2, 0, 0, 0, perth)
	if got := svc.quietDefer(pref, at, perth); !got.Equal(time.Date(2026, 7, 21, 6, 0, 0, 0, perth)) {
		t.Fatalf("in the tenant's zone 02:00 must hold until 06:00 there, got %v", got)
	}
	if got := svc.quietDefer(pref, at, nil); !got.IsZero() {
		t.Fatalf("with no tenant zone the service zone (UTC, 18:00) applies and sends now, got %v", got)
	}
	if got := svc.deferUntil(pref, at, perth, ApplyOutcome{OK: true}); got.IsZero() {
		t.Fatal("deferUntil must pass the tenant zone through")
	}

	// The resolver supplies the zone; without one, or when it names no tenant,
	// tenantOf reports none so the fallback applies.
	ctx := context.Background()
	if loc := svc.tenantOf(ctx, "a@example.com", "perth").Loc; loc != nil {
		t.Fatalf("no resolver: Loc = %v, want nil (service zone)", loc)
	}
	svc.TenantFor = func(_ context.Context, _, tenantID string) *tenant.Tenant {
		if tenantID == "perth" {
			return &tenant.Tenant{ID: "perth", Timezone: "Australia/Perth"}
		}
		return nil
	}
	if loc := svc.tenantOf(ctx, "a@example.com", "perth").Loc; loc == nil || loc.String() != "Australia/Perth" {
		t.Fatalf("resolved tenant: Loc = %v, want Australia/Perth", loc)
	}
	if loc := svc.tenantOf(ctx, "a@example.com", "unknown").Loc; loc != nil {
		t.Fatalf("unresolved tenant: Loc = %v, want nil (service zone)", loc)
	}
}
