package server

import (
	"testing"

	"github.com/uppertoe/pstonn/internal/parking"
)

// TestVisitorNameFallback: the council owns the permit-type display text, and a
// rename used to make every permit unaddable overnight, with the picker flatly
// asserting nothing on the account can be scheduled. The fallback engages only
// when NO permit matches the name and the council itself says a vehicle can be
// changed — and never loosens the normal path while the name still works.
func TestVisitorNameFallback(t *testing.T) {
	visitor := parking.PermitInfo{PermitType: "(A) 1st Visitor Permit", CanChangeVehicle: true}
	renamed := parking.PermitInfo{PermitType: "(A) 1st Guest Parking Entitlement", CanChangeVehicle: true}
	// Confirmed 2026-08-21: real Stonnington resident permits ARE holder-changeable.
	resident := parking.PermitInfo{PermitType: "(A) 1st Resident Permit", CanChangeVehicle: true}
	fixed := parking.PermitInfo{PermitType: "Prescribed Accommodation Permit", CanChangeVehicle: false}

	cases := []struct {
		name    string
		permits []parking.PermitInfo
		want    bool
	}{
		{"normal account: name matches, no fallback", []parking.PermitInfo{visitor, resident}, false},
		{"renamed types with a changeable permit: fallback engages", []parking.PermitInfo{renamed, fixed}, true},
		{"nothing changeable: no fallback (genuinely unschedulable)", []parking.PermitInfo{fixed}, false},
		{"empty account: no fallback", nil, false},
		// visitorNameFallback itself does NOT know about resident permits — a
		// changeable-resident-only account still engages the fallback here; the
		// resident exclusion lives at the call site (visitorSchedulable), verified
		// in TestVisitorSchedulable.
		{"resident-only changeable account: fallback still engages", []parking.PermitInfo{resident}, true},
		// The presence of ANY visitor-named permit disables the fallback for the
		// whole account, even if other changeable permits exist — the name filter
		// is still working, so it stays authoritative.
		{"mixed: visitor name present disables fallback", []parking.PermitInfo{visitor, renamed}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := visitorNameFallback(c.permits); got != c.want {
				t.Fatalf("visitorNameFallback = %v, want %v", got, c.want)
			}
		})
	}
}

func TestIsResidentPermit(t *testing.T) {
	cases := map[string]bool{
		"(A) 1st Resident Permit":         true,
		"(A) 2nd Resident Permit":         true,
		"Resident Permit":                 true,
		"Residential Tradesperson Permit": false, // a DIFFERENT type; "resident" matched as a whole word only
		"(A) 1st Visitor Permit":          false,
		"Special Occasion Permit":         false,
		"Prescribed Accommodation Permit": false,
	}
	for name, want := range cases {
		if got := isResidentPermit(name); got != want {
			t.Errorf("isResidentPermit(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestVisitorSchedulable pins the shared picker/addPermit predicate: a resident
// permit must never be schedulable — not even under the fallback, where it is both
// changeable and non-visitor-named — because it holds the resident's own everyday
// vehicle. A genuinely renamed visitor permit still gets through the fallback.
// The predicate is TYPE eligibility only; the holder-can-change-vehicle check is a
// separate downstream gate (so a locked visitor permit stays type-eligible here
// and earns its own "can't change vehicle" message rather than "only visitor").
func TestVisitorSchedulable(t *testing.T) {
	visitor := parking.PermitInfo{PermitType: "(A) 1st Visitor Permit", CanChangeVehicle: true}
	visitorLocked := parking.PermitInfo{PermitType: "(A) 1st Visitor Permit", CanChangeVehicle: false}
	resident := parking.PermitInfo{PermitType: "(A) 1st Resident Permit", CanChangeVehicle: true}
	renamed := parking.PermitInfo{PermitType: "(A) 1st Guest Parking Entitlement", CanChangeVehicle: true}

	cases := []struct {
		name     string
		p        parking.PermitInfo
		fallback bool
		want     bool
	}{
		{"visitor permit, no fallback: type-eligible", visitor, false, true},
		{"visitor permit with vehicle locked: still type-eligible (changeable gated downstream)", visitorLocked, false, true},
		{"resident permit, no fallback: not schedulable", resident, false, false},
		{"resident permit UNDER fallback: still not schedulable (the footgun)", resident, true, false},
		{"renamed visitor permit under fallback: schedulable", renamed, true, true},
		{"renamed visitor permit without fallback: not schedulable", renamed, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := visitorSchedulable(c.p, c.fallback); got != c.want {
				t.Fatalf("visitorSchedulable(%q, fallback=%v) = %v, want %v", c.p.PermitType, c.fallback, got, c.want)
			}
		})
	}
}
