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
	resident := parking.PermitInfo{PermitType: "Resident Permit", CanChangeVehicle: false}

	cases := []struct {
		name    string
		permits []parking.PermitInfo
		want    bool
	}{
		{"normal account: name matches, no fallback", []parking.PermitInfo{visitor, resident}, false},
		{"renamed types with a changeable permit: fallback engages", []parking.PermitInfo{renamed, resident}, true},
		{"nothing changeable: no fallback (genuinely unschedulable)", []parking.PermitInfo{resident}, false},
		{"empty account: no fallback", nil, false},
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
