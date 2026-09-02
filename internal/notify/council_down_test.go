package notify

import (
	"strings"
	"testing"
)

// TestComposeApplyCouncilDown locks the auth-outage soft copy: it names the council
// as down (not the vague "still updating"), stays a low-priority soft notice, and
// drops the "do it yourself at the council" line — impossible advice when the
// council's own system is down.
func TestComposeApplyCouncilDown(t *testing.T) {
	o := ApplyOutcome{
		PermitLabel: "VPP1", Reg: "WANT1", CurrentReg: "OLD1", OK: false,
		Transient:   true,
		CouncilDown: true,
		Reason:      "The council's parking system is down right now, so p.stonn couldn't update your permit.",
		Action:      "Nothing you need to do — p.stonn keeps trying and will apply your change automatically as soon as the council's system is back.",
	}
	subject, body, priority, _ := composeApply(o, "https://council.example/portal")

	if want := "The council's system is down — your VPP1 change is waiting"; subject != want {
		t.Fatalf("subject = %q, want %q", subject, want)
	}
	if priority != "default" {
		t.Fatalf("auth-outage notice must stay low priority (soft), got %q", priority)
	}
	if !strings.Contains(body, "parking system is down right now") {
		t.Fatalf("body must name the council outage; got:\n%s", body)
	}
	if strings.Contains(body, "yourself at the council") || strings.Contains(body, "council.example/portal") {
		t.Fatalf("body must NOT tell the household to use the council portal while it is down; got:\n%s", body)
	}
}
