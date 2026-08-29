package notify

import (
	"context"
	"strings"
	"testing"
)

// TestOnboardNudgeMessage pins the recovery email to the three drop-off causes
// the 2026-08 access logs actually showed, each with its own actionable line:
// no working ePermits password (reset deep link), a mismatched email (named
// with THEIR address), and the Facebook webview (open the real browser, with
// somewhere to go). Plus the promises the sweep's code relies on: once-ever,
// and honest about needing an existing permit.
func TestOnboardNudgeMessage(t *testing.T) {
	subject, body := onboardNudgeMessage("resident@example.com", "https://p.stonn.example", (&Service{}).tenantOf(context.Background(), ""))

	if subject == "" || strings.Contains(subject, "\n") {
		t.Fatalf("subject unusable: %q", subject)
	}
	for _, want := range []string{
		testResetURL,                      // remedy 1: reset, deep-linked
		"never set one",                   // …including the paper-signup resident
		"resident@example.com",            // remedy 2: the same-email rule names THEIR address
		"different email address",         //
		"built-in browser",                // remedy 3: the webview trap
		"https://p.stonn.example",         // …with the escape hatch to the real browser
		"VISITOR permits only",            // honest scope: never a resident permit…
		"can't apply for one",             // …and never an application, only a permit already held
		testRegisterURL,                   // the no-account-at-all reader gets the sign-up door
		"guest QR codes",                  // what's waiting is the whole permit toolkit, not just a roster
		"the only reminder p.stonn sends", // the once-ever promise the sweep enforces
	} {
		if !strings.Contains(body, want) {
			t.Errorf("nudge body is missing %q", want)
		}
	}

	// Each URL must sit under a SHORT "do this:" label line — the mailer's HTML
	// alternative turns that line into the button text, so a label folded into
	// its sentence renders the whole sentence on the button (shipped that way
	// briefly, 2026-08-23).
	for _, pair := range []string{
		"Reset it at the council:\n" + testResetURL,
		"Open p.stonn in Safari or Chrome:\nhttps://p.stonn.example",
		"Register with the council:\n" + testRegisterURL,
	} {
		if !strings.Contains(body, pair) {
			t.Errorf("nudge body is missing the label/URL pairing %q", pair)
		}
	}

	// A deployment with no public URL keeps the browser advice, minus the address.
	_, body = onboardNudgeMessage("resident@example.com", "", (&Service{}).tenantOf(context.Background(), ""))
	if strings.Contains(body, "p.stonn.example") {
		t.Fatal("stale URL leaked into the no-URL variant")
	}
	if !strings.Contains(body, "built-in browser") {
		t.Fatal("webview advice dropped when no public URL is configured")
	}
}

const (
	testResetURL    = "https://parkingpermits.stonnington.vic.gov.au/idm/account/ForgotPassword"
	testRegisterURL = "https://parkingpermits.stonnington.vic.gov.au/idm/account/Register"
)
