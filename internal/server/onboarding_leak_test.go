package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/identity"
)

// TestInAppBrowserDetection pins the webview matcher to the user agents
// actually observed in the 2026-08 signup cohort, and — just as important —
// to NOT matching real browsers: a false positive tells someone in Safari
// their password manager won't work, which is wrong and worrying.
func TestInAppBrowserDetection(t *testing.T) {
	// Verbatim shapes from the production access logs (Facebook iOS app) plus
	// the documented Android and Instagram markers.
	inApp := []string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/23G71 Safari/604.1 [FBAN/FBIOS;FBAV/575.0.0.30.70;FBDV/iPhone17,2;FBMD/iPhone;FBSN/iOS;FBSV/26.6;FBID/phone;FBLC/en_GB;IABMV/1]",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/apk;]",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/21F90 Instagram 334.0.0.27.93",
	}
	for _, ua := range inApp {
		if !inAppBrowser(ua) {
			t.Errorf("in-app webview not detected: %s", ua)
		}
	}
	real := []string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 26_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		"", // no UA at all
	}
	for _, ua := range real {
		if inAppBrowser(ua) {
			t.Errorf("real browser misread as in-app webview: %q", ua)
		}
	}
}

// TestOnboardingCopyStaysQuietWhereItShould covers the ABSENT side of the new
// leak-fix copy, which the positive render table cannot: advice that shows up
// for the wrong audience is noise that trains people to skip banners.
func TestOnboardingCopyStaysQuietWhereItShould(t *testing.T) {
	loc := melbourne(t)
	user := identity.User{Email: "a@b.com"}
	tm := loadTerms("")

	render := func(d dashboardData) string {
		t.Helper()
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, "dashboard", d); err != nil {
			t.Fatalf("render: %v", err)
		}
		return buf.String()
	}

	// A real browser gets no webview warning.
	out := render(dashboardData{User: user, State: "onboarding", IsPrimary: true, Loc: loc})
	if strings.Contains(out, "In the Facebook or Instagram app") {
		t.Fatal("webview advice shown to a real browser")
	}

	// A secondary waiting on the owner links nothing, so the webview note (a
	// link-form aid) has no business on their page either.
	out = render(dashboardData{User: user, State: "onboarding", IsPrimary: false, SharedWith: "p@example.com", InAppBrowser: true, Loc: loc})
	if strings.Contains(out, "In the Facebook or Instagram app") {
		t.Fatal("webview advice shown to a secondary with no form to fill")
	}

	// A terms RE-ACCEPT returns to a working, already-linked app: telling that
	// person to go reset an ePermits password implies something broke.
	out = render(dashboardData{User: user, State: "terms", IsPrimary: true, Loc: loc,
		Terms: termsView{Version: tm.Version, Clauses: tm.Clauses, Updated: true}})
	if strings.Contains(out, "ePermits password") {
		t.Fatal("next-step password heads-up shown on a terms re-accept")
	}

	// A secondary accepting terms next joins a household, not the tenant.
	out = render(dashboardData{User: user, State: "terms", IsPrimary: false, Loc: loc,
		Terms: termsView{Version: tm.Version, Clauses: tm.Clauses}})
	if strings.Contains(out, "ePermits password") {
		t.Fatal("next-step password heads-up shown to a secondary")
	}
}
