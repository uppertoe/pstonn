package orikan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestDiagLoginProbe performs ONE deliberate council login with (by default)
// credentials for an account that does not exist, and captures everything the
// production flow discards: the credential POST's status, final URL, response
// headers, cookie names, and full body. Its purpose is to characterise what the
// council actually says on a rejected login, and — run from two different
// networks — to distinguish "invalid credentials" from an edge/bot challenge
// that would make every VPS-originated signup fail while blaming the password
// (raised 2026-08-11 after two signups failed identically from the box's IP
// while a known-good reconnect from the same IP succeeded).
//
// Env-gated; never runs in CI:
//
//	PSTONN_DIAG_LOGIN=1 \
//	PSTONN_DIAG_OUT=/tmp/diag-login-body.html \
//	go test ./internal/provider/orikan -run TestDiagLoginProbe -v
//
// PSTONN_DIAG_USERNAME/PSTONN_DIAG_PASSWORD override the fake account (never
// use a real person's email: a nonexistent account cannot be locked out).
func TestDiagLoginProbe(t *testing.T) {
	if os.Getenv("PSTONN_DIAG_LOGIN") == "" {
		t.Skip("set PSTONN_DIAG_LOGIN=1 to run one deliberate failed council login and capture the response")
	}
	username := os.Getenv("PSTONN_DIAG_USERNAME")
	if username == "" {
		username = "pstonn.diagnostic.probe@example.com"
	}
	password := os.Getenv("PSTONN_DIAG_PASSWORD")
	if password == "" {
		password = "not-a-real-password-diagnostic-probe"
	}
	outPath := os.Getenv("PSTONN_DIAG_OUT")
	if outPath == "" {
		outPath = "diag-login-body.html"
	}

	c := New(liveConfig, nil)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	hosts := c.loginHosts()
	lc := &http.Client{Timeout: 30 * time.Second, Jar: jar,
		Transport: c.transport}

	verifier, err := randToken()
	if err != nil {
		t.Fatal(err)
	}
	authQuery, err := c.authorizeQuery(verifier)
	if err != nil {
		t.Fatal(err)
	}

	// Step 1: authorize → login form (matches Link).
	getReq, _ := http.NewRequest(http.MethodGet, c.authURL+"?"+authQuery.Encode(), nil)
	c.navHeaders(getReq)
	getReq.Header.Set("Sec-Fetch-Dest", "document")
	getReq.Header.Set("Sec-Fetch-Site", "none")
	getReq.Header.Set("Sec-Fetch-User", "?1")
	getReq.Header.Del("Referer")
	resp, err := lc.Do(getReq)
	if err != nil {
		t.Fatalf("authorize GET: %v", err)
	}
	loginPage, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	t.Logf("GET: status=%d finalURL=%s bodyBytes=%d", resp.StatusCode, resp.Request.URL, len(loginPage))

	action, fields := parseLoginForm(string(loginPage))
	if err := checkLoginForm(fields); err != nil {
		t.Fatalf("login form did not parse — the shape may have changed: %v", err)
	}
	t.Logf("form parsed: action=%q fields=%d", action, len(fields))
	actionURL, err := resolveAction(resp.Request.URL, action, hosts)
	if err != nil {
		t.Fatal(err)
	}
	fields[fieldUsername] = username
	fields[fieldPassword] = password
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	// Step 2: the credential POST (matches Link), response fully captured.
	postReq, _ := http.NewRequest(http.MethodPost, actionURL, strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.navHeaders(postReq)
	postReq.Header.Set("Sec-Fetch-Dest", "document")
	postReq.Header.Set("Sec-Fetch-Site", "same-origin")
	postReq.Header.Set("Sec-Fetch-User", "?1")
	if c.origin != "" {
		postReq.Header.Set("Origin", c.origin)
	}
	postReq.Header.Set("Referer", resp.Request.URL.String())
	presp, err := lc.Do(postReq)
	if err != nil {
		t.Fatalf("credential POST: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(presp.Body, 2<<20))
	presp.Body.Close()

	t.Logf("POST: status=%d finalURL=%s bodyBytes=%d", presp.StatusCode, presp.Request.URL, len(body))
	for _, h := range []string{"Server", "Content-Type", "X-Powered-By", "Akamai-Grn"} {
		if v := presp.Header.Get(h); v != "" {
			t.Logf("header %s: %s", h, v)
		}
	}
	authURLParsed, _ := url.Parse(c.authURL)
	cookieNames := []string{}
	for _, ck := range jar.Cookies(authURLParsed) {
		cookieNames = append(cookieNames, ck.Name)
	}
	t.Logf("jar cookies for /idm: %v", cookieNames)
	t.Logf("session cookie (%s) present: %v", sessionCookie,
		hasCookieNamed(jarCookieHeader(jar, authURLParsed), sessionCookie))

	// Fingerprint the body without dumping 100KB into the log.
	low := strings.ToLower(string(body))
	for marker, desc := range map[string]string{
		"validation-summary":           "IdentityServer validation block",
		"alert-danger":                 "Bootstrap error alert",
		"invalid username or password": "explicit credential rejection",
		"_abck":                        "Akamai bot cookie reference",
		"bm-verify":                    "Akamai challenge marker",
		"sec-cpt":                      "Akamai challenge (sec-cpt)",
		"captcha":                      "captcha reference",
		"request unsuccessful":         "Akamai/incident block page",
	} {
		if strings.Contains(low, marker) {
			t.Logf("body marker: %-30s (%s)", marker, desc)
		}
	}
	if m := regexp.MustCompile(`(?is)<title>(.*?)</title>`).FindSubmatch(body); m != nil {
		t.Logf("body <title>: %s", strings.TrimSpace(string(m[1])))
	}
	if err := os.WriteFile(outPath, body, 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	fmt.Printf("DIAG: body written to %s\n", outPath)
}
