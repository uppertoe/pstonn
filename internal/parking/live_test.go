package parking

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/uppertoe/pstonn/internal/provider"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider/orikan"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// TestLiveCheckSession is a one-shot "is this cookie still valid right now?"
// probe, the quickest way to sample the idle timeout at a single point (e.g.
// "does a 12-hour-old session still stand?"). It attempts one silent-renew on the
// supplied cookie and reports alive/dead plus the fresh token's expiry. It does
// NOT sleep. Provide the session cookie captured at the earlier login:
//
//	PSTONN_LIVE_COOKIE='idsrv.session=...; Permits.IDM.Identity=...' \
//	go test ./internal/parking -run TestLiveCheckSession -v
func TestLiveCheckSession(t *testing.T) {
	cookie := os.Getenv("PSTONN_LIVE_COOKIE")
	if cookie == "" {
		t.Skip("set PSTONN_LIVE_COOKIE to check whether a session is still valid")
	}
	ctx := context.Background()
	c, _, _ := liveClient(t)

	at, exp, next, err := ork(c).SilentRenew(ctx, cookie)
	switch {
	case err == nil:
		t.Logf("ALIVE ✓ the session still stands, silent-renew minted a fresh token (expires %s, %s from now).",
			exp.Format(time.RFC3339), time.Until(exp).Round(time.Second))
		t.Logf("cookie rotated on renew: %v; token length: %d", next != "", len(at))
		t.Log("=> the idle timeout is AT LEAST the time since this cookie was last used.")
	case errors.Is(err, provider.ErrSessionExpired):
		t.Log("EXPIRED ✗ the session has lapsed, a re-link (fresh login) is required.")
		t.Log("=> the idle timeout is LESS than the time since this cookie was last used.")
	default:
		t.Fatalf("probe error (not a clean expiry): %v", err)
	}
}

// ork returns the Orikan provider behind a live client, for protocol-level probes.
func ork(c *Client) *orikan.Client { return c.Provider().(*orikan.Client) }

func liveClient(t *testing.T) (*Client, *secretbox.Box, *store.Store) {
	t.Helper()
	cfg := &config.Config{Council: config.CouncilConfig{
		Issuer:      "https://parkingpermits.stonnington.vic.gov.au/idm",
		ClientID:    "ePermits.ssp.web",
		RedirectURI: "https://parkingpermits.stonnington.vic.gov.au/ssp/callback",
		Scopes:      []string{"openid", "profile", "ePermits.ssp.api.all"},
		APIBase:     "https://parkingpermits.stonnington.vic.gov.au/ssp-svc",
	}}
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return liveOrikanClient(cfg, st, box), box, st
}

// TestLiveMeasureIdleTimeout empirically brackets the tenant session cookie's
// idle (sliding) timeout, the number that should drive COUNCIL_WARM_INTERVAL.
// Keep-warm exists only to touch the cookie before it lapses from disuse, so the
// cheapest safe interval is a large fraction of this timeout; 45m was a
// conservative guess, not a measurement.
//
// Method: obtain a fresh session (preferably via a headless login so it's
// ISOLATED from any browser you might use), then repeatedly idle for a growing
// gap and drive one keep-warm Refresh (the real production path, silent-renew +
// cookie rotation persisted). Each success resets the sliding clock, so we grow
// the gap; the first failure brackets the idle window between the last success
// and this gap. It logs every probe with an absolute clock time so progress is
// legible in a long unattended run.
//
// Preferred (isolated, survives you using the tenant site in a browser):
//
//	PSTONN_LIVE_USERNAME=you@example.com PSTONN_LIVE_PASSWORD=… \
//	PSTONN_PROBE_START=1h PSTONN_PROBE_FACTOR=1.5 PSTONN_PROBE_MAX=14h \
//	go test ./internal/parking -run TestLiveMeasureIdleTimeout -timeout 0 -v
//
// Or seed a fresh cookie instead of credentials (then DON'T touch that browser
// session while it runs, or it will slide independently):
//
//	PSTONN_LIVE_COOKIE='idsrv.session=…; Permits.IDM.Identity=…' … same flags
//
// Caveat: a failure could also be an ABSOLUTE session cap rather than the idle
// timeout; either way the last-success gap is a SAFE lower bound for the warm
// interval (we'd just renew a little more often than strictly needed).
func TestLiveMeasureIdleTimeout(t *testing.T) {
	user := os.Getenv("PSTONN_LIVE_USERNAME")
	pass := os.Getenv("PSTONN_LIVE_PASSWORD")
	cookie := os.Getenv("PSTONN_LIVE_COOKIE")
	if user == "" && cookie == "" {
		t.Skip("set PSTONN_LIVE_USERNAME+PSTONN_LIVE_PASSWORD (preferred) or PSTONN_LIVE_COOKIE, and run with -timeout 0")
	}
	start := envDurationTest(t, "PSTONN_PROBE_START", time.Hour)
	factor := envFloatTest(t, "PSTONN_PROBE_FACTOR", 1.5)
	max := envDurationTest(t, "PSTONN_PROBE_MAX", 14*time.Hour)
	if factor <= 1 {
		factor = 1.5
	}

	ctx := context.Background()
	c, box, st := liveClient(t)
	const owner = "measure@local"

	// Obtain a fresh, isolated session in the store, then drive keep-warm Refresh.
	// Progress goes to stdout (fmt) not t.Log, so it streams live during the run.
	if user != "" {
		if err := c.Link(ctx, owner, user, pass, false, true, 0); err != nil {
			t.Fatalf("headless login failed: %v", err)
		}
		fmt.Printf("[%s] fresh headless login OK, session isolated to this probe\n", time.Now().Format("15:04:05"))
	} else {
		sealed, err := box.Seal(cookie)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: owner, Cookie: sealed}); err != nil {
			t.Fatal(err)
		}
		if err := c.Refresh(ctx, owner); err != nil {
			t.Fatalf("seed cookie is not valid to begin with: %v", err)
		}
		fmt.Printf("[%s] seed cookie valid, beginning idle probes\n", time.Now().Format("15:04:05"))
	}

	var lastGood time.Duration
	for gap := start; gap <= max; gap = time.Duration(float64(gap) * factor) {
		fmt.Printf("[%s] idling %s (no activity)…\n", time.Now().Format("15:04:05"), gap)
		time.Sleep(gap)
		switch err := c.Refresh(ctx, owner); {
		case err == nil:
			lastGood = gap
			fmt.Printf("[%s] OK   after %-7s idle → session ALIVE (renewed, cookie slid)\n", time.Now().Format("15:04:05"), gap)
		case errors.Is(err, provider.ErrSessionExpired):
			fmt.Printf("[%s] DEAD after %-7s idle → session LAPSED. IDLE WINDOW is (%s, %s].\n", time.Now().Format("15:04:05"), gap, lastGood, gap)
			if lastGood > 0 {
				fmt.Printf("RECOMMENDATION: set COUNCIL_WARM_INTERVAL ~= %s (half the proven-safe %s).\n", (lastGood / 2).Round(time.Minute), lastGood)
			} else {
				fmt.Printf("RECOMMENDATION: even %s was too long; re-run with a smaller PSTONN_PROBE_START.\n", gap)
			}
			return
		default:
			t.Fatalf("probe error (not an expiry) after %s idle: %v", gap, err)
		}
	}
	fmt.Printf("reached PROBE_MAX %s with the session still alive at every gap, idle window is at least %s\n", max, lastGood)
}

func envDurationTest(t *testing.T, key string, def time.Duration) time.Duration {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", key, v, err)
		}
		return d
	}
	return def
}

func envFloatTest(t *testing.T, key string, def float64) float64 {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			t.Fatalf("%s=%q: %v", key, v, err)
		}
		return f
	}
	return def
}

// TestLiveReadFlow exercises the real, end-to-end read path against the live
// tenant site THROUGH the production code: seed a session cookie, then call
// ListPermits, which forces accessToken → silentRenew (prompt=none authorize
// with the cookie → code → /connect/token) → the /ssp-svc/api call. It then
// reads CurrentVehicle for the first permit. It is READ-ONLY; it never calls
// SetVehicle, so nothing on the tenant record changes.
//
// Runs only when PSTONN_LIVE_COOKIE is set to a current session-cookie header,
// e.g. "idsrv.session=...; Permits.IDM.Identity=...".
// TestLiveLinkLogin exercises the real headless onboarding against the live
// site: it logs in with the user's tenant credentials (Link), which stores a
// session cookie and discards the password, then proves the stored cookie works
// by minting a token via silent-renew and listing permits. Credentials are read
// from the environment and never persisted.
//
// This is the ONE core mechanism not yet validated live, and the login POST is
// where Azure Front Door bot-detection is most likely to bite. Runs only when
// PSTONN_LIVE_USERNAME and PSTONN_LIVE_PASSWORD are set.
func TestLiveLinkLogin(t *testing.T) {
	username := os.Getenv("PSTONN_LIVE_USERNAME")
	password := os.Getenv("PSTONN_LIVE_PASSWORD")
	if username == "" || password == "" {
		t.Skip("set PSTONN_LIVE_USERNAME and PSTONN_LIVE_PASSWORD to run the live headless login")
	}
	ctx := context.Background()
	owner := "live-test@example.com"

	cfg := &config.Config{Council: config.CouncilConfig{
		Issuer:      "https://parkingpermits.stonnington.vic.gov.au/idm",
		ClientID:    "ePermits.ssp.web",
		RedirectURI: "https://parkingpermits.stonnington.vic.gov.au/ssp/callback",
		Scopes:      []string{"openid", "profile", "ePermits.ssp.api.all"},
		APIBase:     "https://parkingpermits.stonnington.vic.gov.au/ssp-svc",
	}}
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := liveOrikanClient(cfg, st, box)

	// 1. Headless login → stores the sealed session cookie, discards the password.
	if err := c.Link(ctx, owner, username, password, false, true, 0); err != nil {
		t.Fatalf("Link (headless login) failed: %v", err)
	}
	if !c.Linked(ctx, owner) {
		t.Fatal("Linked reports false after a successful Link")
	}
	t.Log("OK: headless login succeeded, session cookie stored")

	// 2. Prove the captured cookie works end-to-end: ListPermits forces a
	//    silent-renew (mint a token from the cookie) followed by a real API read.
	permits, err := c.ListPermits(ctx, owner)
	if err != nil {
		t.Fatalf("ListPermits after Link (captured cookie / silent-renew broken?): %v", err)
	}
	t.Logf("OK: the cookie from headless login works, %d permit(s):", len(permits))
	for _, p := range permits {
		t.Logf("  %s  %s  rego=%s", p.PermitNumber, p.PermitType, p.CurrentRego)
	}
}

// TestLiveSetVehicle exercises the real WRITE path against the live site: it
// reallocates the visitor permit (VPP24714) to PSTONN_LIVE_SET_REGO, then reads
// back to confirm. This MUTATES a live tenant record, it runs only when both
// PSTONN_LIVE_COOKIE and PSTONN_LIVE_SET_REGO are set.
func TestLiveSetVehicle(t *testing.T) {
	cookie := os.Getenv("PSTONN_LIVE_COOKIE")
	rego := os.Getenv("PSTONN_LIVE_SET_REGO")
	if cookie == "" || rego == "" {
		t.Skip("set PSTONN_LIVE_COOKIE and PSTONN_LIVE_SET_REGO to run the live write")
	}
	ctx := context.Background()
	owner := "live-test@example.com"

	cfg := &config.Config{Council: config.CouncilConfig{
		Issuer:      "https://parkingpermits.stonnington.vic.gov.au/idm",
		ClientID:    "ePermits.ssp.web",
		RedirectURI: "https://parkingpermits.stonnington.vic.gov.au/ssp/callback",
		Scopes:      []string{"openid", "profile", "ePermits.ssp.api.all"},
		APIBase:     "https://parkingpermits.stonnington.vic.gov.au/ssp-svc",
	}}
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := liveOrikanClient(cfg, st, box)
	sealed, err := box.Seal(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: owner, Cookie: sealed}); err != nil {
		t.Fatal(err)
	}

	permit := model.Permit{CouncilPermitID: "14576", PermitTypeID: "14"} // VPP24714
	before, err := c.CurrentVehicle(ctx, owner, permit)
	if err != nil {
		t.Fatalf("CurrentVehicle before: %v", err)
	}
	t.Logf("before: %q", before)

	if err := c.SetVehicle(ctx, owner, permit, rego, ""); err != nil {
		t.Fatalf("SetVehicle(%q): %v", rego, err)
	}
	after, err := c.CurrentVehicle(ctx, owner, permit)
	if err != nil {
		t.Fatalf("CurrentVehicle after: %v", err)
	}
	t.Logf("after: %q (requested %q)", after, rego)
	if after != rego {
		t.Fatalf("permit shows %q, expected %q", after, rego)
	}
	t.Logf("OK: live write succeeded, VPP24714 now = %q", after)
}

// kickKey derives the throwaway secretbox key for the session-kick experiment
// from the DB path, so both phases (separate processes) agree on a key without a
// committed secret. It protects only a local, disposable experiment DB.
func kickKey(dbPath string) []byte {
	sum := sha256.Sum256([]byte("pstonn-session-kick:" + dbPath))
	return sum[:]
}

// TestLiveSessionKick answers, experimentally: does logging in to the tenant
// ePermits site directly invalidate the session p.stonn is holding? (The
// suspected cause of the prod disconnect.) It runs in TWO phases against a
// PERSISTENT DB so you can do a real browser login in between. Run BOTH commands
// in your OWN terminal so your password never enters the Claude session.
//
// Phase 1 — establish an isolated headless session and confirm it's alive:
//
//	export PSTONN_LIVE_USERNAME='you@example.com' PSTONN_LIVE_PASSWORD='…'
//	PSTONN_KICK_DB=/tmp/kick.db PSTONN_KICK_PHASE=link \
//	  go test ./internal/parking -run TestLiveSessionKick -count=1 -v
//
// Then, as the SAME tenant user, log in at
// https://parkingpermits.stonnington.vic.gov.au in a browser and finish the login.
//
// Phase 2 — re-probe the SAME stored session (no credentials needed):
//
//	PSTONN_KICK_DB=/tmp/kick.db PSTONN_KICK_PHASE=probe \
//	  go test ./internal/parking -run TestLiveSessionKick -count=1 -v
//
//	ALIVE   in phase 2 => a browser login does NOT kick p.stonn's session.
//	EXPIRED in phase 2 => it DOES: hypothesis confirmed, and the opt-in
//	                      save-password auto-reconnect is the right mitigation.
//
// For a clean control, you can re-run phase 2 WITHOUT logging in first: it should
// stay ALIVE, proving the kill (if any) is the browser login and not mere time.
func TestLiveSessionKick(t *testing.T) {
	dbPath := os.Getenv("PSTONN_KICK_DB")
	phase := os.Getenv("PSTONN_KICK_PHASE")
	if dbPath == "" || phase == "" {
		t.Skip("set PSTONN_KICK_DB=/path/kick.db and PSTONN_KICK_PHASE=link|probe (see doc comment)")
	}
	ctx := context.Background()
	const owner = "kick-probe@local"

	cfg := &config.Config{Council: config.CouncilConfig{
		Issuer:      "https://parkingpermits.stonnington.vic.gov.au/idm",
		ClientID:    "ePermits.ssp.web",
		RedirectURI: "https://parkingpermits.stonnington.vic.gov.au/ssp/callback",
		Scopes:      []string{"openid", "profile", "ePermits.ssp.api.all"},
		APIBase:     "https://parkingpermits.stonnington.vic.gov.au/ssp-svc",
	}}
	box, err := secretbox.New(kickKey(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := liveOrikanClient(cfg, st, box)

	switch phase {
	case "link":
		user := os.Getenv("PSTONN_LIVE_USERNAME")
		pass := os.Getenv("PSTONN_LIVE_PASSWORD")
		if user == "" || pass == "" {
			t.Fatal("phase=link needs PSTONN_LIVE_USERNAME and PSTONN_LIVE_PASSWORD")
		}
		if err := c.Link(ctx, owner, user, pass, false, true, 0); err != nil {
			t.Fatalf("headless link failed: %v", err)
		}
		// Prove it's alive right now via the exact production keep-warm path.
		if err := c.Refresh(ctx, owner); err != nil {
			t.Fatalf("session not alive immediately after link: %v", err)
		}
		fmt.Printf("[%s] PHASE 1 OK ✓ headless session established and ALIVE (stored in %s).\n",
			time.Now().Format("15:04:05"), dbPath)
		fmt.Println("NEXT: log in to the ePermits site in a browser as the same user, then run PSTONN_KICK_PHASE=probe.")
	case "probe":
		switch err := c.Refresh(ctx, owner); {
		case err == nil:
			fmt.Printf("[%s] RESULT: ALIVE ✓ — the browser login did NOT kick p.stonn's session.\n",
				time.Now().Format("15:04:05"))
		case errors.Is(err, provider.ErrSessionExpired):
			fmt.Printf("[%s] RESULT: EXPIRED ✗ — the browser login KICKED p.stonn's session. Hypothesis confirmed.\n",
				time.Now().Format("15:04:05"))
		default:
			t.Fatalf("probe error (not a clean expiry): %v", err)
		}
	default:
		t.Fatalf("PSTONN_KICK_PHASE must be link or probe, got %q", phase)
	}
}

func TestLiveReadFlow(t *testing.T) {
	cookie := os.Getenv("PSTONN_LIVE_COOKIE")
	if cookie == "" {
		t.Skip("set PSTONN_LIVE_COOKIE to run the live read flow")
	}
	ctx := context.Background()
	owner := "live-test@example.com"

	cfg := &config.Config{Council: config.CouncilConfig{
		Issuer:      "https://parkingpermits.stonnington.vic.gov.au/idm",
		ClientID:    "ePermits.ssp.web",
		RedirectURI: "https://parkingpermits.stonnington.vic.gov.au/ssp/callback",
		Scopes:      []string{"openid", "profile", "ePermits.ssp.api.all"},
		APIBase:     "https://parkingpermits.stonnington.vic.gov.au/ssp-svc",
	}}
	key := make([]byte, 32) // ephemeral in-memory key; the DB is a temp file
	box, err := secretbox.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "live.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	c := liveOrikanClient(cfg, st, box)
	sealed, err := box.Seal(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTenantSession(ctx, store.TenantSession{Owner: owner, Cookie: sealed}); err != nil {
		t.Fatal(err)
	}

	permits, err := c.ListPermits(ctx, owner)
	if err != nil {
		t.Fatalf("ListPermits (silent-renew token source + API): %v", err)
	}
	t.Logf("OK: silent-renew minted a token and Index/grid returned %d permit(s)", len(permits))
	for _, p := range permits {
		t.Logf("  %s  type=%s  status=%s  rego=%s  canChange=%v",
			p.PermitNumber, p.PermitTypeID, p.Status, p.CurrentRego, p.CanChangeVehicle)
	}
	if len(permits) == 0 {
		return
	}
	first := permits[0]
	rego, err := c.CurrentVehicle(ctx, owner, model.Permit{
		CouncilPermitID: first.CouncilPermitID,
		PermitTypeID:    first.PermitTypeID,
	})
	if err != nil {
		t.Fatalf("CurrentVehicle: %v", err)
	}
	t.Logf("OK: CurrentVehicle(%s) = %q", first.PermitNumber, rego)
}

// TestLiveAuthorizeOnlyWarm validates the keep-warm optimisation empirically: does
// the prompt=none AUTHORIZE step alone slide the session cookie, so keep-warm can
// drop the token exchange (halving its request count)? The mechanism is provable
// from the code — the rotated cookie is captured from the authorize response, not
// the token exchange — but this confirms it end to end against the live tenant:
// two authorize-only warms in a row succeed, and the slid cookie is still valid for
// a full renew (real work). READ-ONLY: no permit is touched.
//
//	PSTONN_LIVE_USERNAME=you@example.com PSTONN_LIVE_PASSWORD=… \
//	go test ./internal/parking -run TestLiveAuthorizeOnlyWarm -count=1 -v
func TestLiveAuthorizeOnlyWarm(t *testing.T) {
	user := os.Getenv("PSTONN_LIVE_USERNAME")
	pass := os.Getenv("PSTONN_LIVE_PASSWORD")
	if user == "" || pass == "" {
		t.Skip("set PSTONN_LIVE_USERNAME and PSTONN_LIVE_PASSWORD to run the authorize-only warm experiment")
	}
	ctx := context.Background()
	const owner = "warm-probe@local"
	c, _, st := liveClient(t)

	if err := c.Link(ctx, owner, user, pass, false, true, 0); err != nil {
		t.Fatalf("headless login: %v", err)
	}
	_ = st
	var cookie string
	if err := c.Diagnose(ctx, owner, func(_ provider.Provider, s *provider.Session) error {
		cookie = orikan.CookieOf(*s)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Authorize-only warm, twice, each on the previous result — proving a repeated
	// authorize-only keeps sliding the session with no token exchange.
	c1, err := ork(c).Warm(ctx, cookie)
	if err != nil {
		t.Fatalf("authorize-only warm #1 failed (session not slid): %v", err)
	}
	t.Logf("warm #1 OK — cookie rotated: %v", c1 != cookie)
	c2, err := ork(c).Warm(ctx, c1)
	if err != nil {
		t.Fatalf("authorize-only warm #2 failed: %v", err)
	}
	t.Logf("warm #2 OK — cookie rotated: %v", c2 != c1)

	// The slid cookie must still be valid for REAL work: a full renew mints a token.
	at, exp, _, err := ork(c).SilentRenew(ctx, c2)
	if err != nil {
		t.Fatalf("full renew on the authorize-only-slid cookie FAILED — warming broke the session: %v", err)
	}
	t.Logf("CONFIRMED ✓ authorize-only warming keeps the session valid; a full renew on the slid cookie minted a token (len=%d, expires %s)", len(at), exp.Format(time.RFC3339))
	t.Log("=> keep-warm can drop the token exchange: roughly half the auth-surface requests.")

	// The wired production path end to end: Refresh() is now authorize-only. It must
	// slide the session and leave it able to mint a token on demand.
	if err := c.Refresh(ctx, owner); err != nil {
		t.Fatalf("Refresh (authorize-only keep-warm) failed: %v", err)
	}
	if _, err := c.ListPermits(ctx, owner); err != nil {
		t.Fatalf("a permit read (token minted on demand) after an authorize-only Refresh failed: %v", err)
	}
	t.Log("Refresh (authorize-only) end-to-end OK: session slid, and a token still mints on demand.")
}

// TestLiveWarmRenewIdleTimeout empirically brackets the session idle timeout under
// AUTHORIZE-ONLY keep-warm (warmRenew) — the path Refresh now uses. It answers two
// questions in one unattended run:
//
//  1. Does authorize-only sliding actually hold a session across a real idle
//     window? (The residual left by the 1-second acceptance probe: that test
//     proved warmRenew SUCCEEDS, not that it EXTENDS the idle timeout.)
//  2. How large is that window — i.e. how far COUNCIL_WARM_INTERVAL could grow to
//     cut warm frequency ON TOP of the per-warm halving.
//
// It mirrors TestLiveMeasureIdleTimeout but drives warmRenew directly, threading
// the (possibly rotated) cookie forward IN MEMORY so the probe is isolated from the
// store and exercises only the sliding mechanism. Each success resets the sliding
// clock, so the idle gap grows; the first provider.ErrSessionExpired brackets the window
// between the last success and the failing gap.
//
// Preferred (isolated — survives you using the tenant site in a browser):
//
//	PSTONN_LIVE_USERNAME=you@example.com PSTONN_LIVE_PASSWORD=… \
//	PSTONN_PROBE_START=1h30m PSTONN_PROBE_FACTOR=1.3 PSTONN_PROBE_MAX=8h \
//	go test ./internal/parking -run TestLiveWarmRenewIdleTimeout -timeout 0 -v
//
// Or seed a fresh cookie instead of credentials (then DON'T touch that browser
// session while it runs, or it slides independently):
//
//	PSTONN_LIVE_COOKIE='idsrv.session=…; Permits.IDM.Identity=…' … same flags
//
// Caveat: a failure could be an ABSOLUTE session cap rather than the idle timeout;
// either way the last-success gap is a SAFE lower bound for the warm interval.
func TestLiveWarmRenewIdleTimeout(t *testing.T) {
	user := os.Getenv("PSTONN_LIVE_USERNAME")
	pass := os.Getenv("PSTONN_LIVE_PASSWORD")
	seed := os.Getenv("PSTONN_LIVE_COOKIE")
	if user == "" && seed == "" {
		t.Skip("set PSTONN_LIVE_USERNAME+PSTONN_LIVE_PASSWORD (preferred) or PSTONN_LIVE_COOKIE, and run with -timeout 0")
	}
	start := envDurationTest(t, "PSTONN_PROBE_START", 90*time.Minute)
	factor := envFloatTest(t, "PSTONN_PROBE_FACTOR", 1.3)
	maxGap := envDurationTest(t, "PSTONN_PROBE_MAX", 8*time.Hour)
	if factor <= 1 {
		factor = 1.3
	}

	ctx := context.Background()
	c, _, _ := liveClient(t)
	const owner = "warm-idle-probe@local"

	// Starting cookie: a fresh isolated headless login (preferred), or the seed.
	var cookie string
	if user != "" {
		if err := c.Link(ctx, owner, user, pass, false, true, 0); err != nil {
			t.Fatalf("headless login failed: %v", err)
		}
		if err := c.Diagnose(ctx, owner, func(_ provider.Provider, s *provider.Session) error {
			cookie = orikan.CookieOf(*s)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("[%s] fresh headless login OK; probing AUTHORIZE-ONLY warming\n", time.Now().Format("15:04:05"))
	} else {
		next, err := ork(c).Warm(ctx, seed)
		if err != nil {
			t.Fatalf("seed cookie is not valid to begin with: %v", err)
		}
		cookie = next
		fmt.Printf("[%s] seed cookie valid; beginning idle probes\n", time.Now().Format("15:04:05"))
	}

	var lastGood time.Duration
	for gap := start; gap <= maxGap; gap = time.Duration(float64(gap) * factor) {
		fmt.Printf("[%s] idling %s (no activity)…\n", time.Now().Format("15:04:05"), gap)
		time.Sleep(gap)
		switch next, err := ork(c).Warm(ctx, cookie); {
		case err == nil:
			cookie = next // thread the (possibly rotated) cookie forward
			lastGood = gap
			fmt.Printf("[%s] OK   after %-8s idle → session ALIVE (authorize-only slide)\n", time.Now().Format("15:04:05"), gap)
		case errors.Is(err, provider.ErrSessionExpired):
			fmt.Printf("[%s] DEAD after %-8s idle → session LAPSED. IDLE WINDOW is (%s, %s].\n", time.Now().Format("15:04:05"), gap, lastGood, gap)
			if lastGood > 0 {
				fmt.Printf("RESULT: authorize-only warming held the session up to at least %s.\n", lastGood)
				fmt.Printf("RECOMMENDATION: COUNCIL_WARM_INTERVAL ~= %s (0.7x the proven-safe %s).\n",
					(lastGood * 7 / 10).Round(time.Minute), lastGood)
			} else {
				fmt.Printf("RECOMMENDATION: even %s was too long; re-run with a smaller PSTONN_PROBE_START.\n", gap)
			}
			return
		default:
			// A push-back or transport error is not a clean expiry; fail loudly rather
			// than mis-bracket the idle window on an unrelated hiccup.
			t.Fatalf("probe error (not a clean expiry) after %s idle: %v", gap, err)
		}
	}
	fmt.Printf("reached PROBE_MAX %s with the session still alive at every gap; the idle window under authorize-only warming is at least %s\n", maxGap, lastGood)
}

// liveOrikanClient builds an Orikan-backed client explicitly (the generic client
// no longer hard-codes a connector). Test-only.
func liveOrikanClient(cfg *config.Config, st *store.Store, box *secretbox.Box) *Client {
	tr := NewTransport(LimitsFromConfig(cfg.Council))
	p := orikan.New(orikan.Config{
		Issuer: cfg.Council.Issuer, APIBase: cfg.Council.APIBase, ClientID: cfg.Council.ClientID,
		RedirectURI: cfg.Council.RedirectURI, Scopes: cfg.Council.Scopes,
	}, tr)
	return NewClientFor("", p, st, box, tr)
}
