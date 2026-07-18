package parking

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/model"
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

	at, exp, next, err := c.silentRenew(ctx, cookie)
	switch {
	case err == nil:
		t.Logf("ALIVE ✓ the session still stands, silent-renew minted a fresh token (expires %s, %s from now).",
			exp.Format(time.RFC3339), time.Until(exp).Round(time.Second))
		t.Logf("cookie rotated on renew: %v; token length: %d", next != "", len(at))
		t.Log("=> the idle timeout is AT LEAST the time since this cookie was last used.")
	case errors.Is(err, ErrSessionExpired):
		t.Log("EXPIRED ✗ the session has lapsed, a re-link (fresh login) is required.")
		t.Log("=> the idle timeout is LESS than the time since this cookie was last used.")
	default:
		t.Fatalf("probe error (not a clean expiry): %v", err)
	}
}

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
	return New(cfg, st, box), box, st
}

// TestLiveMeasureIdleTimeout empirically brackets the council session cookie's
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
// Preferred (isolated, survives you using the council site in a browser):
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
		if err := c.Link(ctx, owner, user, pass); err != nil {
			t.Fatalf("headless login failed: %v", err)
		}
		fmt.Printf("[%s] fresh headless login OK, session isolated to this probe\n", time.Now().Format("15:04:05"))
	} else {
		sealed, err := box.Seal(cookie)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: owner, Cookie: sealed}); err != nil {
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
		case errors.Is(err, ErrSessionExpired):
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
// council site THROUGH the production code: seed a session cookie, then call
// ListPermits, which forces accessToken → silentRenew (prompt=none authorize
// with the cookie → code → /connect/token) → the /ssp-svc/api call. It then
// reads CurrentVehicle for the first permit. It is READ-ONLY; it never calls
// SetVehicle, so nothing on the council record changes.
//
// Runs only when PSTONN_LIVE_COOKIE is set to a current session-cookie header,
// e.g. "idsrv.session=...; Permits.IDM.Identity=...".
// TestLiveLinkLogin exercises the real headless onboarding against the live
// site: it logs in with the user's council credentials (Link), which stores a
// session cookie and discards the password, then proves the stored cookie works
// by minting a token via silent-renew and listing permits. Credentials are read
// from the environment and never persisted.
//
// This is the ONE core mechanism not yet validated live, and the login POST is
// where Akamai bot-detection is most likely to bite. Runs only when
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
	c := New(cfg, st, box)

	// 1. Headless login → stores the sealed session cookie, discards the password.
	if err := c.Link(ctx, owner, username, password); err != nil {
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
// back to confirm. This MUTATES a live council record, it runs only when both
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
	c := New(cfg, st, box)
	sealed, err := box.Seal(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: owner, Cookie: sealed}); err != nil {
		t.Fatal(err)
	}

	permit := model.Permit{CouncilPermitID: "14576", PermitTypeID: "14"} // VPP24714
	before, err := c.CurrentVehicle(ctx, owner, permit)
	if err != nil {
		t.Fatalf("CurrentVehicle before: %v", err)
	}
	t.Logf("before: %q", before)

	if err := c.SetVehicle(ctx, owner, permit, rego); err != nil {
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

	c := New(cfg, st, box)
	sealed, err := box.Seal(cookie)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: owner, Cookie: sealed}); err != nil {
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
