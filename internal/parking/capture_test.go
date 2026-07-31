package parking

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// This file answers the shape questions that block the 500-user traffic work.
// Each question is stated with what a YES or NO means for the design, so the run
// is decisive rather than merely informative.
//
// Deliberately cheap: the whole capture is one silent-renew plus four permit-API
// calls — less than a single user's ordinary daily traffic. It is not a load
// test, a rate probe, or an attempt to find where the edge pushes back. Do not
// grow it into one; the operating assumption is that we stay well inside normal
// use, and that only holds if diagnostics stay small too.
//
// Run it yourself so credentials never enter a Claude session:
//
//	export PSTONN_LIVE_USERNAME='you@example.com' PSTONN_LIVE_PASSWORD='…'
//	export PSTONN_CAPTURE_PERMIT_ID=14576
//	export PSTONN_CAPTURE_REGO=ABC123     # optional; see the warning below
//	go test ./internal/parking -run TestLiveCaptureShapes -count=1 -v
//
// WARNING: setting PSTONN_CAPTURE_REGO performs a REAL edit on a REAL permit.
// Pass the plate you actually want on the permit right now, so the write is one
// you wanted anyway and the capture costs the council nothing extra. The plate
// in place beforehand is logged prominently either way.

// ANSWERS (captured 2026-07-31 against permit 14576 / VPP24714):
//
//	Q1 YES  grid.VehicleRego agrees with managedVehicle.RegistrationNumber.
//	Q2 YES  PKPermitVehicleDetailID (16539) survived a successful edit — but see
//	        SetVehicle: acting on this was judged NOT worth it, because writes are
//	        a small share of traffic and the pre-read carries two other guards.
//	Q3 NO   a successful POST returns 200 with an EMPTY body and no Content-Type,
//	        so it proves nothing about the resulting state. The confirm read stays.
//	Q4 YES  the grid row carries rego, status and end date, so one owner-level call
//	        serves both drift detection and expiry (see scheduler.checkDrift).
//
// Also established: the council rejects a lower-case plate with 400 "Vehicle
// Registration has invalid pattern", and accepts the same plate upper-cased even
// while it sits on ANOTHER of the account's permits. Production normalises at every
// entry point (server.normalizeReg), so only a harness can send the rejected form.
//
// captureQ1 through captureQ4 name the questions so the summary can report them.
const (
	captureQ1 = "Q1 grid.VehicleRego == managedVehicle.RegistrationNumber?"
	captureQ2 = "Q2 PKPermitVehicleDetailID stable across an edit?"
	captureQ3 = "Q3 does the manageVehicle POST return permit state?"
	captureQ4 = "Q4 does grid carry everything checkDrift needs?"
)

func TestLiveCaptureShapes(t *testing.T) {
	permitID := os.Getenv("PSTONN_CAPTURE_PERMIT_ID")
	user := os.Getenv("PSTONN_LIVE_USERNAME")
	pass := os.Getenv("PSTONN_LIVE_PASSWORD")
	cookie := os.Getenv("PSTONN_LIVE_COOKIE")
	if permitID == "" || (user == "" && cookie == "") {
		t.Skip("set PSTONN_CAPTURE_PERMIT_ID and either PSTONN_LIVE_USERNAME+PSTONN_LIVE_PASSWORD or PSTONN_LIVE_COOKIE")
	}
	ctx := context.Background()
	const owner = "capture@local"

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
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "capture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := New(cfg, st, box)

	if user != "" {
		if err := c.Link(ctx, owner, user, pass, false, true); err != nil {
			t.Fatalf("headless login failed: %v", err)
		}
	} else {
		sealed, err := box.SealCtx(secretbox.CouncilCookie(owner), cookie)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: owner, Cookie: sealed}); err != nil {
			t.Fatal(err)
		}
	}

	findings := map[string]string{}

	// ---- 1. Index/grid -------------------------------------------------------
	gridRaw := rawGet(t, c, ctx, owner, "/api/Index/grid",
		url.Values{"pageNumber": {"0"}, "pageSize": {"0"}})
	t.Logf("\n=== RAW /api/Index/grid ===\n%s", pretty(gridRaw))

	var grid gridResp
	if err := json.Unmarshal(gridRaw, &grid); err != nil {
		t.Fatalf("grid did not decode into the shape this client expects: %v", err)
	}
	var row *gridRow
	for i := range grid.PermitGrid {
		if fmt.Sprint(grid.PermitGrid[i].PKPermitID) == permitID {
			row = &grid.PermitGrid[i]
		}
	}
	if row == nil {
		t.Fatalf("permit %s not present in the grid (%d permits returned)", permitID, len(grid.PermitGrid))
	}

	// Q4: checkDrift needs a plate; syncPermitExpiry needs status + end date. If
	// the grid carries all three, one owner-level call can replace both, which is
	// the single largest traffic cut available.
	missing := []string{}
	if row.VehicleRego == "" {
		missing = append(missing, "VehicleRego")
	}
	if row.PermitStatus == "" {
		missing = append(missing, "PermitStatus")
	}
	if row.EndDate == "" {
		missing = append(missing, "EndDate")
	}
	if len(missing) == 0 {
		findings[captureQ4] = "YES — grid carries rego, status and end date; it can serve drift AND expiry in one call"
	} else {
		findings[captureQ4] = "NO — grid is missing " + strings.Join(missing, ", ") + "; the per-permit read cannot be fully retired"
	}

	// ---- 2. managedVehicle, before -------------------------------------------
	beforeRaw := rawGet(t, c, ctx, owner, "/api/permits/managedVehicle",
		url.Values{"permitID": {permitID}})
	t.Logf("\n=== RAW /api/permits/managedVehicle (before) ===\n%s", pretty(beforeRaw))

	var before managedVehicleResp
	if err := json.Unmarshal(beforeRaw, &before); err != nil {
		t.Fatalf("managedVehicle did not decode: %v", err)
	}
	if len(before.PermitVehicles) == 0 {
		t.Fatalf("permit %s has no vehicles; pick a permit with one", permitID)
	}
	cur := before.PermitVehicles[0]
	detailBefore := cur.PKPermitVehicleDetailID.String()

	t.Logf("\n*** PLATE CURRENTLY ON PERMIT %s: %q ***", permitID, cur.RegistrationNumber)
	t.Logf("    detail ID before: %s   state: %s   canEdit: %v",
		detailBefore, cur.FKVehicleStateID, before.CanEditOrDeleteVehicle)

	// Q1: does the grid's denormalised plate agree with the authoritative one? If
	// it lags or differs, drift detection would silently invert when moved to the
	// grid, so this gates the whole grid-collapse change.
	switch {
	case strings.EqualFold(row.VehicleRego, cur.RegistrationNumber):
		findings[captureQ1] = fmt.Sprintf("YES — both report %q; the grid can drive drift detection", cur.RegistrationNumber)
	default:
		findings[captureQ1] = fmt.Sprintf("NO — grid says %q, managedVehicle says %q; DO NOT move drift onto the grid",
			row.VehicleRego, cur.RegistrationNumber)
	}

	// ---- 3. The edit ---------------------------------------------------------
	rego := os.Getenv("PSTONN_CAPTURE_REGO")
	if rego == "" {
		findings[captureQ2] = "NOT TESTED — set PSTONN_CAPTURE_REGO to capture an edit"
		findings[captureQ3] = "NOT TESTED — set PSTONN_CAPTURE_REGO to capture an edit"
		report(t, findings)
		return
	}
	// Normalise exactly as the server layer does before any plate reaches the
	// council (server.normalizeReg). Skipping this sent a lower-case plate on the
	// first run and the council answered 400 "Vehicle Registration has invalid
	// pattern" — a harness artefact that looked like an API finding. Every
	// production path normalises; a capture that does not is not testing the
	// production request.
	if norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(rego), " ", "")); norm != rego {
		t.Logf("normalised PSTONN_CAPTURE_REGO %q -> %q (as the server layer would)", rego, norm)
		rego = norm
	}
	if strings.EqualFold(rego, cur.RegistrationNumber) {
		t.Fatalf("PSTONN_CAPTURE_REGO %q is already on the permit; the portal sends no request for a no-op, so nothing would be learned", rego)
	}

	state := cur.FKVehicleStateID
	if state == "" {
		state = "1"
	}
	var permitNum int64
	if _, err := fmt.Sscan(permitID, &permitNum); err != nil {
		t.Fatalf("PSTONN_CAPTURE_PERMIT_ID %q is not numeric: %v", permitID, err)
	}
	body, err := json.Marshal(manageVehicleReq{
		PKPermitID:          permitNum,
		SelectedVehicle:     detailBefore,
		VehicleActionOption: "edit",
		Vehicle: manageVehicleV{
			ChangeSetID:             detailBefore,
			FKPermitID:              permitNum,
			FKVehicleStateID:        state,
			PKPermitVehicleDetailID: detailBefore,
			RegisteredAtAddress:     false,
			RegistrationNumber:      rego,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	at, err := c.accessToken(ctx, owner)
	if err != nil {
		t.Fatalf("access token: %v", err)
	}
	resp, err := c.doAPI(ctx, at, http.MethodPost, "/api/permits/manageVehicle", nil, body)
	if err != nil {
		t.Fatalf("manageVehicle POST: %v", err)
	}
	postBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	resp.Body.Close()
	t.Logf("\n=== RAW POST /api/permits/manageVehicle ===\nstatus: %d\ncontent-type: %s\nbody (%d bytes):\n%s",
		resp.StatusCode, resp.Header.Get("Content-Type"), len(postBody), pretty(postBody))

	// A rejected write answers NEITHER Q2 nor Q3, and saying otherwise is worse than
	// saying nothing: an unchanged detail ID after a POST that never landed looks
	// exactly like a detail ID that survived an edit, and the first version of this
	// test duly reported "YES — caching it can drop the pre-read" off a 400. Both
	// questions are gated on the write actually taking effect.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		reason := councilErrorMessage(postBody)
		if reason == "" {
			reason = safeExcerpt(string(postBody))
		}
		findings[captureQ2] = fmt.Sprintf("UNANSWERED — the edit was refused (%d: %s), so nothing was edited and the detail ID could not change", resp.StatusCode, reason)
		findings[captureQ3] = fmt.Sprintf("UNANSWERED — the body captured is the REFUSAL shape, not the success shape (%d: %s)", resp.StatusCode, reason)
		report(t, findings)
		t.Fatalf("the council refused the edit (%d: %s); fix the request and re-run", resp.StatusCode, reason)
	}

	// Q3: if the POST already returns the resulting permit state, the confirm read
	// can be dropped without weakening the "confirmed by the council" guarantee —
	// the response IS the council's own record.
	switch {
	case len(strings.TrimSpace(string(postBody))) == 0:
		findings[captureQ3] = "NO — empty body; the confirm read must stay"
	case !strings.Contains(resp.Header.Get("Content-Type"), "json"):
		findings[captureQ3] = "NO — non-JSON body; the confirm read must stay"
	case strings.Contains(strings.ToUpper(string(postBody)), strings.ToUpper(rego)):
		findings[captureQ3] = "MAYBE — the response echoes the new plate; inspect the raw body above to see if it is authoritative permit state or just the request reflected"
	default:
		findings[captureQ3] = "NO — body present but does not carry the new plate; the confirm read must stay"
	}

	// ---- 4. managedVehicle, after --------------------------------------------
	afterRaw := rawGet(t, c, ctx, owner, "/api/permits/managedVehicle",
		url.Values{"permitID": {permitID}})
	t.Logf("\n=== RAW /api/permits/managedVehicle (after) ===\n%s", pretty(afterRaw))

	var after managedVehicleResp
	if err := json.Unmarshal(afterRaw, &after); err != nil {
		t.Fatalf("managedVehicle (after) did not decode: %v", err)
	}
	if len(after.PermitVehicles) == 0 {
		t.Fatal("permit has no vehicles after the edit")
	}
	post := after.PermitVehicles[0]
	detailAfter := post.PKPermitVehicleDetailID.String()

	t.Logf("plate after: %q (requested %q)", post.RegistrationNumber, rego)
	t.Logf("detail ID after: %s (before: %s)", detailAfter, detailBefore)

	// Q2: this decides whether caching the detail ID saves a read or costs one.
	// If the ID rotates per edit, every cached value is stale on every write and
	// the "retry once" path fires every time — four calls instead of three.
	switch {
	case detailAfter == detailBefore:
		findings[captureQ2] = fmt.Sprintf("YES — detail ID %s survived the edit; caching it can drop the pre-read", detailBefore)
	default:
		findings[captureQ2] = fmt.Sprintf("NO — detail ID rotated %s -> %s; DO NOT cache it, a cached ID would be stale on every write",
			detailBefore, detailAfter)
	}

	if !strings.EqualFold(post.RegistrationNumber, rego) {
		t.Errorf("the edit did not take: permit shows %q, requested %q", post.RegistrationNumber, rego)
	}
	report(t, findings)
	t.Logf("\nNOTE: permit %s now shows %q (was %q).", permitID, post.RegistrationNumber, cur.RegistrationNumber)
}

// rawGet issues one authenticated GET and returns the undecoded body, so the
// capture reports what the council actually sent rather than what this client's
// structs happen to keep.
func rawGet(t *testing.T, c *Client, ctx context.Context, owner, path string, q url.Values) []byte {
	t.Helper()
	at, err := c.accessToken(ctx, owner)
	if err != nil {
		t.Fatalf("access token: %v", err)
	}
	resp, err := c.doAPI(ctx, at, http.MethodGet, path, q, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("GET %s returned %d: %s", path, resp.StatusCode, safeExcerpt(string(body)))
	}
	return body
}

func pretty(b []byte) string {
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return safeExcerpt(string(b))
	}
	f, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return safeExcerpt(string(b))
	}
	return string(f)
}

func report(t *testing.T, findings map[string]string) {
	t.Helper()
	keys := make([]string, 0, len(findings))
	for k := range findings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Log("\n================ CAPTURE FINDINGS ================")
	for _, k := range keys {
		t.Logf("%s\n    %s", k, findings[k])
	}
	t.Log("==================================================")
}

// TestLiveEdgeHeaders identifies which CDN/WAF fronts the portal, from one
// unauthenticated GET of the public landing page: no credentials, no account
// data, the same request a browser makes when someone opens the site.
//
// RESULT (2026-07-31): Azure Front Door, via X-Azure-Ref. The codebase had
// asserted Akamai in eleven comments and nobody had checked; those are now
// corrected. Re-run this if the portal's hosting ever appears to change, since
// the 403-vs-block-page classification in apiRequest reasons about the vendor's
// error-page behaviour.
//
// Note the landing page answers 403 to everyone — with and without a browser
// User-Agent — so that status is the root simply not serving, NOT evidence of
// bot filtering. Do not read it as a block.
//
//	go test ./internal/parking -run TestLiveEdgeHeaders -count=1 -v
func TestLiveEdgeHeaders(t *testing.T) {
	if os.Getenv("PSTONN_EDGE_PROBE") == "" {
		t.Skip("set PSTONN_EDGE_PROBE=1 to make one unauthenticated request to the portal landing page")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://parkingpermits.stonnington.vic.gov.au/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET portal root: %v", err)
	}
	drainClose(resp)

	t.Logf("status: %d", resp.StatusCode)
	names := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		t.Logf("  %s: %s", k, strings.Join(resp.Header[k], ", "))
	}

	// Vendor tells. Header names are literal and must not be mass-edited along
	// with prose mentions of a vendor — they are wire identifiers, not commentary.
	tells := map[string][]string{
		"Azure Front Door":  {"X-Azure-Ref", "X-Fd-Int-Roxy-Purgeid", "X-Cache-Info"},
		"Akamai":            {"X-Akamai-Transformed", "Akamai-Grn", "X-Akamai-Request-Id", "X-Cache-Key"},
		"Cloudflare":        {"Cf-Ray", "Cf-Cache-Status"},
		"AWS CloudFront":    {"X-Amz-Cf-Id", "X-Amz-Cf-Pop"},
		"F5 / BIG-IP":       {"X-Waf-Event-Info"},
		"Imperva/Incapsula": {"X-Iinfo", "X-Cdn"},
	}
	found := []string{}
	for vendor, hs := range tells {
		for _, h := range hs {
			if resp.Header.Get(h) != "" {
				found = append(found, fmt.Sprintf("%s (via %s: %s)", vendor, h, resp.Header.Get(h)))
				break
			}
		}
	}
	sort.Strings(found)
	switch len(found) {
	case 0:
		t.Log("\nEDGE: no vendor tell in the response headers. Check Server/Via above; " +
			"the code's Azure Front Door assumption would then be back to UNCONFIRMED.")
	default:
		t.Logf("\nEDGE: %s", strings.Join(found, "; "))
	}
}
