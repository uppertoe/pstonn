package scheduler

// Synthetic fleet harness.
//
// Everything we believe about running at 500-1000 households is arithmetic on paper:
// a per-request cost measured once by hand, multiplied out. This measures the parts
// that were never measured — how many council requests a permit ACTUALLY costs to
// converge, how long the orchestration itself takes, and what the single SQLite
// connection does to page reads while a rollover is draining.
//
// It deliberately does NOT wait out the real governor. At the production rate of
// 60 req/min, 500 permits is roughly a quarter of an hour of wall-clock, which is
// useless as a test. Convergence LATENCY is arithmetic once the per-permit request
// cost is known, and the request cost is the thing we can only get by measuring — so
// the harness runs the governor wide open, counts what actually crossed the wire, and
// reports the implied convergence at the real rate.
//
// Skipped unless PSTONN_FLEET is set, but it still COMPILES on every run, so it
// cannot rot quietly the way a build-tagged file does:
//
//	PSTONN_FLEET=1 PSTONN_FLEET_SIZE=500 go test ./internal/scheduler/ -run Fleet -v

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/config"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

// stubCouncil is a stand-in for the council portal that behaves like the real one in
// the ways that matter for cost: an apply is a POST plus a confirming read, and the
// confirm only passes once the POST has actually changed the record.
type stubCouncil struct {
	mu     sync.Mutex
	plates map[string]string // owner -> the plate the council currently holds
	byTag  map[string]string // council cookie value -> owner (the IdM leg)
	byTok  map[string]string // bearer token -> owner (the API leg)
	hits   []time.Time       // every request, for the peak-rate calculation
	byPath map[string]int

	srv *httptest.Server

	// Fault injection. Deterministic: failures are dealt out by a request counter, not
	// a random source, so anything this finds can be reproduced exactly.
	latencyMS atomic.Int64 // artificial delay before every API response
	failEvery atomic.Int64 // refuse 1 API request in N (0 = never)
	failCode  atomic.Int64 // the status to refuse with
	retryPost atomic.Int64 // Retry-After seconds advertised on a refusal
	apiSeq    atomic.Int64 // deals out the deterministic failures
	failures  atomic.Int64 // refusals actually served
	authDead  atomic.Bool  // authorize returns the LOGIN PAGE: the cookie is dead
}

// injectFault applies the configured latency and, on its turn, refuses the request the
// way the council edge does. Reports whether it already wrote the response.
func (s *stubCouncil) injectFault(w http.ResponseWriter) bool {
	if ms := s.latencyMS.Load(); ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
	every := s.failEvery.Load()
	if every <= 0 || s.apiSeq.Add(1)%every != 0 {
		return false
	}
	s.failures.Add(1)
	code := int(s.failCode.Load())
	if code == 0 {
		code = http.StatusTooManyRequests
	}
	if ra := s.retryPost.Load(); ra > 0 {
		w.Header().Set("Retry-After", strconv.FormatInt(ra, 10))
	}
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	return true
}

func newStubCouncil(t *testing.T) *stubCouncil {
	t.Helper()
	s := &stubCouncil{plates: map[string]string{}, byPath: map[string]int{}, byTag: map[string]string{}, byTok: map[string]string{}}
	mux := http.NewServeMux()

	record := func(path string) {
		s.mu.Lock()
		s.hits = append(s.hits, time.Now())
		s.byPath[path]++
		s.mu.Unlock()
	}

	// The IdM leg identifies the caller by the session COOKIE; the API leg by the
	// bearer token. Carrying the owner across the two is what makes a renewed session
	// keep talking about the same household, so the stub does it the same way.
	mux.HandleFunc("/idm/connect/authorize", func(w http.ResponseWriter, r *http.Request) {
		record("authorize")
		if s.authDead.Load() {
			// How the council actually signals a dead cookie: 200 HTML carrying the
			// ASP.NET antiforgery field, instead of the 302 back to the app. This is what
			// turns into ErrSessionExpired and hands the owner to the reconnect worker.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `<html><form><input name="__RequestVerificationToken" value="x"></form></html>`)
			return
		}
		tag := ""
		if c, err := r.Cookie("Permits.IDM.Identity"); err == nil {
			tag = c.Value
		}
		cb := r.URL.Query().Get("redirect_uri")
		http.Redirect(w, r, cb+"?code=code-"+tag+"&state="+r.URL.Query().Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/idm/connect/token", func(w http.ResponseWriter, r *http.Request) {
		record("token")
		_ = r.ParseForm()
		tag := strings.TrimPrefix(r.PostFormValue("code"), "code-")
		s.mu.Lock()
		if owner := s.byTag[tag]; owner != "" {
			s.byTok["tok-"+tag] = owner
		}
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-" + tag, "expires_in": 3600, "token_type": "Bearer",
		})
	})
	// The permit grid. One permit per owner, carrying the plate the council holds.
	mux.HandleFunc("/ssp-svc/api/Index/grid", func(w http.ResponseWriter, r *http.Request) {
		record("grid")
		if s.injectFault(w) {
			return
		}
		owner := s.ownerOf(r)
		s.mu.Lock()
		plate := s.plates[owner]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(`{"TotalItems":1,"PermitGrid":[{
			"PKPermitID":%s,"FKPermitTypeID":3,"PermitNumber":"VPP%s","PermitType":"Resident",
			"PermitStatus":"Active","VehicleRego":%q,"StartDate":"2026-01-01T00:00:00",
			"EndDate":"2027-01-01T00:00:00","PermitTypeAllowsVehicleChangeByHolder":true}]}`,
			councilIDFor(owner), councilIDFor(owner), plate))
	})
	// The current-vehicle read, used both to decide drift and to CONFIRM an apply.
	mux.HandleFunc("/ssp-svc/api/permits/managedVehicle", func(w http.ResponseWriter, r *http.Request) {
		record("managedVehicle")
		if s.injectFault(w) {
			return
		}
		owner := s.ownerOf(r)
		s.mu.Lock()
		plate := s.plates[owner]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"permitNumber": "VPP1", "permitVehicleCount": 1, "maxVehicles": 1,
			"canAddVehicle": false, "canEditOrDeleteVehicle": true,
			"permitVehicles": []map[string]any{{
				"PKPermitVehicleDetailID": 1, "RegistrationNumber": plate, "FKVehicleStateID": "1",
			}},
		})
	})
	// The apply. Mutates the record, so the confirming read that follows can pass —
	// which is what makes an apply cost TWO requests rather than one.
	mux.HandleFunc("/ssp-svc/api/permits/manageVehicle", func(w http.ResponseWriter, r *http.Request) {
		record("manageVehicle")
		if s.injectFault(w) {
			return
		}
		owner := s.ownerOf(r)
		// Mirrors manageVehicleReq: the plate lives on the nested Vehicle object.
		var body struct {
			Vehicle struct {
				RegistrationNumber string `json:"RegistrationNumber"`
			} `json:"Vehicle"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plate := body.Vehicle.RegistrationNumber
		if plate != "" {
			s.mu.Lock()
			s.plates[owner] = plate
			s.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	})

	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// ownerOf identifies the caller the way the council would: by the session cookie the
// client presents. Each seeded owner gets a distinct one, so the stub can hold real
// per-owner state instead of pretending the fleet is one account.
func (s *stubCouncil) ownerOf(r *http.Request) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" {
		if owner := s.byTok[tok]; owner != "" {
			return owner
		}
	}
	if c, err := r.Cookie("Permits.IDM.Identity"); err == nil {
		return s.byTag[c.Value]
	}
	return ""
}

// peakPerMinute is the busiest 60s window the stub saw — the number that matters
// against the governor's ceiling, since an average hides the rollover burst.
func (s *stubCouncil) peakPerMinute() int {
	s.mu.Lock()
	hits := append([]time.Time(nil), s.hits...)
	s.mu.Unlock()
	if len(hits) == 0 {
		return 0
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Before(hits[j]) })
	best, j := 0, 0
	for i := range hits {
		for hits[i].Sub(hits[j]) > time.Minute {
			j++
		}
		if n := i - j + 1; n > best {
			best = n
		}
	}
	return best
}

func (s *stubCouncil) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hits)
}

func councilIDFor(owner string) string {
	// Stable numeric id per owner; the grid needs a positive PKPermitID.
	n := 0
	for _, r := range owner {
		n = n*31 + int(r)
		if n > 1<<20 {
			n %= 1 << 20
		}
	}
	if n <= 0 {
		n = 1
	}
	return strconv.Itoa(n)
}

// cfgConcurrency is the harness's council concurrency. Kept as a named constant so the
// wall-clock budget in the failure test is derived from it rather than guessed.
const cfgConcurrency = 8

// fleetRig is a whole synthetic deployment: a stub council, a real store, a real
// parking client (governor, breaker, token and session handling) and a real scheduler.
type fleetRig struct {
	sched   *Scheduler
	store   *store.Store
	council *stubCouncil
	size    int
}

// converged counts households whose permit THE COUNCIL now holds under the new plate,
// so a local write that never landed cannot pass for success.
func (r *fleetRig) converged() int {
	r.council.mu.Lock()
	defer r.council.mu.Unlock()
	done := 0
	for i := 0; i < r.size; i++ {
		if r.council.plates[fmt.Sprintf("owner%04d@example.com", i)] == fmt.Sprintf("NEW%03d", i%1000) {
			done++
		}
	}
	return done
}

func requireFleet(t *testing.T) {
	t.Helper()
	if os.Getenv("PSTONN_FLEET") == "" {
		t.Skip("set PSTONN_FLEET=1 to run the synthetic fleet harness")
	}
}

func fleetSize(t *testing.T, def int) int {
	t.Helper()
	v := os.Getenv("PSTONN_FLEET_SIZE")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		t.Fatalf("PSTONN_FLEET_SIZE=%q is not a positive integer", v)
	}
	return n
}

// newFleetRig seeds size households into the midnight-rollover shape: every permit due
// to change at once, which is the worst honest case.
func newFleetRig(t *testing.T, size int) *fleetRig {
	return newFleetRigTokens(t, size, os.Getenv("PSTONN_FLEET_FRESH_TOKENS") != "")
}

// newFleetRigTokens seeds the fleet with either a still-valid cached access token or an
// already-expired one.
//
// Expired is the DEFAULT because it is what production actually looks like: keep-warm
// is authorize-only and mints no token, so by the time a rollover runs, the 1h token
// has long gone and the operation costs an authorize + token exchange on top of its
// API calls. Seeding fresh tokens quietly removed two requests per owner from the
// headline number, making the measurement a lower bound rather than the real thing.
func newFleetRigTokens(t *testing.T, size int, freshTokens bool) *fleetRig {
	t.Helper()
	ctx := context.Background()
	council := newStubCouncil(t)

	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Council.Issuer = council.srv.URL + "/idm"
	cfg.Council.APIBase = council.srv.URL + "/ssp-svc"
	cfg.Council.RedirectURI = council.srv.URL + "/ssp/callback"
	cfg.Council.ClientID = "fleet-client"
	cfg.Council.Scopes = []string{"openid"}
	// Wide open ON PURPOSE. We are measuring request COST and orchestration, not
	// waiting out the pacer; convergence at the real rate is computed from the count.
	cfg.Council.GovRatePerMin = 1 << 20
	cfg.Council.GovBurst = 1 << 20
	cfg.Council.GovConcurrency = cfgConcurrency

	client := parking.New(cfg, st, box)
	sched := New(st, client, time.UTC, Options{WarmInterval: time.Hour, DriftInterval: time.Hour})

	// Seed the fleet: a linked session, a permit the council already holds under an
	// OLD plate, a vehicle, and a rule for today naming the NEW one. That is exactly
	// the midnight-rollover shape — every permit due to change at once.
	desired := map[int64]string{}
	seal := func(v string) string {
		s, err := box.Seal(v)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for i := 0; i < size; i++ {
		owner := fmt.Sprintf("owner%04d@example.com", i)
		tag := fmt.Sprintf("fleet%04d", i)
		council.mu.Lock()
		council.plates[owner] = "OLD" + fmt.Sprintf("%03d", i%1000)
		council.byTag[tag] = owner
		council.mu.Unlock()

		if err := st.SaveCouncilSession(ctx, store.CouncilSession{Owner: owner, Cookie: seal("Permits.IDM.Identity=" + tag)}); err != nil {
			t.Fatalf("seed session %d: %v", i, err)
		}
		cs, err := st.GetCouncilSession(ctx, owner)
		if err != nil {
			t.Fatalf("read session %d: %v", i, err)
		}
		council.mu.Lock()
		council.byTok["tok-"+tag] = owner
		council.mu.Unlock()
		tokenExpiry := time.Now().Add(-time.Minute) // expired: the realistic rollover
		if freshTokens {
			tokenExpiry = time.Now().Add(time.Hour)
		}
		if err := st.UpdateCouncilToken(ctx, owner, cs.Cookie, seal("tok-"+tag), tokenExpiry, cs.Generation); err != nil {
			t.Fatalf("seed token %d: %v", i, err)
		}
		pid, err := st.UpsertPermit(ctx, owner, councilIDFor(owner), "14", "Permit")
		if err != nil {
			t.Fatalf("seed permit %d: %v", i, err)
		}
		plate := fmt.Sprintf("NEW%03d", i%1000)
		vid, err := st.CreateVehicle(ctx, owner, plate, "car")
		if err != nil {
			t.Fatalf("seed vehicle %d: %v", i, err)
		}
		if err := st.SetRule(ctx, pid, time.Now().In(time.UTC).Weekday(), vid); err != nil {
			t.Fatalf("seed rule %d: %v", i, err)
		}
		desired[pid] = plate
	}

	return &fleetRig{sched: sched, store: st, council: council, size: size}
}

func TestFleetConvergenceAndContention(t *testing.T) {
	requireFleet(t)
	ctx := context.Background()
	size := fleetSize(t, 100)
	rig := newFleetRig(t, size)
	sched, st, council := rig.sched, rig.store, rig.council

	// A background "page load" while the fleet converges. Every request in this app
	// serialises through ONE SQLite connection (SetMaxOpenConns(1)), so this is the
	// number that says whether the UI stays usable during a rollover.
	stopLoad := make(chan struct{})
	var loadMu sync.Mutex
	var samples []time.Duration
	go func() {
		for {
			select {
			case <-stopLoad:
				return
			default:
			}
			start := time.Now()
			// Representative of what a signed-in dashboard costs.
			if _, err := st.ListPermitsFor(ctx, "owner0000@example.com"); err != nil {
				return
			}
			d := time.Since(start)
			loadMu.Lock()
			samples = append(samples, d)
			loadMu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	start := time.Now()
	deadline := time.Now().Add(60 * time.Second)
	passes := 0
	for {
		sched.reconcileAll(ctx)
		passes++
		done := rig.converged()
		if done == size {
			break
		}
		if time.Now().After(deadline) {
			council.mu.Lock()
			sample := map[string]string{}
			for k, v := range council.plates {
				sample[k] = v
				if len(sample) >= 5 {
					break
				}
			}
			tags := len(council.byTag)
			council.mu.Unlock()
			t.Fatalf("only %d/%d permits converged after %d passes in %s; stub holds %d plate key(s) for %d tag(s), sample=%v",
				done, size, passes, time.Since(start).Round(time.Second), len(sample), tags, sample)
		}
	}
	elapsed := time.Since(start)
	close(stopLoad)

	loadMu.Lock()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p := func(q float64) time.Duration {
		if len(samples) == 0 {
			return 0
		}
		return samples[int(float64(len(samples)-1)*q)]
	}
	p50, p95, p99, n := p(0.50), p(0.95), p(0.99), len(samples)
	loadMu.Unlock()

	total := council.total()
	perPermit := float64(total) / float64(size)
	council.mu.Lock()
	byPath := map[string]int{}
	for k, v := range council.byPath {
		byPath[k] = v
	}
	council.mu.Unlock()

	// Convergence at the REAL governor rate is arithmetic once the cost is measured.
	const prodRate = 60.0 // COUNCIL_GOV_RATE default, requests/minute
	impliedMin := float64(total) / prodRate

	t.Logf("\n"+
		"  fleet size .................. %d owners (1 permit each)\n"+
		"  orchestration wall-clock .... %s over %d reconcile pass(es)\n"+
		"  council requests ............ %d total, %.2f per permit\n"+
		"  by endpoint ................. %v\n"+
		"  peak requests/min (unpaced) . %d\n"+
		"  IMPLIED convergence @ %.0f/min %.1f min\n"+
		"  dashboard read under load ... p50 %s  p95 %s  p99 %s  (n=%d)\n",
		size, elapsed.Round(time.Millisecond), passes,
		total, perPermit, byPath, council.peakPerMinute(),
		prodRate, impliedMin, p50, p95, p99, n)

	// Guard rails rather than tuning targets: these catch a REGRESSION in cost or
	// contention, which is the thing a harness can honestly assert.
	if perPermit > 6 {
		t.Errorf("a permit cost %.2f council requests to converge, over the budget of 6; "+
			"at 500 owners that is %.0f requests a rollover and the convergence bound moves with it",
			perPermit, perPermit*500)
	}
	if p95 > 250*time.Millisecond {
		t.Errorf("dashboard reads hit p95 %s while the fleet converged; every request shares one "+
			"SQLite connection, so this is what the UI feels during a rollover", p95)
	}
}

// probeReads runs a representative dashboard read in a loop and returns its latency
// distribution. This is the cascade detector: every request in this app serialises
// through ONE SQLite connection, so if any council call were made while holding it, a
// slow or refusing council would freeze the UI for everyone rather than just delaying
// permits. The council here is deliberately far slower than the store.
func probeReads(ctx context.Context, st *store.Store, stop <-chan struct{}) func() (p50, p95, p99 time.Duration, n int) {
	var mu sync.Mutex
	var samples []time.Duration
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			if _, err := st.ListPermitsFor(ctx, "owner0000@example.com"); err != nil {
				return
			}
			d := time.Since(start)
			mu.Lock()
			samples = append(samples, d)
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
		}
	}()
	return func() (time.Duration, time.Duration, time.Duration, int) {
		<-done
		mu.Lock()
		defer mu.Unlock()
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		q := func(f float64) time.Duration {
			if len(samples) == 0 {
				return 0
			}
			return samples[int(float64(len(samples)-1)*f)]
		}
		return q(0.50), q(0.95), q(0.99), len(samples)
	}
}

// TestFleetUnderFailure asks the question a clean-path harness cannot: when the council
// is slow, refusing, or has killed every session, does the damage stay in the council
// path, or does it cascade into the app?
//
// Three things would count as a cascade and are asserted against:
//   - dashboard reads degrading with council latency (a council call under the DB lock)
//   - failures producing MORE council traffic than the clean run (a retry storm feeding
//     the very block that caused it, on a shared egress IP)
//   - the pass never terminating
func TestFleetUnderFailure(t *testing.T) {
	requireFleet(t)
	size := fleetSize(t, 100)

	// Clean baseline to measure the failure runs against.
	base := newFleetRig(t, size)
	baseStop := make(chan struct{})
	baseReads := probeReads(context.Background(), base.store, baseStop)
	baseStart := time.Now()
	base.sched.reconcileAll(context.Background())
	baseElapsed := time.Since(baseStart)
	close(baseStop)
	_, baseP95, _, _ := baseReads()
	baseReqs := base.council.total()
	t.Logf("baseline: %d requests, %s, dashboard p95 %s", baseReqs, baseElapsed.Round(time.Millisecond), baseP95)

	cases := []struct {
		name      string
		latencyMS int64
		failEvery int64
		failCode  int64
		retryPost int64
		authDead  bool
		// maxReqFactor bounds total council traffic against the clean baseline.
		maxReqFactor float64
	}{
		{name: "slow council (250ms every call)", latencyMS: 250, maxReqFactor: 1.5},
		{name: "1-in-3 rate-limited (429 + Retry-After 60)", failEvery: 3, failCode: 429, retryPost: 60, maxReqFactor: 3},
		{name: "1-in-2 gateway errors (503)", failEvery: 2, failCode: 503, maxReqFactor: 3},
		{name: "every session killed (401)", failEvery: 1, failCode: 401, maxReqFactor: 4},
		{name: "slow AND refusing", latencyMS: 100, failEvery: 4, failCode: 429, maxReqFactor: 3},
		// Not an API refusal: the session COOKIE is dead, so authorize returns the login
		// page. This is the churn incident's shape, and the only scenario that reaches
		// the reconnect worker.
		{name: "every cookie rejected (login page)", authDead: true, maxReqFactor: 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rig := newFleetRig(t, size)
			rig.council.latencyMS.Store(tc.latencyMS)
			rig.council.failEvery.Store(tc.failEvery)
			rig.council.failCode.Store(tc.failCode)
			rig.council.retryPost.Store(tc.retryPost)
			rig.council.authDead.Store(tc.authDead)

			stop := make(chan struct{})
			reads := probeReads(ctx, rig.store, stop)

			// A fixed number of passes rather than "until converged": under a hard block
			// convergence is SUPPOSED to be incomplete, and hanging until it isn't would
			// only be measuring the deadline.
			start := time.Now()
			const passes = 3
			for i := 0; i < passes; i++ {
				rig.sched.reconcileAll(ctx)
			}
			elapsed := time.Since(start)
			close(stop)
			p50, p95, p99, n := reads()

			reqs := rig.council.total()
			open := rig.sched.council.(*parking.Client).Blocked()
			t.Logf("\n"+
				"    council requests ...... %d over %d passes (baseline %d for 1)\n"+
				"    refusals served ....... %d\n"+
				"    converged ............. %d/%d\n"+
				"    wall-clock ............ %s\n"+
				"    breaker open .......... %v\n"+
				"    dashboard reads ....... p50 %s  p95 %s  p99 %s  (n=%d)\n",
				reqs, passes, baseReqs, rig.council.failures.Load(),
				rig.converged(), size, elapsed.Round(time.Millisecond), open, p50, p95, p99, n)

			// CASCADE 1: the UI must not feel the council at all.
			if p95 > 50*time.Millisecond {
				t.Errorf("dashboard reads hit p95 %s while the council was degraded; the council "+
					"path is holding the single SQLite connection, so one slow upstream freezes "+
					"the whole app rather than just delaying permits", p95)
			}
			// CASCADE 2: trouble must not generate MORE load on the thing in trouble.
			if limit := float64(baseReqs) * tc.maxReqFactor * float64(passes); float64(reqs) > limit {
				t.Errorf("failure produced %d council requests, over the %.0f budget: retrying "+
					"into a refusing edge from one shared IP is how a soft block becomes a hard one",
					reqs, limit)
			}
			// CASCADE 3: the pass must still finish, and "finish" has to scale with the
			// work. A fixed ceiling was really an assertion about fleet size: at 250ms a
			// call, 500 owners cannot possibly come in under 90s, so the test failed on
			// arithmetic rather than on anything going wrong. Budget the injected latency
			// explicitly and allow 4x headroom over it.
			budget := 10 * time.Second
			if tc.latencyMS > 0 {
				perPass := time.Duration(tc.latencyMS) * time.Millisecond * time.Duration(size) * 3
				budget += 4 * time.Duration(passes) * perPass / time.Duration(cfgConcurrency)
			}
			if elapsed > budget {
				t.Errorf("%d reconcile passes took %s against a budget of %s; the scheduler is "+
					"not shedding work and a rollover would never land", passes, elapsed, budget)
			}
		})
	}
}
