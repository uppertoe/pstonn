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

func TestFleetConvergenceAndContention(t *testing.T) {
	if os.Getenv("PSTONN_FLEET") == "" {
		t.Skip("set PSTONN_FLEET=1 to run the synthetic fleet harness")
	}
	size := 100
	if v := os.Getenv("PSTONN_FLEET_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("PSTONN_FLEET_SIZE=%q is not a positive integer", v)
		}
		size = n
	}
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
	cfg.Council.GovConcurrency = 8

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
		if err := st.UpdateCouncilToken(ctx, owner, cs.Cookie, seal("tok-"+tag), time.Now().Add(time.Hour), cs.Generation); err != nil {
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
		done := 0
		council.mu.Lock()
		for i := 0; i < size; i++ {
			if council.plates[fmt.Sprintf("owner%04d@example.com", i)] == fmt.Sprintf("NEW%03d", i%1000) {
				done++
			}
		}
		council.mu.Unlock()
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
