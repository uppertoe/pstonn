package parking

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/uppertoe/pstonn/internal/provider"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/uppertoe/pstonn/internal/model"
)

// End to end through the real client: a response that dropped permitVehicleCount is
// an unexpected shape, NOT an empty permit — so CurrentVehicle errors rather than
// reporting a false clearing. An explicit count:0 + [] is a believed empty permit.
func TestCurrentVehicleRejectsMissingCount(t *testing.T) {
	const owner = "shape@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	f.apiBody.Store(`{"permitNumber":"VPP1"}`) // count and vehicles both absent
	if _, err := c.CurrentVehicle(context.Background(), owner, p); err == nil {
		t.Fatal("a response missing permitVehicleCount must not read as an empty permit")
	}

	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":0,"permitVehicles":[]}`)
	reg, err := c.CurrentVehicle(context.Background(), owner, p)
	if err != nil || reg != "" {
		t.Fatalf("an explicit empty permit should read as no vehicle, got reg=%q err=%v", reg, err)
	}
}

// The visitor-permit model is one managed vehicle. More than one is an unexpected
// shape: reading (or editing) only [0] could act on the wrong record, so refuse.
func TestCurrentVehicleRejectsMultipleVehicles(t *testing.T) {
	const owner = "multi@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}

	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":2,"permitVehicles":[` +
		`{"PKPermitVehicleDetailID":1,"RegistrationNumber":"AAA111","FKVehicleStateID":"1"},` +
		`{"PKPermitVehicleDetailID":2,"RegistrationNumber":"BBB222","FKVehicleStateID":"1"}]}`)
	_, err := c.CurrentVehicle(context.Background(), owner, p)
	if err == nil || !strings.Contains(err.Error(), "exactly one managed vehicle") {
		t.Fatalf("two managed vehicles should be refused as unexpected, got %v", err)
	}
}

// A plate read that was already in flight when the permit was FORGOTTEN must not
// resurrect the cache entry: storeRegIfCurrent drops a write whose generation is
// stale.
func TestForgetPermitInvalidatesInFlightRefresh(t *testing.T) {
	c := NewClient(nil, nil, nil, nil)
	key := regKey{"owner@example.com", "p1"}

	gen := c.regGeneration(key)             // captured "before the read"
	c.ForgetPermit(key.owner, key.permitID) // permit removed while the read runs
	c.storeRegIfCurrent(key, gen, "STALE1") // the read completes and tries to store

	if _, ok := c.regCache.Load(key); ok {
		t.Fatal("a forgotten permit's cache entry was resurrected by an in-flight refresh")
	}

	// A fresh read (generation captured after the forget) stores normally.
	gen2 := c.regGeneration(key)
	c.storeRegIfCurrent(key, gen2, "FRESH1")
	if v, ok := c.regCache.Load(key); !ok || v.(cachedReg).reg != "FRESH1" {
		t.Fatalf("a current-generation write should store, got %v (ok=%v)", v, ok)
	}
}

// A PRESENT vehicle record with a blank registration is not "no vehicle": returning
// "" would cache and display an uncorroborated clearing. It must be an unexpected shape.
func TestCurrentVehicleRejectsBlankRegoOnPresentVehicle(t *testing.T) {
	const owner = "blank@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}
	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":1,"permitVehicles":[{"PKPermitVehicleDetailID":1,"RegistrationNumber":"   ","FKVehicleStateID":"1"}]}`)
	if _, err := c.CurrentVehicle(context.Background(), owner, p); err == nil {
		t.Fatal("a present vehicle with a blank registration must be unexpected, not an empty permit")
	}
}

// A 200 whose body decoded to nothing useful must be an API-shape failure, not "this
// account has no permits" — believing the latter makes a real permit look gone and
// lets drift record a clean empty snapshot over live state.
func TestListPermitsRejectsInconsistentGrid(t *testing.T) {
	const owner = "grid@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	f.mux.HandleFunc("/ssp-svc/api/Index/grid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, f.gridBody.Load().(string))
	})

	// row builds a COMPLETE grid row. Every field drift acts on must be present, so
	// tests that are about something else (counts, ids) must not accidentally also be
	// testing absence.
	row := func(id int64, over string) string {
		base := fmt.Sprintf(`"PKPermitID":%d,"FKPermitTypeID":3,"PermitNumber":"P1","PermitType":"Resident",`+
			`"PermitStatus":"Active","VehicleRego":"ABC123","StartDate":"2026-01-01T00:00:00",`+
			`"EndDate":"2026-12-31T00:00:00","PermitTypeAllowsVehicleChangeByHolder":true`, id)
		if over != "" {
			base += "," + over
		}
		return "{" + base + "}"
	}

	// `{}` — every field absent — must NOT read as "no permits" (the missing-vs-zero
	// trap: absent decodes to nil/0 and looked identical to a genuinely empty account).
	for _, body := range []string{`{}`, `{"TotalItems":0}`, `{"PermitGrid":[]}`} {
		f.gridBody.Store(body)
		if _, err := c.ListPermits(context.Background(), owner); err == nil {
			t.Fatalf("%s must be refused as a shape change, not read as an empty account", body)
		}
	}
	// More rows than the count claims is impossible: refuse.
	f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[` + row(1, "") + `,` + row(2, "") + `]}`)
	if _, err := c.ListPermits(context.Background(), owner); err == nil {
		t.Fatal("more rows than TotalItems must be refused")
	}
	// FEWER rows than the count is tolerated: a permit missing from the grid is skipped
	// by drift, never stripped, whereas an error aborts the pass before expiry warnings
	// go out and breaks the picker for the whole account. But it must not pass unseen —
	// it means the tenant has started paging and we owe it real pagination.
	f.gridBody.Store(`{"TotalItems":2,"PermitGrid":[` + row(1, "") + `]}`)
	if ps, err := c.ListPermits(context.Background(), owner); err != nil || len(ps) != 1 {
		t.Fatalf("a partial page should degrade, not fail: %v / %d", err, len(ps))
	}
	// The bool drift actually branches on must be asserted directly, not inferred from
	// the Stats side-effect: if `complete = true` were ever moved below the truncation
	// branch, every truncated read would report itself whole and the guard would revert
	// silently, with the Stats assertion below still passing.
	if _, complete, err := c.ListPermitsComplete(context.Background(), owner); err != nil || complete {
		t.Fatalf("ListPermitsComplete reported complete=%v (err %v) for a truncated grid; "+
			"drift would check the owner off on the strength of one page", complete, err)
	}
	if st := c.Stats(); st.TruncatedGridAt.IsZero() || st.TruncatedGridGot != 1 || st.TruncatedGridWant != 2 {
		t.Fatalf("a truncated permit grid was not recorded for the operator: %+v; "+
			"acting on a partial list while reporting nothing is how a paging change stays invisible", st)
	}
	// An OMITTED field must be refused, not coerced to "": absent PermitStatus or
	// EndDate would be written over good stored metadata. VehicleRego is exempt —
	// asserted separately below — because the tenant genuinely sends null for a
	// permit with no vehicle assigned, and drift corroborates an empty grid rego
	// against managedVehicle before ever acting on it.
	for _, field := range []string{"PermitStatus", "EndDate", "PermitType", "PermitNumber",
		"FKPermitTypeID", "PermitTypeAllowsVehicleChangeByHolder"} {
		full := row(9, "")
		var partial map[string]any
		if err := json.Unmarshal([]byte(full), &partial); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		delete(partial, field)
		b, _ := json.Marshal([]any{partial})
		f.gridBody.Store(`{"TotalItems":1,"PermitGrid":` + string(b) + `}`)
		if _, err := c.ListPermits(context.Background(), owner); err == nil {
			t.Fatalf("a grid row missing %s was accepted; an absent key is indistinguishable "+
				"from an empty value once decoded, and drift acts on the difference", field)
		}
	}
	// VehicleRego null or omitted is a permit with NO VEHICLE ASSIGNED YET — the
	// normal state of a freshly granted permit — and must parse as an empty plate,
	// not be refused as drift. Requiring it locked a real signup out of the picker
	// (observed live 2026-08-22): their only permit had never had a rego set, so
	// every load of their account failed as "API shape change".
	for _, over := range []string{`"VehicleRego":null`, ""} {
		full := row(9, "")
		if over != "" {
			full = strings.Replace(full, `"VehicleRego":"ABC123"`, over, 1)
		} else {
			full = strings.Replace(full, `"VehicleRego":"ABC123",`, "", 1)
		}
		f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[` + full + `]}`)
		ps, err := c.ListPermits(context.Background(), owner)
		if err != nil || len(ps) != 1 {
			t.Fatalf("a row with VehicleRego %q must be accepted as an unassigned permit: %v / %d", over, err, len(ps))
		}
		if ps[0].CurrentRego != "" {
			t.Fatalf("an unassigned permit must read as an empty plate, got %q", ps[0].CurrentRego)
		}
	}
	// A COMPLETE row still passes, so the guard above rejects absence and not shape.
	f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[` + row(9, "") + `]}`)
	if ps, err := c.ListPermits(context.Background(), owner); err != nil || len(ps) != 1 {
		t.Fatalf("a complete grid row must be accepted: %v / %d", err, len(ps))
	}
	if _, complete, err := c.ListPermitsComplete(context.Background(), owner); err != nil || !complete {
		t.Fatalf("ListPermitsComplete reported complete=%v (err %v) for a WHOLE account; "+
			"drift would never check anyone off", complete, err)
	}
	// Negative ids are as unusable as zero.
	f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[` + row(-4, "") + `]}`)
	if _, err := c.ListPermits(context.Background(), owner); err == nil {
		t.Fatal("a negative PKPermitID must be refused")
	}
	// A malformed date must not silently become the zero time: end_date drives expiry.
	f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[` + row(7, `"EndDate":"31/12/2026"`) + `]}`)
	if _, err := c.ListPermits(context.Background(), owner); err == nil {
		t.Fatal("an unparseable date must be refused, not zeroed")
	}
	// The tenant's own count contradicts the empty grid: refuse.
	f.gridBody.Store(`{"TotalItems":3,"PermitGrid":[]}`)
	if _, err := c.ListPermits(context.Background(), owner); err == nil {
		t.Fatal("an empty grid contradicting TotalItems must not read as 'no permits'")
	}
	// A row with no permit id is unusable and must not become the string "0".
	f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[{"PermitNumber":"VPP1"}]}`)
	if _, err := c.ListPermits(context.Background(), owner); err == nil {
		t.Fatal("a permit row with no PKPermitID must be refused")
	}
	// A genuinely empty account still works.
	f.gridBody.Store(`{"TotalItems":0,"PermitGrid":[]}`)
	if ps, err := c.ListPermits(context.Background(), owner); err != nil || len(ps) != 0 {
		t.Fatalf("a corroborated empty account should read as no permits: %v / %d", err, len(ps))
	}
}

// The detail id is the only field on the manageVehicle write that was taken on trust.
// Absent, json.Number("").String() is "", and we would POST an edit with an empty
// SelectedVehicle/ChangeSetID — on the one code path that can put a wrong plate on a
// real permit. It must fail closed.
func TestSetVehicleRejectsMissingDetailID(t *testing.T) {
	const owner = "detail@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}
	// A well-formed record in every respect EXCEPT the detail id, and a plate that
	// differs from the target so the no-op short-circuit does not hide it.
	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":1,"maxVehicles":1,"canEditOrDeleteVehicle":true,` +
		`"permitVehicles":[{"RegistrationNumber":"AAA111","FKVehicleStateID":"1"}]}`)
	err := c.SetVehicle(context.Background(), owner, p, "BBB222", "")
	if err == nil {
		t.Fatal("a managed vehicle with no PKPermitVehicleDetailID must not be written to")
	}
	if kind, _ := provider.FailureOf(err); kind != provider.FailUnexpected {
		t.Fatalf("kind = %v, want provider.FailUnexpected (a shape change, not a durable refusal)", kind)
	}
}

// TestListPermitsPagesUntilComplete covers the case the truncation guard only ever
// reported. We ask for pageSize=0 ("everything") and the tenant has always honoured
// it, but if it ever applies a default page size, accepting the first page is silently
// wrong in a way households feel: the picker shows a short list, and addPermit reads
// absence from that page as "this permit is not yours" and refuses a permit they hold.
func TestListPermitsPagesUntilComplete(t *testing.T) {
	const owner = "paged@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)

	row := func(id int64) string {
		return fmt.Sprintf(`{"PKPermitID":%d,"FKPermitTypeID":3,"PermitNumber":"P%d","PermitType":"Resident",`+
			`"PermitStatus":"Active","VehicleRego":"ABC%03d","StartDate":"2026-01-01T00:00:00",`+
			`"EndDate":"2026-12-31T00:00:00","PermitTypeAllowsVehicleChangeByHolder":true}`, id, id, id)
	}
	var pages int32
	f.mux.HandleFunc("/ssp-svc/api/Index/grid", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pages, 1)
		w.Header().Set("Content-Type", "application/json")
		// Three permits, one per page — the tenant's own count stays at the unpaged total.
		switch r.URL.Query().Get("pageNumber") {
		case "0":
			io.WriteString(w, `{"TotalItems":3,"PermitGrid":[`+row(1)+`]}`)
		case "1":
			io.WriteString(w, `{"TotalItems":3,"PermitGrid":[`+row(2)+`]}`)
		default:
			io.WriteString(w, `{"TotalItems":3,"PermitGrid":[`+row(3)+`]}`)
		}
	})

	ps, complete, err := c.ListPermitsComplete(context.Background(), owner)
	if err != nil {
		t.Fatalf("ListPermitsComplete: %v", err)
	}
	if !complete {
		t.Error("a fully-collected list reported itself partial, so drift would never " +
			"check this owner off again")
	}
	if len(ps) != 3 {
		t.Fatalf("collected %d permits across pages, want 3: a permit beyond the first page "+
			"is invisible to the picker and refused by addPermit", len(ps))
	}
	if n := atomic.LoadInt32(&pages); n != 3 {
		t.Errorf("made %d page requests, want 3", n)
	}
	// The truncation signal must stay quiet: paging worked, nothing was lost.
	if !c.Stats().TruncatedGridAt.IsZero() {
		t.Error("successful paging still reported a truncated grid to the operator")
	}
}

// TestListPermitsStopsWhenPagingMakesNoProgress pins the guard against a tenant that
// ignores pageNumber: repeating page 0 forever must terminate, not loop against the
// shared egress IP.
func TestListPermitsStopsWhenPagingMakesNoProgress(t *testing.T) {
	const owner = "stuck@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)

	var reqs int32
	f.mux.HandleFunc("/ssp-svc/api/Index/grid", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqs, 1)
		w.Header().Set("Content-Type", "application/json")
		// Claims 5, always returns the same single row whatever page we ask for.
		io.WriteString(w, `{"TotalItems":5,"PermitGrid":[{"PKPermitID":1,"FKPermitTypeID":3,
			"PermitNumber":"P1","PermitType":"Resident","PermitStatus":"Active","VehicleRego":"ABC001",
			"StartDate":"2026-01-01T00:00:00","EndDate":"2026-12-31T00:00:00",
			"PermitTypeAllowsVehicleChangeByHolder":true}]}`)
	})

	ps, complete, err := c.ListPermitsComplete(context.Background(), owner)
	if err != nil {
		t.Fatalf("ListPermitsComplete: %v", err)
	}
	if complete {
		t.Error("a list we could not complete reported itself whole")
	}
	if len(ps) != 1 {
		t.Fatalf("got %d permits, want the 1 distinct row", len(ps))
	}
	if n := atomic.LoadInt32(&reqs); n > 3 {
		t.Errorf("made %d requests against a council that ignores pageNumber; it must stop "+
			"as soon as a page adds nothing, not hammer a shared IP", n)
	}
	if c.Stats().TruncatedGridAt.IsZero() {
		t.Error("an incomplete list was not reported to the operator")
	}
}

// TestListPermitsRefusesAShiftingSnapshot pins that pagination fails closed when the
// account changes underneath it. Completion used to be judged against whatever the
// LATEST page claimed, so a count that shrank mid-read could be satisfied by rows
// collected earlier while a permit that exists right now was never returned — and
// drift would check the owner off as fully seen.
func TestListPermitsRefusesAShiftingSnapshot(t *testing.T) {
	const owner = "shifting@example.com"
	f := newFakeTenant(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)

	row := func(id int64) string {
		return fmt.Sprintf(`{"PKPermitID":%d,"FKPermitTypeID":3,"PermitNumber":"P%d","PermitType":"Resident",`+
			`"PermitStatus":"Active","VehicleRego":"ABC%03d","StartDate":"2026-01-01T00:00:00",`+
			`"EndDate":"2026-12-31T00:00:00","PermitTypeAllowsVehicleChangeByHolder":true}`, id, id, id)
	}
	f.mux.HandleFunc("/ssp-svc/api/Index/grid", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("pageNumber") == "0" {
			io.WriteString(w, `{"TotalItems":3,"PermitGrid":[`+row(1)+`]}`)
			return
		}
		// The account "shrank" between pages: two rows now, and we already hold one, so
		// a naive check would call this complete while permit 3 was never sent.
		io.WriteString(w, `{"TotalItems":2,"PermitGrid":[`+row(2)+`]}`)
	})

	ps, complete, err := c.ListPermitsComplete(context.Background(), owner)
	if err != nil {
		t.Fatalf("ListPermitsComplete: %v", err)
	}
	if complete {
		t.Fatalf("a list read across a changing account reported itself whole (%d rows); "+
			"drift would advance its checkpoint having never seen every permit", len(ps))
	}
	if c.Stats().TruncatedGridAt.IsZero() {
		t.Error("a snapshot we could not trust was not reported to the operator")
	}
}
