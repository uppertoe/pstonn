package parking

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/model"
)

// emptyIsCredible must require every corroborating field to be EXPLICITLY present.
// A shape change that drops permitVehicleCount (or the permitVehicles array) while
// keeping permitNumber must NOT read as a credible empty permit.
func TestEmptyIsCredibleRequiresExplicitFields(t *testing.T) {
	zero := 0
	one := 1
	cases := []struct {
		name string
		mv   managedVehicleResp
		want bool
	}{
		{"count 0 and explicit empty array", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &zero, PermitVehicles: []permitVehicle{}}, true},
		{"count field absent", managedVehicleResp{PermitNumber: "VPP1", PermitVehicles: []permitVehicle{}}, false},
		{"permitVehicles key absent", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &zero}, false},
		{"permitNumber absent", managedVehicleResp{PermitVehicleCount: &zero, PermitVehicles: []permitVehicle{}}, false},
		{"count present but non-zero", managedVehicleResp{PermitNumber: "VPP1", PermitVehicleCount: &one, PermitVehicles: []permitVehicle{}}, false},
	}
	for _, c := range cases {
		if got := c.mv.emptyIsCredible(); got != c.want {
			t.Errorf("%s: emptyIsCredible = %v, want %v", c.name, got, c.want)
		}
	}
}

// End to end through the real client: a response that dropped permitVehicleCount is
// an unexpected shape, NOT an empty permit — so CurrentVehicle errors rather than
// reporting a false clearing. An explicit count:0 + [] is a believed empty permit.
func TestCurrentVehicleRejectsMissingCount(t *testing.T) {
	const owner = "shape@example.com"
	f := newFakeCouncil(t)
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
	f := newFakeCouncil(t)
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
	c := &Client{}
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
	f := newFakeCouncil(t)
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
	f := newFakeCouncil(t)
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
	// it means the council has started paging and we owe it real pagination.
	f.gridBody.Store(`{"TotalItems":2,"PermitGrid":[` + row(1, "") + `]}`)
	if ps, err := c.ListPermits(context.Background(), owner); err != nil || len(ps) != 1 {
		t.Fatalf("a partial page should degrade, not fail: %v / %d", err, len(ps))
	}
	if st := c.Stats(); st.TruncatedGridAt.IsZero() || st.TruncatedGridGot != 1 || st.TruncatedGridWant != 2 {
		t.Fatalf("a truncated permit grid was not recorded for the operator: %+v; "+
			"acting on a partial list while reporting nothing is how a paging change stays invisible", st)
	}
	// An OMITTED field must be refused, not coerced to "". Absent VehicleRego would read
	// as "the council holds no plate", so drift would clear the stored plate and issue a
	// corrective write for every permit on every account at once; absent PermitStatus or
	// EndDate would be written over good stored metadata.
	for _, field := range []string{"VehicleRego", "PermitStatus", "EndDate", "PermitType", "PermitNumber",
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
	// A COMPLETE row still passes, so the guard above rejects absence and not shape.
	f.gridBody.Store(`{"TotalItems":1,"PermitGrid":[` + row(9, "") + `]}`)
	if ps, err := c.ListPermits(context.Background(), owner); err != nil || len(ps) != 1 {
		t.Fatalf("a complete grid row must be accepted: %v / %d", err, len(ps))
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
	// The council's own count contradicts the empty grid: refuse.
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

// A token-shape failure must classify as FailUnexpected. Left unclassified, FailureOf
// defaults it to FailTransient — and a transient verdict on a FLEET-WIDE shape change
// means every owner retries it on every warm tick instead of the operator being told.
func TestTokenShapeFailuresAreUnexpectedNotTransient(t *testing.T) {
	const owner = "tok@example.com"
	for name, body := range map[string]string{
		"no expires_in":     `{"access_token":"a","token_type":"Bearer"}`,
		"zero expires_in":   `{"access_token":"a","expires_in":0,"token_type":"Bearer"}`,
		"absurd expires_in": `{"access_token":"a","expires_in":999999,"token_type":"Bearer"}`,
		"wrong token_type":  `{"access_token":"a","expires_in":3600,"token_type":"Mac"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCouncil(t)
			c, st, box := testClient(t, f)
			linkOwner(t, c, st, box, owner)
			f.mux.HandleFunc("/idm2/connect/token", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, body)
			})
			c.tokenURL = f.srv.URL + "/idm2/connect/token"
			_, err := c.exchangeCode(context.Background(), owner, "code", "verifier")
			if err == nil {
				t.Fatalf("%s should be refused", name)
			}
			if kind, _ := FailureOf(err); kind != FailUnexpected {
				t.Fatalf("%s classified as %v, want FailUnexpected (transient would retry forever)", name, kind)
			}
		})
	}
}

// The detail id is the only field on the manageVehicle write that was taken on trust.
// Absent, json.Number("").String() is "", and we would POST an edit with an empty
// SelectedVehicle/ChangeSetID — on the one code path that can put a wrong plate on a
// real permit. It must fail closed.
func TestSetVehicleRejectsMissingDetailID(t *testing.T) {
	const owner = "detail@example.com"
	f := newFakeCouncil(t)
	c, st, box := testClient(t, f)
	linkOwner(t, c, st, box, owner)
	p := model.Permit{CouncilPermitID: "1"}
	// A well-formed record in every respect EXCEPT the detail id, and a plate that
	// differs from the target so the no-op short-circuit does not hide it.
	f.apiBody.Store(`{"permitNumber":"VPP1","permitVehicleCount":1,"maxVehicles":1,"canEditOrDeleteVehicle":true,` +
		`"permitVehicles":[{"RegistrationNumber":"AAA111","FKVehicleStateID":"1"}]}`)
	err := c.SetVehicle(context.Background(), owner, p, "BBB222")
	if err == nil {
		t.Fatal("a managed vehicle with no PKPermitVehicleDetailID must not be written to")
	}
	if kind, _ := FailureOf(err); kind != FailUnexpected {
		t.Fatalf("kind = %v, want FailUnexpected (a shape change, not a durable refusal)", kind)
	}
}
