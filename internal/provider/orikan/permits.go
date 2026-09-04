package orikan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/provider"
)

// ---- permit list ----

// POINTERS, so an ABSENT key is distinguishable from a present zero/empty. Without
// that, `{}` decodes to (nil, 0) and reads as "this account has no permits".
type gridResp struct {
	PermitGrid *[]gridRow `json:"PermitGrid"`
	TotalItems *int       `json:"TotalItems"`
}

// gridRow is decoded with POINTERS for every field drift acts on, so an omitted key
// is distinguishable from a legitimately empty value: blank PermitStatus/EndDate
// would otherwise be written over good stored metadata.
//
// VehicleRego is the one deliberate EXEMPTION: the portal sends null for a permit
// that has never had a vehicle assigned (observed live 2026-08-22), and a nil
// pointer cannot tell that from a dropped key. Treating it as "" is safe because
// drift never blanks a stored plate on the grid's word alone — an empty grid rego
// triggers a corroborating managedVehicle read first.
type gridRow struct {
	PKPermitID                            int64   `json:"PKPermitID"`
	FKPermitTypeID                        *int64  `json:"FKPermitTypeID"`
	PermitNumber                          *string `json:"PermitNumber"`
	PermitType                            *string `json:"PermitType"`
	PermitStatus                          *string `json:"PermitStatus"`
	VehicleRego                           *string `json:"VehicleRego"`
	StartDate                             *string `json:"StartDate"`
	EndDate                               *string `json:"EndDate"`
	PermitTypeAllowsVehicleChangeByHolder *bool   `json:"PermitTypeAllowsVehicleChangeByHolder"`
	IsCoHolder                            bool    `json:"IsCoHolder"`
}

// missingGridFields names the absent keys on a row, so the shape-change error says
// which field vanished rather than just that something did.
func (r gridRow) missingGridFields() []string {
	var missing []string
	for _, f := range []struct {
		name    string
		present bool
	}{
		{"FKPermitTypeID", r.FKPermitTypeID != nil},
		{"PermitNumber", r.PermitNumber != nil},
		{"PermitType", r.PermitType != nil},
		{"PermitStatus", r.PermitStatus != nil},
		// VehicleRego deliberately absent: null means "no vehicle assigned yet".
		{"StartDate", r.StartDate != nil},
		{"EndDate", r.EndDate != nil},
		{"PermitTypeAllowsVehicleChangeByHolder", r.PermitTypeAllowsVehicleChangeByHolder != nil},
	} {
		if !f.present {
			missing = append(missing, f.name)
		}
	}
	return missing
}

// maxPermitPages bounds the paging loop. A household with more than this many
// permits does not exist; the cap is here so a portal that ignores pageNumber
// cannot turn one read into an unbounded request loop.
const maxPermitPages = 20

// ListPermits reads the account's whole permit list, paging if the portal gives us
// one, and returns the total the portal claims. len(permits) < total means we ended
// up holding a page rather than the account: the account changed mid-read, paging
// stalled, or the cap was hit. The rows are still usable; the generic client and
// the core decide what a partial list may be used for.
//
// We ask for pageSize=0 ("everything") and the portal has always honoured it, so
// the loop normally runs exactly once.
func (c *Client) ListPermits(ctx context.Context, s *provider.Session) ([]provider.Permit, int, error) {
	ss, err := load(s)
	if err != nil {
		return nil, 0, err
	}
	permits, total, err := c.listPermits(ctx, ss)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return permits, total, err
}

func (c *Client) listPermits(ctx context.Context, ss *session) ([]provider.Permit, int, error) {
	var all []provider.Permit
	seen := make(map[string]bool)
	expected := -1 // the account size the FIRST page claimed
	for page := 0; page < maxPermitPages; page++ {
		rows, total, err := c.permitPage(ctx, ss, page)
		if err != nil {
			return nil, 0, err
		}
		if expected < 0 {
			expected = total
		} else if total != expected {
			// The account changed under us mid-read. Accepting the new count would let
			// stale rows collected earlier satisfy a smaller total while a permit that
			// exists right now was never returned. A snapshot we cannot trust is
			// reported incomplete; the next pass reads it cleanly.
			// Reported as partial by construction (total > len), whichever way the
			// count moved, so a caller can never mistake it for the whole account.
			log.Printf("orikan: permit count changed mid-read (%d -> %d at page %d); treating this list as incomplete", expected, total, page)
			return all, max(expected, total, len(all)+1), nil
		}
		added := 0
		for _, p := range rows {
			if seen[p.CouncilPermitID] {
				continue // a portal that ignores pageNumber would repeat page 0 forever
			}
			seen[p.CouncilPermitID] = true
			all = append(all, p)
			added++
		}
		if len(all) >= expected {
			return all, expected, nil
		}
		if added == 0 {
			// No progress and still short of the count: paging is not working the way
			// we assumed, so report what we have as partial.
			log.Printf("orikan: permit list stalled at %d of %d after %d page(s); reporting a partial list", len(all), expected, page+1)
			return all, expected, nil
		}
	}
	log.Printf("orikan: permit list still incomplete after %d pages; reporting a partial list", maxPermitPages)
	return all, expected, nil
}

// permitPage reads ONE page of the grid and returns its rows plus the total the
// portal says the account holds.
func (c *Client) permitPage(ctx context.Context, ss *session, page int) (_ []provider.Permit, total int, err error) {
	const op = provider.OpListPermits
	resp, err := c.apiRequest(ctx, ss, http.MethodGet, "/api/Index/grid", op,
		url.Values{"pageNumber": {strconv.Itoa(page)}, "pageSize": {"0"}}, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var g gridResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&g); err != nil {
		return nil, 0, provider.Fail(provider.FailUnexpected, op, err)
	}
	// A 200 whose body decoded to nothing useful is an API-SHAPE failure, not "this
	// account has no permits". BOTH top-level fields must be explicitly present.
	if g.PermitGrid == nil || g.TotalItems == nil {
		return nil, 0, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("permit grid response is missing PermitGrid=%t/TotalItems=%t: API shape change?", g.PermitGrid == nil, g.TotalItems == nil))
	}
	rows, total := *g.PermitGrid, *g.TotalItems
	// Deliberately NOT exact equality (a default page size would make TotalItems the
	// unpaged total). What must never pass: the portal says there ARE permits and
	// sent none, or more rows than it says exist.
	if len(rows) == 0 && total != 0 {
		return nil, 0, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("permit grid is empty but the response claims %d items: API shape change?", total))
	}
	if total < len(rows) {
		return nil, 0, provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("permit grid has %d rows but the response claims only %d items: API shape change?", len(rows), total))
	}
	out := make([]provider.Permit, 0, len(rows))
	for _, r := range rows {
		if r.PKPermitID <= 0 {
			return nil, 0, provider.Fail(provider.FailUnexpected, op,
				fmt.Errorf("a permit row has a non-positive PKPermitID (%d): API shape change?", r.PKPermitID))
		}
		if missing := r.missingGridFields(); len(missing) > 0 {
			return nil, 0, provider.Fail(provider.FailUnexpected, op,
				fmt.Errorf("permit %d is missing %s: API shape change? Treating an absent field as empty would blank the stored permit and clear its plate", r.PKPermitID, strings.Join(missing, ", ")))
		}
		start, serr := tenantDate(*r.StartDate)
		end, eerr := tenantDate(*r.EndDate)
		if serr != nil || eerr != nil {
			return nil, 0, provider.Fail(provider.FailUnexpected, op,
				fmt.Errorf("permit %d has an unparseable date (start=%q end=%q): API shape change?", r.PKPermitID, safeExcerpt(*r.StartDate), safeExcerpt(*r.EndDate)))
		}
		out = append(out, provider.Permit{
			CouncilPermitID:  strconv.FormatInt(r.PKPermitID, 10),
			PermitTypeID:     strconv.FormatInt(*r.FKPermitTypeID, 10),
			PermitNumber:     *r.PermitNumber,
			PermitType:       *r.PermitType,
			Status:           *r.PermitStatus,
			CurrentRego:      strOrEmpty(r.VehicleRego),
			StartDate:        start,
			EndDate:          end,
			CanChangeVehicle: *r.PermitTypeAllowsVehicleChangeByHolder,
			IsCoHolder:       r.IsCoHolder,
		})
	}
	return out, total, nil
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// tenantDate parses a portal date, reporting a malformed one instead of
// swallowing it. Empty means "not set" and is not an error.
func tenantDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse("2006-01-02T15:04:05", s)
}
