package orikan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/provider"
)

// managedVehicleResp is the response of GET /ssp-svc/api/permits/managedVehicle.
//
// Verified against a live response. NOTE the casing is mixed: the top-level keys
// are camelCase, but the permitVehicles[] element keys are PascalCase. Within an
// element, PKPermitVehicleDetailID arrives as a bare JSON number while
// FKVehicleStateID arrives as a quoted string, hence the differing Go types.
// POINTERS wherever an absent key must be distinguishable from a present zero:
// an omitted field must surface as an unexpected shape, never as a durable "the
// portal does not allow…" refusal or as "this permit has no vehicle".
type managedVehicleResp struct {
	PermitNumber           string          `json:"permitNumber"`
	PermitVehicleCount     *int            `json:"permitVehicleCount"`
	MaxVehicles            int             `json:"maxVehicles"`
	CanAddVehicle          *bool           `json:"canAddVehicle"`
	CanEditOrDeleteVehicle *bool           `json:"canEditOrDeleteVehicle"`
	PermitVehicles         []permitVehicle `json:"permitVehicles"`
}

// permitVehicle is one vehicle currently attached to the permit.
type permitVehicle struct {
	PKPermitVehicleDetailID json.Number `json:"PKPermitVehicleDetailID"`
	RegistrationNumber      string      `json:"RegistrationNumber"`
	FKVehicleStateID        string      `json:"FKVehicleStateID"`
}

// manageVehicleReq is the body of POST /ssp-svc/api/permits/manageVehicle.
// Field names, casing, and value types (note the string-typed IDs) mirror a
// captured, server-accepted request exactly.
type manageVehicleReq struct {
	PKPermitID          int64          `json:"PKPermitID"`
	SelectedVehicle     string         `json:"SelectedVehicle"`
	VehicleActionOption string         `json:"VehicleActionOption"`
	Vehicle             manageVehicleV `json:"Vehicle"`
}

type manageVehicleV struct {
	ChangeSetID             string  `json:"ChangeSetID"`
	FKPermitID              int64   `json:"FKPermitID"`
	FKVehicleColourID       *int64  `json:"FKVehicleColourID"`
	FKVehicleMakeID         *int64  `json:"FKVehicleMakeID"`
	FKVehicleModelID        *int64  `json:"FKVehicleModelID"`
	FKVehicleTypeID         *int64  `json:"FKVehicleTypeID"`
	FKVehicleStateID        string  `json:"FKVehicleStateID"`
	PKPermitVehicleDetailID string  `json:"PKPermitVehicleDetailID"`
	RegisteredAtAddress     bool    `json:"RegisteredAtAddress"`
	RegistrationNumber      string  `json:"RegistrationNumber"`
	VehicleColour           *string `json:"VehicleColour"`
	VehicleMake             *string `json:"VehicleMake"`
	VehicleModel            *string `json:"VehicleModel"`
	VehicleNotes            *string `json:"VehicleNotes"`
	VehicleState            *string `json:"VehicleState"`
	VehicleStatus           *string `json:"VehicleStatus"`
	VehicleType             *string `json:"VehicleType"`
}

// emptyIsCredible reports whether an EMPTY permitVehicles list can be believed.
//
// A JSON object that simply lacks the keys we expect decodes into a zero-valued
// struct, so "this permit has no vehicle" and "we did not understand this
// response" arrive looking identical. Treating the second as the first is not a
// harmless default: the scheduler would write an empty plate and SetVehicle would
// turn it into a durable refusal. So an empty list is believed only when the rest
// of the response corroborates it: the permit is identified, the portal's own
// count came back and says zero, AND permitVehicles is an explicit empty array.
func (mv *managedVehicleResp) emptyIsCredible() bool {
	return mv.PermitNumber != "" &&
		mv.PermitVehicleCount != nil && *mv.PermitVehicleCount == 0 &&
		mv.PermitVehicles != nil
}

// errVehicleShape describes an empty vehicle list that nothing corroborates.
func errVehicleShape(mv *managedVehicleResp) error {
	count := "absent"
	if mv.PermitVehicleCount != nil {
		count = fmt.Sprintf("%d", *mv.PermitVehicleCount)
	}
	return fmt.Errorf("the portal returned no vehicles but the response does not look like a permit record (permitNumber=%q, permitVehicleCount=%s, permitVehiclesPresent=%t): API shape change?",
		mv.PermitNumber, count, mv.PermitVehicles != nil)
}

// managedVehicle fetches the vehicle(s) currently on the permit.
func (c *Client) managedVehicle(ctx context.Context, ss *session, p provider.PermitRef, op provider.Op) (*managedVehicleResp, error) {
	resp, err := c.apiRequest(ctx, ss, http.MethodGet, "/api/permits/managedVehicle", op, url.Values{"permitID": {p.ID}}, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var mv managedVehicleResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIBody)).Decode(&mv); err != nil {
		return nil, provider.Fail(provider.FailUnexpected, op, err)
	}
	return &mv, nil
}

// CurrentVehicle returns the registration currently on the permit, or "" if the
// permit genuinely has no vehicle. An empty list the response does not corroborate
// is an error, not an empty plate — see emptyIsCredible.
func (c *Client) CurrentVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) (provider.Vehicle, error) {
	ss, err := load(s)
	if err != nil {
		return provider.Vehicle{}, err
	}
	reg, stateToken, err := c.currentVehicle(ctx, ss, p, provider.OpReadVehicle)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return provider.Vehicle{Registration: reg, Region: tokenRegion(stateToken)}, err
}

// currentVehicle returns the plate on the permit and its state token ("" for a
// genuinely empty permit). The token is the portal's FKVehicleStateID; callers
// that only need the plate ignore it.
func (c *Client) currentVehicle(ctx context.Context, ss *session, p provider.PermitRef, op provider.Op) (reg, stateToken string, err error) {
	mv, err := c.managedVehicle(ctx, ss, p, op)
	if err != nil {
		return "", "", err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return "", "", provider.Fail(provider.FailUnexpected, op, errVehicleShape(mv))
		}
		return "", "", nil
	}
	if len(mv.PermitVehicles) != 1 {
		// The visitor-permit model is one managed vehicle per permit. More than one is
		// an unexpected shape: reading (or later editing) only [0] could act on the
		// wrong record, so refuse rather than guess.
		return "", "", provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	if strings.TrimSpace(mv.PermitVehicles[0].RegistrationNumber) == "" {
		// A PRESENT vehicle record with a blank plate is not "no vehicle": returning ""
		// would report an uncorroborated clearing.
		return "", "", provider.Fail(provider.FailUnexpected, op,
			errors.New("a managed vehicle record has an empty registration: API shape change?"))
	}
	return mv.PermitVehicles[0].RegistrationNumber, mv.PermitVehicles[0].FKVehicleStateID, nil
}

// SetVehicle reallocates the permit to the given registration, the core action.
//
// The portal implements this as an in-place edit of the permit's single vehicle,
// so we first read the current vehicle to obtain its detail ID (and preserve its
// state), then POST the edit. A no-op edit (unchanged plate) is skipped, mirroring
// the portal. A credibly-empty permit gets an ADD instead (the normal state of a
// freshly granted permit). Success is any 2xx with an empty body, which says
// nothing about the resulting state — so the change is confirmed by re-reading the
// portal's own record before success is reported.
func (c *Client) SetVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef, v provider.Vehicle) error {
	ss, err := load(s)
	if err != nil {
		return err
	}
	err = c.setVehicle(ctx, ss, p, v.Registration, v.Region)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return err
}

func (c *Client) setVehicle(ctx context.Context, ss *session, p provider.PermitRef, registration, region string) error {
	const op = provider.OpSetVehicle
	mv, err := c.managedVehicle(ctx, ss, p, op)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return provider.Fail(provider.FailUnexpected, op, errVehicleShape(mv))
		}
		if mv.CanAddVehicle == nil {
			// Absent, not false: cannot tell "not permitted" from "field gone".
			return provider.Fail(provider.FailUnexpected, op, errors.New("response has no canAddVehicle field: API shape change?"))
		}
		if !*mv.CanAddVehicle {
			return provider.Fail(provider.FailRejected, op, errors.New("the portal does not allow adding a vehicle to this permit"))
		}
		return c.addVehicle(ctx, ss, p, registration, region)
	}
	if mv.CanEditOrDeleteVehicle == nil {
		return provider.Fail(provider.FailUnexpected, op, errors.New("response has no canEditOrDeleteVehicle field: API shape change?"))
	}
	if !*mv.CanEditOrDeleteVehicle {
		return provider.Fail(provider.FailRejected, op, errors.New("the portal does not allow changing this permit's vehicle"))
	}
	if len(mv.PermitVehicles) != 1 {
		return provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	cur := mv.PermitVehicles[0]
	// An absent PKPermitVehicleDetailID yields json.Number("") and we would POST an
	// edit with empty ids. This is the one code path that can put a wrong plate on a
	// real permit — so fail closed.
	if strings.TrimSpace(cur.PKPermitVehicleDetailID.String()) == "" {
		return provider.Fail(provider.FailUnexpected, op, errors.New("managed vehicle has no PKPermitVehicleDetailID: API shape change?"))
	}
	// The desired state: an explicit region wins; otherwise keep the state already
	// on the permit, falling back to the tenant home. A same-plate write is skipped
	// only when the state is ALSO already what we want — so correcting just the state
	// on an already-active plate is still applied.
	state := c.writeToken(region, cur.FKVehicleStateID)
	if model.SamePlate(cur.RegistrationNumber, registration) && state == cur.FKVehicleStateID {
		return nil // plate and state already as desired; the read above IS the confirmation
	}
	permitID, err := strconv.ParseInt(p.ID, 10, 64)
	if err != nil {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("invalid permit id %q", p.ID))
	}
	detailID := cur.PKPermitVehicleDetailID.String()
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     detailID,
		VehicleActionOption: "edit",
		Vehicle: manageVehicleV{
			ChangeSetID:             detailID,
			FKPermitID:              permitID,
			FKVehicleStateID:        state,
			PKPermitVehicleDetailID: detailID,
			RegisteredAtAddress:     false,
			RegistrationNumber:      registration,
		},
	}
	if err := c.postManage(ctx, ss, reqBody, op); err != nil {
		return err
	}
	return c.confirmWrite(ctx, ss, p, registration, op)
}

// postManage sends a manageVehicle request and discards the (empty) 2xx body.
func (c *Client) postManage(ctx context.Context, ss *session, reqBody manageVehicleReq, op provider.Op) error {
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	resp, err := c.apiRequest(ctx, ss, http.MethodPost, "/api/permits/manageVehicle", op, nil, buf)
	if err != nil {
		return err
	}
	drainClose(resp)
	return nil
}

// confirmRetryDelay is the single pause confirmWrite takes when the first
// read-back after a 2xx write does not yet show the plate we sent, before it
// reads once more. A variable so tests can shorten it; the transport's governor
// still paces the request itself.
var confirmRetryDelay = 2 * time.Second

// confirmWrite re-reads the portal's OWN record after a 2xx write and only
// reports success once it shows the plate we sent. An unreadable confirm is
// transient (retry). A mismatch on the FIRST read is treated as the portal not
// having caught up yet (a 2xx followed by a stale read has been observed to be
// lag, not refusal): wait briefly and read once more. Only when that second
// read still disagrees is it a durable refusal (act-now notice) — at the cost of
// exactly one extra request, and only on the mismatch path.
// registration "" means "expect the permit empty" (the clear path).
func (c *Client) confirmWrite(ctx context.Context, ss *session, p provider.PermitRef, registration string, op provider.Op) error {
	confirmed, _, err := c.currentVehicle(ctx, ss, p, op)
	if err != nil {
		return provider.Fail(provider.FailTransient, op, fmt.Errorf("change sent but could not be confirmed: %w", err))
	}
	if model.SamePlate(confirmed, registration) {
		return nil
	}
	select {
	case <-ctx.Done():
		return provider.Fail(provider.FailTransient, op, fmt.Errorf("change sent but not yet confirmed (portal still shows %q): %w", confirmed, ctx.Err()))
	case <-time.After(confirmRetryDelay):
	}
	confirmed, _, err = c.currentVehicle(ctx, ss, p, op)
	if err != nil {
		return provider.Fail(provider.FailTransient, op, fmt.Errorf("change sent but could not be confirmed: %w", err))
	}
	if !model.SamePlate(confirmed, registration) {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("change was accepted but the portal still shows %q", confirmed))
	}
	return nil
}

// addVehicle attaches a NEW vehicle to a permit that currently has none — the
// portal's "add" action, distinct from "edit". Captured live 2026-08-23 against an
// empty permit: VehicleActionOption "add", an empty SelectedVehicle, and a Vehicle
// with no prior detail id / change-set (the portal assigns a fresh one).
func (c *Client) addVehicle(ctx context.Context, ss *session, p provider.PermitRef, registration, region string) error {
	const op = provider.OpAddVehicle
	permitID, err := strconv.ParseInt(p.ID, 10, 64)
	if err != nil {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("invalid permit id %q", p.ID))
	}
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     "",
		VehicleActionOption: "add",
		Vehicle: manageVehicleV{
			ChangeSetID:             "",
			FKPermitID:              permitID,
			FKVehicleStateID:        c.writeToken(region, ""), // a bare-plate add carries no prior state
			PKPermitVehicleDetailID: "",                       // new record — the portal assigns the id
			RegisteredAtAddress:     false,
			RegistrationNumber:      registration,
		},
	}
	if err := c.postManage(ctx, ss, reqBody, op); err != nil {
		return err
	}
	return c.confirmWrite(ctx, ss, p, registration, op)
}

// ClearVehicle removes the vehicle from a permit, leaving it with none — the
// portal's "delete" action. Idempotent: an already-empty permit is success.
func (c *Client) ClearVehicle(ctx context.Context, s *provider.Session, p provider.PermitRef) error {
	ss, err := load(s)
	if err != nil {
		return err
	}
	err = c.clearVehicle(ctx, ss, p)
	if serr := save(s, ss); serr != nil && err == nil {
		err = serr
	}
	return err
}

func (c *Client) clearVehicle(ctx context.Context, ss *session, p provider.PermitRef) error {
	const op = provider.OpClearVehicle
	mv, err := c.managedVehicle(ctx, ss, p, op)
	if err != nil {
		return err
	}
	if len(mv.PermitVehicles) == 0 {
		if !mv.emptyIsCredible() {
			return provider.Fail(provider.FailUnexpected, op, errVehicleShape(mv))
		}
		return nil // already empty, corroborated
	}
	if len(mv.PermitVehicles) != 1 {
		return provider.Fail(provider.FailUnexpected, op,
			fmt.Errorf("expected exactly one managed vehicle, got %d: API shape change?", len(mv.PermitVehicles)))
	}
	cur := mv.PermitVehicles[0]
	detailID := cur.PKPermitVehicleDetailID.String()
	if strings.TrimSpace(detailID) == "" {
		return provider.Fail(provider.FailUnexpected, op, errors.New("managed vehicle has no PKPermitVehicleDetailID: API shape change?"))
	}
	permitID, err := strconv.ParseInt(p.ID, 10, 64)
	if err != nil {
		return provider.Fail(provider.FailRejected, op, fmt.Errorf("invalid permit id %q", p.ID))
	}
	state := cur.FKVehicleStateID
	if state == "" {
		state = c.homeToken
	}
	reqBody := manageVehicleReq{
		PKPermitID:          permitID,
		SelectedVehicle:     detailID,
		VehicleActionOption: "delete",
		Vehicle: manageVehicleV{
			ChangeSetID:             detailID,
			FKPermitID:              permitID,
			FKVehicleStateID:        state,
			PKPermitVehicleDetailID: detailID,
			RegisteredAtAddress:     false,
			RegistrationNumber:      cur.RegistrationNumber,
		},
	}
	if err := c.postManage(ctx, ss, reqBody, op); err != nil {
		return err
	}
	return c.confirmWrite(ctx, ss, p, "", op)
}
