package parking

// The council sandbox (COUNCIL_SANDBOX=1) fakes the council in memory for local
// development and demos: any credentials link, ListPermits returns a canned
// visitor permit, and SetVehicle "lands" a few seconds later — returning
// transient until the fake council's own record shows the plate — so the whole
// pending → settled pipeline (scheduler retries, read-back confirmation, guest
// page polling) runs exactly as it does against the real council. Never enable
// in production.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/store"
)

// sandboxApplyDelay is how long a plate change takes to "land" — long enough to
// see the applying state, short enough to feel live.
const sandboxApplyDelay = 6 * time.Second

type councilSandbox struct {
	mu     sync.Mutex
	plates map[string]string // councilPermitID → plate the fake council currently shows
}

func newCouncilSandbox() *councilSandbox {
	return &councilSandbox{plates: map[string]string{}}
}

func (sb *councilSandbox) current(id string) (string, bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	reg, ok := sb.plates[id]
	return reg, ok
}

func (sb *councilSandbox) applyLater(id, reg string) {
	time.AfterFunc(sandboxApplyDelay, func() {
		sb.mu.Lock()
		sb.plates[id] = reg
		sb.mu.Unlock()
	})
}

// ---- Client hooks (each public method short-circuits here in sandbox mode) ----

func (c *Client) sandboxLink(ctx context.Context, owner, username string) error {
	cookie, err := c.box.Seal("sandbox-session")
	if err != nil {
		return err
	}
	return c.store.SaveCouncilSession(ctx, store.CouncilSession{
		Owner: owner, Sub: "sandbox", CouncilEmail: username, Cookie: cookie,
	})
}

func (c *Client) sandboxCurrentVehicle(p model.Permit) (string, error) {
	if reg, ok := c.sandbox.current(p.CouncilPermitID); ok {
		return reg, nil
	}
	// No reading yet: error (transient) so callers fall back to their stored
	// belief instead of treating "unknown" as an empty permit.
	return "", councilErr(FailTransient, "read the vehicle on your permit",
		errors.New("sandbox: no council reading for this permit yet"))
}

func (c *Client) sandboxSetVehicle(p model.Permit, registration string) error {
	const op = "change the vehicle on your permit"
	if cur, ok := c.sandbox.current(p.CouncilPermitID); ok && strings.EqualFold(cur, registration) {
		return nil // the fake council's own record confirms the plate
	}
	c.sandbox.applyLater(p.CouncilPermitID, registration)
	return councilErr(FailTransient, op, errors.New("sandbox: the change lands in a few seconds"))
}

func (c *Client) sandboxListPermits() []PermitInfo {
	now := time.Now()
	reg, _ := c.sandbox.current("90001")
	return []PermitInfo{{
		CouncilPermitID:  "90001",
		PermitTypeID:     "14",
		PermitNumber:     "VPP-SANDBOX",
		PermitType:       "(A) 1st Visitor Permit",
		Status:           "Granted",
		CurrentRego:      reg,
		StartDate:        now.AddDate(0, -1, 0),
		EndDate:          now.AddDate(0, 6, 0),
		CanChangeVehicle: true,
	}}
}
