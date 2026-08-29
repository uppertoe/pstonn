package council

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
)

// ErrCouncilUnavailable: the account belongs to a council this process is not
// serving (disabled, or removed from the registry). Treated like "not linked".
var ErrCouncilUnavailable = errors.New("council: the account's council is not available")

// Mux routes each per-owner council call to the client for the owner's council.
// The scheduler and the server keep calling one thing keyed by owner, exactly as
// with a single council; the resolution (sign-up choice → linked session →
// process default) is the store's. It satisfies both server.Council and
// scheduler.Council.
type Mux struct {
	st      councilResolver
	clients map[string]*parking.Client
	ids     []string
}

// councilResolver is the one store method the mux needs.
type councilResolver interface {
	CouncilIDFor(ctx context.Context, owner string) (string, error)
}

// NewMux builds a mux over one client per council id.
func NewMux(st councilResolver, clients map[string]*parking.Client) *Mux {
	m := &Mux{st: st, clients: clients}
	for id := range clients {
		m.ids = append(m.ids, id)
	}
	sort.Strings(m.ids)
	return m
}

// For returns the client for the owner's council.
func (m *Mux) For(ctx context.Context, owner string) (*parking.Client, error) {
	id, err := m.st.CouncilIDFor(ctx, owner)
	if err != nil {
		return nil, err
	}
	if id == "" && len(m.clients) == 1 {
		return m.clients[m.ids[0]], nil
	}
	c, ok := m.clients[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrCouncilUnavailable, id)
	}
	return c, nil
}

// Client returns the client for a council id (admin/status views).
func (m *Mux) Client(id string) (*parking.Client, bool) {
	c, ok := m.clients[id]
	return c, ok
}

// IDs lists the councils served, sorted.
func (m *Mux) IDs() []string { return append([]string(nil), m.ids...) }

func (m *Mux) Link(ctx context.Context, owner, username, password string, savePassword, interactive bool, expectedGen int64) error {
	c, err := m.For(ctx, owner)
	if err != nil {
		return err
	}
	return c.Link(ctx, owner, username, password, savePassword, interactive, expectedGen)
}

func (m *Mux) Reconnect(ctx context.Context, owner string) error {
	c, err := m.For(ctx, owner)
	if err != nil {
		return err
	}
	return c.Reconnect(ctx, owner)
}

func (m *Mux) Refresh(ctx context.Context, owner string) error {
	c, err := m.For(ctx, owner)
	if err != nil {
		return err
	}
	return c.Refresh(ctx, owner)
}

func (m *Mux) Linked(ctx context.Context, owner string) bool {
	c, err := m.For(ctx, owner)
	return err == nil && c.Linked(ctx, owner)
}

func (m *Mux) ListPermitsComplete(ctx context.Context, owner string) ([]parking.PermitInfo, bool, error) {
	c, err := m.For(ctx, owner)
	if err != nil {
		return nil, false, err
	}
	return c.ListPermitsComplete(ctx, owner)
}

func (m *Mux) CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error) {
	c, err := m.For(ctx, owner)
	if err != nil {
		return "", err
	}
	return c.CurrentVehicle(ctx, owner, p)
}

func (m *Mux) CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (string, time.Duration, bool, error) {
	c, err := m.For(ctx, owner)
	if err != nil {
		return "", 0, false, err
	}
	return c.CurrentVehicleCached(ctx, owner, p, maxAge)
}

func (m *Mux) RefreshFailingFor(owner string, p model.Permit) time.Duration {
	c, err := m.For(context.Background(), owner)
	if err != nil {
		return 0
	}
	return c.RefreshFailingFor(owner, p)
}

func (m *Mux) ForgetPermit(owner, councilPermitID string) {
	if c, err := m.For(context.Background(), owner); err == nil {
		c.ForgetPermit(owner, councilPermitID)
	}
}

func (m *Mux) SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error {
	c, err := m.For(ctx, owner)
	if err != nil {
		return err
	}
	return c.SetVehicle(ctx, owner, p, registration)
}

func (m *Mux) ClearVehicle(ctx context.Context, owner string, p model.Permit) error {
	c, err := m.For(ctx, owner)
	if err != nil {
		return err
	}
	return c.ClearVehicle(ctx, owner, p)
}

// Blocked reports whether ANY council's fleet circuit is open: the scheduler's
// user-facing "confirmed block" warning is about our shared egress address.
func (m *Mux) Blocked() bool {
	for _, c := range m.clients {
		if c.Blocked() {
			return true
		}
	}
	return false
}

// Stats sums traffic across councils and reports the most recent push-back; the
// per-council breakdown is available through Client.
func (m *Mux) Stats() parking.Stats {
	var out parking.Stats
	out.PersistOK = true
	for _, id := range m.ids {
		s := m.clients[id].Stats()
		out.Login += s.Login
		out.Auth += s.Auth
		out.API += s.API
		out.Other += s.Other
		out.Pushback += s.Pushback
		out.LastMinute += s.LastMinute
		out.Last5Min += s.Last5Min
		if s.BreakerOpen {
			out.BreakerOpen = true
			if s.BreakerFor > out.BreakerFor {
				out.BreakerFor = s.BreakerFor
			}
		}
		if s.LastPushbackAt.After(out.LastPushbackAt) {
			out.LastPushbackAt, out.LastPushbackSurface, out.LastPushbackStatus, out.LastPushbackRef =
				s.LastPushbackAt, s.LastPushbackSurface, s.LastPushbackStatus, s.LastPushbackRef
		}
		if !s.PersistOK {
			out.PersistOK, out.PersistError = false, s.PersistError
		}
		if s.TruncatedGridAt.After(out.TruncatedGridAt) {
			out.TruncatedGridAt, out.TruncatedGridGot, out.TruncatedGridWant = s.TruncatedGridAt, s.TruncatedGridGot, s.TruncatedGridWant
		}
	}
	return out
}
