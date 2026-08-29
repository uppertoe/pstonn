package tenant

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
)

// ErrTenantUnavailable: the account belongs to a tenant this process is not
// serving (disabled, or removed from the registry). Treated like "not linked".
var ErrTenantUnavailable = fmt.Errorf("%w: the account's council is not available", parking.ErrNotLinked)

// Mux routes each per-owner tenant call to the client for the owner's tenant.
// The scheduler and the server keep calling one thing keyed by owner, exactly as
// with a single tenant; the resolution (sign-up choice → linked session →
// process default) is the store's. It satisfies both server.Tenant and
// scheduler.Tenant.
type Mux struct {
	st      tenantResolver
	clients map[string]*parking.Client
	ids     []string
}

// tenantResolver is the one store method the mux needs.
type tenantResolver interface {
	TenantIDFor(ctx context.Context, owner string) (string, error)
}

// NewMux builds a mux over one client per tenant id.
func NewMux(st tenantResolver, clients map[string]*parking.Client) *Mux {
	m := &Mux{st: st, clients: clients}
	for id := range clients {
		m.ids = append(m.ids, id)
	}
	sort.Strings(m.ids)
	return m
}

// For returns the client for the owner's tenant.
func (m *Mux) For(ctx context.Context, owner string) (*parking.Client, error) {
	id, err := m.st.TenantIDFor(ctx, owner)
	if err != nil {
		return nil, err
	}
	if id == "" && len(m.clients) == 1 {
		return m.clients[m.ids[0]], nil
	}
	c, ok := m.clients[id]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrTenantUnavailable, id)
	}
	return c, nil
}

// Client returns the client for a tenant id (admin/status views).
func (m *Mux) Client(id string) (*parking.Client, bool) {
	c, ok := m.clients[id]
	return c, ok
}

// IDs lists the registry served, sorted.
func (m *Mux) IDs() []string { return append([]string(nil), m.ids...) }

// client picks the client for an explicit tenant, or the owner's current tenant
// when none is named.
func (m *Mux) client(ctx context.Context, owner, tenantID string) (*parking.Client, error) {
	if tenantID == "" {
		return m.For(ctx, owner)
	}
	c, ok := m.clients[tenantID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrTenantUnavailable, tenantID)
	}
	return c, nil
}

// forPermit picks the client for the tenant a permit belongs to.
func (m *Mux) forPermit(ctx context.Context, owner string, p model.Permit) (*parking.Client, error) {
	return m.client(ctx, owner, p.TenantID)
}

func (m *Mux) Link(ctx context.Context, owner, tenantID, username, password string, savePassword, interactive bool, expectedGen int64) error {
	c, err := m.client(ctx, owner, tenantID)
	if err != nil {
		return err
	}
	return c.Link(ctx, owner, username, password, savePassword, interactive, expectedGen)
}

func (m *Mux) Reconnect(ctx context.Context, owner, tenantID string) error {
	c, err := m.client(ctx, owner, tenantID)
	if err != nil {
		return err
	}
	return c.Reconnect(ctx, owner)
}

func (m *Mux) Refresh(ctx context.Context, owner, tenantID string) error {
	c, err := m.client(ctx, owner, tenantID)
	if err != nil {
		return err
	}
	return c.Refresh(ctx, owner)
}

func (m *Mux) Linked(ctx context.Context, owner, tenantID string) bool {
	c, err := m.client(ctx, owner, tenantID)
	return err == nil && c.Linked(ctx, owner)
}

func (m *Mux) ListPermitsComplete(ctx context.Context, owner, tenantID string) ([]parking.PermitInfo, bool, error) {
	c, err := m.client(ctx, owner, tenantID)
	if err != nil {
		return nil, false, err
	}
	return c.ListPermitsComplete(ctx, owner)
}

func (m *Mux) CurrentVehicle(ctx context.Context, owner string, p model.Permit) (string, error) {
	c, err := m.forPermit(ctx, owner, p)
	if err != nil {
		return "", err
	}
	return c.CurrentVehicle(ctx, owner, p)
}

func (m *Mux) CurrentVehicleCached(ctx context.Context, owner string, p model.Permit, maxAge time.Duration) (string, time.Duration, bool, error) {
	c, err := m.forPermit(ctx, owner, p)
	if err != nil {
		return "", 0, false, err
	}
	return c.CurrentVehicleCached(ctx, owner, p, maxAge)
}

func (m *Mux) RefreshFailingFor(owner string, p model.Permit) time.Duration {
	c, err := m.forPermit(context.Background(), owner, p)
	if err != nil {
		return 0
	}
	return c.RefreshFailingFor(owner, p)
}

func (m *Mux) ForgetPermit(owner, tenantID, tenantPermitID string) {
	if c, err := m.client(context.Background(), owner, tenantID); err == nil {
		c.ForgetPermit(owner, tenantPermitID)
	}
}

func (m *Mux) SetVehicle(ctx context.Context, owner string, p model.Permit, registration string) error {
	c, err := m.forPermit(ctx, owner, p)
	if err != nil {
		return err
	}
	return c.SetVehicle(ctx, owner, p, registration)
}

func (m *Mux) ClearVehicle(ctx context.Context, owner string, p model.Permit) error {
	c, err := m.forPermit(ctx, owner, p)
	if err != nil {
		return err
	}
	return c.ClearVehicle(ctx, owner, p)
}

// Blocked reports whether ANY tenant's fleet circuit is open: the scheduler's
// user-facing "confirmed block" warning is about our shared egress address.
func (m *Mux) Blocked() bool {
	for _, c := range m.clients {
		if c.Blocked() {
			return true
		}
	}
	return false
}

// Stats sums traffic across registry and reports the most recent push-back; the
// per-tenant breakdown is available through Client.
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

// Single adapts one client to the tenant-aware interfaces the scheduler and
// server speak (tests, and any single-tenant wiring): a tenant other than the
// client's own reads as not linked.
type Single struct{ *parking.Client }

func (s Single) mine(tenantID string) bool {
	return tenantID == "" || tenantID == s.Client.TenantID
}

func (s Single) Link(ctx context.Context, owner, tenantID, username, password string, savePassword, interactive bool, expectedGen int64) error {
	if !s.mine(tenantID) {
		return ErrTenantUnavailable
	}
	return s.Client.Link(ctx, owner, username, password, savePassword, interactive, expectedGen)
}
func (s Single) Reconnect(ctx context.Context, owner, tenantID string) error {
	if !s.mine(tenantID) {
		return ErrTenantUnavailable
	}
	return s.Client.Reconnect(ctx, owner)
}
func (s Single) Refresh(ctx context.Context, owner, tenantID string) error {
	if !s.mine(tenantID) {
		return ErrTenantUnavailable
	}
	return s.Client.Refresh(ctx, owner)
}
func (s Single) Linked(ctx context.Context, owner, tenantID string) bool {
	return s.mine(tenantID) && s.Client.Linked(ctx, owner)
}
func (s Single) ListPermitsComplete(ctx context.Context, owner, tenantID string) ([]parking.PermitInfo, bool, error) {
	if !s.mine(tenantID) {
		return nil, false, ErrTenantUnavailable
	}
	return s.Client.ListPermitsComplete(ctx, owner)
}
func (s Single) ForgetPermit(owner, tenantID, tenantPermitID string) {
	if s.mine(tenantID) {
		s.Client.ForgetPermit(owner, tenantPermitID)
	}
}
