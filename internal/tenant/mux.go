package tenant

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider"
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

// Capabilities reports what the named tenant's portal supports, so a page can
// adapt (hide the clear action, drop the state chooser, treat expiry as unknown)
// without knowing any portal. tenantID names the tenant a permit belongs to;
// "" is the owner's current tenant. A tenant this process does not serve reports
// the zero value: nothing supported, so nothing is offered.
func (m *Mux) Capabilities(ctx context.Context, owner, tenantID string) provider.Capabilities {
	c, err := m.client(ctx, owner, tenantID)
	if err != nil || c == nil {
		return provider.Capabilities{}
	}
	return c.Capabilities()
}

// Regions returns the registration jurisdictions a vehicle may carry, for the
// UI's state chooser. tenantID names the tenant a permit belongs to — every
// permit-scoped page passes its permit's tenant, never the account's current
// selection, because the two differ for an account linked in two areas. "" is the
// account-wide case (the vehicles page, where a car is not yet tied to a permit):
// the union over every tenant this process serves, the owner's current tenant
// first, deduplicated by code. Empty means no served provider has the concept
// (the UI then shows no chooser).
func (m *Mux) Regions(ctx context.Context, owner, tenantID string) []provider.Region {
	if tenantID != "" {
		c, ok := m.clients[tenantID]
		if !ok {
			return nil
		}
		return c.Capabilities().Regions
	}
	var out []provider.Region
	seen := map[string]bool{}
	add := func(c *parking.Client) {
		for _, r := range c.Capabilities().Regions {
			if !seen[r.Code] {
				seen[r.Code] = true
				out = append(out, r)
			}
		}
	}
	if c, err := m.For(ctx, owner); err == nil && c != nil {
		add(c)
	}
	for _, id := range m.ids {
		add(m.clients[id])
	}
	return out
}

// RegionValid reports whether code is one the named tenant offers ("" tenant: any
// served tenant). "" code (the tenant's home state) is always valid.
func (m *Mux) RegionValid(ctx context.Context, owner, tenantID, code string) bool {
	if code == "" {
		return true
	}
	for _, r := range m.Regions(ctx, owner, tenantID) {
		if r.Code == code {
			return true
		}
	}
	return false
}

func (m *Mux) SetVehicle(ctx context.Context, owner string, p model.Permit, registration, region string) error {
	c, err := m.forPermit(ctx, owner, p)
	if err != nil {
		return err
	}
	return c.SetVehicle(ctx, owner, p, registration, region)
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
