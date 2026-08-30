package orikanv7

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// noIO is a transport that fails the test if anything ever goes over it.
type noIO struct{ t *testing.T }

func (n noIO) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("unexpected I/O: %s %s", r.Method, r.URL)
	return nil, errors.New("no I/O permitted")
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	return New(Config{
		Issuer:      "https://example.test/idm",
		PortalBase:  "https://example.test/ssp",
		ClientID:    "ePermits.ssp.web.v7",
		RedirectURI: "https://example.test/ssp/",
		Scopes:      []string{"openid", "profile"},
		HomeState:   "VIC",
	}, noIO{t})
}

// Constructing the connector must not touch the network: New is called for
// every descriptor at boot, enabled or not.
func TestNewDoesNoIO(t *testing.T) {
	c := newTestClient(t)
	if c.ID() != ID || c.ID() != "orikan-ssp-v7" {
		t.Fatalf("ID() = %q", c.ID())
	}
	if New(Config{}, nil) == nil {
		t.Fatal("nil transport must be accepted (tests)")
	}
}

func TestCapabilitiesValidate(t *testing.T) {
	caps := newTestClient(t).Capabilities()
	if err := caps.Validate(); err != nil {
		t.Fatalf("Capabilities().Validate(): %v", err)
	}
	if caps.CanClearVehicle {
		t.Fatal("clear-to-empty is unconfirmed for v7 and must stay off until captured")
	}
	if !caps.SupportsRefresh || !caps.NeedsKeepWarm {
		t.Fatal("a cookie session needs keep-warm, which needs Refresh")
	}
}

// Every op is honest about being uncaptured: ErrNotCaptured, classified
// FailUnexpected so a wrongly-enabled descriptor alerts the operator loudly
// instead of retrying quietly (transient) or telling the user to act (rejected).
func TestEveryOpReturnsErrNotCapturedUnexpected(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	sess := provider.Session([]byte(`{}`))
	ref := provider.PermitRef{ID: "1"}
	ops := map[provider.Op]func() error{
		provider.OpLogin: func() error {
			s, err := c.Login(ctx, provider.Credentials{Username: "u", Password: "p"})
			if s != nil {
				t.Error("Login returned a session alongside its error")
			}
			return err
		},
		provider.OpRefresh: func() error { return c.Refresh(ctx, &sess) },
		provider.OpListPermits: func() error {
			ps, total, err := c.ListPermits(ctx, &sess)
			if ps != nil || total != 0 {
				t.Errorf("ListPermits returned %v/%d alongside its error", ps, total)
			}
			return err
		},
		provider.OpReadVehicle: func() error {
			v, err := c.CurrentVehicle(ctx, &sess, ref)
			if v != (provider.Vehicle{}) {
				t.Errorf("CurrentVehicle returned %+v alongside its error", v)
			}
			return err
		},
		provider.OpSetVehicle:   func() error { return c.SetVehicle(ctx, &sess, ref, provider.Vehicle{Registration: "ABC123"}) },
		provider.OpClearVehicle: func() error { return c.ClearVehicle(ctx, &sess, ref) },
	}
	for want, call := range ops {
		err := call()
		if !errors.Is(err, provider.ErrNotCaptured) {
			t.Errorf("%v: got %v, want ErrNotCaptured", want, err)
			continue
		}
		if kind, op := provider.FailureOf(err); kind != provider.FailUnexpected || op != want {
			t.Errorf("%v: classified %v/%v, want FailUnexpected/%v", want, kind, op, want)
		}
	}
}

// The registry entry that names this connector must stay disabled until the
// capture checklist in the package doc is done.
func TestRegistryEntryStaysDisabled(t *testing.T) {
	reg, err := tenant.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tn := range reg.All() {
		if tn.Connector != ID {
			continue
		}
		found = true
		if tn.Enabled {
			t.Errorf("tenant %q uses %s but is enabled: nothing is captured yet", tn.ID, ID)
		}
	}
	if !found {
		t.Fatalf("no embedded tenant names connector %s (the seam is meant to be wired)", ID)
	}
}
