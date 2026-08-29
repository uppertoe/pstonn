package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestFailureOfClassifies(t *testing.T) {
	cases := []struct {
		err  error
		kind FailureKind
		op   Op
	}{
		{Fail(FailRejected, OpSetVehicle, errors.New("no")), FailRejected, OpSetVehicle},
		{fmt.Errorf("wrapped: %w", Fail(FailUnexpected, OpListPermits, errors.New("shape"))), FailUnexpected, OpListPermits},
		{errors.New("bare"), FailTransient, OpUnknown},
		{nil, FailTransient, OpUnknown},
		{ErrSessionExpired, FailTransient, OpUnknown},
	}
	for _, c := range cases {
		k, o := FailureOf(c.err)
		if k != c.kind || o != c.op {
			t.Errorf("FailureOf(%v) = %v/%v, want %v/%v", c.err, k, o, c.kind, c.op)
		}
	}
}

func TestDetailCarriesTenantText(t *testing.T) {
	err := FailDetail(FailRejected, OpSetVehicle, "Vehicle Registration has invalid pattern", errors.New("400"))
	if DetailOf(err) != "Vehicle Registration has invalid pattern" {
		t.Fatalf("DetailOf = %q", DetailOf(err))
	}
	if DetailOf(errors.New("x")) != "" {
		t.Fatal("detail on a plain error")
	}
	// The identifier, not a sentence, is what the string form carries.
	if got := err.Error(); got != "provider: set-vehicle: Vehicle Registration has invalid pattern: 400" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestUnavailableUnwraps(t *testing.T) {
	err := fmt.Errorf("ctx: %w", &Unavailable{RetryAfter: 30 * time.Second, Status: 429, Surface: SurfaceAuth})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("Unavailable must be ErrUnavailable")
	}
	var u *Unavailable
	if !errors.As(err, &u) || u.RetryAfter != 30*time.Second || u.Surface != SurfaceAuth {
		t.Fatalf("particulars lost: %+v", u)
	}
}

func TestOpNamesAreStable(t *testing.T) {
	want := map[Op]string{OpUnknown: "unknown", OpLogin: "login", OpRefresh: "refresh", OpListPermits: "list-permits",
		OpReadVehicle: "read-vehicle", OpSetVehicle: "set-vehicle", OpAddVehicle: "add-vehicle", OpClearVehicle: "clear-vehicle"}
	for op, s := range want {
		if op.String() != s {
			t.Errorf("%d.String() = %q, want %q", op, op.String(), s)
		}
	}
	if Op(99).String() != "unknown" {
		t.Error("out-of-range op must read as unknown")
	}
}

func TestSurfaceContext(t *testing.T) {
	if SurfaceOf(context.Background()) != SurfaceOther {
		t.Fatal("untagged context must be other")
	}
	if SurfaceOf(WithSurface(context.Background(), SurfaceLogin)) != SurfaceLogin {
		t.Fatal("tag lost")
	}
}
