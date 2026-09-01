package store

import (
	"context"
	"path/filepath"
	"testing"
)

// notify_driver defaults ON for a new car (so an added driver email works
// without extra setup) and the per-car toggle round-trips through every read.
func TestVehicleNotifyDriverDefaultsOnAndToggles(t *testing.T) {
	ctx := context.Background()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const owner = "owner@example.com"
	id, err := st.CreateVehicle(ctx, owner, "NAN123", "Nanny", "")
	if err != nil {
		t.Fatal(err)
	}

	vs, err := st.ListVehiclesFor(ctx, owner)
	if err != nil || len(vs) != 1 {
		t.Fatalf("list: %v, %d", err, len(vs))
	}
	if !vs[0].NotifyDriver {
		t.Fatal("a new vehicle should default notify_driver=true")
	}

	if err := st.SetVehicleNotifyDriver(ctx, owner, id, false); err != nil {
		t.Fatal(err)
	}
	vs, _ = st.ListVehiclesFor(ctx, owner)
	if vs[0].NotifyDriver {
		t.Fatal("toggle to false did not persist in ListVehiclesFor")
	}
	refs, err := st.ListVehicleRefs(ctx)
	if err != nil || len(refs) != 1 || refs[0].NotifyDriver {
		t.Fatalf("ListVehicleRefs should reflect the toggle: %v %+v", err, refs)
	}

	// Owner scoping: another owner cannot flip this car.
	if err := st.SetVehicleNotifyDriver(ctx, "someone@else.com", id, true); err != ErrNotFound {
		t.Fatalf("cross-owner toggle should be ErrNotFound, got %v", err)
	}
}
