package council

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/provider/fake"
	"github.com/uppertoe/pstonn/internal/secretbox"
	"github.com/uppertoe/pstonn/internal/store"
)

func muxRig(t *testing.T, ids ...string) (*Mux, *store.Store, map[string]*fake.Provider) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, _ := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	clients := map[string]*parking.Client{}
	fakes := map[string]*fake.Provider{}
	for _, id := range ids {
		f := fake.New()
		f.ApplyDelay = 0
		fakes[id] = f
		clients[id] = parking.NewClientFor(id, f, st, box, nil)
	}
	return NewMux(st, clients), st, fakes
}

func TestMuxRoutesByAccountCouncil(t *testing.T) {
	ctx := context.Background()
	m, st, fakes := muxRig(t, "stonnington", "othertown")
	if err := st.SetAccountCouncil(ctx, "a@example.com", "othertown"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAccountCouncil(ctx, "b@example.com", "stonnington"); err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{"a@example.com", "b@example.com"} {
		if err := m.Link(ctx, o, o, "pw", false, true, 0); err != nil {
			t.Fatal(err)
		}
	}
	// Sessions are stamped with the client's council.
	if cs, _ := st.GetCouncilSession(ctx, "a@example.com"); cs.CouncilID != "othertown" {
		t.Fatalf("a's session filed under %q", cs.CouncilID)
	}
	// A write from a goes to othertown's portal, not stonnington's.
	perm := model.Permit{CouncilPermitID: "90001"}
	if err := m.SetVehicle(ctx, "a@example.com", perm, "AAA111"); err != nil {
		t.Fatal(err)
	}
	if got, _ := fakes["othertown"].Current("90001"); got != "AAA111" {
		t.Fatalf("othertown shows %q", got)
	}
	if got, _ := fakes["stonnington"].Current("90001"); got == "AAA111" {
		t.Fatal("the write leaked into the other council's portal")
	}
	if !m.Linked(ctx, "a@example.com") || m.Linked(ctx, "nobody@example.com") {
		t.Fatal("Linked did not route")
	}
}

func TestMuxUnknownCouncilIsUnavailable(t *testing.T) {
	ctx := context.Background()
	m, st, _ := muxRig(t, "stonnington", "othertown")
	if err := st.SetAccountCouncil(ctx, "z@example.com", "gone"); err != nil {
		t.Fatal(err)
	}
	if err := m.Link(ctx, "z@example.com", "z@example.com", "pw", false, true, 0); !errors.Is(err, ErrCouncilUnavailable) {
		t.Fatalf("err = %v, want ErrCouncilUnavailable", err)
	}
	// With no choice and TWO councils there is no safe default either.
	if err := m.Refresh(ctx, "new@example.com"); !errors.Is(err, ErrCouncilUnavailable) {
		t.Fatalf("no choice among several = %v", err)
	}
}

func TestMuxSingleCouncilNeedsNoChoice(t *testing.T) {
	ctx := context.Background()
	m, st, _ := muxRig(t, "stonnington")
	if err := m.Link(ctx, "solo@example.com", "solo@example.com", "pw", false, true, 0); err != nil {
		t.Fatal(err)
	}
	if cs, _ := st.GetCouncilSession(ctx, "solo@example.com"); cs.CouncilID != "stonnington" {
		t.Fatalf("session filed under %q", cs.CouncilID)
	}
	if s := m.Stats(); !s.PersistOK {
		t.Fatalf("aggregate stats: %+v", s)
	}
}

// Unlink, then try to sign up with another council: the permits kept for a
// re-link bind the account to its original council, and a permit filed under
// one council is never acted on by another council's client.
func TestMuxRefusesSwitchingCouncilWhilePermitsRemain(t *testing.T) {
	ctx := context.Background()
	m, st, fakes := muxRig(t, "stonnington", "othertown")
	const o = "mover@example.com"
	if err := st.SetAccountCouncil(ctx, o, "stonnington"); err != nil {
		t.Fatal(err)
	}
	if err := m.Link(ctx, o, o, "pw", false, true, 0); err != nil {
		t.Fatal(err)
	}
	pid, err := st.UpsertPermit(ctx, o, "90001", "14", "V")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCouncilSession(ctx, o); err != nil { // unlink keeps the permit
		t.Fatal(err)
	}
	if err := st.SetAccountCouncil(ctx, o, "othertown"); !errors.Is(err, store.ErrCouncilMismatch) {
		t.Fatalf("switching council with permits kept = %v, want ErrCouncilMismatch", err)
	}
	// Belt and braces: even if the account were re-pointed, the other council's
	// client refuses a permit that is not its own.
	perm, _ := st.GetPermit(ctx, pid)
	other, _ := m.Client("othertown")
	_ = st.DeleteAllForOwner(ctx, o)
	_ = st.SetAccountCouncil(ctx, o, "othertown")
	_ = m.Link(ctx, o, o, "pw", false, true, 0)
	if err := other.SetVehicle(ctx, o, perm, "AAA111"); !errors.Is(err, parking.ErrNotLinked) {
		t.Fatalf("other council acted on a foreign permit: %v", err)
	}
	if got, _ := fakes["othertown"].Current("90001"); got == "AAA111" {
		t.Fatal("the write reached the wrong portal")
	}
	// A disabled/unknown council reads as not linked, so the scheduler stays quiet.
	_ = st.SetAccountCouncil(ctx, "ghost@example.com", "gone")
	if err := m.Refresh(ctx, "ghost@example.com"); !errors.Is(err, parking.ErrNotLinked) {
		t.Fatalf("unavailable council = %v, want ErrNotLinked", err)
	}
}
