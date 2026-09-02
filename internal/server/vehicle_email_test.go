package server

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/uppertoe/pstonn/internal/store"
)

// TestVehicleEmailOnMissingCarLogsNothing: the driver-email save tolerated a car
// that no longer exists (a stale page) but still wrote the audit row, so the
// Activity page said an address had been set when nothing was. A missing car
// logs nothing; a real one logs exactly the change.
func TestVehicleEmailOnMissingCarLogsNothing(t *testing.T) {
	s := newAuthzServer(t)
	ctx := context.Background()
	const owner = "cars@example.com"
	const origin = "https://app.example.com"
	if err := s.store.RecordConsent(ctx, owner, s.terms.Version, s.terms.Hash()); err != nil {
		t.Fatal(err)
	}
	emailRows := func(t *testing.T) []store.Change {
		t.Helper()
		all, err := s.store.ListChanges(ctx, owner, 20)
		if err != nil {
			t.Fatal(err)
		}
		var out []store.Change
		for _, c := range all {
			if c.Action == store.ActionVehicleEmail {
				out = append(out, c)
			}
		}
		return out
	}

	w := s.doReq("POST", "/vehicles/999/email", owner, origin, url.Values{"email": {"driver@example.com"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("email on a missing car = %d, want the tolerant redirect", w.Code)
	}
	if rows := emailRows(t); len(rows) != 0 {
		t.Fatalf("a save that changed nothing was logged: %+v", rows)
	}

	vid, err := s.store.CreateVehicle(ctx, owner, "ABC123", "Van", "")
	if err != nil {
		t.Fatal(err)
	}
	if w := s.doReq("POST", "/vehicles/"+itoa64(vid)+"/email", owner, origin, url.Values{"email": {"driver@example.com"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("email on a real car = %d", w.Code)
	}
	rows := emailRows(t)
	if len(rows) != 1 || rows[0].Target != "ABC123" || rows[0].Detail != "set" {
		t.Fatalf("audit rows after a real save = %+v, want one: ABC123 set", rows)
	}
}
