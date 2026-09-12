package server

import (
	"context"
	"testing"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// TestChecklistTicksAndRetires: each tab's card reflects what the account has
// done, ticked lines lose their link, and a fully ticked card is not shown.
func TestChecklistTicksAndRetires(t *testing.T) {
	s := newAuthzServer(t)
	ctx := context.Background()
	const owner = "own@example.com"
	if s.checklistFor(ctx, owner, owner, "schedule") != nil {
		t.Fatal("schedule card offered before any permit is managed")
	}
	pid, err := s.store.UpsertPermit(ctx, owner, "14576", "14", "")
	if err != nil {
		t.Fatal(err)
	}
	v := s.checklistFor(ctx, owner, owner, "schedule")
	if v == nil || v.Done != 0 || len(v.Items) != 2 {
		t.Fatalf("fresh schedule card = %+v", v)
	}
	vid, err := s.store.CreateVehicle(ctx, owner, "ABC123", "Nana", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetRule(ctx, pid, 0, time.Monday, vid); err != nil {
		t.Fatal(err)
	}
	v = s.checklistFor(ctx, owner, owner, "schedule")
	if v == nil || v.Done != 1 || len(v.Items) != 3 || !v.Items[0].Done || v.Items[0].Href != "" || v.Items[1].Href == "" {
		t.Fatalf("after a roster day: %+v", v)
	}
	// Regos: one saved, no email yet.
	v = s.checklistFor(ctx, owner, owner, "vehicles")
	if v == nil || v.Done != 1 || !v.Items[0].Done || v.Items[1].Done {
		t.Fatalf("regos card = %+v", v)
	}
	if err := s.store.SetVehicleEmail(ctx, owner, vid, "nana@example.com"); err != nil {
		t.Fatal(err)
	}
	if s.checklistFor(ctx, owner, owner, "vehicles") != nil {
		t.Fatal("regos card still shown with everything done")
	}
	// Guests: the three tools come from the change log.
	if err := s.store.RecordChange(ctx, owner, owner, store.ActionDoorQRShow, "", ""); err != nil {
		t.Fatal(err)
	}
	v = s.checklistFor(ctx, owner, owner, "guests")
	if v == nil || v.Done != 1 || !v.Items[0].Done {
		t.Fatalf("guests card = %+v", v)
	}
	// Settings: nothing done on a fresh account.
	v = s.checklistFor(ctx, owner, owner, "settings")
	if v == nil || v.Done != 0 || len(v.Items) != 4 {
		t.Fatalf("settings card = %+v", v)
	}
	if s.checklistFor(ctx, owner, owner, "activity") != nil {
		t.Fatal("a tab without a card returned one")
	}
}
