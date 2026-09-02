package server

import (
	"strings"
	"testing"

	"github.com/uppertoe/pstonn/internal/provider"
)

// Interactive auto-reconnect (reconnect.go + the picker's expired branch). The
// picker does not log in itself: on a dead session with a saved password it hands
// the expiry to the scheduler's audited reconnect queue and shows a pending page.
// These tests assert the picker's behaviour and its delegation to that queue; the
// login mechanics (recover, generation guard, retire-and-notify, pacing) are the
// scheduler's own and are covered there. The rig does not run the drain worker, so
// a reconnect stays queued until the test resolves it explicitly.

// linkSaved links the rig user WITH the password kept — the state auto-reconnect
// exists for (the rig's plain link deliberately keeps nothing).
func (r *tenantRig) linkSaved(t *testing.T, email, password string) {
	t.Helper()
	if err := r.s.tenant.Link(r.ctx, email, "", email, password, true, true, 0); err != nil {
		t.Fatal(err)
	}
}

func TestPickerExpiredWithSavedPasswordQueuesReconnect(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.linkSaved(t, rigUser, "ok")
	loginsAfterLink := r.fake.Logins

	// The session dies while the account holds no permits — the state the
	// scheduler never proactively warms, so the picker is where it surfaces.
	r.fake.ListErr = provider.ErrSessionExpired
	rr := r.get("/schedule", rigUser)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "signing back in") {
		t.Fatalf("expected the reconnecting page, got code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if strings.Contains(rr.Body.String(), "portal_password") {
		t.Fatal("the pending page must not carry the password form")
	}
	// Delegated to the audited queue for THIS tenant, not logged in inline.
	tid := r.s.tenantIDOf(r.ctx, rigUser)
	if !r.s.sched.ReconnectActive(rigUser, tid) {
		t.Fatal("expected an active reconnect queued for the owner's tenant")
	}
	if r.fake.Logins != loginsAfterLink {
		t.Fatalf("the picker logged in inline (logins %d -> %d); it must delegate", loginsAfterLink, r.fake.Logins)
	}

	// A second load while queued still shows pending, WITHOUT another tenant read
	// (the top-of-picker gate short-circuits before the read).
	rr = r.get("/schedule", rigUser)
	if !strings.Contains(rr.Body.String(), "signing back in") {
		t.Fatalf("second load should still be pending, got: %s", excerpt(rr.Body.String()))
	}

	// The scheduler recovers the session and dequeues it: the picker resumes.
	r.s.sched.CancelReconnect(rigUser) // stand in for the drain worker dequeuing
	r.fake.ListErr = nil
	rr = r.get("/schedule", rigUser)
	if !strings.Contains(rr.Body.String(), "VPP-SANDBOX") {
		t.Fatalf("expected the picker once reconnected, got: %s", excerpt(rr.Body.String()))
	}
}

func TestPickerExpiredWithoutSavedPasswordShowsForm(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.link(t, rigUser) // the rig's plain link keeps no password

	r.fake.ListErr = provider.ErrSessionExpired
	rr := r.get("/schedule", rigUser)
	if !strings.Contains(rr.Body.String(), "portal_password") {
		t.Fatalf("expected the re-link form straight away, got: %s", excerpt(rr.Body.String()))
	}
	if strings.Contains(rr.Body.String(), "signing back in") {
		t.Fatal("no saved password: the reconnecting page must not appear")
	}
	if r.s.sched.ReconnectActive(rigUser, r.s.tenantIDOf(r.ctx, rigUser)) {
		t.Fatal("no saved password: nothing should have been queued")
	}
}

func TestPickerFreshLinkRejectionShowsDiagnostic(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	r.linkSaved(t, rigUser, "ok") // LinkedAt = now, so the link is genuinely fresh

	// First read right after linking fails expired: the "account not set up yet"
	// diagnostic, NOT a reconnect (their password just worked).
	r.fake.ListErr = provider.ErrSessionExpired
	rr := r.s.doReq("GET", "/schedule?linked=1", rigUser, "", nil)
	if rr.Code != 502 || !strings.Contains(rr.Body.String(), "turned the request away") {
		t.Fatalf("expected the session_rejected diagnostic, got code=%d body=%s", rr.Code, excerpt(rr.Body.String()))
	}
	if r.s.sched.ReconnectActive(rigUser, r.s.tenantIDOf(r.ctx, rigUser)) {
		t.Fatal("a fresh-link rejection must not queue a reconnect")
	}
}
