package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Resending exists because the heads-up is best-effort: throttled, or skipped
// entirely when SMTP is off. Before it, an owner whose invitee never got that
// email could only withdraw and re-invite, which reads as a mistake and loses
// the original date.
func TestResendInvite(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)
	const member = "invitee@example.com"
	if err := r.s.store.AddMemberCapped(r.ctx, rigUser, member, 2); err != nil {
		t.Fatal(err)
	}

	t.Run("a pending invitation can be sent again", func(t *testing.T) {
		rr := r.post("/account/members/resend", rigUser, url.Values{"email": {member}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("code=%d", rr.Code)
		}
		if loc := rr.Header().Get("Location"); !strings.Contains(loc, "resent=") {
			t.Fatalf("location=%q, want the settings page reporting the resend", loc)
		}
	})

	t.Run("an address with no pending invitation is not mailed", func(t *testing.T) {
		rr := r.post("/account/members/resend", rigUser, url.Values{"email": {"stranger@example.com"}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("code=%d", rr.Code)
		}
		if loc := rr.Header().Get("Location"); strings.Contains(loc, "resent=") {
			t.Fatalf("location=%q, want no claim that anything was sent", loc)
		}
	})

	t.Run("an accepted membership is not a pending invitation", func(t *testing.T) {
		const joined = "joined@example.com"
		if err := r.s.store.AddMemberCapped(r.ctx, rigUser, joined, 2); err != nil {
			t.Fatal(err)
		}
		if err := r.s.store.AcceptInvite(r.ctx, joined, rigUser); err != nil {
			t.Fatal(err)
		}
		rr := r.post("/account/members/resend", rigUser, url.Values{"email": {joined}})
		if loc := rr.Header().Get("Location"); strings.Contains(loc, "resent=") {
			t.Fatalf("location=%q, want nothing sent to someone who already accepted", loc)
		}
	})

	// Shared access is capped at two, so this reuses the member accepted above
	// rather than adding a third.
	t.Run("a secondary cannot resend", func(t *testing.T) {
		const second = "joined@example.com"
		r.consent(t, second)
		rr := r.post("/account/members/resend", second, url.Values{"email": {member}})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("code=%d, want a secondary refused", rr.Code)
		}
	})
}
