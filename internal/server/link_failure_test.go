package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/uppertoe/pstonn/internal/provider"
	"github.com/uppertoe/pstonn/internal/store"
)

// A link attempt that fails must leave a durable trace. The journal already
// carried one, but journald on the box keeps only days, so by the time the
// September 2026 cohort was reviewed there was no way to tell a signup who never
// had a council account from one who tried and could not get in.
func TestLinkFailuresAreRecordedDurably(t *testing.T) {
	r := newTenantRig(t)
	r.consent(t, rigUser)

	t.Run("a rejected password is counted, with its reason", func(t *testing.T) {
		r.post("/tenant/link", rigUser, url.Values{"portal_password": {"wrong"}})
		n, last, reason, err := r.s.store.LinkFailures(r.ctx, rigUser)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 || reason != string(store.LinkFailRejected) || last == "" {
			t.Fatalf("count=%d reason=%q last=%q, want one rejection with a timestamp", n, reason, last)
		}
	})

	t.Run("attempts accumulate", func(t *testing.T) {
		r.post("/tenant/link", rigUser, url.Values{"portal_password": {"wrong"}})
		r.post("/tenant/link", rigUser, url.Values{"portal_password": {"wrong"}})
		n, _, _, _ := r.s.store.LinkFailures(r.ctx, rigUser)
		if n != 3 {
			t.Fatalf("count=%d, want 3 — a run of rejections is the signal, not a single one", n)
		}
	})

	t.Run("portal push-back is filed apart from a bad password", func(t *testing.T) {
		const busy = "busy-record@example.com"
		r.consent(t, busy)
		r.fake.LoginErr = &provider.Unavailable{Status: 503, Surface: provider.SurfaceLogin}
		defer func() { r.fake.LoginErr = nil }()
		r.post("/tenant/link", busy, url.Values{"portal_password": {"ok"}})
		n, _, reason, _ := r.s.store.LinkFailures(r.ctx, busy)
		if n != 1 || reason != string(store.LinkFailBusy) {
			t.Fatalf("count=%d reason=%q, want one attempt filed as busy", n, reason)
		}
	})

	t.Run("a successful link retires the tally", func(t *testing.T) {
		rr := r.post("/tenant/link", rigUser, url.Values{"portal_password": {"ok"}})
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("link code=%d", rr.Code)
		}
		n, _, reason, _ := r.s.store.LinkFailures(r.ctx, rigUser)
		if n != 0 || reason != "" {
			t.Fatalf("count=%d reason=%q, want the tally cleared once the account got in", n, reason)
		}
	})
}
