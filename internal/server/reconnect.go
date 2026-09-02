package server

import (
	"context"
	"net/http"
	"time"
)

// Interactive auto-reconnect. "Save my password so p.stonn can reconnect on its
// own" was honoured only by the scheduler — and the scheduler proactively warms
// only sessions with a permit to act on, so a linked-but-permitless account (a
// signup waiting on the council to grant its visitor permit) idled out and met
// the password form again on return: the documented conversion killer, at the
// person most likely to come back days later.
//
// The recovery machinery already exists and is audited: the scheduler's reconnect
// queue enqueues generation-tagged, deduped per (owner, tenant); a single worker
// drains it under panic-recovery, reconnects from the saved password, retires and
// notifies the user on a rejected or absent one, and paces itself against the
// request governor. The parking client already feeds that queue from its
// background reads. So the picker does NOT reconnect inline (a headless login is
// several round trips — it cannot fit the render deadline, and a login cancelled
// mid-flight is a half-completed IdP authentication) and does NOT re-implement any
// of those guard rails. It only adds the interactive trigger — handing the expiry
// to the same queue — and an honest pending page.

// freshLinkWindow bounds how recently a link must have happened for a first-read
// expiry to read as "the council account isn't set up yet" (picker.session_rejected)
// rather than an ordinary idle lapse. A genuine just-linked flow is seconds old;
// an old /schedule?linked=1 reopened from history days later is far outside it and
// must still reach auto-reconnect.
const freshLinkWindow = 10 * time.Minute

// tenantIDOf is the concrete tenant id for owner's current tenant ("" if none),
// as the reconnect queue keys by it.
func (s *Server) tenantIDOf(ctx context.Context, owner string) string {
	if t := s.tenantFor(ctx, owner); t != nil {
		return t.ID
	}
	return ""
}

// renderReconnecting answers a picker load while a background reconnect is in
// flight: an honest in-progress page that refreshes itself back into the picker.
// The refresh targets the bare page PATH (no query), so a reconnect reached from a
// stale /schedule?linked=1 bookmark drops the parameter on the next tick — its
// refreshes then hit the read-avoiding gate instead of spending a throttle slot each.
func (s *Server) renderReconnecting(w http.ResponseWriter, r *http.Request, owner string) {
	w.Header().Set("Refresh", "4; url="+r.URL.Path)
	s.message(w, http.StatusOK, s.say(r.Context(), owner, "picker.reconnecting"))
}
