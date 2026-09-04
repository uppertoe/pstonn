package server

import (
	"context"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
)

// referralDailyCap bounds how many introductions one account may ask p.stonn to
// send per day. The form is behind sign-in and consent, so this is not the open
// relay the guest page would be — but a keen (or compromised) account must not
// turn it into a mailer either.
const referralDailyCap = 5

// sharePage is the signed-in Share page: the share sheet, an invite form, and a
// printable card. Reachable by anyone signed in and consented; the fortnight
// email links here.
func (s *Server) sharePage(w http.ResponseWriter, r *http.Request) {
	u, ok := s.user(w, r)
	if !ok {
		return
	}
	base := s.shareShell(r.Context(), u)
	switch r.URL.Query().Get("sent") {
	case "1":
		base.Flash = "Invitation sent."
	}
	base.Share = &shareData{ShareEmailAvailable: s.notify != nil && s.notify.EmailAvailable()}
	// The card preview: same QR the printable page renders.
	if url := strings.TrimRight(s.cfg.PublicBaseURL, "/"); url != "" {
		if img, err := qrDataURI(url); err == nil {
			base.Share.ShareQR = template.URL(img)
		}
	}
	s.render(w, base)
}

// shareShell is the Share page's base view: appShell's account resolution
// without its gates, because this page is reachable before a permit is set up.
// Owner is the ACCOUNT (a secondary's primary), not the signed-in address — the
// two were once swapped here, which put a secondary's own email where the nav
// expects the household — and the tenant switcher is filled the way appShell
// fills it, so the menu does not lose its areas on this one page.
func (s *Server) shareShell(ctx context.Context, u identity.User) dashboardData {
	_, owner, isPrimary := s.resolveAccount(ctx)
	base := dashboardData{User: u, Owner: owner, IsPrimary: isPrimary, State: "share", OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(), Loc: s.locFor(ctx, owner), Contact: s.cfg.ContactEnabled(),
		Tenants: s.tenantsFor(ctx, owner), CanConnectArea: s.canConnectArea(ctx, owner)}
	if !isPrimary {
		base.SharedWith = owner
	}
	return base
}

// shareCard is the printable card: a QR code straight to the landing page.
func (s *Server) shareCard(w http.ResponseWriter, r *http.Request) {
	u, ok := s.user(w, r)
	if !ok {
		return
	}
	url := strings.TrimRight(s.cfg.PublicBaseURL, "/")
	if url == "" {
		url = "https://p.stonn.org"
	}
	img, err := qrDataURI(url)
	if err != nil {
		s.serverError(w, err)
		return
	}
	base := dashboardData{User: u, State: "share-card", OIDCEnabled: s.auth != nil, LogoutURL: s.logoutURL(), Loc: s.cfg.DisplayLocation}
	base.Share = &shareData{ShareQR: template.URL(img), ShareURL: strings.TrimPrefix(url, "https://")}
	s.render(w, base)
}

// sendReferral emails the introduction to the address the signed-in person chose.
func (s *Server) sendReferral(w http.ResponseWriter, r *http.Request) {
	u, ok := s.user(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	to := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !looksLikeEmail(to) {
		s.formError(w, r, "Enter the email address to send the invitation to.")
		return
	}
	if strings.EqualFold(to, u.Email) {
		s.formError(w, r, "That's your own address.")
		return
	}
	if s.notify == nil || !s.notify.EmailAvailable() {
		s.formError(w, r, "Email isn't set up on this p.stonn, so invitations can't be sent from here.")
		return
	}
	// Resolved BEFORE the send and the write, and fail-closed: the lenient
	// resolver's fallback is the caller's own address, which would file a
	// secondary's referral in a phantom account's log — and a 503 is only honest
	// if nothing has been sent or spent yet. It sat below the invite record for a
	// while, so a refused request still consumed one of the day's five.
	_, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	n, err := s.store.CountReferralInvitesSince(ctx, u.Email, time.Now().Add(-24*time.Hour))
	if err != nil {
		s.serverError(w, err)
		return
	}
	if n >= referralDailyCap {
		s.formError(w, r, "That's the limit for today — you can send more tomorrow.")
		return
	}
	if err := s.store.RecordReferralInvite(ctx, u.Email, to); err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.notify.SendReferralInvite(ctx, to, u.Email); err != nil {
		// A suppressed address (bounced, complained, unsubscribed) is not the
		// sender's problem to solve, and the reason is not theirs to see.
		alog.Infof("referral from %s: %v", redact.Email(u.Email), err)
	}
	s.logChange(ctx, owner, u.Email, store.ActionReferralSend, to, "")
	http.Redirect(w, r, "/share?sent=1", http.StatusSeeOther)
}
