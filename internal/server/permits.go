package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/i18n"
	"github.com/uppertoe/pstonn/internal/model"
	"github.com/uppertoe/pstonn/internal/parking"
	"github.com/uppertoe/pstonn/internal/redact"
	"github.com/uppertoe/pstonn/internal/store"
	"github.com/uppertoe/pstonn/internal/tenant"
)

// pickerPage renders the permit picker on its own route (for "manage another
// permit" from the dashboard). It goes through appShell so it gets the same
// gating (terms, tenant link) and chrome (sign-out, contact) as every other
// signed-in page; appShell already renders the picker itself for a user with
// no managed permits, so this handler only adds the "manage another" case.
func (s *Server) pickerPage(w http.ResponseWriter, r *http.Request) {
	base, ok := s.appShell(w, r, "")
	if !ok {
		return
	}
	s.renderPicker(w, r, base)
}

// renderPicker lists the user's tenant permits (excluding already-managed ones)
// for them to nominate. A dead session cookie routes back to onboarding.
// The live tenant read is inherent to this page, so it gets a deadline well
// inside the server's 20s WriteTimeout: a slow portal yields the error branch
// (a rendered page), not a dropped connection.
//
// The throttle lives HERE rather than in the /permits/picker handler because
// appShell renders this page directly for any linked account with no managed
// permits yet — the normal onboarding state. Gating only the named route left
// every page load by such a user as one uncached tenant request, which is
// exactly the one-for-one hole the throttle was introduced to close.
func (s *Server) renderPicker(w http.ResponseWriter, r *http.Request, base dashboardData) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	owner := base.Owner
	// This page makes an uncached, synchronous tenant read, so one HTTP request
	// is one tenant request. Throttled per account: opening the picker a few
	// times is normal, hammering it is not, and the tenant's opinion of us is
	// the scarcest resource the app has.
	if !s.tenantRead.allow("cr:" + owner) {
		s.message(w, http.StatusTooManyRequests,
			"You have refreshed the permit list several times in the last few minutes. Please wait a minute before trying again. p.stonn deliberately limits how often it contacts the council.")
		return
	}
	// The picker lists the CURRENT tenant's permits; an account linked elsewhere
	// but not here (a second home, just selected) is offered the link form.
	if !s.tenant.Linked(ctx, owner, "") {
		base.State = "onboarding"
		base.AutoReconnect = s.hasSavedPassword(ctx, owner)
		if enabled := s.registry.Enabled(); s.registry != nil && len(enabled) > 1 {
			current := s.tenantFor(ctx, owner)
			for _, c := range enabled {
				base.TenantOptions = append(base.TenantOptions, tenantOption{ID: c.ID, Name: c.Name, Selected: current != nil && current.ID == c.ID})
			}
			base.Flash = s.say(ctx, owner, "picker.connect_first")
		}
		s.render(w, base)
		return
	}
	permits, complete, err := s.tenant.ListPermitsComplete(ctx, owner, "")
	if err != nil {
		if errors.Is(err, parking.ErrSessionExpired) {
			// A dead session on THIS page is diagnostic, never routine ageing: only a
			// linked account reaches the picker, and in the ?linked=1 case the session
			// was established seconds ago. This branch used to be fully silent, which
			// hid a whole failure mode (observed live 2026-08-22): a signup whose
			// tenant password was accepted four times in a row was bounced back to
			// the link form after each success — under a green "Tenant account
			// linked." flash — because the fresh session failed this very read, until
			// the password throttle stopped them with advice about wrong passwords.
			freshLink := r.URL.Query().Get("linked") == "1"
			log.Printf("picker: council permit read for %s failed as session-expired (fresh link: %v)", redact.Email(owner), freshLink)
			if freshLink {
				// The one thing this person must NOT be shown is the password form
				// again: their password already worked, and every resubmit is a real
				// tenant login. Say what actually happened and where to look.
				s.message(w, http.StatusBadGateway, s.say(ctx, owner, "picker.session_rejected"))
				return
			}
			base.State = "onboarding"
			base.AutoReconnect = s.hasSavedPassword(ctx, owner)
			base.Relink = true
			s.render(w, base)
			return
		}
		base.State = "onboarding"
		base.AutoReconnect = s.hasSavedPassword(ctx, owner)
		log.Printf("list council permits for %s: %v", redact.Email(owner), err)
		base.Warn = "Couldn't reach the council to load your permits. Try re-linking."
		s.render(w, base)
		return
	}
	managed, err := s.store.ListPermitsFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !complete {
		// Say so rather than presenting a page as the whole account. Without this the
		// household simply cannot see a permit they hold and has no way to know why.
		base.Warn = "We could only load part of your permit list from the council just now, " +
			"so a permit you hold may be missing below. Try again in a few minutes."
		base.PermitsUnknown = true
	}
	base.HasPermits = len(permits) > 0
	base.HasManaged = len(managed) > 0
	already := map[string]bool{}
	for _, p := range managed {
		already[p.CouncilPermitID] = true
	}
	fallback := s.visitorNameFallback(ctx, owner, permits)
	if fallback && complete {
		// The tenant appears to have renamed its permit types out from under the
		// name-match — systemic (hits every new signup), so the operator must
		// hear. Once per process: a rename doesn't unhappen between requests.
		s.renameAlertOnce.Do(func() {
			// Name the types actually seen AND what the picker did with each:
			// without that the alert cannot distinguish "the tenant renamed its
			// types" (systemic) from "this account just holds no visitor permit"
			// (benign) — and an earlier wording that flatly claimed permits were
			// being "offered with a caution" sent the operator investigating a
			// resident-only household whose permit was never offered at all
			// (2026-08-23). Type names are tenant catalog labels shared by every
			// holder of the type, not personal data — never log permit numbers or
			// regos here.
			types := make([]string, 0, len(permits))
			offered := 0
			for _, p := range permits {
				t := fmt.Sprintf("%q", p.PermitType)
				switch {
				case !p.CanChangeVehicle:
					t += " (not changeable — not offered)"
				case s.isResidentPermit(ctx, owner, p.PermitType):
					t += " (changeable, resident — excluded, never offered)"
				default:
					t += " (changeable — offered with a caution)"
					offered++
				}
				types = append(types, t)
			}
			seen := strings.Join(types, ", ")
			log.Printf("picker: account %s holds changeable permits but NONE named 'visitor' — council may have renamed permit types; fallback engaged; %s", redact.Email(owner), seen)
			outcome := "Nothing was offered: every changeable permit here is a resident permit, which the fallback excludes outright (it holds the resident's own car). The household saw their permits greyed out with the reason."
			if offered > 0 {
				outcome = "Non-resident changeable permits were offered with a caution; resident permits (if any) stayed excluded."
			}
			nctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = s.notify.NotifyAdmin(nctx, "Council may have renamed permit types",
				"An account holds permits with CanChangeVehicle=true but none whose type name contains \"visitor\" — either the council renamed its permit types (systemic: hits every new signup) or this household simply holds no visitor permit (benign).\n\n"+
					"What the picker did with each type:\n"+seen+"\n\n"+
					outcome+"\n\n"+
					"If these are ordinary non-visitor types, no action is needed. If a visitor-like type has a new name, update the council policy's VisitorWord.")
		})
	}
	for _, p := range permits {
		if already[p.CouncilPermitID] {
			continue
		}
		// Show every permit the account holds, but only a visitor permit whose
		// holder can change the vehicle can actually be scheduled. The rest are
		// listed greyed-out with the reason, so the user sees them and isn't left
		// wondering where a permit went.
		visitor := s.visitorSchedulable(ctx, owner, p, fallback)
		addable := visitor && p.CanChangeVehicle
		reason := ""
		switch {
		case !visitor:
			reason = "Only visitor permits can be scheduled."
		case !p.CanChangeVehicle:
			reason = "Your council account can't change this permit's vehicle."
		}
		// An expired/cancelled permit is still listed and still addable (a user may
		// be reconstructing a schedule to copy onto a renewal), but say so plainly:
		// nothing will ever be applied to it, and silently accepting it looks to the
		// user like the app is working when it can't be.
		warn := ""
		if addable && fallback {
			warn = fallbackWarn
		}
		dead, status := false, ""
		if addable {
			meta := model.Permit{Status: p.Status, EndDate: p.EndDate}
			if meta.Inactive(time.Now(), s.locFor(ctx, owner)) {
				dead = true
				status = p.Status
				if status == "" || status == "Granted" {
					status = "Expired"
				}
				warn = "This permit is no longer active, so nothing will be applied to it."
				if !p.EndDate.IsZero() {
					warn = "This permit expired on " + p.EndDate.In(s.locFor(ctx, owner)).Format("2 Jan 2006") + ", so nothing will be applied to it."
				}
			}
		}
		base.Pick = append(base.Pick, pickView{
			CouncilPermitID: p.CouncilPermitID, PermitTypeID: p.PermitTypeID,
			PermitNumber: p.PermitNumber, PermitType: p.PermitType, CurrentRego: p.CurrentRego,
			Addable: addable, Reason: reason, Warn: warn, Dead: dead, Status: status,
		})
	}
	// Live permits first, dead ones last; the tenant's own order within each
	// group. The template renders the dead group under its own heading.
	slices.SortStableFunc(base.Pick, func(a, b pickView) int {
		switch {
		case a.Dead == b.Dead:
			return 0
		case a.Dead:
			return 1
		default:
			return -1
		}
	})
	base.State = "picker"
	s.render(w, base)
}

// claimedByAnotherAccount explains the one picker outcome the user cannot fix
// themselves. A household permit is often visible to two tenant logins (an
// ex-housemate, a previous tenant, a partner), so "already managed" needs to say
// who can release it and how — otherwise the button just keeps failing with no
// route forward.
const claimedByAnotherAccount = "That permit is already being scheduled through another p.stonn account — usually someone else at your address who set it up first. " +
	"Only one account can manage a permit, so ask them to open p.stonn and choose \"Stop managing\" on it (or to share access with you from their Settings), and then you can add it here. " +
	"If you think nobody else should have it, get in touch and we'll sort it out."

// Which permit types may be scheduled is the COUNCIL's policy, not the server's:
// see tenant.PermitPolicy (the visitor-name match, the resident exclusion, and the
// rename fallback, with the reasoning for each). The helpers below are the server's
// view of the policy for the tenant this account belongs to.

// say renders a catalog message as plain text for the owner's tenant (message
// pages, redirect flashes). A missing key is a programming error, logged, and
// the key itself is shown rather than nothing.
func (s *Server) say(ctx context.Context, owner, key string) string {
	data := map[string]any{"Tenant": s.tenantViewFor(ctx, owner)}
	out, err := catalog.For(i18n.DefaultLocale).Text(key, data)
	if err != nil {
		log.Printf("i18n: %v", err)
		return key
	}
	return out
}

// tenantFor returns the descriptor of the owner's tenant. Nil-safe for tests
// that build a Server without a registry (Stonnington), and falls back to the
// registry default when the account has no resolvable tenant.
func (s *Server) tenantFor(ctx context.Context, owner string) *tenant.Tenant {
	if s.registry == nil {
		return tenant.Default()
	}
	if s.store != nil && owner != "" {
		if id, err := s.store.TenantIDFor(ctx, owner); err == nil {
			if c, ok := s.registry.ByID(id); ok {
				return c
			}
		}
	}
	return s.registry.Default
}

// locFor is the timezone the owner's permit days are reckoned in: their tenant's
// when the registry knows it, else the process default. Public pages with no
// owner keep the default.
func (s *Server) locFor(ctx context.Context, owner string) *time.Location {
	if s.registry != nil && owner != "" {
		if c := s.tenantFor(ctx, owner); c != nil {
			return c.Location()
		}
	}
	return s.cfg.DisplayLocation
}

// policyFor returns the permit policy of the owner's tenant.
func (s *Server) policyFor(ctx context.Context, owner string) tenant.PermitPolicy {
	return s.tenantFor(ctx, owner).Policy
}

func (s *Server) isResidentPermit(ctx context.Context, owner, permitType string) bool {
	return s.policyFor(ctx, owner).IsResident(permitType)
}
func (s *Server) visitorNameFallback(ctx context.Context, owner string, permits []parking.PermitInfo) bool {
	return s.policyFor(ctx, owner).NameFallback(permits)
}
func (s *Server) visitorSchedulable(ctx context.Context, owner string, p parking.PermitInfo, fallback bool) bool {
	return s.policyFor(ctx, owner).Schedulable(p, fallback)
}

// fallbackWarn is the caution shown on a permit offered via the name fallback.
const fallbackWarn = "This permit isn't named as a visitor permit, but the council allows its vehicle to be changed. " +
	"Only add it if it's the permit your visitors park on."

func (s *Server) addPermit(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	// Bounded well inside the server's 20s WriteTimeout: the tenant authorization
	// read below must fail with a rendered error, not a dropped connection.
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cpid := strings.TrimSpace(r.FormValue("council_permit_id"))
	if cpid == "" {
		s.formError(w, r, "Council permit ID is required.")
		return
	}

	// Authorize the permit against the account's tenant record. The tenant
	// username is pinned to the primary's verified email, so ListPermits only
	// returns permits the account actually holds; a forged tenant_permit_id (not
	// from the picker) is rejected here. We take the permit type and current plate
	// from the authoritative tenant record, never from the form.
	if !s.tenantRead.allow("cr:" + owner) {
		s.message(w, http.StatusTooManyRequests,
			"Too many council lookups in a short time. Please wait a moment and try again.")
		return
	}
	permits, complete, err := s.tenant.ListPermitsComplete(ctx, owner, "")
	if err != nil {
		if errors.Is(err, parking.ErrSessionExpired) || errors.Is(err, parking.ErrNotLinked) {
			s.message(w, http.StatusConflict, "Your council sign-in has expired. Please re-link and try again.")
			return
		}
		log.Printf("addPermit list council permits for %s: %v", redact.Email(owner), err)
		s.message(w, http.StatusBadGateway, "Couldn't reach the council to confirm the permit. Try again shortly.")
		return
	}
	var match *parking.PermitInfo
	for i := range permits {
		if permits[i].CouncilPermitID == cpid {
			match = &permits[i]
			break
		}
	}
	if match == nil {
		if !complete {
			// We never saw the whole account, so absence proves nothing. Telling the
			// household "that permit isn't yours" would be a flat falsehood about a permit
			// they hold, and one they cannot act on. Fail retryable instead.
			s.message(w, http.StatusBadGateway,
				"We could only load part of your permit list from the council just now, so we can't yet "+
					"confirm this permit is on your account. Nothing has changed — please try again in a few minutes.")
			return
		}
		s.message(w, http.StatusForbidden, "That permit isn't one your council account can manage.")
		return
	}
	// Enforce the same rule the picker shows: p.stonn only schedules visitor
	// permits whose vehicle the holder can change. This is the authoritative
	// gate (the greyed-out picker button is only a UI hint) — it shares
	// visitorSchedulable with the picker so the two can't drift and offer a
	// permit this gate then refuses.
	if !s.visitorSchedulable(ctx, owner, *match, s.visitorNameFallback(ctx, owner, permits)) {
		s.message(w, http.StatusForbidden, "p.stonn only manages visitor permits.")
		return
	}
	if !match.CanChangeVehicle {
		s.message(w, http.StatusForbidden, "Your council account can't change the vehicle on that permit.")
		return
	}

	// Never take over a permit another account already manages (e.g. a shared
	// household permit both tenant accounts can see).
	tenantID, err := s.store.TenantIDFor(ctx, owner)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if existing, err := s.store.PermitInTenant(ctx, tenantID, cpid); err == nil && existing.Owner != owner {
		s.message(w, http.StatusConflict, claimedByAnotherAccount)
		return
	}

	pid, err := s.store.UpsertPermit(ctx, owner, cpid, match.PermitTypeID,
		cleanLabel(r.FormValue("label")))
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			// Raced the pre-check above: another account claimed it in between.
			s.message(w, http.StatusConflict, claimedByAnotherAccount)
			return
		}
		s.serverError(w, err)
		return
	}
	// Seed "on permit now" from the plate the tenant record already reports, so
	// it shows immediately instead of "unknown" until the first live refresh.
	// Seeding failures are not fatal — the scheduler refreshes both on its own cadence —
	// but they must not be invisible: silently swallowing them meant a permit that
	// showed "unknown" with no clue why, and no signal if the writes were failing for
	// everyone.
	if match.CurrentRego != "" {
		if err := s.store.SetPermitActive(ctx, pid, match.CurrentRego); err != nil {
			log.Printf("addPermit: seed current plate for permit %d: %v", pid, err)
		}
	}
	// Seed expiry + status + identifiers so the schedule shows them straight away;
	// the scheduler keeps them fresh on the keep-warm cadence thereafter.
	if err := s.store.UpdatePermitMeta(ctx, owner, cpid, match.Status, match.PermitNumber, match.PermitType, match.EndDate); err != nil {
		log.Printf("addPermit: seed metadata for permit %s: %v", cpid, err)
	}
	target := match.PermitNumber
	if target == "" {
		target = cpid
	}
	s.logChange(ctx, owner, user, store.ActionPermitAdd, target, "")
	// Land with the outcome said out loud. An EXPIRED permit is deliberately
	// addable (its schedule can be copied onto a renewal), but it renders inside
	// the collapsed "Expired permits" section — so the picker's "Manage" press
	// used to land on a page where the just-added permit was nowhere visible and
	// nothing acknowledged it. The active case gets a first-steps nudge instead.
	meta := model.Permit{Status: match.Status, EndDate: match.EndDate}
	if meta.Inactive(time.Now(), s.locFor(ctx, owner)) {
		http.Redirect(w, r, "/schedule?added=expired", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/schedule?added=1", http.StatusSeeOther)
}

// deletePermit stops p.stonn administering a permit: it drops the permit and its
// schedule (weekly rules + one-offs) and history. The tenant permit is left
// exactly as it is; we simply stop changing its plate.
//
// OWNER ONLY, unlike the rest of schedule management. This is the one action a
// secondary could use to lock the primary out: the delete is irreversible (roster,
// bookings and 90 days of history go with it) and a tenant permit can only be
// claimed by one p.stonn account, so a secondary holding their own tenant login
// for the same address could delete it here and immediately re-add it under their
// own account — leaving the primary with no self-service recovery. Everything a
// household member legitimately needs (roster, one-offs, guest passes, vehicles)
// stays open to them; retiring a permit is account-structural, like unlinking.
func (s *Server) deletePermit(w http.ResponseWriter, r *http.Request) {
	user, owner, isPrimary, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if !isPrimary {
		s.message(w, http.StatusForbidden,
			"Only the account owner can stop managing a permit. Ask them if this permit should be removed.")
		return
	}
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	if err := s.store.DeletePermit(r.Context(), p.ID, owner); err != nil {
		s.serverError(w, err)
		return
	}
	// Forget the tenant's last plate reading for this permit. The tenant client
	// caches it to keep the dashboard's "on permit now" honest without a live read,
	// and a household permit is often visible to two tenant logins — so "stop
	// managing" here followed by "manage" from the other resident's account is the
	// ordinary way a permit changes hands. Nothing else evicts the entry, and a
	// plate shown to the wrong household is how someone parks on a permit that no
	// longer says what they think it says.
	s.tenant.ForgetPermit(owner, p.TenantID, p.CouncilPermitID)
	label := permitLabel(p)
	s.logChange(r.Context(), owner, user, store.ActionPermitRemove, label, "")
	s.notifyDestructive(r.Context(), owner, user,
		user+" stopped managing the permit \""+label+"\". Its weekly roster, one-off bookings and change history were deleted, and p.stonn will no longer update that permit.")
	// Re-evaluate so the scheduler drops the now-removed permit promptly, and drop
	// its backoff entry with it — nothing else ever removes one, so a deployment
	// that churns permits leaks a map entry per deleted permit until restart.
	// KickPermit rather than Kick: clearing a dead permit's own entry cannot give
	// anyone else's permit a cheaper retry.
	s.sched.KickPermit(p.ID)
	redirectHome(w, r)
}

// copySchedule clones the weekly roster and active/upcoming one-offs from another
// of the account's permits onto this one — the "I renewed my permit, put my
// schedule back" flow. Any account member may do it (it's schedule management).
// dismissCopyOffer retires the "renewed this permit?" copy pitch for one permit
// without copying anything. One-way: the pitch never leads again; the quiet
// "Copy schedule from another permit" button remains.
func (s *Server) dismissCopyOffer(w http.ResponseWriter, r *http.Request) {
	_, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	if err := s.store.MarkCopyOfferDone(r.Context(), p.ID); err != nil {
		s.serverError(w, err)
		return
	}
	p.CopyOfferDone = true
	s.respondPermit(w, r, owner, p)
}

func (s *Server) copySchedule(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	dst, ok := s.ownedPermit(w, r, owner) // target = permit in the path
	if !ok {
		return
	}
	src := atoi64(r.FormValue("source"))
	if src == 0 || src == dst.ID {
		s.formError(w, r, "Choose which permit to copy the schedule from.")
		return
	}
	// Confirm the source is also this account's (CopySchedule re-checks, but this
	// gives a clean 404 rather than a generic error).
	sp, err := s.store.GetPermit(r.Context(), src)
	if err != nil || sp.Owner != owner {
		s.message(w, http.StatusNotFound, "That permit isn't one of yours.")
		return
	}
	n, err := s.store.CopySchedule(r.Context(), owner, src, dst.ID, time.Now())
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Copying FROM a dead permit is the renewal gesture, so the guest surface
	// moves across with the schedule: re-pointing a grant keeps its tokens, and
	// a token IS a link's identity — passes saved to guests' phones and printed
	// door posters keep working with nothing re-sent or re-printed. Never done
	// between two live permits: there "copy" means duplicate, and silently
	// re-targeting someone's standing access would be a surprise, not a rescue.
	// And never ONTO a dead permit: with two expired permits and one renewal,
	// dead-to-dead would strand every pass on a target that still 410s while
	// this handler announces the links work.
	now := time.Now()
	moved, stranded := 0, false
	var moveErr error
	if sp.Inactive(now, s.locForPermit(r.Context(), dst)) && !dst.Inactive(now, s.locForPermit(r.Context(), dst)) {
		if moved, stranded, moveErr = s.store.MoveGuestGrants(r.Context(), owner, src, dst.ID); moveErr != nil {
			// The unmoved passes stay safely refused by the inactive-permit gate
			// rather than half-working — but the failure must reach the user (below),
			// not just the log: the whole promise of this path is "links keep
			// working", and a silent miss surfaces only through a confused guest.
			log.Printf("copy schedule: move guest passes %d -> %d: %v", src, dst.ID, moveErr)
			moved = 0
		}
	}
	label := permitLabel(dst)
	if n > 0 {
		s.logChange(r.Context(), owner, user, store.ActionScheduleCopy, label, "")
	}
	if moved > 0 {
		s.logChange(r.Context(), owner, user, store.ActionGuestMove, label, "")
	}
	if moveErr != nil {
		// Partial outcome, said out loud. Re-running the copy is safe (CopySchedule
		// is idempotent; the move is a plain re-point), so that is the advice.
		if n > 0 {
			s.notifyDestructive(r.Context(), owner, user,
				user+" copied another permit's schedule onto \""+label+"\". That replaced its weekly roster and any upcoming one-off bookings.")
			s.sched.KickPermit(dst.ID)
			s.message(w, http.StatusInternalServerError,
				"The schedule was copied, but the old permit's guest passes couldn't be moved across. Run “Copy schedule from another permit” again to move them.")
			return
		}
		s.message(w, http.StatusInternalServerError,
			"The old permit's guest passes couldn't be moved across just now. Nothing was changed — please try again.")
		return
	}
	if n == 0 && moved == 0 {
		s.formError(w, r, "That permit has no schedule to copy.")
		return
	}
	msg := user + " copied another permit's schedule onto \"" + label + "\". That replaced its weekly roster and any upcoming one-off bookings."
	if moved > 0 {
		msg += " Guest passes and QR codes moved across with it — links that people have saved keep working."
	}
	if n == 0 {
		msg = user + " moved guest passes and QR codes from an old permit onto \"" + label + "\" — links that people have saved keep working."
	}
	if stranded {
		msg += " The old permit's printed door QR wasn't moved (this permit already has its own) — that old poster no longer works, so take it down."
	} else if moved > 0 {
		msg += " Printed posters keep working too."
	}
	s.notifyDestructive(r.Context(), owner, user, msg)
	// The same facts for the person who did it, in their own frame: the change
	// notice above goes to everyone else on the account.
	notice := "Schedule copied. This permit's weekly roster and upcoming bookings were replaced."
	if n == 0 {
		notice = "Guest passes and QR codes moved onto this permit — links that people have saved keep working."
	} else if moved > 0 {
		notice += " Guest passes and QR codes moved across with it — links that people have saved keep working."
	}
	if stranded {
		notice += " The old permit's printed door QR wasn't moved (this permit already has its own) — that old poster no longer works, so take it down."
	} else if moved > 0 {
		notice += " Printed posters keep working too."
	}
	s.sched.KickPermit(dst.ID)
	// Running a copy answers the "renewed this permit?" pitch for good — matters
	// even in the moved-passes-only case (n == 0), where the roster stays empty
	// and nothing else would retire it. dst is a local copy; mirror the flag for
	// the render below.
	if !dst.CopyOfferDone {
		if err := s.store.MarkCopyOfferDone(r.Context(), dst.ID); err == nil {
			dst.CopyOfferDone = true
		}
	}
	s.respondPermitNotice(w, r, owner, dst, notice)
}

// clearPermit takes the vehicle OFF a permit, leaving it with no plate — the one
// way a car comes off, since "nothing scheduled" deliberately leaves the last
// plate in place. A specific, confirmed action, never a schedulable value: making
// "nobody" a roster/one-off option would turn every gap into an automatic
// blanking, inverting the app's core "nothing scheduled = touch nothing" safety.
//
// Refused when a schedule covers now: the scheduler would re-apply the scheduled
// plate on its next tick, so clearing would be a confusing no-op. The UI only
// offers the button in the lingering-plate state; this is the authoritative gate.
func (s *Server) clearPermit(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	now := time.Now().In(s.locForPermit(r.Context(), p))

	// Detached + capped like every other tenant write on a request path, so a
	// closed tab can't cancel the write half-done and a slow portal still leaves
	// room to render inside the server's WriteTimeout.
	bg := context.WithoutCancel(r.Context())
	applyCtx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	release, claimed := s.sched.AcquireApply(applyCtx, p.ID)
	if !claimed {
		s.formError(w, r, "The permit is busy with another change right now. Please try again in a moment.")
		return
	}
	// Re-check under the claim, immediately before the write: if a schedule now
	// covers this moment, clearing would be undone on the next reconcile.
	rules, rerr := s.store.ListRules(applyCtx, p.ID)
	ovs, oerr := s.store.ListOverrides(applyCtx, p.ID, now)
	if rerr != nil || oerr != nil {
		release()
		s.serverError(w, cmp.Or(rerr, oerr))
		return
	}
	if res := model.Resolve(now, rules, ovs); res.Source != model.SourceNone {
		release()
		s.formError(w, r, "This permit has a car scheduled right now, so it can't be left empty — change or clear that day's schedule instead.")
		return
	}
	err := s.tenant.ClearVehicle(applyCtx, owner, p)
	if err == nil {
		if e := s.store.SetPermitActive(bg, p.ID, ""); e != nil {
			log.Printf("clearPermit: council cleared permit %d but local commit failed: %v", p.ID, e)
		}
		// Reflect the cleared plate on the struct we re-render from. Without this the
		// card shows the OLD plate: respondPermit renders from this p, and the
		// tenant-cache adopt inside buildPermitView is a compare-and-swap against the
		// STORED plate, which the line above already moved to "" — so the CAS no-ops
		// and the stale struct value would win.
		p.ActiveRegistration = ""
	}
	release()

	label := permitLabel(p)
	if err != nil {
		log.Printf("clearPermit %d for %s: %v", p.ID, redact.Email(owner), err)
		if kind, _ := parking.FailureOf(err); kind == parking.FailTransient {
			s.formError(w, r, "Couldn't reach the council just now — nothing was changed. Please try again shortly.")
			return
		}
		s.formError(w, r, "The council didn't accept removing the vehicle. The account holder may need to reconnect their council login.")
		return
	}
	_ = s.store.RecordApply(bg, p.ID, "", "manual", "success", "vehicle removed by "+user)
	s.logChange(bg, owner, user, store.ActionVehicleClear, label, "")
	s.notifyDestructive(bg, owner, user,
		user+" removed the car from the permit \""+label+"\". It now has no vehicle — nothing is covered on that permit until a car is set or scheduled.")
	s.respondPermit(w, r, owner, p)
}

// cleanLabel trims a user-supplied name and strips control characters (including
// CR/LF), so a label can't smuggle newlines into an email header (defence in depth
// alongside the mailer's own sanitisation) or odd control bytes into the UI.
func cleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// renamePermit gives a permit a friendly name the user chooses (e.g. "Nanny"),
// shown everywhere it appears — schedule, guest passes, door QRs. It's purely a
// display label; the tenant record is untouched.
func (s *Server) renamePermit(w http.ResponseWriter, r *http.Request) {
	user, owner, _, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	p, ok := s.ownedPermit(w, r, owner)
	if !ok {
		return
	}
	label := cleanLabel(r.FormValue("label"))
	if label == "" {
		s.formError(w, r, "Give the permit a name.")
		return
	}
	if rs := []rune(label); len(rs) > 40 {
		label = string(rs[:40])
	}
	if err := s.store.SetPermitLabel(r.Context(), owner, p.ID, label); err != nil {
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionPermitRename, label, "")
	redirectHome(w, r)
}
