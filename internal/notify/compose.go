package notify

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/store"
)

// neutraliseLinks strips whole URLs out of owner-supplied free text (a permit
// label) before it reaches mail we send to people who never opted in.
//
// The label is the owner's own text, capped at 40 characters and shown in the
// app, but a guest-pass email is DKIM-signed by our domain and sent to any
// address the owner types. The HTML alternative turns bare URLs in the body into
// real links (mailer.linkify), so without this an account is a machine for
// mailing a clickable attacker link from a domain with our reputation — and the
// recipient's spam report lands as a complaint, which is the one suppression that
// is never pruned and never user-clearable. Removing just the URL keeps every
// legitimate label ("Nanny", "12 Example St") completely intact.
func neutraliseLinks(label string) string {
	return strings.TrimSpace(linkRun.ReplaceAllString(label, "(link removed)"))
}

// linkRun matches what the mail layer would turn into a clickable link, and must
// be at least as broad as the linkifier (mailer.inlineURL, `https?://[^\s<>()]+`)
// or a URL slips past here and is still hyperlinked there. It deliberately has NO
// leading word boundary: `\bhttps` does not anchor inside `2https://evil` (the
// boundary the linkifier does not require either), so a label like "2https://evil"
// would otherwise survive the strip and reach the recipient as a live link. `\S*`
// is strictly broader than the linkifier's character class, so nothing it would
// wrap can escape this.
var linkRun = regexp.MustCompile(`(?i)https?://\S*`)

// ApplyOutcome is what NotifyApply describes to the user: a successful change,
// or a failure with a plain-English reason, the consequence (what plate is still
// on the permit), and what to do. Transient softens the wording (we keep trying).
type ApplyOutcome struct {
	Owner       string
	TenantID    string // the permit's tenant: the council and portal the message points at
	PermitLabel string
	Reg         string // the vehicle we tried to set
	Name        string // friendly name of that vehicle ("" for an ad-hoc plate)
	By          string // who made the change, when it was a guest activation ("" otherwise)
	Source      string // "roster" / "override" / "guest" / "doorqr" (success context)
	OK          bool
	CurrentReg  string // what is still on the permit on failure ("" if unknown)
	Reason      string // one plain sentence: why it failed
	Action      string // one plain sentence: what the user should do
	Transient   bool   // failure expected to self-heal → soften wording
	// CouncilDown says we KNOW the council's own sign-in is down (the auth circuit is
	// open) — so the household cannot reach the council either. It keeps the soft tier
	// but names the cause plainly and drops the "do it yourself at the council" line,
	// which would be impossible advice during a council-wide outage.
	CouncilDown bool
	// ResolvesFailure marks a success that closes a failure episode the household
	// was told about. It reaches members on "only tell me about problems" too:
	// they heard the problem, so they hear that it is over.
	ResolvesFailure bool
	// Urgent overrides the transient softening for a CONFIRMED, ongoing block: the
	// change genuinely will not apply until the block clears, so the household must
	// act now (change the plate manually) rather than be reassured it is "still
	// updating". It forces the act-now subject and a high-priority push even though
	// the underlying failure is technically transient.
	Urgent bool

	// PermitID scopes Key: two permits on one account can produce the identical
	// outcome key (a tenant-wide "council unavailable"), and each is its own notice.
	PermitID int64
	// Key is the caller's identity for this outcome: the same Key means the same
	// message, retried. When set, NotifyApply remembers which members it reached
	// inline, so a retry after a partial delivery skips them (still counting them
	// as delivered) and goes only to the members who were missed. "" means no
	// memory — a one-shot caller.
	Key string

	// DisplacedReg is the plate of a still-live third-party booking this change
	// bumped off the permit ("" when nothing of note was displaced), and
	// DisplacedTold whether its driver got their own heads-up email. When they
	// couldn't be reached, the account notification asks the members to relay
	// the warning — otherwise the displaced car sits uncovered with nobody told.
	DisplacedReg  string
	DisplacedTold bool
}

// actionNeeded reports a hard failure the user must act on (a non-transient
// error: a dead tenant session, a rejected plate). These bypass the quiet-hours
// hold and send immediately — an unattended fine risk shouldn't wait until 6am.
// Urgent counts as action-needed even when Transient. A CONFIRMED fleet block is
// flagged Transient (it will clear) but its body says "change the vehicle yourself at
// the tenant now to avoid a fine" — quiet hours were holding exactly that message
// until 06:00, so a block at 23:30 left the household on the wrong plate all night
// with the high-priority push suppressed.
func (o ApplyOutcome) actionNeeded() bool { return !o.OK && (!o.Transient || o.Urgent) }

// fromSchedule reports whether a successful change was the household's own
// schedule acting — the roster, or a one-off booking they made. The "only tell
// me about problems" preference (FailuresOnly) mutes these, but NOT a change
// made by someone else (a guest link, an approved door-QR request): that is a
// third party touching the permit, which the household should hear about even
// with routine confirmations off.
func (o ApplyOutcome) fromSchedule() bool { return o.Source == "roster" || o.Source == "override" }

// emailWanted decides whether this member's verified address gets the outcome.
// Email-off means "no routine confirmations", never "no safety alerts": an
// action-needed failure ("change the plate yourself now or someone gets a fine")
// always goes to the verified address, the same rule broadcastAccount applies to
// the re-link and reconnect-stalled notices. A push channel has no delivery
// receipt — an uninstalled app, a silenced phone or a wrong topic fails without
// a trace — and this is the one message that must not depend on it. The only
// live push-only household (2026-08) was exactly that exposure.
func (s *Service) emailWanted(pref store.NotifyPref, o ApplyOutcome) bool {
	return (pref.EmailEnabled || o.actionNeeded()) && s.mail.Enabled()
}

// deferUntil returns the quiet-hours delivery time for this outcome, or the zero
// time (send now) when the outcome is a hard action-needed failure. loc is the
// zone the member's quiet hours are read in (see quietDefer).
func (s *Service) deferUntil(pref store.NotifyPref, now time.Time, loc *time.Location, o ApplyOutcome) time.Time {
	if o.actionNeeded() {
		return time.Time{}
	}
	return s.quietDefer(pref, now, loc)
}

// firstApplyLine is the once-ever referral ask, appended to the confirmation of
// the household's FIRST successful tenant write: the moment the product has just
// proven itself. RecordApply runs before notification, so a count of exactly one
// means this outcome is that first success. Any store error means no line.
func (s *Service) firstApplyLine(ctx context.Context, o ApplyOutcome) string {
	if !o.OK || s.store == nil {
		return ""
	}
	if n, err := s.store.CountSuccessfulApplies(ctx, o.Owner); err != nil || n != 1 {
		return ""
	}
	return "\n\n" + say(s.tenantOf(ctx, o.Owner, o.TenantID), "mail.referral_line", nil)
}

// composeApply builds the subject/body/priority/tags for an apply notification,
// shared by the inline NotifyApply (scheduler) and the durable EnqueueApply.
func composeApply(o ApplyOutcome, portalURL string) (subject, body, priority, tags string) {
	// "car" names the vehicle by friendly name and plate where we have both, joined
	// with an em-dash so a nickname that itself contains brackets (e.g.
	// "Anita's Car (Nanny)") doesn't produce confusing nested parentheses.
	car := o.Reg
	if o.Name != "" {
		car = fmt.Sprintf("%s — %s", o.Name, o.Reg)
	}
	if o.OK {
		subject = fmt.Sprintf("Permit updated: %s now shows %s", o.PermitLabel, o.Reg)
		const confirm = "\n\nNothing to do — this is just your confirmation it went through."
		switch {
		case o.Source == "doorqr":
			body = fmt.Sprintf("Your %s is now set to %s.\n\n%s approved a visitor's request from your printed QR code, so it overrides your schedule until that booking ends — then your roster takes over again.",
				o.PermitLabel, car, o.By)
		case o.Source == "guest":
			body = fmt.Sprintf("Your %s is now set to %s.\n\n%s activated it with a guest link, so it overrides your schedule until that booking ends — then your roster takes over again.",
				o.PermitLabel, car, o.By)
		case o.Source == "override" && o.By != "":
			// Name whoever made the booking. On a shared account this is the only
			// signal distinguishing "the schedule ran" from "someone booked over it",
			// and the plate alone doesn't say who decided it.
			body = fmt.Sprintf("Your %s is now set to %s, for a one-off booking made by %s.%s",
				o.PermitLabel, car, o.By, confirm)
		case o.Source == "roster":
			body = fmt.Sprintf("Your %s is now set to %s for today, as scheduled by your weekly roster.%s", o.PermitLabel, car, confirm)
		case o.Source == "override":
			body = fmt.Sprintf("Your %s is now set to %s, for the one-off booking you made.%s", o.PermitLabel, car, confirm)
		default:
			body = fmt.Sprintf("Your %s is now set to %s.%s", o.PermitLabel, car, confirm)
		}
		if o.DisplacedReg != "" {
			if o.DisplacedTold {
				body += fmt.Sprintf("\n\nThis replaced %s, which an active booking had put on — we've emailed the person responsible for that car a heads-up.", o.DisplacedReg)
			} else {
				body += fmt.Sprintf("\n\nThis replaced %s, which an active booking had put on. We had no way to reach whoever drives it — if %s is still parked there, please let them know it's no longer covered.", o.DisplacedReg, o.DisplacedReg)
			}
		}
	} else {
		// A confirmed ongoing block is transient-but-urgent: soften only when it is
		// transient AND not urgent, so the act-now subject and high-priority push
		// fire once we KNOW the change will not apply until the block clears.
		soft := o.Transient && !o.Urgent
		switch {
		case o.CouncilDown:
			// The council itself is down; name that, and don't promise it "shows X for
			// now" as if a quick retry will fix it. Neutral "council" (not a hard-coded
			// name) for the multi-council guard.
			subject = fmt.Sprintf("The council's system is down — your %s change is waiting", o.PermitLabel)
		case o.CurrentReg != "" && soft:
			subject = fmt.Sprintf("Still updating your %s — it shows %s for now", o.PermitLabel, o.CurrentReg)
		case o.CurrentReg != "":
			subject = fmt.Sprintf("Action needed: your %s still shows %s", o.PermitLabel, o.CurrentReg)
		case soft:
			subject = fmt.Sprintf("Still updating your %s", o.PermitLabel)
		default:
			subject = fmt.Sprintf("Action needed: your %s wasn't updated", o.PermitLabel)
		}
		lines := []string{fmt.Sprintf("p.stonn tried to set your %s to %s but couldn't.", o.PermitLabel, car)}
		if o.CurrentReg != "" {
			lines = append(lines, fmt.Sprintf("The permit still shows %s, so that is the vehicle currently covered.", o.CurrentReg))
		} else {
			lines = append(lines, "The vehicle on the permit has not been changed.")
		}
		if o.Reason != "" {
			lines = append(lines, "", o.Reason)
		}
		if o.Action != "" {
			lines = append(lines, o.Action)
		}
		// A failure is normally a "sort it yourself" moment: link the tenant portal.
		// But when the council's own system is down, the portal is unreachable too, so
		// pointing them at it would be impossible advice — the honest Action already
		// stands on its own.
		if !o.CouncilDown {
			lines = append(lines, "", "You can set the vehicle on your permit yourself at the council:", portalURL)
		}
		body = strings.Join(lines, "\n")
	}
	priority, tags = "default", "white_check_mark"
	if !o.OK {
		tags = "warning"
		if o.Transient && !o.Urgent {
			priority = "default"
		} else {
			priority = "high"
		}
	}
	return
}

// onboardNudgeMessage composes the recovery email. Split from the send so its
// content — each line answers a distinct observed drop-off cause — is testable
// without an SMTP conversation.
func onboardNudgeMessage(to, appURL string, c mailTenant) (subject, body string) {
	subject = "One step left to start managing your visitor permit"
	// Layout note: a SHORT "do this:" line directly above each URL becomes that
	// button's label in the HTML alternative (see mailer/html.go). Folding the
	// label into the preceding sentence puts the whole sentence on the button.
	lines := []string{
		"You signed up for p.stonn, but it isn't connected to your council account yet — so nothing is running. The weekly plate schedule, guest QR codes and one-off bookings all start from that one connection.",
		"",
		say(c, "mail.nudge_connect", nil),
		"",
		say(c, "mail.nudge_password", nil),
		"Reset it at the council:",
		c.Links.ResetPassword,
		"",
		say(c, "mail.nudge_email", map[string]any{"To": to}),
		"",
	}
	// The webview escape needs somewhere to point; a deployment that never set
	// its public URL keeps the advice without the address.
	if appURL != "" {
		lines = append(lines,
			"3. Your usual browser. If you signed up from a Facebook link, you were inside Facebook's built-in browser, where saved passwords don't auto-fill.",
			"Open p.stonn in Safari or Chrome:",
			appURL,
			"")
	} else {
		lines = append(lines,
			"3. Your usual browser. If you signed up from a Facebook link, you were inside Facebook's built-in browser, where saved passwords don't auto-fill. Open p.stonn in Safari or Chrome instead.",
			"")
	}
	lines = append(lines,
		"One thing to know: p.stonn manages VISITOR permits only — the permit your guests' cars go on — and only one you already hold; it can't apply for one, and it never touches a resident permit.",
		"",
		say(c, "mail.nudge_apply", nil),
		"Register with the council:",
		c.Links.Register,
		"",
		"This is the only reminder p.stonn sends. If you've decided it's not for you, there's nothing to undo — your details go no further than the sign-up you made.",
	)
	return subject, strings.Join(lines, "\n")
}
