package notify

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/mailer"
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
	Color       string // that vehicle's plate colour (hex), so the mail's chip matches the app's ("" = neutral)
	By          string // who made the change, when it was a guest activation ("" otherwise)
	Source      string // "roster" / "override" / "guest" / "doorqr" / "picker" (success context)
	// Empty means the schedule asked for NO rego on the permit (an "empty" roster
	// day or booking): Reg is "" and the change is a clear, not a set.
	Empty      bool
	OK         bool
	CurrentReg string // what is still on the permit on failure ("" if unknown)
	Reason     string // one plain sentence: why it failed
	Action     string // one plain sentence: what the user should do
	Transient  bool   // failure expected to self-heal → soften wording
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

	// DriverTold is the address of the car's own driver when they were sent their
	// notice about this outcome (the per-rego "tell the driver" toggle), so each
	// member's copy can name them among the others told. "" when nobody was.
	DriverTold string
}

// hero is the plate chip at the top of the HTML mail: the rego now on the
// permit, in its colour, as the app shows it. Only a success has one; a failure
// notice leads with what is still on the permit in words, and a chip there
// would read as the change having gone through.
func (o ApplyOutcome) hero() mailer.Hero {
	if !o.OK {
		return mailer.Hero{}
	}
	return mailer.Hero{Plate: o.Reg, Color: o.Color}
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
func (o ApplyOutcome) fromSchedule() bool {
	// The quick picker is the household tapping its own phone: their choice, not a
	// third party's, so it is muted under failures-only exactly as a booking is.
	return o.Source == "roster" || o.Source == "override" || o.Source == "picker"
}

// mutedByFailuresOnly reports whether a member who asked to hear about problems
// only should be spared this outcome: a successful, household-scheduled apply that
// is not itself the resolution of a prior failure they were told about. The single
// source of the rule NotifyApply and EnqueueApply both apply per member.
func (o ApplyOutcome) mutedByFailuresOnly(pref store.NotifyPref) bool {
	return o.OK && pref.FailuresOnly && o.fromSchedule() && !o.ResolvesFailure
}

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
		subject = fmt.Sprintf("%s is now on your permit “%s”", o.Reg, o.PermitLabel)
		const confirm = "\n\nThis is simply to confirm the change, and you don’t need to do anything."
		if o.Empty {
			subject = fmt.Sprintf("Your permit “%s” now has no rego on it", o.PermitLabel)
		}
		switch {
		case o.Empty && o.Source == "roster":
			body = fmt.Sprintf("Your permit “%s” has no rego on it for today, as scheduled by your roster (regos are removed on this day). No car is covered by that permit until you select a rego.%s", o.PermitLabel, confirm)
		case o.Empty && o.Source == "override" && o.By != "":
			body = fmt.Sprintf("Your permit “%s” has no rego on it, because %s has scheduled the permit to be cleared. No car is covered by that permit until the booking ends.%s", o.PermitLabel, o.By, confirm)
		case o.Empty && o.Source == "override":
			body = fmt.Sprintf("Your permit “%s” has no rego on it, because you scheduled the permit to be cleared. No car is covered by that permit until the booking ends.%s", o.PermitLabel, confirm)
		case o.Empty:
			body = fmt.Sprintf("Your permit “%s” now has no rego on it.%s", o.PermitLabel, confirm)
		case o.Source == "doorqr":
			body = fmt.Sprintf("%s is now on your permit “%s”.\n\n%s approved a visitor’s request from your printed QR. When the booking ends, your roster takes over, or if nothing is scheduled, the rego stays on until the next change.",
				car, o.PermitLabel, o.By)
		case o.Source == "guest":
			body = fmt.Sprintf("%s is now on your permit “%s”.\n\n%s put it on with their guest pass. When the booking ends, your roster takes over, or if nothing is scheduled, the rego stays on until the next change.",
				car, o.PermitLabel, o.By)
		case o.Source == "picker":
			body = fmt.Sprintf("%s is now on your permit “%s”. Someone in your household put it on with the quick picker. When the booking ends, your roster takes over, or if nothing is scheduled, the rego stays on until the next change.%s",
				car, o.PermitLabel, confirm)
		case o.Source == "override" && o.By != "":
			// Name whoever made the booking. On a shared account this is the only
			// signal distinguishing "the schedule ran" from "someone booked over it",
			// and the plate alone doesn't say who decided it.
			body = fmt.Sprintf("%s is now on your permit “%s”, for a booking %s made.%s",
				car, o.PermitLabel, o.By, confirm)
		case o.Source == "roster":
			// "your roster", not "your weekly roster": a multi-week cycle is still
			// the roster, and the weekly case loses nothing.
			body = fmt.Sprintf("%s is on your permit “%s” for today, as scheduled by your roster.%s", car, o.PermitLabel, confirm)
		case o.Source == "override":
			body = fmt.Sprintf("%s is now on your permit “%s”, for the booking you made.%s", car, o.PermitLabel, confirm)
		default:
			body = fmt.Sprintf("%s is now on your permit “%s”.%s", car, o.PermitLabel, confirm)
		}
		if o.DisplacedReg != "" {
			if o.DisplacedTold {
				body += fmt.Sprintf("\n\nTo make this change, p.stonn removed %s, which a booking had set. We have emailed the person whose rego that is.", o.DisplacedReg)
			} else {
				body += fmt.Sprintf("\n\nTo make this change, p.stonn removed %s, which a booking had set. We have no way to contact that person, so if %s is still parked there, please let them know the car is no longer covered.", o.DisplacedReg, o.DisplacedReg)
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
			subject = fmt.Sprintf("Your permit “%s” will change once the council’s system is back", o.PermitLabel)
		case o.CurrentReg != "" && soft:
			subject = fmt.Sprintf("Your permit “%s” still shows %s while p.stonn keeps trying", o.PermitLabel, o.CurrentReg)
		case o.CurrentReg != "":
			subject = fmt.Sprintf("Action needed: your permit “%s” still shows %s", o.PermitLabel, o.CurrentReg)
		case soft:
			subject = fmt.Sprintf("p.stonn is still trying to update your permit “%s”", o.PermitLabel)
		default:
			subject = fmt.Sprintf("Action needed: p.stonn could not update your permit “%s”", o.PermitLabel)
		}
		lines := []string{fmt.Sprintf("p.stonn has not been able to put %s on your permit “%s”.", car, o.PermitLabel)}
		if o.Empty {
			lines[0] = fmt.Sprintf("p.stonn has not been able to clear your permit “%s” (regos are removed on this day, as scheduled).", o.PermitLabel)
		}
		if o.CurrentReg != "" {
			lines = append(lines, fmt.Sprintf("%s is still on the permit, so the car with that rego is the one covered.", o.CurrentReg))
		} else {
			lines = append(lines, "The rego on the permit has not changed.")
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
			lines = append(lines, "", "You can set the rego on your permit yourself at the council:", portalURL)
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

// unusedPassMessage is the once-ever note telling a household that a guest pass
// they sent has never been used.
//
// It goes to the HOLDER, not to the guest. The guest has already had one cold
// email from a service they had not heard of; a second would be nagging a
// stranger, and the person who can actually do something — ask them to look for
// it, send it again, or remove it — is the one who sent it. Scoped to emailed
// passes: an on-screen QR is consumed at the door and an unused one is its normal
// end state (see store.UnusedPassCandidates).
// andList writes a list the way it is read aloud: "a", "a and b", "a, b and c".
func andList(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	case 2:
		return xs[0] + " and " + xs[1]
	default:
		return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
	}
}

func unusedPassMessage(to []string, appURL string) (subject, body string) {
	// Keyed on the RECIPIENTS, not on how many grants the household made: each
	// person gets their own link, so "the guest passes you created for A and B"
	// is the true sentence whether that came from one pass form or two. The
	// household's grants are grouped by the caller and named here once.
	many := len(to) != 1
	pass, guest, link, have := "pass", "guest", "The link still works", "has"
	if many {
		pass, guest, link, have = "passes", "guests", "The links still work", "have"
	}
	subject = fmt.Sprintf("The guest %s you sent have not been used yet", pass)
	if !many {
		subject = "The guest pass you sent has not been used yet"
	}
	// A grant whose recipients have all been revoked still deserves a readable
	// sentence, so the list is simply left out rather than printed empty.
	forWhom := ""
	if who := andList(to); who != "" {
		forWhom = " for " + who
	}
	lines := []string{
		fmt.Sprintf("The guest %s you created%s %s not been opened or used yet.", pass, forWhom, have),
		"",
		fmt.Sprintf("You may want to check with your %s that they received the email with their pass. You can also send the pass again from the Guests tab:", guest),
		"",
	}
	if appURL != "" {
		lines = append(lines, appURL+"/guests", "")
	}
	lines = append(lines, fmt.Sprintf("%s, so if they have received the pass, you don’t need to do anything else.", link))
	return subject, strings.Join(lines, "\n")
}

// portalNudgeMessage is the once-ever note to a household that changes the rego
// on the council's own website while p.stonn quietly follows along.
//
// The drift pass says nothing on this path on purpose (scheduler.holdExternalChange:
// a permit with nothing scheduled simply adopts the plate, and telling a household
// every time that we noticed them managing their own permit is a nag). This message
// is the single exception, sent once and never again, because the September 2026
// cohort review found accounts doing exactly that for a month — plainly active
// permit-holders — who had connected p.stonn and never once used it to make a change.
// Nothing here asks them to stop using the council's site; it offers the three
// things p.stonn does that the portal does not.
//
// contactURL may be empty, in which case the offer of help is dropped rather than
// pointed at a dead link.
func portalNudgeMessage(plate, appURL, contactURL string, c mailTenant) (subject, body string) {
	subject = "p.stonn has noticed a change you made on the council’s website"
	lines := []string{
		say(c, "mail.portal_nudge_lead", map[string]any{"Plate": plate}),
		"",
		say(c, "mail.portal_nudge_fine", nil),
		"",
		"If you would like, we can help you set up a guest pass for your visitors, a quick picker for regos on your phone, or put number plate changes on a schedule.",
		"",
	}
	// A SHORT "do this:" line directly above a URL becomes that button's label in
	// the HTML alternative (mailer/html.go), so the invitation and the address are
	// two lines, not one sentence wrapped around a link.
	if appURL != "" {
		lines = append(lines, "Open p.stonn:", appURL, "")
	}
	if contactURL != "" {
		lines = append(lines, "Contact us for assistance:", contactURL, "")
	}
	lines = append(lines, "p.stonn will not send you this note again.")
	return subject, strings.Join(lines, "\n")
}

// onboardNudgeMessage composes the recovery email. Split from the send so its
// content — each line answers a distinct observed drop-off cause — is testable
// without an SMTP conversation.
func onboardNudgeMessage(to, appURL string, c mailTenant) (subject, body string) {
	subject = "One step remains before p.stonn can manage your visitor permit"
	// Layout note: a SHORT "do this:" line directly above each URL becomes that
	// button's label in the HTML alternative (see mailer/html.go). Folding the
	// label into the preceding sentence puts the whole sentence on the button.
	lines := []string{
		"You signed up for p.stonn, but you have not linked your council account yet, so p.stonn cannot do anything for you. The roster, bookings, guest passes and visitor QR all depend on that link.",
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
			"3. If you signed up from a Facebook link, you were using Facebook’s built-in browser, which does not fill in saved passwords.",
			"Open p.stonn in Safari or Chrome:",
			appURL,
			"")
	} else {
		lines = append(lines,
			"3. If you signed up from a Facebook link, you were using Facebook’s built-in browser, which does not fill in saved passwords. Please open p.stonn in Safari or Chrome instead.",
			"")
	}
	lines = append(lines,
		"p.stonn can only manage a visitor permit you already hold, and it never changes a resident permit or applies for a new one.",
		"",
		say(c, "mail.nudge_apply", nil),
		"Register with the council:",
		c.Links.Register,
		"",
		"This is the only reminder p.stonn sends. If you’ve decided it’s not for you, there’s nothing to undo. Your details go no further than the sign-up you made.",
	)
	return subject, strings.Join(lines, "\n")
}
