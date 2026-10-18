package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/inbound"
	"github.com/uppertoe/pstonn/internal/mailer"
	"github.com/uppertoe/pstonn/internal/notify"
	"github.com/uppertoe/pstonn/internal/store"
)

// The hello@ mailbox. SES receives the mail (a receipt rule saves the raw
// message to S3 and publishes it to the inbound SNS topic), the signed hook hands
// it here, and the operator reads and answers it on /admin/mail. Answers go out
// from MAILBOX_FROM as plain one-to-one letters, so the operator never answers
// from a personal address.

// sesReceived is the subset of an SES "Received" notification the mailbox uses.
type sesReceived struct {
	NotificationType string `json:"notificationType"`
	Mail             struct {
		MessageID     string `json:"messageId"` // also the S3 object's key under the rule's prefix
		Source        string `json:"source"`
		CommonHeaders struct {
			From    []string `json:"from"`
			Subject string   `json:"subject"`
		} `json:"commonHeaders"`
	} `json:"mail"`
	Receipt struct {
		Spam   sesVerdict `json:"spamVerdict"`
		Virus  sesVerdict `json:"virusVerdict"`
		SPF    sesVerdict `json:"spfVerdict"`
		DKIM   sesVerdict `json:"dkimVerdict"`
		DMARC  sesVerdict `json:"dmarcVerdict"`
		Action struct {
			Encoding string `json:"encoding"`
		} `json:"action"`
	} `json:"receipt"`
	Content string `json:"content"` // absent when the message was over SES's 150 KB limit
}

type sesVerdict struct {
	Status string `json:"status"`
}

// mailS3Prefix is the receipt rule's object key prefix, shown with the SES id
// so a message too large to show here can be fetched from the bucket.
const mailS3Prefix = "hello/"

// maxMailThreads bounds the threads /admin/mail lists; older ones age out at
// store.MailRetention.
const maxMailThreads = 60

// handleInboundMail stores one received message. It returns an error only for
// a storage failure worth a redelivery; a payload that will never parse is
// logged and acknowledged.
func (s *Server) handleInboundMail(ctx context.Context, raw string) error {
	var ev sesReceived
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		alog.Warnf("mailbox: unparseable SES notification: %v", err)
		return nil
	}
	if !strings.EqualFold(ev.NotificationType, "Received") || ev.Mail.MessageID == "" {
		alog.Infof("mailbox: ignoring SES notification %q", ev.NotificationType)
		return nil
	}
	rc := ev.Receipt
	verdict := "spam " + rc.Spam.Status + " · virus " + rc.Virus.Status + " · SPF " + rc.SPF.Status +
		" · DKIM " + rc.DKIM.Status + " · DMARC " + rc.DMARC.Status
	fail := func(v sesVerdict) bool { return strings.EqualFold(v.Status, "FAIL") }
	m := store.MailMessage{
		Inbound:      true,
		SESMessageID: ev.Mail.MessageID,
		Verdict:      verdict,
		Flagged:      fail(rc.Spam) || fail(rc.Virus) || fail(rc.DMARC),
		Subject:      ev.Mail.CommonHeaders.Subject,
	}
	if len(ev.Mail.CommonHeaders.From) > 0 {
		if a, err := mail.ParseAddress(ev.Mail.CommonHeaders.From[0]); err == nil {
			m.FromAddr, m.FromName = strings.ToLower(a.Address), a.Name
		}
	}
	if m.FromAddr == "" {
		m.FromAddr = strings.ToLower(ev.Mail.Source)
	}
	var inReplyTo string
	switch {
	case fail(rc.Virus):
		// Keep the row so the operator sees that something arrived, but not its content.
		m.Body = "SES found a virus in this message, so p.stonn has not kept its content."
	case ev.Content == "":
		m.Truncated = true
	default:
		content := []byte(ev.Content)
		if strings.EqualFold(rc.Action.Encoding, "BASE64") {
			dec, err := base64.StdEncoding.DecodeString(ev.Content)
			if err != nil {
				alog.Warnf("mailbox: undecodable content for SES message %s: %v", ev.Mail.MessageID, err)
				m.Truncated = true
				break
			}
			content = dec
		}
		p, err := inbound.Parse(content)
		if err != nil {
			alog.Warnf("mailbox: unparseable message %s: %v", ev.Mail.MessageID, err)
			m.Truncated = true
			break
		}
		if p.FromAddr != "" {
			m.FromAddr, m.FromName = p.FromAddr, p.FromName
		}
		if p.Subject != "" {
			m.Subject = p.Subject
		}
		m.ToAddr, m.Body, m.Truncated = p.To, p.Text, p.Truncated
		m.MessageID, m.References, inReplyTo = p.MessageID, p.References, p.InReplyTo
		if p.AutoSubmitted {
			m.Flagged = true
			m.Verdict += " · automatic reply"
		}
	}
	_, _, err := s.store.AddMail(ctx, m, inReplyTo)
	if errors.Is(err, store.ErrDuplicate) {
		return nil // an SNS redelivery of a message already stored
	}
	if err != nil {
		return err
	}
	alog.Infof("mailbox: received mail from %s (ses message id %s)", notify.RedactEmail(m.FromAddr), ev.Mail.MessageID)
	if !m.Flagged && s.notify != nil {
		if err := s.notify.NotifyMail(ctx, m.FromAddr, m.Subject, firstReply(m.Body)); err != nil {
			alog.Infof("mailbox: push: %v", err)
		}
	}
	return nil
}

func firstReply(body string) string {
	r, _ := inbound.SplitQuoted(body)
	return r
}

type mailboxView struct {
	Enabled bool
	Push    bool
	From    string // the address answers go out from
	Threads []mailThreadView
}

type mailThreadView struct {
	ID       int64
	Subject  string
	With     string // the other party's address
	Messages []mailRowView
	// ReplyTo is the latest inbound message's id, the one an answer replies to; 0
	// when the thread holds only what the operator sent.
	ReplyTo      int64
	ReplySubject string
	Waiting      bool // the latest message is inbound and unflagged
}

type mailRowView struct {
	Inbound   bool
	Who       string
	When      string
	Reply     string
	Quoted    string
	Verdict   string
	Flagged   bool
	Truncated bool
	S3Key     string
}

func (s *Server) adminMailPage(w http.ResponseWriter, r *http.Request) {
	u, ok := s.user(w, r)
	if !ok {
		return
	}
	loc := s.cfg.DisplayLocation
	v := &mailboxView{Enabled: s.cfg.MailboxEnabled(), From: s.cfg.MailboxFrom}
	if s.notify != nil {
		v.Push = s.notify.ContactPushConfigured()
	}
	threads, err := s.store.MailThreads(r.Context(), maxMailThreads)
	if err != nil {
		s.serverError(w, err)
		return
	}
	now := time.Now()
	for _, t := range threads {
		v.Threads = append(v.Threads, mailThread(t, now, loc))
	}
	data := dashboardData{State: "admin-mail", User: u, LogoutURL: s.logoutURL(), Loc: loc, Mailbox: v}
	switch r.URL.Query().Get("sent") {
	case "1":
		data.Flash = "Your message has been sent."
	}
	s.render(w, data)
}

func mailThread(t []store.MailMessage, now time.Time, loc *time.Location) mailThreadView {
	tv := mailThreadView{ID: t[0].ThreadID, Subject: t[0].Subject}
	if tv.Subject == "" {
		tv.Subject = "(no subject)"
	}
	for _, m := range t {
		row := mailRowView{Inbound: m.Inbound, When: m.At.In(loc).Format("Mon 2 Jan, 3:04 pm") + " (" + agoText(now, m.At) + ")",
			Verdict: m.Verdict, Flagged: m.Flagged, Truncated: m.Truncated}
		if m.Inbound {
			row.Who = m.FromAddr
			if m.FromName != "" {
				row.Who = m.FromName + " <" + m.FromAddr + ">"
			}
			row.Reply, row.Quoted = inbound.SplitQuoted(m.Body)
			if m.Truncated {
				row.S3Key = mailS3Prefix + m.SESMessageID
			}
			tv.With = m.FromAddr
			tv.ReplyTo, tv.ReplySubject = m.ID, replySubject(m.Subject)
		} else {
			row.Who = "To " + m.ToAddr
			row.Reply = m.Body
			if tv.With == "" {
				tv.With = m.ToAddr
			}
		}
		tv.Messages = append(tv.Messages, row)
	}
	last := t[len(t)-1]
	tv.Waiting = last.Inbound && !last.Flagged
	return tv
}

func replySubject(s string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "re:") {
		return s
	}
	return "Re: " + s
}

// maxMailBody caps what the operator can send in one message.
const maxMailBody = 20000

// adminMailSend sends a reply to a received message, or a new message, from
// MAILBOX_FROM, and records it in the thread.
func (s *Server) adminMailSend(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.MailboxEnabled() || s.mail == nil {
		s.formError(w, r, "The mailbox is not set up, so p.stonn cannot send this message.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.formError(w, r, "p.stonn could not read the form. Please try again.")
		return
	}
	ctx := r.Context()
	body := strings.TrimSpace(r.PostForm.Get("body"))
	subject := strings.TrimSpace(r.PostForm.Get("subject"))
	if body == "" {
		s.formError(w, r, "Write a message before sending.")
		return
	}
	if len(body) > maxMailBody {
		s.formError(w, r, "The message is too long to send from here.")
		return
	}
	p := mailer.Personal{From: s.cfg.MailboxFrom, Subject: subject, Body: body}
	out := store.MailMessage{Body: body}
	if id, _ := strconv.ParseInt(r.PostForm.Get("reply"), 10, 64); id > 0 {
		orig, err := s.store.MailByID(ctx, id)
		if err != nil || !orig.Inbound || orig.FromAddr == "" {
			s.formError(w, r, "p.stonn could not find the message you are replying to.")
			return
		}
		p.To = orig.FromAddr
		if p.Subject == "" {
			p.Subject = replySubject(orig.Subject)
		}
		if orig.MessageID != "" {
			p.InReplyTo = orig.MessageID
			p.References = append(append([]string{}, orig.References...), orig.MessageID)
		}
		out.ThreadID = orig.ThreadID
	} else {
		p.To = strings.TrimSpace(r.PostForm.Get("to"))
		if !looksLikeEmail(p.To) {
			s.formError(w, r, "Enter the email address to send to.")
			return
		}
		if p.Subject == "" {
			s.formError(w, r, "Give the message a subject.")
			return
		}
	}
	if sup, _, err := s.store.IsSuppressed(ctx, p.To); err == nil && sup {
		s.formError(w, r, "Mail to "+p.To+" has bounced or been reported, so p.stonn will not send to that address.")
		return
	}
	msgID, err := s.mail.SendPersonal(p)
	if err != nil {
		alog.Errorf("mailbox: send to %s: %v", notify.RedactEmail(p.To), err)
		s.formError(w, r, "The message could not be sent. Please try again in a moment.")
		return
	}
	out.ToAddr, out.Subject, out.MessageID, out.References = strings.ToLower(p.To), p.Subject, msgID, p.References
	out.FromAddr = strings.ToLower(envelopeOf(s.cfg.MailboxFrom))
	if _, _, err := s.store.AddMail(ctx, out, ""); err != nil {
		// Sent but not recorded: the page must not suggest it was never sent.
		alog.Errorf("mailbox: sent to %s but not recorded: %v", notify.RedactEmail(p.To), err)
	}
	alog.Infof("mailbox: sent mail to %s", notify.RedactEmail(p.To))
	http.Redirect(w, r, "/admin/mail?sent=1", http.StatusSeeOther)
}

func envelopeOf(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}
