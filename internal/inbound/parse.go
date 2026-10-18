// Package inbound turns a raw email received through SES into the few fields the
// operator's mail page shows: who wrote, the subject, the threading headers and
// a plain-text body. It is deliberately small: a reply to one of our notes is a
// person typing a few lines, so the parser prefers the text/plain part, falls
// back to a crude rendering of text/html, and never keeps attachments.
//
// Everything here is untrusted input from the open internet. Nothing is
// rendered as HTML (the page escapes the text), nothing is followed, and the
// body is capped so a large message cannot become a large database row.
package inbound

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxBody caps the stored body. A reply to a note is a few hundred bytes; the
// quoted original below it is most of the rest.
const MaxBody = 32 << 10

// maxDepth bounds multipart nesting, which a hostile message can make deep.
const maxDepth = 6

// Message is the parsed form of one received email.
type Message struct {
	FromAddr   string
	FromName   string
	To         string
	Subject    string
	MessageID  string   // the Message-ID header, angle brackets kept
	InReplyTo  string   // the In-Reply-To header, angle brackets kept
	References []string // the References header, each id with its angle brackets
	Text       string
	Truncated  bool // the body was cut at MaxBody
	// AutoSubmitted is true for an automatic message (a vacation reply, a
	// delivery report). Replying to one starts a mail loop.
	AutoSubmitted bool
}

// Parse reads a raw RFC 5322 message.
func Parse(raw []byte) (*Message, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	h := msg.Header
	m := &Message{
		Subject:   decodeHeader(h.Get("Subject")),
		MessageID: strings.TrimSpace(h.Get("Message-Id")),
		InReplyTo: firstID(h.Get("In-Reply-To")),
		To:        decodeHeader(h.Get("To")),
	}
	m.References = idList(h.Get("References"))
	if a, err := addrParser.Parse(h.Get("From")); err == nil {
		m.FromAddr, m.FromName = strings.ToLower(a.Address), a.Name
	}
	auto := strings.ToLower(strings.TrimSpace(h.Get("Auto-Submitted")))
	m.AutoSubmitted = (auto != "" && auto != "no") ||
		h.Get("X-Autoreply") != "" || h.Get("X-Autorespond") != "" ||
		strings.EqualFold(h.Get("Precedence"), "auto_reply")
	plain, htm := walk(h, msg.Body, 0)
	text := plain
	if strings.TrimSpace(text) == "" && htm != "" {
		text = htmlToText(htm)
	}
	m.Text, m.Truncated = clip(normalise(text), MaxBody)
	return m, nil
}

var addrParser = mail.AddressParser{WordDecoder: wordDecoder}

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

// header is the subset of a header map that walk needs, so nested parts (which
// mime/multipart hands back as textproto.MIMEHeader) and the top level
// (mail.Header) share one code path.
type header interface{ Get(string) string }

// walk returns the first text/plain and first text/html content in the part
// tree, decoded to UTF-8. Attachments and other types are skipped.
func walk(h header, body io.Reader, depth int) (plain, htm string) {
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	media, params, err := mime.ParseMediaType(ct)
	if err != nil {
		media = "text/plain"
	}
	if strings.HasPrefix(media, "multipart/") {
		if depth >= maxDepth || params["boundary"] == "" {
			return "", ""
		}
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				break
			}
			pl, ht := walk(p.Header, p, depth+1)
			if plain == "" {
				plain = pl
			}
			if htm == "" {
				htm = ht
			}
			if plain != "" && htm != "" {
				break
			}
		}
		return plain, htm
	}
	if disp, _, _ := mime.ParseMediaType(h.Get("Content-Disposition")); disp == "attachment" {
		return "", ""
	}
	if media != "text/plain" && media != "text/html" {
		return "", ""
	}
	data, err := io.ReadAll(io.LimitReader(decodeTransfer(h.Get("Content-Transfer-Encoding"), body), 4*MaxBody))
	if err != nil && len(data) == 0 {
		return "", ""
	}
	s := toUTF8(data, params["charset"])
	if media == "text/html" {
		return "", s
	}
	return s, ""
}

func decodeTransfer(enc string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, &stripSpace{r: r})
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}

// stripSpace drops the line breaks inside a base64 body, which the standard
// decoder does not tolerate on its own.
type stripSpace struct{ r io.Reader }

func (s *stripSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for _, c := range p[:n] {
		if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			p[j] = c
			j++
		}
	}
	if j == 0 && n > 0 && err == nil {
		return s.Read(p)
	}
	return j, err
}

// toUTF8 decodes the charsets a reply realistically arrives in. Anything else
// is treated as UTF-8 with invalid sequences replaced, which keeps every ASCII
// character intact.
func toUTF8(b []byte, charset string) string {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "iso-8859-1", "latin1", "iso-8859-15", "windows-1252", "cp1252":
		var sb strings.Builder
		for _, c := range b {
			sb.WriteRune(rune(c))
		}
		return sb.String()
	}
	return strings.ToValidUTF8(string(b), "�")
}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	b, err := io.ReadAll(io.LimitReader(input, 4096))
	if err != nil {
		return nil, err
	}
	return strings.NewReader(toUTF8(b, charset)), nil
}

func decodeHeader(s string) string {
	d, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		d = s
	}
	return strings.TrimSpace(strings.ToValidUTF8(d, "�"))
}

var idRe = regexp.MustCompile(`<[^<>\s]+>`)

func idList(s string) []string {
	ids := idRe.FindAllString(s, 50)
	return ids
}

func firstID(s string) string {
	if ids := idList(s); len(ids) > 0 {
		return ids[0]
	}
	return ""
}

var (
	reBlock = regexp.MustCompile(`(?is)<(script|style|head)\b.*?</(script|style|head)>`)
	reBreak = regexp.MustCompile(`(?i)<br\s*/?>|</(p|div|li|tr|h[1-6]|blockquote)>`)
	reTag   = regexp.MustCompile(`(?s)<[^>]*>`)
)

// htmlToText is a crude rendering for the message that has no plain part: drop
// scripts and styles, turn block ends into line breaks, drop the tags.
func htmlToText(s string) string {
	s = reBlock.ReplaceAllString(s, "")
	s = reBreak.ReplaceAllString(s, "\n")
	s = reTag.ReplaceAllString(s, "")
	return html.UnescapeString(s)
}

var reBlankRun = regexp.MustCompile(`\n{3,}`)

func normalise(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t ")
	}
	s = strings.Join(lines, "\n")
	return strings.TrimSpace(reBlankRun.ReplaceAllString(s, "\n\n"))
}

func clip(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

var reAttribution = regexp.MustCompile(`(?m)^(On .{6,200}wrote:|-{2,} ?Original Message ?-{2,}|From: .+)$`)

// SplitQuoted separates a reply from the original it quotes, so the page can
// show what the person wrote and fold the rest. It cuts at the first
// attribution line ("On 18 Oct 2026, at 9:17 am, p.stonn wrote:") or the first
// run of "> " lines, whichever comes first. A message with neither is all reply.
func SplitQuoted(text string) (reply, quoted string) {
	cut := -1
	if loc := reAttribution.FindStringIndex(text); loc != nil {
		cut = loc[0]
	}
	if i := strings.Index("\n"+text, "\n>"); i >= 0 && (cut < 0 || i < cut) {
		cut = i
	}
	if cut <= 0 {
		return text, ""
	}
	return strings.TrimSpace(text[:cut]), strings.TrimSpace(text[cut:])
}
