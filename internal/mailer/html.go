package mailer

import (
	"encoding/base64"
	"html"
	"html/template"
	"regexp"
	"strings"
)

// This file wraps the app's plain-text emails in a small, brand-consistent HTML
// layout (sent as the text/html alternative alongside the plain text). It is
// deliberately email-safe: table layout, inline styles, a system font stack, no
// remote assets — the palette mirrors the app (teal primary, slate neutrals).

const (
	colBg       = "#eceff5"
	colCard     = "#ffffff"
	colLine     = "#e4e8f0"
	colInk      = "#0f1729"
	colMuted    = "#5b6675"
	colPrimary  = "#0d9488"
	colOnPrim   = "#ffffff"
	colChipTint = "#f4f6fa" // neutral plate-chip fill when the car has no colour
)

const emailFont = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"

// plateFont matches the monospace stack the site uses for its plate chips.
const plateFont = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"

var (
	// A whole-block URL becomes a button; inline URLs are linkified in place.
	standaloneURL = regexp.MustCompile(`^https?://\S+$`)
	inlineURL     = regexp.MustCompile(`https?://[^\s<>()]+`)
	blankLine     = regexp.MustCompile(`\n[ \t]*\n`)
	// A block that is only dashes is a section separator (rendered as an <hr>).
	ruleLine = regexp.MustCompile(`^-{3,}$`)
	hexColor = regexp.MustCompile(`^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	// A trailing "-- p.stonn" signature: the footer replaces it in HTML.
	signature = regexp.MustCompile(`(?s)\n*--\s*p\.stonn\s*$`)
)

// htmlDocument renders the branded HTML alternative for a plain-text email body.
func htmlDocument(subject, body, footer, provenance, unsubURL string, hero Hero) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>` + html.EscapeString(subject) + `</title></head>`)
	b.WriteString(`<body style="margin:0;padding:0;background:` + colBg + `;">`)
	b.WriteString(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:` + colBg + `;"><tr><td align="center" style="padding:24px 12px;">`)
	b.WriteString(`<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;">`)
	// Card
	b.WriteString(`<tr><td style="background:` + colCard + `;border:1px solid ` + colLine + `;border-radius:14px;padding:28px 30px;font-family:` + emailFont + `;">`)
	b.WriteString(`<div style="font-size:21px;font-weight:700;letter-spacing:-0.02em;color:` + colInk + `;">p<span style="color:` + colPrimary + `;">.</span>stonn</div>`)
	b.WriteString(`<div style="height:3px;width:46px;background:` + colPrimary + `;border-radius:2px;margin:14px 0 22px;"></div>`)
	if hero.Plate != "" {
		b.WriteString(plateChip(hero))
	}
	b.WriteString(bodyToHTML(body))
	b.WriteString(`</td></tr>`)
	// Footer: provenance (why you got this), the affiliation line, and a plain
	// Unsubscribe link — rendered once here, well-spaced and muted, rather than
	// dumped into the message body.
	b.WriteString(`<tr><td style="padding:20px 30px 4px;text-align:center;font-family:` + emailFont + `;font-size:12px;line-height:1.6;color:` + colMuted + `;">`)
	if provenance != "" {
		b.WriteString(`<div style="margin-bottom:12px;">` + template.HTMLEscapeString(provenance) + `</div>`)
	}
	b.WriteString(`<div>p<span style="color:` + colPrimary + `;">.</span>stonn — a free, unofficial tool.`)
	if footer != "" {
		b.WriteString(` ` + template.HTMLEscapeString(footer))
	}
	b.WriteString(`</div>`)
	if unsubURL != "" {
		b.WriteString(`<div style="margin-top:12px;"><a href="` + html.EscapeString(unsubURL) + `" style="color:` + colMuted + `;text-decoration:underline;">Unsubscribe</a></div>`)
	}
	b.WriteString(`</td></tr>`)
	b.WriteString(`</table></td></tr></table></body></html>`)
	return b.String()
}

// bodyToHTML turns the plain body into paragraphs. A URL sitting on its own line
// (whether its own blank-separated block, or the last line of a block after a
// "do this:" label) becomes a button; other URLs are linkified inline.
func bodyToHTML(body string) string {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = signature.ReplaceAllString(body, "")

	var out strings.Builder
	for _, blk := range blankLine.Split(strings.TrimSpace(body), -1) {
		blk = strings.TrimSpace(blk)
		if blk == "" {
			continue
		}
		if ruleLine.MatchString(blk) {
			out.WriteString(`<hr style="border:0;border-top:1px solid ` + colLine + `;margin:6px 0 20px;">`)
			continue
		}
		lines := strings.Split(blk, "\n")
		last := strings.TrimSpace(lines[len(lines)-1])
		if !standaloneURL.MatchString(last) {
			out.WriteString(paragraph(blk)) // ordinary paragraph (inline links)
			continue
		}
		// The block ends with a URL line: render any preceding lines as text and the
		// URL as a button, labelled by a trailing "do this:" line when there is one.
		lead := strings.TrimSpace(strings.Join(lines[:len(lines)-1], "\n"))
		label := "Open link"
		if strings.Contains(last, "stonn.org") {
			label = "Open p.stonn"
		}
		if strings.HasSuffix(lead, ":") {
			// Use the label line as the button text; keep anything above it as a paragraph.
			leadLines := strings.Split(lead, "\n")
			label = strings.TrimRight(strings.TrimSpace(leadLines[len(leadLines)-1]), ":")
			lead = strings.TrimSpace(strings.Join(leadLines[:len(leadLines)-1], "\n"))
		}
		if lead != "" {
			out.WriteString(paragraph(lead))
		}
		out.WriteString(button(last, label))
	}
	return out.String()
}

func paragraph(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = linkify(ln)
	}
	return `<p style="margin:0 0 14px;font-size:15px;line-height:1.6;color:` + colInk + `;">` +
		strings.Join(lines, "<br>") + `</p>`
}

// linkify HTML-escapes a line and turns any bare URLs in it into links.
func linkify(line string) string {
	var b strings.Builder
	last := 0
	for _, loc := range inlineURL.FindAllStringIndex(line, -1) {
		b.WriteString(html.EscapeString(line[last:loc[0]]))
		u := line[loc[0]:loc[1]]
		b.WriteString(`<a href="` + html.EscapeString(u) + `" style="color:` + colPrimary + `;text-decoration:underline;word-break:break-all;">` + html.EscapeString(u) + `</a>`)
		last = loc[1]
	}
	b.WriteString(html.EscapeString(line[last:]))
	return b.String()
}

func button(url, label string) string {
	return `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 18px;"><tr>` +
		`<td style="border-radius:9px;background:` + colPrimary + `;">` +
		`<a href="` + html.EscapeString(url) + `" style="display:inline-block;padding:12px 22px;color:` + colOnPrim + `;font-size:15px;font-weight:600;text-decoration:none;border-radius:9px;">` +
		html.EscapeString(label) + `</a></td></tr></table>`
}

// plateChip renders the car's registration as a centred plate chip that mirrors
// the plates on the site: monospace, upper-case, letter-spaced, with a coloured
// border and a light tint of the same colour. Email-safe — a table for centring,
// all styles inline, no color-mix (the tint is computed here).
func plateChip(h Hero) string {
	border := colLine
	fill := colChipTint
	if hex := normHex(h.Color); hex != "" {
		border = hex
		fill = tintColor(hex)
	}
	plate := strings.ToUpper(strings.TrimSpace(h.Plate))
	return `<table role="presentation" align="center" cellpadding="0" cellspacing="0" style="margin:2px auto 22px;"><tr>` +
		`<td style="border:2px solid ` + border + `;background:` + fill + `;border-radius:10px;` +
		`padding:13px 24px;font-family:` + plateFont + `;font-size:26px;font-weight:700;` +
		`letter-spacing:4px;text-transform:uppercase;color:` + colInk + `;white-space:nowrap;">` +
		html.EscapeString(plate) + `</td></tr></table>`
}

// normHex returns a canonical "#rrggbb" for a 3- or 6-digit hex colour, or ""
// if s is not one (so the chip falls back to the neutral palette).
func normHex(s string) string {
	s = strings.TrimSpace(s)
	m := hexColor.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	h := strings.ToLower(m[1])
	if len(h) == 3 { // expand shorthand: abc -> aabbcc
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	return "#" + h
}

// tintColor mixes a canonical "#rrggbb" colour ~12% into white, matching the
// pale plate fill the site produces with color-mix (unavailable in email).
func tintColor(hex string) string {
	if len(hex) != 7 {
		return colChipTint
	}
	const a = 0.12
	ch := func(i int) int {
		var v int
		for _, c := range hex[i : i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= int(c - '0')
			case c >= 'a' && c <= 'f':
				v |= int(c-'a') + 10
			}
		}
		return int(float64(v)*a + 255*(1-a) + 0.5)
	}
	r, g, bl := ch(1), ch(3), ch(5)
	const digits = "0123456789abcdef"
	buf := []byte{'#', 0, 0, 0, 0, 0, 0}
	for j, v := range []int{r, g, bl} {
		buf[1+j*2] = digits[(v>>4)&0xf]
		buf[2+j*2] = digits[v&0xf]
	}
	return string(buf)
}

// b64Wrap base64-encodes a body and hard-wraps it at 76 columns, so a MIME part
// with long lines (inline-styled HTML) can't trip the SMTP 1000-char line limit.
func b64Wrap(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	var out strings.Builder
	for len(enc) > 76 {
		out.WriteString(enc[:76])
		out.WriteString("\r\n")
		enc = enc[76:]
	}
	out.WriteString(enc)
	return out.String()
}
