// Package redact reduces personal data to a form safe to leave in a log.
//
// Logs are the leakiest surface the app has: unlike the sealed tenant session
// in the database, they are plaintext, read on-call, pasted into bug reports,
// and retained by journald for weeks. So an email is reduced to its first
// character and (lower-cased) domain here before it reaches any log line. That
// still lets an operator correlate events for one account within an incident,
// while keeping the plaintext address — the most identifying field — out of the
// logs. The full address is one lookup away in the database when genuinely
// needed. Plates are deliberately NOT redacted: they are the safety-critical
// fact for diagnosing a wrong-plate change (the failure that causes a fine), and
// a plate alongside the tenant's internal permit id is far less identifying
// than an email.
package redact

import "strings"

// Email reduces an address to something safe to log: the provider is what an
// operator debugging a delivery problem needs, and the first character of the
// mailbox is enough to tell two accounts apart without spelling either out.
func Email(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return "(none)"
	}
	at := strings.LastIndex(a, "@")
	if at <= 0 {
		return "***" // not an address shape; say nothing about it
	}
	local := []rune(a[:at])
	return string(local[:1]) + "***" + strings.ToLower(a[at:])
}

// InText replaces every occurrence of the given addresses inside free text with
// their redacted form. It exists for error strings we did not compose: an SMTP
// server's rejection routinely echoes the recipient ("550 5.1.1 <a@b.com>: user
// unknown"), and that text is stored in outbox.last_error, repeated in the
// dead-letter log line and mailed to the operator — three copies that all
// outlive the notification. Matching is case-insensitive because servers
// re-case addresses freely. An empty address is skipped rather than matched
// everywhere.
func InText(text string, addrs ...string) string {
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		text = replaceFold(text, a, Email(a))
	}
	return text
}

// replaceFold is strings.ReplaceAll under ASCII case folding. ASCII only, on
// purpose: Unicode lower-casing can change byte length, which would put the
// indexes computed on the folded copy out of step with the original.
func replaceFold(s, old, new string) string {
	if old == "" {
		return s
	}
	lower, oldLower := asciiLower(s), asciiLower(old)
	if !strings.Contains(lower, oldLower) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(lower, oldLower)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(new)
		s, lower = s[i+len(old):], lower[i+len(oldLower):]
	}
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Emails is Email over a list, joined for a single log field.
func Emails(list []string) string {
	if len(list) == 0 {
		return "(none)"
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, Email(a))
	}
	return strings.Join(out, ", ")
}
