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
