package server

import (
	"context"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/uppertoe/pstonn/internal/store"
)

// householdNameMax bounds the visitor-facing name: a family name or a short
// phrase, never a paragraph.
const householdNameMax = 40

// householdOrEmpty reads the holder's chosen name, treating a read error as
// "none": the guest page still renders, naming only the permit.
func (s *Server) householdOrEmpty(ctx context.Context, owner string) string {
	name, err := s.store.HouseholdName(ctx, owner)
	if err != nil {
		return ""
	}
	return name
}

// validHouseholdName accepts a short line of printable text. Angle brackets and
// control characters are refused rather than escaped: the name is rendered in
// HTML and in email subjects, and a name that needs escaping is not a name.
func validHouseholdName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > householdNameMax {
		return false
	}
	for _, r := range name {
		if r == '<' || r == '>' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// possessive turns a household name into its possessive: "the Nguyens" becomes
// "the Nguyens'", "Nana" becomes "Nana's".
func possessive(name string) string {
	if strings.HasSuffix(strings.ToLower(name), "s") {
		return name + "\u2019"
	}
	return name + "\u2019s"
}

// sentenceCase upper-cases the first letter, so a name entered as "the Nguyens"
// still opens a heading properly.
func sentenceCase(s string) string {
	for i, r := range s {
		return string(unicode.ToUpper(r)) + s[i+utf8.RuneLen(r):]
	}
	return s
}

// maskRego hides all but the last two characters of a rego: "SBX1AB" reads
// "\u2022\u2022\u2022\u2022AB". Regos shorter than four characters mask entirely.
func maskRego(reg string) string {
	n := utf8.RuneCountInString(reg)
	if n < 4 {
		return strings.Repeat("\u2022", n)
	}
	rs := []rune(reg)
	return strings.Repeat("\u2022", n-2) + string(rs[n-2:])
}

// setHouseholdName saves the visitor-facing name from Settings; blank clears it.
func (s *Server) setHouseholdName(w http.ResponseWriter, r *http.Request) {
	user, owner, isPrimary, ok := s.accountForWrite(w, r)
	if !ok {
		return
	}
	if !isPrimary {
		s.message(w, http.StatusForbidden, "Only the account owner can name the household.")
		return
	}
	name := strings.Join(strings.Fields(r.FormValue("household_name")), " ")
	if name != "" && !validHouseholdName(name) {
		s.formError(w, r, "Keep the household name to a short line of plain text, up to 40 characters.")
		return
	}
	if err := s.store.SetHouseholdName(r.Context(), owner, name); err != nil {
		s.serverError(w, err)
		return
	}
	s.logChange(r.Context(), owner, user, store.ActionHouseholdName, name, "")
	http.Redirect(w, r, "/settings?named=1", http.StatusSeeOther)
}
