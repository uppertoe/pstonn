package server

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"os"
	"strings"
)

// defaultTermsMD is the built-in agreement, editable as markdown. Operators can
// override it live by mounting a file and setting TERMS_PATH.
//
//go:embed terms.md
var defaultTermsMD string

// Terms is a versioned agreement the user must accept before using the app (and
// again whenever it changes). Authored in markdown: a `version:` line, optional
// intro prose, and one `- ` list item per tickable clause. The Hash is a
// fingerprint of the exact source, recorded on acceptance for an audit trail;
// any edit changes it and re-prompts every user.
type Terms struct {
	Version string
	Intro   string
	Clauses []string
	hash    string
}

// Hash returns the fingerprint of the exact terms source.
func (t Terms) Hash() string { return t.hash }

// loadTerms reads the terms from TERMS_PATH if set, else the embedded default.
func loadTerms(path string) Terms {
	content := defaultTermsMD
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			content = string(b)
		}
	}
	return parseTerms(content)
}

// parseTerms extracts the version, intro and tickable clauses from the markdown.
// Clause text is used verbatim (rendered as escaped plain text, not HTML), keep
// clauses to plain sentences.
func parseTerms(content string) Terms {
	t := Terms{}
	var intro []string
	for _, raw := range strings.Split(content, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case l == "" || l == "---":
			// blank / front-matter delimiter
		case strings.HasPrefix(strings.ToLower(l), "version:"):
			t.Version = strings.TrimSpace(l[len("version:"):])
		case strings.HasPrefix(l, "- "), strings.HasPrefix(l, "* "):
			t.Clauses = append(t.Clauses, strings.TrimSpace(l[2:]))
		case strings.HasPrefix(l, "#"):
			// heading, the page supplies its own, so ignore
		default:
			intro = append(intro, l)
		}
	}
	t.Intro = strings.Join(intro, " ")
	sum := sha256.Sum256([]byte(content))
	t.hash = hex.EncodeToString(sum[:])
	return t
}
