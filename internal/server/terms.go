package server

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/uppertoe/pstonn/internal/identity"
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

// consentStatus reports whether the user has accepted the CURRENT terms, and
// whether they had accepted an earlier version (so the UI can say "terms
// changed" rather than "welcome").
func (s *Server) consentStatus(ctx context.Context, owner string) (accepted bool, hadPrevious bool) {
	c, err := s.store.LatestConsent(ctx, owner)
	if err != nil {
		return false, false // never accepted
	}
	if c.Hash == s.terms.Hash() {
		return true, false
	}
	return false, true // accepted an older version; terms have changed
}

// acceptTerms records the user's acceptance of the current terms (all clauses
// must be ticked) and returns them to the app.
func (s *Server) acceptTerms(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromContext(r.Context())
	for i := range s.terms.Clauses {
		if r.FormValue(fmt.Sprintf("agree%d", i)) == "" {
			s.formError(w, r, "Please tick every box to continue.")
			return
		}
	}
	if err := s.store.RecordConsent(r.Context(), u.Email, s.terms.Version, s.terms.Hash()); err != nil {
		s.serverError(w, err)
		return
	}
	redirectHome(w, r)
}

// declineTerms handles a user declining updated terms. A primary has their
// council account disconnected (so the app stops acting without consent) and is
// notified. A secondary simply leaves the shared account (they never held the
// council connection), leaving the primary's account untouched.
func (s *Server) declineTerms(w http.ResponseWriter, r *http.Request) {
	user, _, isPrimary := s.resolveAccount(r.Context())
	ctx := r.Context()

	if !isPrimary {
		if err := s.store.RemoveMembership(ctx, user); err != nil {
			s.serverError(w, err)
			return
		}
		log.Printf("secondary %s declined updated terms, left the shared account", user)
		msg := "You declined the updated terms, so your shared access has been removed. The account owner's data is unaffected."
		if s.logoutURL() != "" {
			s.messageWithLink(w, http.StatusOK, msg, "Sign out", s.logoutURL(), ".")
			return
		}
		s.message(w, http.StatusOK, msg)
		return
	}

	_, err := s.store.GetCouncilSession(ctx, user)
	wasLinked := err == nil
	if derr := s.store.DeleteCouncilSession(ctx, user); derr != nil {
		s.serverError(w, derr)
		return
	}
	if wasLinked {
		log.Printf("user %s declined updated terms, council account disconnected", user)
		go func() {
			nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if e := s.notify.NotifyDisconnected(nctx, user); e != nil {
				log.Printf("notify disconnect %s: %v", user, e)
			}
		}()
	}
	// Only claim a disconnection if there was one. A first-time visitor who reads
	// the terms and declines never linked anything, and telling them their permit
	// is no longer managed is alarming and false.
	msg := "You declined the terms, so p.stonn hasn't set anything up and isn't managing any permit for you. Nothing was connected, and nothing has changed with the council."
	after := ". You can come back and accept any time."
	if wasLinked {
		msg = "You declined the updated terms, so your council account has been disconnected and p.stonn is no longer managing your permit. Please check your visitor permit with the council."
		after = ", or accept the terms below to reconnect."
	}
	if s.logoutURL() != "" {
		s.messageWithLink(w, http.StatusOK, msg, "Sign out", s.logoutURL(), after)
		return
	}
	s.message(w, http.StatusOK, msg)
}
