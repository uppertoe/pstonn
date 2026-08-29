package server

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The decoupling guard: a council's name, portal host or phone number may appear
// only where a council is DESCRIBED — the registry — never in code, templates or
// catalogs, which must speak through the Council view. Without this the
// coupling creeps back one string at a time (docs/council-connections.md).
func TestNoCouncilLiteralsOutsideTheRegistry(t *testing.T) {
	root := filepath.Join("..", "..")
	literal := regexp.MustCompile(`(?i)stonnington|8290 1333`)
	allowed := map[string]bool{
		"internal/council/councils.json": true, // the registry: where a council is described
		"internal/council/council.go":    true, // the registry package: the named accessor and env-override mapping
		"internal/council/registry.go":   true,
		"internal/config/config.go":      true, // COUNCIL_* defaults: the single-council override path
		"internal/store/migrate.go":      true, // backfill of pre-multi-council rows, which were all this council's
		"internal/server/terms.md":       true, // terms copy: wording changes need approval (re-consent)
	}
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "testdata", "docs", "deploy", "scripts":
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(rel, "_test.go"), strings.HasSuffix(rel, ".md") && rel != "internal/server/terms.md":
			return nil
		case !(strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, ".html") || strings.HasSuffix(rel, ".json")):
			return nil
		}
		if allowed[rel] {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			// Comments may name the council (history, captures); output may not.
			if strings.HasPrefix(strings.TrimSpace(line), "//") || strings.HasPrefix(strings.TrimSpace(line), "{{/*") {
				continue
			}
			if literal.MatchString(line) {
				offenders = append(offenders, rel+":"+itoa(n)+": "+strings.TrimSpace(line))
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("council literals outside the registry (speak through .Council / the catalog instead):\n  %s", strings.Join(offenders, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Every message the templates and code ask for exists, and every message in the
// catalog is asked for by something: a typo cannot render as the raw key on a
// page, and dead entries cannot accumulate.
func TestCatalogKeysMatchUsage(t *testing.T) {
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	// {{T "key" .}} in templates; in Go and catalog nesting, any dotted string
	// literal that names a catalog key counts as a use.
	tmplRe := regexp.MustCompile(`\{\{-?\s*T\s+"([^"]+)"`)
	litRe := regexp.MustCompile(`\\?"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)\\?"`)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return err
		}
		if !(strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".json")) || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".go") {
			// Comments explain the mechanism with example keys; only code counts.
			var kept []string
			for _, line := range strings.Split(string(b), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(line), "//") {
					kept = append(kept, line)
				}
			}
			b = []byte(strings.Join(kept, "\n"))
		}
		for _, m := range tmplRe.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
		for _, m := range litRe.FindAllStringSubmatch(string(b), -1) {
			if catalog.For("en-AU").Has(m[1]) {
				used[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cat := catalog.For("en-AU")
	for k := range used {
		if !cat.Has(k) {
			t.Errorf("message %q is used but not in the en-AU catalog", k)
		}
	}
	for _, k := range cat.Keys() {
		if !used[k] {
			t.Errorf("catalog message %q is defined but nothing uses it", k)
		}
	}
	// Every locale defines every default-locale key (a partial translation
	// falls back silently otherwise, and a missing key would only show on the page).
	for _, loc := range catalog.Locales() {
		for _, k := range cat.Keys() {
			if !catalog.For(loc).Has(k) {
				t.Errorf("locale %s lacks %q", loc, k)
			}
		}
	}
}
