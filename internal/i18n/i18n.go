// Package i18n holds every sentence the app says to a person, keyed, in
// per-locale catalogs, resolved against a council's terminology. Two things vary
// that plain string literals cannot express: the reader's language, and what the
// council calls things — "visitor permit", "guest permit", "digital permit";
// "ePermits" or something else. A message is a small template over the data it is
// rendered with (which always carries the Council view), so wording, links and
// vocabulary are one lookup, and a second council or a second language is a
// catalog entry rather than another sweep of the code.
//
// Catalogs are embedded JSON (catalog/<locale>.json): a "terms" table of default
// vocabulary and a "messages" table of keyed templates. HTML messages are parsed
// with html/template (interpolated data is escaped in context; the message text
// itself is trusted, it is ours); text messages (email bodies) with text/template.
package i18n

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	"sort"
	"strings"
	"sync"
	texttemplate "text/template"
)

//go:embed catalog/*.json
var catalogFS embed.FS

// DefaultLocale is the catalog every other locale falls back to.
const DefaultLocale = "en-AU"

type catalogFile struct {
	Locale   string            `json:"locale"`
	Terms    map[string]string `json:"terms"`
	Messages map[string]string `json:"messages"`
}

// Catalog is one locale's messages and default terminology.
type Catalog struct {
	Locale string
	terms  map[string]string
	raw    map[string]string
	html   map[string]*htmltemplate.Template
	text   map[string]*texttemplate.Template
}

// Bundles is every loaded locale, with fallback to the default.
type Bundles struct {
	by map[string]*Catalog
}

// Load parses every embedded catalog. A message that does not parse is a load
// error, so a broken catalog fails at boot, not on the page that uses it.
func Load() (*Bundles, error) {
	b := &Bundles{by: map[string]*Catalog{}}
	entries, err := fs.ReadDir(catalogFS, "catalog")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		raw, err := catalogFS.ReadFile("catalog/" + e.Name())
		if err != nil {
			return nil, err
		}
		c, err := parse(raw)
		if err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", e.Name(), err)
		}
		b.by[c.Locale] = c
	}
	if _, ok := b.by[DefaultLocale]; !ok {
		return nil, fmt.Errorf("i18n: no %s catalog", DefaultLocale)
	}
	return b, nil
}

// Default is the process-wide catalogs, loaded once.
func Default() *Bundles {
	defaultOnce.Do(func() { defaultBundles = MustLoad() })
	return defaultBundles
}

var (
	defaultOnce    sync.Once
	defaultBundles *Bundles
)

// MustLoad is Load for package-level initialisation.
func MustLoad() *Bundles {
	b, err := Load()
	if err != nil {
		panic(err)
	}
	return b
}

func parse(raw []byte) (*Catalog, error) {
	var f catalogFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if f.Locale == "" {
		return nil, fmt.Errorf("catalog has no locale")
	}
	c := &Catalog{Locale: f.Locale, terms: f.Terms, raw: f.Messages,
		html: map[string]*htmltemplate.Template{}, text: map[string]*texttemplate.Template{}}
	if c.terms == nil {
		c.terms = map[string]string{}
	}
	// Messages may include one another with {{T "key" .}}.
	htmlFuncs := htmltemplate.FuncMap{"T": func(key string, data any) (htmltemplate.HTML, error) { return c.HTML(key, data) }}
	textFuncs := texttemplate.FuncMap{"T": func(key string, data any) (string, error) { return c.Text(key, data) }}
	for k, v := range f.Messages {
		ht, err := htmltemplate.New(k).Funcs(htmlFuncs).Parse(v)
		if err != nil {
			return nil, fmt.Errorf("message %q: %w", k, err)
		}
		c.html[k] = ht
		tt, err := texttemplate.New(k).Funcs(textFuncs).Parse(v)
		if err != nil {
			return nil, fmt.Errorf("message %q (text): %w", k, err)
		}
		c.text[k] = tt
	}
	return c, nil
}

// For returns the catalog for a locale, falling back to the default.
func (b *Bundles) For(locale string) *Catalog {
	if c, ok := b.by[locale]; ok {
		return c
	}
	return b.by[DefaultLocale]
}

// Locales lists the loaded locales, sorted.
func (b *Bundles) Locales() []string {
	var out []string
	for l := range b.by {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// HTML renders a message for an HTML page.
func (c *Catalog) HTML(key string, data any) (htmltemplate.HTML, error) {
	t, ok := c.html[key]
	if !ok {
		return "", fmt.Errorf("i18n: no message %q in %s", key, c.Locale)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("i18n: %s: %w", key, err)
	}
	return htmltemplate.HTML(buf.String()), nil
}

// Text renders a message as plain text (email bodies, notifications).
func (c *Catalog) Text(key string, data any) (string, error) {
	t, ok := c.text[key]
	if !ok {
		return "", fmt.Errorf("i18n: no message %q in %s", key, c.Locale)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("i18n: %s: %w", key, err)
	}
	return buf.String(), nil
}

// Has reports whether the catalog defines key.
func (c *Catalog) Has(key string) bool { _, ok := c.raw[key]; return ok }

// Keys lists the catalog's message keys, sorted.
func (c *Catalog) Keys() []string {
	var out []string
	for k := range c.raw {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Terms returns the vocabulary for a council: the catalog's defaults with the
// council's own words laid over them.
func (c *Catalog) Terms(overrides map[string]string) map[string]string {
	out := make(map[string]string, len(c.terms)+len(overrides))
	for k, v := range c.terms {
		out[k] = v
	}
	for k, v := range overrides {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	return out
}
