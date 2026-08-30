// Package i18n holds every sentence the app says to a person, keyed, in
// per-locale catalogs, resolved against a tenant's terminology. Two things vary
// that plain string literals cannot express: the reader's language, and what the
// tenant calls things — "visitor permit", "guest permit", "digital permit";
// "ePermits" or something else. A message is a small template over the data it is
// rendered with (which always carries the Tenant view), so wording, links and
// vocabulary are one lookup, and a second tenant or a second language is a
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
	"regexp"
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

// Slot is markup a template lends to a message: the message says WHERE a link
// or emphasis goes and what words it carries; the template says what it IS.
// A Slot receives the translator's words (already escaped) and returns the
// wrapped fragment.
type Slot func(inner htmltemplate.HTML) htmltemplate.HTML

// Slots is the set of slots a call site provides, by name.
type Slots map[string]Slot

// LinkOption is a typed attribute for Link. The set is closed on purpose: the
// anchor's attributes are emitted as raw HTML, so accepting free-form strings
// here would be an injection primitive waiting for the first caller to pass
// something user-derived. Add a new option when a new attribute is needed.
type LinkOption func(*linkAttrs)

type linkAttrs struct {
	newTab  bool
	noBoost bool
}

// NewTab opens the link in a new tab with the referrer/opener severed
// (target="_blank" rel="noopener noreferrer").
func NewTab() LinkOption { return func(a *linkAttrs) { a.newTab = true } }

// NoBoost opts the link out of htmx boosting (hx-boost="false"), for links
// that must be a full navigation.
func NoBoost() LinkOption { return func(a *linkAttrs) { a.noBoost = true } }

// Link is an anchor slot. href is attribute-escaped and must be an http(s) or
// site-relative URL — anything else (javascript:, data:, a scheme-relative
// host) renders as "#" so a bad value from configuration or a future caller
// can never become a script-bearing link.
func Link(href string, opts ...LinkOption) Slot {
	var a linkAttrs
	for _, o := range opts {
		o(&a)
	}
	open := `<a href="` + htmltemplate.HTMLEscapeString(safeHref(href)) + `"`
	if a.newTab {
		open += ` target="_blank" rel="noopener noreferrer"`
	}
	if a.noBoost {
		open += ` hx-boost="false"`
	}
	return func(inner htmltemplate.HTML) htmltemplate.HTML {
		return htmltemplate.HTML(open + ">" + string(inner) + "</a>")
	}
}

// safeHref admits absolute http(s) URLs and site-relative paths (a single
// leading slash, or a bare relative path/fragment/query); everything else is
// replaced with "#".
func safeHref(href string) string {
	h := strings.TrimSpace(href)
	lower := strings.ToLower(h)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"):
		return h
	case strings.HasPrefix(h, "//"):
		return "#" // scheme-relative: a different host in disguise
	case strings.HasPrefix(h, "/"), strings.HasPrefix(h, "#"), strings.HasPrefix(h, "?"):
		return h
	case h != "" && !strings.Contains(h, ":"):
		return h // bare relative path
	}
	return "#"
}

// Strong is an emphasis slot.
func Strong() Slot {
	return func(inner htmltemplate.HTML) htmltemplate.HTML { return "<strong>" + inner + "</strong>" }
}

// Markers: a message's {{slot "name"}}words{{endslot}} renders to private
// markers around the words (which are ordinary message text, so they may carry
// interpolations) that the catalog resolves against the call site's Slots AFTER
// template execution — slots need no place in the message's data, and a nested
// {{T}} passes them through to the top level.
const (
	slotOpen  = "\x00slot\x00"
	slotSep   = "\x00"
	slotClose = "\x00/slot\x00"
)

var slotRe = regexp.MustCompile(regexp.QuoteMeta(slotOpen) + `([^\x00]*)` + regexp.QuoteMeta(slotSep) + `((?:[^\x00])*?)` + regexp.QuoteMeta(slotClose))

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
	// Messages may include one another with {{T "key" .}} (slots resolve at the
	// top level), and mark a slot with {{slot "name"}}words{{endslot}}.
	htmlFuncs := htmltemplate.FuncMap{
		"T":       func(key string, data any) (htmltemplate.HTML, error) { return c.renderHTML(key, data) },
		"slot":    func(name string) htmltemplate.HTML { return htmltemplate.HTML(slotOpen + name + slotSep) },
		"endslot": func() htmltemplate.HTML { return slotClose },
	}
	textFuncs := texttemplate.FuncMap{
		"T":       func(key string, data any) (string, error) { return c.Text(key, data) },
		"slot":    func(name string) string { return "" }, // prose keeps its words, loses the markup
		"endslot": func() string { return "" },
	}
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

// HTML renders a message for an HTML page, filling its slots from the call
// site. A slot the message names but the caller did not supply is an error: the
// page must not quietly lose a link.
func (c *Catalog) HTML(key string, data any, slots Slots) (htmltemplate.HTML, error) {
	out, err := c.renderHTML(key, data)
	if err != nil {
		return "", err
	}
	var missing []string
	resolved := slotRe.ReplaceAllStringFunc(string(out), func(m string) string {
		sub := slotRe.FindStringSubmatch(m)
		name, inner := sub[1], htmltemplate.HTML(sub[2])
		slot, ok := slots[name]
		if !ok {
			missing = append(missing, name)
			return string(inner)
		}
		return string(slot(inner))
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("i18n: %s: no slot %v supplied by the call site", key, missing)
	}
	return htmltemplate.HTML(resolved), nil
}

// renderHTML executes a message, leaving slot markers for HTML to resolve.
func (c *Catalog) renderHTML(key string, data any) (htmltemplate.HTML, error) {
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

// Lint reports messages that carry markup or entities: those belong to the
// templates and to slots, so a translator only ever sees prose.
func (c *Catalog) Lint() []string {
	var out []string
	for _, k := range c.Keys() {
		v := c.raw[k]
		if strings.Contains(v, "<") || entityRe.MatchString(v) {
			out = append(out, k)
		}
	}
	return out
}

var entityRe = regexp.MustCompile(`&[a-zA-Z]+;|&#`)

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

// Terms returns the vocabulary for a tenant: the catalog's defaults with the
// tenant's own words laid over them.
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
