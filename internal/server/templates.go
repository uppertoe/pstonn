package server

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"time"
)

// One file per feature: layout.html holds the "dashboard" skeleton and
// dispatches on .State to a page-* template (and, inside the signed-in app,
// on .Page); htmx fragments live next to the page that swaps them.
//
//go:embed templates/*.html
var templateFS embed.FS

// staticFS holds vendored front-end assets (htmx, Alpine, the wordmark font) so
// the app makes zero external requests, self-contained and privacy-preserving.
//
//go:embed static/*
var staticFS embed.FS

// staticVersion fingerprints the embedded static files. It is appended to static
// URLs as ?v=… so the aggressive immutable cache is busted exactly when a file's
// content changes across a release (and never otherwise). Identical across
// replicas because it is derived from content, not build time.
var staticVersion = computeStaticVersion()

func computeStaticVersion() string {
	h := sha256.New()
	_ = fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, e := staticFS.ReadFile(p)
		if e != nil {
			return e
		}
		h.Write([]byte(p))
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:10]
}

// asset builds a cache-busted URL for a vendored static file.
func asset(path string) string { return "/static/" + path + "?v=" + staticVersion }

// weekdaysDisplay is the roster order shown in the UI (Sunday first), matching
// the fortnight calendar's weekday columns so the same day lines up in both.
var weekdaysDisplay = []time.Weekday{
	time.Sunday, time.Monday, time.Tuesday, time.Wednesday,
	time.Thursday, time.Friday, time.Saturday,
}

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"asset":       asset,
	"weekdayName": func(w time.Weekday) string { return w.String() },
	"localTime": func(t time.Time, loc *time.Location) string {
		if t.IsZero() {
			return ""
		}
		// Australian style: day-first, 12-hour with lowercase am/pm.
		return t.In(loc).Format("Mon 2 Jan, 3:04pm")
	},
	"datetimeLocal": func(t time.Time, loc *time.Location) string {
		return t.In(loc).Format("2006-01-02T15:04")
	},
	// hours lists 0..23 for the quiet-hours hour selects.
	"hours": func() []int {
		h := make([]int, 24)
		for i := range h {
			h[i] = i
		}
		return h
	},
	// hourLabel formats an hour-of-day like "6:00 am" / "10:00 pm".
	"hourLabel": func(h int) string {
		suffix, hr := "am", h
		if h >= 12 {
			suffix = "pm"
		}
		if hr == 0 {
			hr = 12
		} else if hr > 12 {
			hr -= 12
		}
		return fmt.Sprintf("%d:00 %s", hr, suffix)
	},
}).ParseFS(templateFS, "templates/*.html"))
