package server

import (
	"embed"
	"html/template"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

// staticFS holds vendored front-end assets (htmx, Alpine, the wordmark font) so
// the app makes zero external requests, self-contained and privacy-preserving.
//
//go:embed static/*
var staticFS embed.FS

// weekdaysDisplay is the roster order shown in the UI (Monday first).
var weekdaysDisplay = []time.Weekday{
	time.Monday, time.Tuesday, time.Wednesday, time.Thursday,
	time.Friday, time.Saturday, time.Sunday,
}

var templates = template.Must(template.New("").Funcs(template.FuncMap{
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
}).ParseFS(templateFS, "templates/*.html"))
