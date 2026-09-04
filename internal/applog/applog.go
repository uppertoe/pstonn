// Package applog is p.stonn's structured logging: a thin level + subsystem layer
// over log/slog. It exists so operational output can be filtered by SEVERITY
// (journalctl -p warning) and by SUBSYSTEM during an incident — the standard log
// package the app grew up on had neither. The methods are printf-style so the
// migration from log.Printf stays mechanical, and each logger tags its lines with
// a subsystem attribute instead of an ad-hoc "scheduler: " message prefix.
package applog

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

// Setup installs the process-wide slog logger. Lines go to stderr, which journald
// captures and stamps with its own receive time — so slog's timestamp is dropped
// to keep each line compact. level is the minimum severity emitted; everything the
// app logs today maps to Info/Warn/Error, so an Info threshold hides nothing that
// the standard logger used to show.
func Setup(level slog.Level) {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{} // journald provides the timestamp
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
}

// Logger is a subsystem-scoped, printf-style front end to the default slog logger.
// It resolves slog.Default() at log time, so a package-level For(...) initialised
// before Setup still logs through the configured handler.
type Logger struct{ subsystem string }

// For returns a logger that tags every line with subsystem=<name>.
func For(subsystem string) *Logger { return &Logger{subsystem: subsystem} }

func (l *Logger) log(level slog.Level, format string, args ...any) {
	slog.Default().LogAttrs(context.Background(), level, fmt.Sprintf(format, args...),
		slog.String("subsystem", l.subsystem))
}

// Infof / Warnf / Errorf / Debugf log a printf-formatted message at that level,
// tagged with the logger's subsystem.
func (l *Logger) Infof(format string, args ...any)  { l.log(slog.LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.log(slog.LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.log(slog.LevelError, format, args...) }
func (l *Logger) Debugf(format string, args ...any) { l.log(slog.LevelDebug, format, args...) }
