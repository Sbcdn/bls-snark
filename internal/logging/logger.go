// Package logging provides the project-wide zerolog instance. Logs go to
// stderr; the per-command JSON results go to stdout (handled in cli).
package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// New returns a zerolog.Logger writing human-readable output to stderr.
// Level is controlled by the BLS_SNARK_LOG env var (debug|info|warn|error).
// Default level is info.
func New() zerolog.Logger {
	level := zerolog.InfoLevel
	switch os.Getenv("BLS_SNARK_LOG") {
	case "debug":
		level = zerolog.DebugLevel
	case "warn":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	}
	// Time format is governed by ConsoleWriter.TimeFormat below; we avoid
	// mutating the zerolog.TimeFieldFormat package global as a side effect.
	w := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	return zerolog.New(w).Level(level).With().Timestamp().Logger()
}
