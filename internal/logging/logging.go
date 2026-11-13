// Package logging builds the process-wide slog logger.
package logging

import (
	"fmt"
	"io"
	"log/slog"
)

// New returns a logger writing to w. format is "json" (production) or
// "text" (development); level is debug, info, warn or error.
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("logging: level %q: %w", level, err)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("logging: unknown format %q", format)
	}
}
