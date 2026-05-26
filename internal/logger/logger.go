// Package logger provides a minimal levelled logger for kl-scan and controls
// the verbosity of the underlying klog used by client-go.
package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// Level represents the log verbosity level.
type Level int

const (
	LevelError Level = iota // default: only errors; klog output suppressed
	LevelInfo               // info: stream start/end messages to stderr
	LevelDebug              // debug: full klog output (client-go requests, throttle, etc.)
)

// L is the package-level logger used across kl-scan.
var L = &Logger{level: LevelError, w: os.Stderr}

// Logger writes structured messages to an io.Writer.
type Logger struct {
	level Level
	w     io.Writer
}

// Init configures the global logger and klog verbosity from a level string.
// Valid values: "error" (default), "info", "debug".
// Must be called once before any logging.
func Init(levelStr string) error {
	lvl, err := parse(levelStr)
	if err != nil {
		return err
	}
	L.level = lvl

	switch lvl {
	case LevelError:
		// Silence all klog output — suppresses the client-go throttle/request
		// messages that otherwise spam stderr at default verbosity.
		klog.SetOutput(io.Discard)

	case LevelInfo:
		// Still suppress klog (client-go internals); kl-scan writes its own
		// progress messages via this logger.
		klog.SetOutput(io.Discard)

	case LevelDebug:
		// Let klog write to stderr at full verbosity so the user sees
		// client-go request/throttle details.
		klog.SetOutput(os.Stderr)
	}

	return nil
}

// Infof logs a formatted message at info level.
func Infof(format string, args ...any) {
	L.Infof(format, args...)
}

// Debugf logs a formatted message at debug level.
func Debugf(format string, args ...any) {
	L.Debugf(format, args...)
}

// Errorf logs a formatted message at error level (always emitted).
func Errorf(format string, args ...any) {
	L.Errorf(format, args...)
}

func (l *Logger) Infof(format string, args ...any) {
	if l.level >= LevelInfo {
		l.write("INFO", format, args...)
	}
}

func (l *Logger) Debugf(format string, args ...any) {
	if l.level >= LevelDebug {
		l.write("DEBUG", format, args...)
	}
}

func (l *Logger) Errorf(format string, args ...any) {
	l.write("ERROR", format, args...)
}

func (l *Logger) write(lvl, format string, args ...any) {
	ts := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.w, "%s  %-5s  %s\n", ts, lvl, msg)
}

func parse(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "error":
		return LevelError, nil
	case "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	default:
		return LevelError, fmt.Errorf("unknown log level %q; valid values: error, info, debug", s)
	}
}
