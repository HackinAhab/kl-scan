package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
)

// ConsoleWriter writes human-readable findings to an io.Writer.
// Color is auto-disabled on non-TTY destinations.
type ConsoleWriter struct {
	mu     sync.Mutex
	w      io.Writer
	colors bool
}

// NewConsoleWriter constructs a ConsoleWriter. Pass os.Stdout in normal use.
func NewConsoleWriter(w io.Writer) *ConsoleWriter {
	useColor := false
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			useColor = true
		}
	}
	if !useColor {
		color.NoColor = true
	}
	return &ConsoleWriter{w: w, colors: useColor}
}

func severityColor(sev string) *color.Color {
	switch strings.ToLower(sev) {
	case SeverityCritical:
		return color.New(color.FgHiRed, color.Bold)
	case SeverityHigh:
		return color.New(color.FgRed, color.Bold)
	case SeverityMedium:
		return color.New(color.FgYellow)
	case SeverityLow:
		return color.New(color.FgCyan)
	default:
		return color.New(color.FgWhite)
	}
}

// Write emits a single finding as a multi-line, human-readable record.
func (c *ConsoleWriter) Write(f Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	sev := strings.ToUpper(f.Severity)
	if sev == "" {
		sev = "INFO"
	}
	sevC := severityColor(f.Severity).SprintFunc()

	header := fmt.Sprintf("%s/%s [%s]  %s  %s:%s  line %d",
		f.Namespace, f.Pod, f.Container,
		sevC(sev),
		f.Detector, f.RuleID,
		f.LineNo,
	)
	if _, err := fmt.Fprintln(c.w, header); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.w, "  %s\n", f.Match); err != nil {
		return err
	}
	if f.Context != "" {
		if _, err := fmt.Fprintf(c.w, "  context: %s\n", f.Context); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(c.w)
	return err
}

// Summary describes the run-level totals.
type Summary struct {
	TotalFindings    int
	BySeverity       map[string]int
	PodsScanned      int
	ContainersScanned int
	PodsWithFindings int
	DurationSeconds  float64
	StreamErrors     int
}

// WriteSummary prints the summary; safe for concurrent callers.
func (c *ConsoleWriter) WriteSummary(s Summary) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	parts := []string{}
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		if n, ok := s.BySeverity[sev]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	bd := strings.Join(parts, ", ")
	if bd == "" {
		bd = "0"
	}
	_, err := fmt.Fprintf(c.w,
		"Summary: %d findings across %d pods (%s)  \u2022  scanned %d pods / %d containers in %.1fs",
		s.TotalFindings, s.PodsWithFindings, bd, s.PodsScanned, s.ContainersScanned, s.DurationSeconds,
	)
	if err != nil {
		return err
	}
	if s.StreamErrors > 0 {
		fmt.Fprintf(c.w, "  \u2022  %d stream error(s)", s.StreamErrors)
	}
	fmt.Fprintln(c.w)
	return nil
}
