package detect

import "time"

// LineContext is the per-line input to a Detector.
type LineContext struct {
	Namespace string
	Pod       string
	PodUID    string
	Container string
	Node      string
	LineNo    int
	Timestamp time.Time
	Line      string
}

// Match is a detector-agnostic representation of a single hit on a line.
// Detectors return Matches; the pipeline converts them into report.Findings.
type Match struct {
	RuleID      string
	Description string
	Severity    string
	Value       string  // raw matched value
	Context     string  // surrounding text (typically the line)
	Entropy     float64 // optional
}

// Detector is the pluggable detection interface.
type Detector interface {
	Name() string
	Inspect(ctx LineContext) []Match
}
