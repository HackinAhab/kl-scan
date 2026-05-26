package cli

import "time"

// Flags holds all parsed CLI flag values.
type Flags struct {
	// Pod selection
	Namespace     string
	AllNamespaces bool
	Selector      string
	FieldSelector string

	// Log scope
	Since        time.Duration
	Tail         int64
	MaxLineBytes int

	// Detection
	Detectors []string
	Rules     string

	// Concurrency
	MaxStreams int
	MaxWorkers int

	// Output
	Output   string // "console" | "json"
	Redacted bool
	Out      string // optional file path to write output to

	// Auth
	Kubeconfig string
	Context    string

	// Logging
	LogLevel string // error | info | debug
}
