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

	// Continuous (watch) mode
	Watch            bool          // enable rotational watch mode
	WatchBatchSize   int           // targets per batch (concurrent streams in a window)
	WatchWindow      time.Duration // observation window per batch
	WatchSince       time.Duration // history fetched on first attach to a target
	CyclePause       time.Duration // pause between batches
	SummaryInterval  time.Duration // heartbeat summary cadence on stderr (0 = off)
	StateFile        string        // persisted dedup file (NDJSON)
	StateDisabled    bool          // skip persistence
}
