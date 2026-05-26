package report

import (
	"encoding/json"
	"io"
	"sync"
)

// NDJSONWriter writes findings as newline-delimited JSON to an io.Writer.
// Safe for concurrent use; each Write produces exactly one line.
type NDJSONWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewNDJSONWriter wraps w with a mutex-protected JSON encoder.
// json.Encoder.Encode appends a newline, producing valid NDJSON.
func NewNDJSONWriter(w io.Writer) *NDJSONWriter {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &NDJSONWriter{enc: enc}
}

// Write emits a single finding as one NDJSON line.
func (n *NDJSONWriter) Write(f Finding) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.enc.Encode(f)
}
