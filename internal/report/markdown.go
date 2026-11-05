package report

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// MarkdownWriter writes findings immediately so watch reports stay usable mid-run.
type MarkdownWriter struct {
	mu       sync.Mutex
	pods     *os.File
	evidence *os.File
	seen     map[string]bool
	err      error
}

// NewMarkdownWriter creates both reports without overwriting previous evidence.
func NewMarkdownWriter() (*MarkdownWriter, error) {
	for {
		w, err := newMarkdownWriter(time.Now().Format("2006-01-02-150405"))
		if errors.Is(err, os.ErrExist) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return w, err
	}
}

func newMarkdownWriter(stamp string) (*MarkdownWriter, error) {
	pods, err := os.OpenFile("kl-scan-pods-"+stamp+".md", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create pod report: %w", err)
	}
	evidence, err := os.OpenFile("kl-scan-evidence-"+stamp+".md", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = pods.Close()
		_ = os.Remove(pods.Name())
		return nil, fmt.Errorf("create evidence report: %w", err)
	}
	return &MarkdownWriter{pods: pods, evidence: evidence, seen: make(map[string]bool)}, nil
}

// Paths returns the paired report filenames for startup diagnostics.
func (w *MarkdownWriter) Paths() (string, string) {
	return w.pods.Name(), w.evidence.Name()
}

// Write is safe for concurrent pipeline workers. The first write error is retained.
func (w *MarkdownWriter) Write(f Finding) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	if !w.seen[f.Pod] {
		if _, w.err = fmt.Fprintln(w.pods, f.Pod); w.err != nil {
			return
		}
		w.seen[f.Pod] = true
	}
	message := f.LogMessage
	if f.Redacted {
		message = "[Log context omitted in redacted mode]"
	}
	// A longer fence prevents untrusted log content from ending the code block.
	fence := "```"
	for strings.Contains(message, fence) || strings.Contains(f.Match, fence) {
		fence += "`"
	}
	_, w.err = fmt.Fprintf(w.evidence,
		"## %s/%s\n\n- Container: %s\n- Node: %s\n- Detector/rule: %s/%s\n- Severity: %s\n- Timestamp: %s\n- Line: %d\n\nMatched secret:\n\n%stext\n%s\n%s\n\nLog message (joined fragments for cross-line detections):\n\n%stext\n%s\n%s\n\n",
		f.Namespace, f.Pod, f.Container, f.Node, f.Detector, f.RuleID,
		f.Severity, f.Timestamp.Format(time.RFC3339Nano), f.LineNo,
		fence, f.Match, fence, fence, message, fence)
}

// Close returns write and close errors so a failed report cannot look successful.
func (w *MarkdownWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := errors.Join(w.err, w.pods.Close(), w.evidence.Close()); err != nil {
		return fmt.Errorf("write Markdown reports: %w", err)
	}
	return nil
}
