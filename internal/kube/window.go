package kube

import (
	"context"
	"strings"
	"time"

	"kl-scan/internal/detect"
	"kl-scan/internal/logger"
)

// Per-stream window sizing.
//
// windowCapLines bounds how many recent lines are kept and joined for the
// cross-line detection pass. 3 covers the common cases:
//
//   - kubelet 16KiB partial-fragment splits (1 split → 2 fragments).
//   - applications that emit a record across 2-3 lines (header / body /
//     trailer style logging).
//
// windowCapBytes is a defensive byte budget: even if MaxLineBytes is bumped
// to 1 MiB by an operator, per-stream window memory stays bounded. With the
// default 64 KiB max-line-bytes, three lines fit comfortably under this cap;
// the byte limit only kicks in when individual lines are unusually large.
const (
	windowCapLines = 3
	windowCapBytes = 192 * 1024 // 192 KiB
)

// windowEntry holds enough metadata to reconstruct a synthetic LogLine for
// the joined view. Storing the timestamp per entry also leaves the door
// open for timestamp-based coalescing (kubelet partial-fragment recovery,
// "Option C") without changing the struct shape.
type windowEntry struct {
	ts      time.Time
	lineNo  int
	payload string
}

// lineWindow is a fixed-capacity FIFO of recent log lines from a single
// stream. It is owned by exactly one streamer goroutine — no locking.
//
// The window lives in the streamer (not the pipeline) because the streamer
// is the only place where lines from a given (pod, container) are
// guaranteed to arrive in sequential order on a single goroutine. The
// pipeline runs N workers consuming a shared channel, so a per-stream
// rolling buffer there would need locking and per-PodUID partitioning.
//
// Future extension hook: to add timestamp-based coalescing (merge adjacent
// entries when their RFC3339Nano timestamps are byte-equal, recovering
// kubelet partial-fragment splits at the source), inspect the previous
// entry inside push and either replace-and-extend instead of appending, or
// rewrite the joined() output. The struct already carries every field
// needed for that decision.
type lineWindow struct {
	capLines int
	capBytes int
	bytes    int
	entries  []windowEntry
}

func newLineWindow(capLines, capBytes int) *lineWindow {
	if capLines < 2 {
		// A 1-line "window" would never produce a joined view; reject by
		// clamping to the minimum useful size.
		capLines = 2
	}
	if capBytes < 1 {
		capBytes = 1
	}
	return &lineWindow{
		capLines: capLines,
		capBytes: capBytes,
		entries:  make([]windowEntry, 0, capLines),
	}
}

// push appends a new entry, evicting the oldest entries (FIFO) until both
// the line and byte caps are respected. Entries that on their own exceed
// capBytes are still admitted (we cannot truncate a single fragment
// without breaking detection); the byte cap is best-effort.
func (w *lineWindow) push(e windowEntry) {
	w.entries = append(w.entries, e)
	w.bytes += len(e.payload)

	// Line cap: drop oldest until we fit.
	for len(w.entries) > w.capLines {
		w.bytes -= len(w.entries[0].payload)
		w.entries = w.entries[1:]
	}
	// Byte cap: drop oldest until we fit, but never drop the just-pushed
	// entry (otherwise the window has nothing useful for the joined view).
	for w.bytes > w.capBytes && len(w.entries) > 1 {
		w.bytes -= len(w.entries[0].payload)
		w.entries = w.entries[1:]
	}
}

// joined returns the concatenated payload of the current entries (no
// separator) plus the metadata of the most recent entry (used to anchor
// the synthetic LogLine). ok is false when the window holds fewer than 2
// entries — in that case the joined view would be identical to the line
// just emitted and would only generate redundant detector work + dedup
// churn.
//
// The empty separator is intentional: the kubelet (and other log
// transports) split at byte boundaries without inserting any character at
// the split point. Joining with "\n" would introduce a byte that breaks
// regex character classes like [a-zA-Z0-9], preventing detectors from
// matching a token that spans the boundary. Concatenation without a
// separator faithfully reconstructs the original single application line.
func (w *lineWindow) joined() (joined string, lastLineNo int, lastTS time.Time, ok bool) {
	if len(w.entries) < 2 {
		return "", 0, time.Time{}, false
	}
	parts := make([]string, len(w.entries))
	for i, e := range w.entries {
		parts[i] = e.payload
	}
	last := w.entries[len(w.entries)-1]
	return strings.Join(parts, ""), last.lineNo, last.ts, true
}

// emitWithWindow emits the raw LogLine and, when the window has more than
// one entry, also emits a synthetic LogLine carrying the bare concatenation
// of the last N lines from this stream (no separator — see joined() for
// rationale). The synthetic line uses the most recent fragment's LineNo
// and Timestamp so operators searching with `kubectl logs --since-time=...`
// land on the trailing fragment of any cross-line secret.
//
// Pipeline-side dedup (sha256(value) keyed on PodUID+detector+rule) makes
// this safe: a secret matched on both the raw and joined views collapses
// to a single finding.
//
// Returns ctx.Err() if the context is cancelled mid-send so the caller
// can exit cleanly.
func emitWithWindow(
	ctx context.Context,
	out chan<- detect.LogLine,
	base detect.LogLine,
	w *lineWindow,
) error {
	logger.Tracef("emit raw   %s/%s [%s] line=%d  len=%d  payload=%q",
		base.Namespace, base.Pod, base.Container, base.LineNo, len(base.Line), base.Line)

	if err := sendLine(ctx, out, base); err != nil {
		return err
	}
	w.push(windowEntry{
		ts:      base.Timestamp,
		lineNo:  base.LineNo,
		payload: base.Line,
	})

	logger.Tracef("window     %s/%s [%s] entries=%d  bytes=%d",
		base.Namespace, base.Pod, base.Container, len(w.entries), w.bytes)

	joined, lastLineNo, lastTS, ok := w.joined()
	if !ok {
		return nil
	}

	logger.Tracef("emit joined %s/%s [%s] line=%d  fragments=%d  joined_len=%d  joined=%q",
		base.Namespace, base.Pod, base.Container, lastLineNo, len(w.entries), len(joined), joined)

	windowed := base
	windowed.Line = joined
	windowed.LineNo = lastLineNo
	windowed.Timestamp = lastTS
	return sendLine(ctx, out, windowed)
}

// sendLine pushes a LogLine onto out, respecting context cancellation.
func sendLine(ctx context.Context, out chan<- detect.LogLine, ll detect.LogLine) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case out <- ll:
		return nil
	}
}
