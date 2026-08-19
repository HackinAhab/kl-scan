package kube

import (
	"context"
	"testing"
	"time"

	"kl-scan/internal/detect"
	"kl-scan/internal/detect/betterleaks"
)

// splitJWT is a real HS256 JWT (synthetic — fabricated claims, not a live
// credential) whose payload contains structured low-entropy JSON matching
// the user-reported access-token shape. It is split at position 20 to
// simulate a kubelet 16KiB partial-fragment boundary (we choose 20 to keep
// the test readable; the mechanism under test is boundary-agnostic).
const (
	fullJWT = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NWZkMWU1NC0yZGE0LTRmYzUtODA4NS01ZDA4ZmFmZmQ3MjUiLCJzdWIiOiJTaHJhZGRoYS5QYXJpa2gxIiwiZW5kX3VzZXIiOiJTaHJhZGRoYS5QYXJpa2gxIiwib3JnX25hbWUiOiJHTTRDIiwiYWNjdE5hbWUiOiJ3M0lCTSIsInJvbGUiOiJHdWVzdCIsInR5cGUiOiJTU08iLCJleHAiOjE3ODAzMDI2MzEsImlhdCI6MTc4MDI5OTAzMX0.olVIiAsroMhXhSh8howvwsdkFTmrXnA2wckgUK4APog`

	// splitAt is where we cut the JWT to produce two fragments.
	// Chosen so frag1 is a valid-looking partial token but does not satisfy
	// the betterleaks jwt regex (no complete three-segment structure), and
	// frag2 has no eyJ prefix so also can't match alone.
	splitAt = 20
)

var (
	jwtFrag1 = "accesstoken: '" + fullJWT[:splitAt]
	jwtFrag2 = fullJWT[splitAt:] + "'"
)

// ── lineWindow unit tests ──────────────────────────────────────────────────

// TestLineWindowJoinsLastN verifies the FIFO cap: after pushing 4 entries
// into a 3-line window the oldest is evicted and joined() spans lines 2-4.
func TestLineWindowJoinsLastN(t *testing.T) {
	w := newLineWindow(3, windowCapBytes)
	ts := time.Now()

	for i := 1; i <= 4; i++ {
		w.push(windowEntry{ts: ts, lineNo: i, payload: string(rune('A' - 1 + i))})
	}

	joined, lastLineNo, _, ok := w.joined()
	if !ok {
		t.Fatal("joined() returned ok=false; expected 3 entries in window")
	}
	if lastLineNo != 4 {
		t.Errorf("lastLineNo = %d; want 4", lastLineNo)
	}
	// Window must hold lines 2, 3, 4 (line 1 evicted).
	// joined() concatenates without a separator (see window.go rationale).
	want := "BCD"
	if joined != want {
		t.Errorf("joined = %q; want %q", joined, want)
	}
}

// TestLineWindowByteCap verifies that entries are evicted FIFO when the
// cumulative byte budget is exceeded, while always keeping at least 1 entry.
func TestLineWindowByteCap(t *testing.T) {
	const cap = 10
	w := newLineWindow(windowCapLines, cap)
	ts := time.Now()

	// Push three 5-byte payloads. Total = 15 > cap=10 so the oldest
	// should be dropped after the third push.
	w.push(windowEntry{ts: ts, lineNo: 1, payload: "AAAAA"}) // bytes=5
	w.push(windowEntry{ts: ts, lineNo: 2, payload: "BBBBB"}) // bytes=10
	w.push(windowEntry{ts: ts, lineNo: 3, payload: "CCCCC"}) // bytes=15 → evict line 1

	if w.bytes > cap && len(w.entries) > 1 {
		t.Errorf("byte budget exceeded: w.bytes=%d cap=%d entries=%d",
			w.bytes, cap, len(w.entries))
	}

	// The window must still hold at least the most-recently-pushed entry.
	last := w.entries[len(w.entries)-1]
	if last.payload != "CCCCC" {
		t.Errorf("last entry payload = %q; want CCCCC", last.payload)
	}
}

// TestLineWindowSingleEntry verifies joined() returns ok=false when only
// one entry is in the window (joined view would be identical to the raw line).
func TestLineWindowSingleEntry(t *testing.T) {
	w := newLineWindow(windowCapLines, windowCapBytes)
	w.push(windowEntry{ts: time.Now(), lineNo: 1, payload: "only line"})
	_, _, _, ok := w.joined()
	if ok {
		t.Error("joined() returned ok=true with only one entry; want false")
	}
}

// ── emitWithWindow regression test ────────────────────────────────────────

// TestStreamerEmitsWindowedJWTDetection is the primary regression test for
// the user-reported access-token miss.
//
// It verifies two things:
//
//  1. BEFORE THE FIX (single-line only): neither fragment alone matches the
//     betterleaks jwt rule. If this assertion fails, the split chosen in
//     splitAt has accidentally kept a complete regex-matchable fragment,
//     and the test needs a different split point.
//
//  2. AFTER THE FIX (windowed view): emitWithWindow produces a synthetic
//     line containing frag1+"\n"+frag2, which does match the jwt rule.
//
// The test feeds lines through emitWithWindow, collects every LogLine emitted
// to the channel, runs the betterleaks detector over each one, and asserts
// that at least one jwt match comes from a windowed (multi-fragment) line.
func TestStreamerEmitsWindowedJWTDetection(t *testing.T) {
	bl, err := betterleaks.New("")
	if err != nil {
		t.Fatalf("betterleaks.New: %v", err)
	}

	// ── Part 1: confirm neither fragment alone matches ─────────────────
	for _, frag := range []string{jwtFrag1, jwtFrag2} {
		matches := bl.Inspect(detect.LineContext{Line: frag})
		for _, m := range matches {
			if m.RuleID == "jwt" {
				t.Fatalf(
					"fragment alone matched jwt rule — split point needs adjusting.\n"+
						"fragment: %q\nmatch value: %q",
					frag, m.Value,
				)
			}
		}
	}

	// ── Part 2: confirm windowed view matches ──────────────────────────
	out := make(chan detect.LogLine, 16)
	ctx := context.Background()
	w := newLineWindow(windowCapLines, windowCapBytes)
	ts := time.Now()

	for i, frag := range []string{jwtFrag1, jwtFrag2} {
		ll := detect.LogLine{
			Namespace: "ns", Pod: "pod", PodUID: "uid",
			Container: "c", LineNo: i + 1, Timestamp: ts, Line: frag,
		}
		if err := emitWithWindow(ctx, out, ll, w); err != nil {
			t.Fatalf("emitWithWindow: %v", err)
		}
	}
	close(out)

	var emitted []detect.LogLine
	for ll := range out {
		emitted = append(emitted, ll)
	}

	// Expect: frag1 (raw), frag2 (raw), [frag1+frag2] (windowed).
	// The windowed line is longer than either fragment because it is the
	// bare concatenation of both (no separator — see window.go for rationale).
	frag1Len := len(jwtFrag1)
	frag2Len := len(jwtFrag2)

	var windowedJWTFound bool
	for _, ll := range emitted {
		if len(ll.Line) <= frag1Len || len(ll.Line) <= frag2Len {
			continue // raw fragment, already confirmed not matching above
		}
		matches := bl.Inspect(detect.LineContext{Line: ll.Line})
		for _, m := range matches {
			if m.RuleID == "jwt" {
				windowedJWTFound = true
			}
		}
	}

	if !windowedJWTFound {
		for _, ll := range emitted {
			t.Logf("emitted line (lineNo=%d, len=%d): %q", ll.LineNo, len(ll.Line), ll.Line[:min(len(ll.Line), 80)])
		}
		t.Fatal("windowed view did not produce a jwt match; cross-line detection is broken")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
