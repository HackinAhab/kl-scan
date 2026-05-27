package trufflehog

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	thdetectors "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"

	"kl-scan/internal/detect"
)

// Name is the registered detector identifier.
const Name = "trufflehog"

// contextSnippetMax bounds the length of the line text we attach to a
// finding's Context field. Pod log lines can be up to --max-line-bytes
// (65536 by default); reproducing the full line in every finding would
// bloat output. The matched secret value is reported separately, so
// this snippet is purely for human triage context.
const contextSnippetMax = 200

// Detector adapts the Trufflehog detector set + decoder set to the
// kl-scan detect.Detector interface.
//
// Verification is permanently disabled: every call to det.FromData below
// passes verify=false. kl-scan must never make outbound calls to validate
// live secrets during a pentest engagement, regardless of which detection
// engine is active. There is no flag, env var, or build tag to override
// this — it is a hardcoded literal.
type Detector struct {
	detectors []thdetectors.Detector
	decoders  []decoders.Decoder
	prefilter *ahocorasick.Core
}

// New builds a Trufflehog-backed detect.Detector.
//
// rulesPath is currently ignored. Trufflehog rule customization (custom
// regex detectors via YAML) is not exposed in v1; the embedded set of
// ~800 default detectors is used unconditionally. The kl-scan --rules
// flag still applies to the betterleaks detector.
func New(rulesPath string) (detect.Detector, error) {
	ds := defaults.DefaultDetectors()
	return &Detector{
		detectors: ds,
		decoders:  selectedDecoders(),
		prefilter: ahocorasick.NewAhoCorasickCore(ds),
	}, nil
}

// Name implements detect.Detector.
func (d *Detector) Name() string { return Name }

// Inspect implements detect.Detector.
//
// Each line is scanned in up to four passes:
//   - the raw bytes ("plain")
//   - base64-decoded bytes, if the line is decodable
//   - UTF-16 decoded bytes, if applicable
//   - escaped-unicode decoded bytes, if applicable
//
// Decoder passes are single-pass: the output of one decoder is not fed
// back through the others (no chaining). Trufflehog's engine performs
// chained decoding up to depth 5, but for line-oriented log scanning
// the marginal recall is not worth the per-line CPU cost.
//
// Dedup keys downstream use sha256(value). A secret found via both the
// plain pass and a decoder pass therefore collapses to a single finding
// in the pipeline (correct: the underlying secret is the same).
func (d *Detector) Inspect(lc detect.LineContext) []detect.Match {
	if lc.Line == "" {
		return nil
	}
	base := []byte(lc.Line)

	var out []detect.Match
	out = append(out, d.scanBytes(base, base)...)

	chunk := &sources.Chunk{Data: base}
	for _, dec := range d.decoders {
		dc := dec.FromChunk(chunk)
		if dc == nil || len(dc.Data) == 0 {
			continue
		}
		// Some decoders (notably Base64) will happily "decode" arbitrary
		// ASCII into garbage; rely on the detector's own keyword/regex
		// validation rather than trying to second-guess here.
		out = append(out, d.scanBytes(dc.Data, base)...)
	}
	return out
}

// scanBytes runs the Aho-Corasick keyword prefilter against `data` and
// invokes FromData(verify=false) on each detector that had a keyword hit.
// `original` is the pre-decode byte slice used to build the human-facing
// Context snippet so operators see the actual log line (not, e.g., a
// base64-decoded blob that may not even be printable).
func (d *Detector) scanBytes(data, original []byte) []detect.Match {
	if len(data) == 0 {
		return nil
	}

	candidates := d.prefilter.FindDetectorMatches(data)
	if len(candidates) == 0 {
		return nil
	}

	ctx := context.Background()
	var out []detect.Match

	for _, dm := range candidates {
		// verify=false is hardcoded. Do not parameterize.
		results, err := dm.Detector.FromData(ctx, false, data)
		if err != nil {
			// A single detector erroring should not poison the line;
			// other detectors may still produce valid results.
			continue
		}
		if len(results) == 0 {
			continue
		}

		ruleID := dm.Detector.Type().String()
		description := dm.Detector.Description()
		severity := severityFor(dm.Detector.Type())

		for _, r := range results {
			value := preferredSecretValue(r)
			if value == "" {
				continue
			}
			out = append(out, detect.Match{
				RuleID:      ruleID,
				Description: description,
				Severity:    severity,
				Value:       value,
				Context:     contextSnippet(original),
			})
		}
	}
	return out
}

// preferredSecretValue picks the best string to report for a Trufflehog
// Result. Raw is the canonical identifier (preferred for dedup hashing);
// RawV2 is the multi-part variant used when a credential has both an ID
// and a secret (AWS keys, etc.) — we fall back to that if Raw is empty.
func preferredSecretValue(r thdetectors.Result) string {
	if len(r.Raw) > 0 {
		return string(r.Raw)
	}
	if len(r.RawV2) > 0 {
		return string(r.RawV2)
	}
	if r.Redacted != "" {
		return r.Redacted
	}
	return ""
}

// contextSnippet returns a short, single-line excerpt of the original
// log line for human triage. Pod logs occasionally contain embedded
// newlines or null bytes from misbehaving applications; we trim and
// truncate so the rendered finding stays on one line.
func contextSnippet(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > contextSnippetMax {
		// Trim on a UTF-8 boundary so we don't emit an invalid rune.
		cut := contextSnippetMax
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}
