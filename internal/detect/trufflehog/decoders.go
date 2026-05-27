package trufflehog

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
)

// selectedDecoders returns the decoder set kl-scan applies to each log line
// before scanning with Trufflehog detectors.
//
// We deliberately exclude the HTML decoder:
//
//   - HTML content is essentially never present in pod log streams.
//   - Trufflehog itself gates HTML behind feature.HTMLDecoderEnabled, which
//     is off by default; matching that posture avoids surprising the user.
//
// UTF8 (the passthrough) is omitted from this list because the adapter
// always scans the raw input as a "plain" pass; running UTF8 again would
// just produce a duplicate scan.
//
// Order is not significant — each decoder is run independently in
// detector.Inspect; we do not chain decoder output back through the
// decoder set (single-pass decoding).
func selectedDecoders() []decoders.Decoder {
	return []decoders.Decoder{
		&decoders.Base64{},
		&decoders.UTF16{},
		&decoders.EscapedUnicode{},
	}
}
