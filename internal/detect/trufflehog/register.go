// Package trufflehog registers the Trufflehog-backed detector on import.
//
// Importing this package for side effects only (`_ "kl-scan/internal/detect/trufflehog"`)
// is sufficient to make the detector available via the `--detectors trufflehog`
// CLI flag.
package trufflehog

import "kl-scan/internal/detect"

func init() {
	detect.Register(Name, New)
}
