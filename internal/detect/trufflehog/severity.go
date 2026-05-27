package trufflehog

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

// severityFor maps a Trufflehog DetectorType to a kl-scan severity string.
//
// Trufflehog has no first-class severity field; this mapping reflects
// pentest-relevant impact:
//
//   - critical: cryptographic identities (private keys) — full account /
//     host takeover, broad blast radius.
//   - high:     concrete cloud/SaaS credentials (AWS, GCP, Azure, GitHub,
//     Slack, Stripe, etc.) — direct access to specific provider APIs.
//     This is the default for any classified Trufflehog detector type.
//   - medium:   generic/heuristic patterns (Generic, JWT) — often correct
//     but more prone to false positives and noise.
//
// Anything not explicitly listed falls through to "high" — Trufflehog has
// classified the data as a credential of *some* known type, which is the
// signal an operator wants to surface.
func severityFor(t detector_typepb.DetectorType) string {
	switch t {
	case detector_typepb.DetectorType_PrivateKey:
		return "critical"

	case detector_typepb.DetectorType_Generic,
		detector_typepb.DetectorType_JWT:
		return "medium"

	default:
		return "high"
	}
}
