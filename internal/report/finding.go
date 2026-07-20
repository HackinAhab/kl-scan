package report

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Severity levels.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is the canonical detection result.
type Finding struct {
	Detector    string    `json:"detector"`
	RuleID      string    `json:"rule_id"`
	Description string    `json:"description,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Namespace   string    `json:"namespace"`
	Pod         string    `json:"pod"`
	PodUID      string    `json:"pod_uid,omitempty"`
	Container   string    `json:"container"`
	Node        string    `json:"node,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	LineNo      int       `json:"line_no"`
	Match       string    `json:"match"`
	ValueSHA256 string    `json:"value_sha256"`
	Context     string    `json:"context,omitempty"`
	Entropy     float64   `json:"entropy,omitempty"`
	Redacted    bool      `json:"redacted"`
}

// HashValue returns the hex-encoded sha256 of the raw secret value.
func HashValue(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// DedupeKey returns the per-pod dedupe key tuple as a string.
func DedupeKey(podUID, detector, ruleID, valueHash string) string {
	return strings.Join([]string{podUID, detector, ruleID, valueHash}, "|")
}
