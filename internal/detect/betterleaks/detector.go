package betterleaks

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	blconfig "github.com/betterleaks/betterleaks/config"
	bldetect "github.com/betterleaks/betterleaks/detect"

	"kl-scan/internal/detect"
)

// Name is the registered detector identifier.
const Name = "betterleaks"

// Detector wraps the betterleaks detect.Detector to implement detect.Detector.
type Detector struct {
	bl *bldetect.Detector
}

// New builds a betterleaks Detector. If rulesPath is non-empty, that TOML file
// replaces the embedded default ruleset. Verification is always disabled —
// kl-scan never makes outbound calls to validate live secrets.
func New(rulesPath string) (detect.Detector, error) {
	var bl *bldetect.Detector
	var err error

	if rulesPath != "" {
		bl, err = newFromPath(rulesPath)
	} else {
		bl, err = newFromDefault()
	}
	if err != nil {
		return nil, fmt.Errorf("betterleaks init: %w", err)
	}
	return &Detector{bl: bl}, nil
}

// newFromDefault constructs a Detector from the embedded default TOML with
// validation explicitly disabled.
func newFromDefault() (*bldetect.Detector, error) {
	viper.Reset()
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(blconfig.DefaultConfig)); err != nil {
		return nil, fmt.Errorf("read default config: %w", err)
	}
	var vc blconfig.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return nil, fmt.Errorf("unmarshal default config: %w", err)
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, fmt.Errorf("translate default config: %w", err)
	}
	// Apply kl-scan-specific overrides to the embedded ruleset BEFORE the
	// detector is constructed, because NewDetectorContext compiles each
	// rule's CEL Filter program at construction time. Mutating Filter
	// after that point has no effect on detection.
	applyKLScanOverrides(cfg)
	// Validation is disabled by passing the zero value of ValidationOptions.
	return bldetect.NewDetectorContext(context.Background(), cfg, bldetect.ValidationOptions{}), nil
}

// applyKLScanOverrides mutates the embedded default betterleaks ruleset to
// raise recall for secret classes that the upstream defaults systematically
// miss in pod-log contexts.
//
// Current overrides:
//
//   - jwt: clear the entropy filter (default: drop secrets with Shannon
//     entropy ≤ 3.0 bits/char). Real JWTs in pod logs frequently fall
//     under that threshold because their payloads are short structured
//     JSON (usernames, role names, "Guest", "SSO", etc.) rather than the
//     high-entropy random bytes the threshold was tuned for. The regex
//     itself already enforces the characteristic `ey…ey…` base64 header
//     structure (which is the literal base64 of `{"`), so non-JWT
//     collisions remain rare. The trade-off is a small FP-rate increase
//     for substantial recall gains. Pentest operators triage findings;
//     missed credentials are the worse failure mode.
//
//     Necessary because trufflehog's JWT detector by design skips
//     HMAC-signed JWTs (HS256/HS384/HS512) — see
//     trufflehog/pkg/detectors/jwt/jwt.go — leaving betterleaks as the
//     only detector covering that algorithm family. With the default
//     entropy filter in place, low-entropy HS256 session tokens
//     (extremely common in enterprise apps) slipped through both
//     detectors.
//
// This override is applied ONLY to the embedded default ruleset.
// `--rules <path>` users retain full control of their configuration and
// are not silently overridden.
func applyKLScanOverrides(cfg *blconfig.Config) {
	if r, ok := cfg.Rules["jwt"]; ok {
		r.Filter = ""
		cfg.Rules["jwt"] = r
	}
}

// newFromPath loads a custom TOML rules file (replaces embedded ruleset).
func newFromPath(path string) (*bldetect.Detector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	viper.Reset()
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(string(data))); err != nil {
		return nil, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	var vc blconfig.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return nil, fmt.Errorf("unmarshal rules file %q: %w", path, err)
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, fmt.Errorf("translate rules file %q: %w", path, err)
	}
	return bldetect.NewDetectorContext(context.Background(), cfg, bldetect.ValidationOptions{}), nil
}

// Name implements detect.Detector.
func (d *Detector) Name() string { return Name }

// Inspect implements detect.Detector.
func (d *Detector) Inspect(ctx detect.LineContext) []detect.Match {
	bf := d.bl.DetectString(ctx.Line)
	if len(bf) == 0 {
		return nil
	}
	out := make([]detect.Match, 0, len(bf))
	for _, f := range bf {
		out = append(out, detect.Match{
			RuleID:      f.RuleID,
			Description: f.Description,
			Severity:    severityFromTags(f.Tags),
			Value:       f.Secret,
			Context:     f.Match,
			Entropy:     float64(f.Entropy),
		})
	}
	return out
}

// severityFromTags derives a severity string from betterleaks rule tags.
// Betterleaks rules don't have a first-class severity field, but many
// rulesets annotate tags with "critical", "high", "medium", "low".
func severityFromTags(tags []string) string {
	for _, t := range tags {
		switch strings.ToLower(t) {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		case "low":
			return "low"
		}
	}
	// Default: treat all betterleaks hits as high — they are secrets.
	return "high"
}
