package betterleaks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kl-scan/internal/detect"
)

// User-reported HS256 JWT (synthetic — header `HS256` and fabricated payload
// claims; no live credential). Wrapped in single quotes exactly as in the
// reported pod log line. Triggers betterleaks's `jwt` rule once the entropy
// filter is cleared by applyKLScanOverrides.
const userReportedJWTLine = `accesstoken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NWZkMWU1NC0yZGE0LTRmYzUtODA4NS01ZDA4ZmFmZmQ3MjUiLCJzdWIiOiJTaHJhZGRoYS5QYXJpa2gxIiwiZW5kX3VzZXIiOiJTaHJhZGRoYS5QYXJpa2gxIiwib3JnX25hbWUiOiJHTTRDIiwiYWNjdE5hbWUiOiJ3M0lCTSIsInJvbGUiOiJHdWVzdCIsInR5cGUiOiJTU08iLCJleHAiOjE3ODAzMDI2MzEsImlhdCI6MTc4MDI5OTAzMX0.olVIiAsroMhXhSh8howvwsdkFTmrXnA2wckgUK4APog'`

func newDetector(t *testing.T) detect.Detector {
	t.Helper()
	d, err := New("")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	return d
}

func inspect(d detect.Detector, line string) []detect.Match {
	return d.Inspect(detect.LineContext{
		Namespace: "ns",
		Pod:       "pod",
		PodUID:    "uid",
		Container: "c",
		LineNo:    1,
		Timestamp: time.Now(),
		Line:      line,
	})
}

func hasRule(matches []detect.Match, ruleID string) bool {
	for _, m := range matches {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestDefaultDetectorMatchesUserReportedJWT is the regression test for the
// originally reported miss: a quoted HS256 JWT with low-entropy structured
// claims. This must produce a `jwt` finding under the kl-scan override.
func TestDefaultDetectorMatchesUserReportedJWT(t *testing.T) {
	d := newDetector(t)
	matches := inspect(d, userReportedJWTLine)
	if !hasRule(matches, "jwt") {
		t.Fatalf("expected `jwt` rule to match user-reported HS256 token; got matches: %+v", matches)
	}
}

// TestDefaultDetectorJWTCases covers the full quoting / structure matrix
// to keep the override honest: standard high-entropy HS256, RS256 wrapped
// in double quotes, and bare HS256 at end-of-line.
func TestDefaultDetectorJWTCases(t *testing.T) {
	d := newDetector(t)

	cases := []struct {
		name       string
		line       string
		wantJWTHit bool
	}{
		{
			name:       "user-reported HS256 single-quoted low-entropy",
			line:       userReportedJWTLine,
			wantJWTHit: true,
		},
		{
			name:       "standard HS256 high-entropy bearer",
			line:       `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`,
			wantJWTHit: true,
		},
		{
			name:       "RS256 double-quoted",
			line:       `token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzAwMDAwMDAwfQ.xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"`,
			wantJWTHit: true,
		},
		{
			name: "non-JWT prose with eyJ prefix only",
			// Single segment, no dots — must not match the jwt regex
			// even with the entropy filter cleared.
			line:       `log message containing eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 alone`,
			wantJWTHit: false,
		},
		{
			name: "truncated two-segment token",
			// Header.payload only (no signature segment). The jwt regex
			// requires three segments.
			line:       `t=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0`,
			wantJWTHit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := inspect(d, tc.line)
			got := hasRule(matches, "jwt")
			if got != tc.wantJWTHit {
				t.Fatalf("jwt rule hit = %v; want %v\nline: %q\nmatches: %+v",
					got, tc.wantJWTHit, tc.line, matches)
			}
		})
	}
}

// TestCustomRulesPathBypassesOverride asserts that --rules consumers retain
// full control: applyKLScanOverrides must NOT mutate a user-supplied config.
//
// We construct a minimal custom TOML that defines a single `jwt` rule with
// an extremely strict entropy filter (drop everything with entropy <= 99).
// Under that rule the user's token should NOT match. If the override leaked
// into newFromPath, the filter would be cleared and we'd see a false hit.
func TestCustomRulesPathBypassesOverride(t *testing.T) {
	const strictRules = `
title = "kl-scan test rules"

[[rules]]
id = "jwt"
description = "strict jwt for override-leak test"
regex = '''\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:\\?['"\x60]|[\s;]|\\[nr]|$)'''
keywords = ["ey"]
filter = '''
entropy(finding["secret"]) <= 99.0
'''
`
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.toml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(strictRules)), 0o600); err != nil {
		t.Fatalf("write temp rules: %v", err)
	}

	d, err := New(path)
	if err != nil {
		t.Fatalf("New(%q): %v", path, err)
	}
	matches := inspect(d, userReportedJWTLine)
	if hasRule(matches, "jwt") {
		t.Fatalf("custom strict ruleset unexpectedly matched; override leaked into newFromPath. matches: %+v", matches)
	}
}
