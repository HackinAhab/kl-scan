package report

import (
	"fmt"
	"strings"
)

// Mask replaces a secret value with a redacted form: first 4 + ellipsis + last 2 + length.
// Short values (<= 6 chars) are fully replaced with "REDACTED (n)".
func Mask(v string) string {
	n := len(v)
	if n == 0 {
		return ""
	}
	if n <= 6 {
		return fmt.Sprintf("REDACTED (%d)", n)
	}
	return fmt.Sprintf("%s\u2026%s (%d)", v[:4], v[n-2:], n)
}

// RedactSpan replaces all occurrences of `match` in `context` with the masked form.
// Only the matched span is replaced; surrounding context is preserved.
func RedactSpan(context, match string) string {
	if match == "" || context == "" {
		return context
	}
	return strings.ReplaceAll(context, match, Mask(match))
}
