// Package betterleaks registers the betterleaks detector on import.
package betterleaks

import "kl-scan/internal/detect"

func init() {
	detect.Register(Name, New)
}
