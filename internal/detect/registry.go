package detect

import (
	"fmt"
	"sort"
	"sync"
)

// Constructor builds a Detector. `rulesPath` is optional and detector-specific
// (empty means "use built-in defaults").
type Constructor func(rulesPath string) (Detector, error)

var (
	regMu sync.RWMutex
	reg   = map[string]Constructor{}
)

// Register makes a detector available by name.
func Register(name string, c Constructor) {
	regMu.Lock()
	defer regMu.Unlock()
	reg[name] = c
}

// Build instantiates the named detectors. `rulesPath` is forwarded to each.
func Build(names []string, rulesPath string) ([]Detector, error) {
	regMu.RLock()
	defer regMu.RUnlock()

	out := make([]Detector, 0, len(names))
	for _, n := range names {
		c, ok := reg[n]
		if !ok {
			return nil, fmt.Errorf("unknown detector: %q (available: %v)", n, available())
		}
		d, err := c(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("detector %q: %w", n, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func available() []string {
	names := make([]string, 0, len(reg))
	for n := range reg {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
