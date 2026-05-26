package detect

import (
	"context"
	"sync"
	"time"

	"kl-scan/internal/report"
	"kl-scan/internal/state"
)

// LogLine is a single line of pod log output flowing into the pipeline.
type LogLine struct {
	Namespace string
	Pod       string
	PodUID    string
	Container string
	Node      string
	LineNo    int
	Timestamp time.Time
	Line      string
}

// Sink receives findings emitted by the pipeline.
type Sink interface {
	Emit(report.Finding)
}

// Pipeline runs detectors against incoming log lines and emits deduped findings.
type Pipeline struct {
	detectors []Detector
	sink      Sink
	redacted  bool
	workers   int

	// In-process dedup map. Used when no persistent store is configured.
	dedupe sync.Map // key: report.DedupeKey(...) -> struct{}{}

	// store, if non-nil, supersedes the in-memory dedupe map and persists
	// dedup keys to disk (with single-instance flock semantics).
	store *state.Store

	// stats
	statsMu          sync.Mutex
	totalFindings    int
	bySeverity       map[string]int
	podsWithFindings map[string]struct{}
}

// NewPipeline constructs a Pipeline.
func NewPipeline(detectors []Detector, sink Sink, redacted bool, workers int) *Pipeline {
	if workers < 1 {
		workers = 1
	}
	return &Pipeline{
		detectors:        detectors,
		sink:             sink,
		redacted:         redacted,
		workers:          workers,
		bySeverity:       map[string]int{},
		podsWithFindings: map[string]struct{}{},
	}
}

// SetStore wires a persistent dedup store into the pipeline. When set, the
// store's MarkSeen replaces the in-memory dedupe map.
func (p *Pipeline) SetStore(s *state.Store) {
	p.store = s
}

// Run consumes from `lines` until it is closed or ctx is cancelled.
// Blocks until all worker goroutines exit.
func (p *Pipeline) Run(ctx context.Context, lines <-chan LogLine) {
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.worker(ctx, lines)
		}()
	}
	wg.Wait()
}

func (p *Pipeline) worker(ctx context.Context, lines <-chan LogLine) {
	for {
		select {
		case <-ctx.Done():
			return
		case ll, ok := <-lines:
			if !ok {
				return
			}
			p.processLine(ll)
		}
	}
}

func (p *Pipeline) processLine(ll LogLine) {
	lc := LineContext{
		Namespace: ll.Namespace,
		Pod:       ll.Pod,
		PodUID:    ll.PodUID,
		Container: ll.Container,
		Node:      ll.Node,
		LineNo:    ll.LineNo,
		Timestamp: ll.Timestamp,
		Line:      ll.Line,
	}
	for _, d := range p.detectors {
		matches := d.Inspect(lc)
		for _, m := range matches {
			valHash := report.HashValue(m.Value)
			key := report.DedupeKey(ll.PodUID, d.Name(), m.RuleID, valHash)

			if !p.markSeen(key, ll, d.Name(), m.RuleID) {
				continue
			}

			f := report.Finding{
				Detector:    d.Name(),
				RuleID:      m.RuleID,
				Description: m.Description,
				Severity:    m.Severity,
				Namespace:   ll.Namespace,
				Pod:         ll.Pod,
				PodUID:      ll.PodUID,
				Container:   ll.Container,
				Node:        ll.Node,
				Timestamp:   ll.Timestamp,
				LineNo:      ll.LineNo,
				Match:       m.Value,
				ValueSHA256: valHash,
				Context:     m.Context,
				Entropy:     m.Entropy,
				Redacted:    p.redacted,
			}
			if p.redacted {
				f.Context = report.RedactSpan(f.Context, m.Value)
				f.Match = report.Mask(m.Value)
			}
			p.recordStats(ll.Pod, m.Severity)
			p.sink.Emit(f)
		}
	}
}

// markSeen returns true if the (key) is new and the caller should emit the
// finding. Uses the persistent store if configured, otherwise the in-memory
// sync.Map.
func (p *Pipeline) markSeen(key string, ll LogLine, detector, ruleID string) bool {
	if p.store != nil {
		isNew, _ := p.store.MarkSeen(state.Record{
			Key:       key,
			Namespace: ll.Namespace,
			Pod:       ll.Pod,
			Container: ll.Container,
			Detector:  detector,
			Rule:      ruleID,
			First:     time.Now().UTC(),
		})
		return isNew
	}
	_, loaded := p.dedupe.LoadOrStore(key, struct{}{})
	return !loaded
}

func (p *Pipeline) recordStats(pod, severity string) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	p.totalFindings++
	if severity == "" {
		severity = report.SeverityInfo
	}
	p.bySeverity[severity]++
	p.podsWithFindings[pod] = struct{}{}
}

// Stats returns a snapshot of pipeline emission counters.
func (p *Pipeline) Stats() (total int, bySev map[string]int, podsWithFindings int) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	cp := make(map[string]int, len(p.bySeverity))
	for k, v := range p.bySeverity {
		cp[k] = v
	}
	return p.totalFindings, cp, len(p.podsWithFindings)
}
