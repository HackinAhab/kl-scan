package kube

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"kl-scan/internal/detect"
	"kl-scan/internal/logger"
)

// RotatorConfig controls the rotational watch loop.
type RotatorConfig struct {
	BatchSize    int           // targets streamed concurrently per batch
	Window       time.Duration // observation window per batch
	CyclePause   time.Duration // pause between batches (and between cycles)
	WatchSince   time.Duration // history fetched on first attach to a target
	MaxLineBytes int

	// MaxBatchFailures: after this many consecutive batch failures for a single
	// target, skip it for one cycle. Defaults to 3.
	MaxBatchFailures int
}

// CycleEvent is emitted on each cycle boundary for callers that want to react
// (e.g. emit a heartbeat).
type CycleEvent struct {
	Cycle           int
	StartedAt       time.Time
	CompletedAt     time.Time
	Targets         int     // total live targets at cycle completion
	BatchesRun      int     // batches in this cycle
	CoverageWindow  time.Duration
}

// Rotator drives the rotational watch loop.
//
// Each iteration:
//  1. Take a snapshot from the TargetIndex (informer-backed cache).
//  2. Pick up to BatchSize "uncovered" targets in deterministic order.
//  3. Stream all of them with Follow=true for Window duration.
//  4. Mark them as covered. Update watermarks.
//  5. When every live target has been covered, the cycle is complete: reset
//     coverage and start a new cycle.
type Rotator struct {
	client *Client
	idx    *TargetIndex
	cfg    RotatorConfig
	out    chan<- detect.LogLine

	// Coverage state for the current cycle.
	covered map[TargetKey]struct{}

	// Watermark per target — the timestamp of the last log line we observed.
	watermarks map[TargetKey]time.Time
	wmMu       sync.Mutex

	// consecutiveFailures per target. Targets at or above MaxBatchFailures are
	// skipped for one cycle (then reset).
	failCounts map[TargetKey]int

	// Counters
	streamErrors atomic.Int32
	cycleNum     atomic.Int32
	batchNum     atomic.Int32

	// onCycleComplete, if set, is invoked at the end of every cycle.
	onCycleComplete func(CycleEvent)
}

// NewRotator constructs a Rotator. Apply defaults for any unset fields.
func NewRotator(client *Client, idx *TargetIndex, cfg RotatorConfig, out chan<- detect.LogLine) *Rotator {
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 50
	}
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	if cfg.CyclePause < 0 {
		cfg.CyclePause = 0
	}
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = defaultMaxLineBytes
	}
	if cfg.MaxBatchFailures <= 0 {
		cfg.MaxBatchFailures = 3
	}
	return &Rotator{
		client:     client,
		idx:        idx,
		cfg:        cfg,
		out:        out,
		covered:    make(map[TargetKey]struct{}),
		watermarks: make(map[TargetKey]time.Time),
		failCounts: make(map[TargetKey]int),
	}
}

// SetOnCycleComplete registers a callback invoked when each cycle finishes.
func (r *Rotator) SetOnCycleComplete(fn func(CycleEvent)) {
	r.onCycleComplete = fn
}

// StreamErrors returns the cumulative count of stream errors observed across
// all batches so far.
func (r *Rotator) StreamErrors() int {
	return int(r.streamErrors.Load())
}

// Cycle returns the current cycle number (1-indexed; 0 before the first
// cycle starts).
func (r *Rotator) Cycle() int {
	return int(r.cycleNum.Load())
}

// Run drives the rotation loop until ctx is cancelled.
func (r *Rotator) Run(ctx context.Context) {
	cycleStart := time.Now()
	r.cycleNum.Add(1)
	batchesThisCycle := 0

	for {
		if ctx.Err() != nil {
			return
		}

		snapshot := r.idx.Snapshot()
		if len(snapshot) == 0 {
			// No live targets. Wait briefly and retry.
			if !sleep(ctx, 2*time.Second) {
				return
			}
			continue
		}

		liveSet := make(map[TargetKey]PodTarget, len(snapshot))
		for _, t := range snapshot {
			liveSet[TargetKeyOf(t)] = t
		}

		// Prune coverage entries for pods that have disappeared.
		for k := range r.covered {
			if _, ok := liveSet[k]; !ok {
				delete(r.covered, k)
			}
		}

		// Compute uncovered targets.
		var uncovered []PodTarget
		for k, t := range liveSet {
			if _, ok := r.covered[k]; ok {
				continue
			}
			// Skip targets that recently failed too many times. Reset their
			// counter so they get retried next cycle.
			if r.failCounts[k] >= r.cfg.MaxBatchFailures {
				r.covered[k] = struct{}{} // skip for this cycle
				continue
			}
			uncovered = append(uncovered, t)
		}

		// Cycle complete?
		if len(uncovered) == 0 {
			ev := CycleEvent{
				Cycle:          int(r.cycleNum.Load()),
				StartedAt:      cycleStart,
				CompletedAt:    time.Now(),
				Targets:        len(liveSet),
				BatchesRun:     batchesThisCycle,
				CoverageWindow: r.cfg.Window,
			}
			logger.Infof("cycle complete  cycle=%d  targets=%d  batches=%d  duration=%.1fs",
				ev.Cycle, ev.Targets, ev.BatchesRun, ev.CompletedAt.Sub(ev.StartedAt).Seconds())
			if r.onCycleComplete != nil {
				r.onCycleComplete(ev)
			}
			// Reset for next cycle.
			r.covered = make(map[TargetKey]struct{})
			r.failCounts = make(map[TargetKey]int)
			r.cycleNum.Add(1)
			cycleStart = time.Now()
			batchesThisCycle = 0
			if r.cfg.CyclePause > 0 {
				if !sleep(ctx, r.cfg.CyclePause) {
					return
				}
			}
			continue
		}

		// Deterministic order: by namespace, pod name, container.
		sort.Slice(uncovered, func(a, b int) bool {
			if uncovered[a].Namespace != uncovered[b].Namespace {
				return uncovered[a].Namespace < uncovered[b].Namespace
			}
			if uncovered[a].PodName != uncovered[b].PodName {
				return uncovered[a].PodName < uncovered[b].PodName
			}
			return uncovered[a].Container < uncovered[b].Container
		})

		// Pick batch.
		n := r.cfg.BatchSize
		if n > len(uncovered) {
			n = len(uncovered)
		}
		batch := uncovered[:n]

		r.runBatch(ctx, batch)
		batchesThisCycle++

		// Mark as covered regardless of stream success — failed targets are
		// tracked separately via failCounts so we don't loop forever on a
		// permanently broken pod.
		for _, t := range batch {
			r.covered[TargetKeyOf(t)] = struct{}{}
		}

		if r.cfg.CyclePause > 0 {
			if !sleep(ctx, r.cfg.CyclePause) {
				return
			}
		}
	}
}

// runBatch streams the given batch concurrently for cfg.Window duration.
// All goroutines exit before runBatch returns.
func (r *Rotator) runBatch(ctx context.Context, batch []PodTarget) {
	batchCtx, cancel := context.WithTimeout(ctx, r.cfg.Window)
	defer cancel()

	r.batchNum.Add(1)
	bn := int(r.batchNum.Load())
	logger.Infof("batch start  n=%d  size=%d  window=%s",
		bn, len(batch), r.cfg.Window)

	var wg sync.WaitGroup
	for i := range batch {
		t := batch[i]
		key := TargetKeyOf(t)

		// Determine SinceTime / SinceSeconds for this target.
		opts := FollowOpts{MaxLineBytes: r.cfg.MaxLineBytes}
		r.wmMu.Lock()
		wm, hasWM := r.watermarks[key]
		r.wmMu.Unlock()
		if hasWM {
			// Resume just after the last seen line.
			next := wm.Add(time.Nanosecond)
			opts.SinceTime = &next
		} else {
			opts.SinceSeconds = SinceToSeconds(r.cfg.WatchSince)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			err := StreamOneFollow(batchCtx, r.client, t, opts, r.out, func(ts time.Time) {
				r.wmMu.Lock()
				cur := r.watermarks[key]
				if ts.After(cur) {
					r.watermarks[key] = ts
				}
				r.wmMu.Unlock()
			})

			if err != nil {
				r.streamErrors.Add(1)
				r.failCounts[key]++
			} else {
				// Reset failure counter on a clean stream.
				delete(r.failCounts, key)
			}
		}()
	}
	wg.Wait()

	logger.Infof("batch end    n=%d", bn)
}

// sleep blocks for d or until ctx is done. Returns false if ctx was
// cancelled.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
