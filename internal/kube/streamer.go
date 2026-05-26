package kube

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"golang.org/x/sync/errgroup"

	"kl-scan/internal/detect"
	"kl-scan/internal/logger"
)

// StreamConfig controls log retrieval behaviour.
type StreamConfig struct {
	SinceSeconds int64 // --since converted to seconds; 0 = no limit
	TailLines    int64 // --tail; 0 = no limit
	MaxLineBytes int   // lines longer than this are skipped; 0 = use default
	MaxStreams   int   // semaphore capacity
}

const defaultMaxLineBytes = 65536

// StreamAll opens a log stream for each target concurrently (up to
// cfg.MaxStreams in flight), reads lines, and pushes them to `out`.
// It closes `out` when all streams have completed.
// Returns the number of streams that encountered errors.
func StreamAll(
	ctx context.Context,
	client *Client,
	targets []PodTarget,
	cfg StreamConfig,
	out chan<- detect.LogLine,
) (streamErrors int) {
	if cfg.MaxLineBytes <= 0 {
		cfg.MaxLineBytes = defaultMaxLineBytes
	}
	if cfg.MaxStreams < 1 {
		cfg.MaxStreams = 50
	}

	var errCnt atomic.Int32

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.MaxStreams)

	for i := range targets {
		t := targets[i]
		g.Go(func() error {
			if err := streamOne(gctx, client, t, cfg, out); err != nil {
				errCnt.Add(1)
			}
			// Always return nil so errgroup does not cancel the context on the
			// first stream error — we want best-effort across all targets.
			return nil
		})
	}

	_ = g.Wait() // never errors (goroutines always return nil)
	return int(errCnt.Load())
}

func streamOne(
	ctx context.Context,
	client *Client,
	t PodTarget,
	cfg StreamConfig,
	out chan<- detect.LogLine,
) error {
	opts := &corev1.PodLogOptions{
		Container:  t.Container,
		Timestamps: true,
		Follow:     false,
	}
	if cfg.SinceSeconds > 0 {
		s := cfg.SinceSeconds
		opts.SinceSeconds = &s
	}
	if cfg.TailLines > 0 {
		tl := cfg.TailLines
		opts.TailLines = &tl
	}

	logger.Infof("opening stream  %s/%s [%s]", t.Namespace, t.PodName, t.Container)
	logger.Debugf("GET pods/%s/log?container=%s&sinceSeconds=%d&tailLines=%d  ns=%s",
		t.PodName, t.Container, cfg.SinceSeconds, cfg.TailLines, t.Namespace)

	req := client.Clientset.CoreV1().Pods(t.Namespace).GetLogs(t.PodName, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		logger.Errorf("stream error  %s/%s [%s]: %v", t.Namespace, t.PodName, t.Container, err)
		return fmt.Errorf("stream %s/%s[%s]: %w", t.Namespace, t.PodName, t.Container, err)
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, cfg.MaxLineBytes), cfg.MaxLineBytes)

	lineNo := 0
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		raw := scanner.Text()
		lineNo++

		ts, line := parseTimestamp(raw)

		select {
		case <-ctx.Done():
			return nil
		case out <- detect.LogLine{
			Namespace: t.Namespace,
			Pod:       t.PodName,
			PodUID:    t.PodUID,
			Container: t.Container,
			Node:      t.NodeName,
			LineNo:    lineNo,
			Timestamp: ts,
			Line:      line,
		}:
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		logger.Errorf("scan error  %s/%s [%s]: %v", t.Namespace, t.PodName, t.Container, err)
		return fmt.Errorf("scan %s/%s[%s]: %w", t.Namespace, t.PodName, t.Container, err)
	}

	logger.Infof("stream closed  %s/%s [%s]  lines=%d", t.Namespace, t.PodName, t.Container, lineNo)
	return nil
}

// parseTimestamp splits the RFC3339Nano timestamp prefix that Kubernetes
// prepends when Timestamps=true. If parsing fails, returns time.Now() and
// the raw line unchanged.
func parseTimestamp(raw string) (time.Time, string) {
	if len(raw) < 20 {
		return time.Now(), raw
	}
	// Kubernetes timestamps are RFC3339Nano followed by a space.
	idx := 0
	for idx < len(raw) && raw[idx] != ' ' {
		idx++
	}
	if idx >= len(raw) {
		return time.Now(), raw
	}
	ts, err := time.Parse(time.RFC3339Nano, raw[:idx])
	if err != nil {
		return time.Now(), raw
	}
	return ts, raw[idx+1:]
}

// SinceToSeconds converts a time.Duration to whole seconds for the K8s API.
func SinceToSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64(d.Seconds())
}

// CountContainers returns the total number of (pod, container) targets.
func CountContainers(targets []PodTarget) int {
	return len(targets)
}

// CountPods returns the number of unique pods across all targets.
func CountPods(targets []PodTarget) int {
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		seen[t.Namespace+"/"+t.PodName] = struct{}{}
	}
	return len(seen)
}

// Ensure metav1 import is used.
var _ = metav1.ListOptions{}
