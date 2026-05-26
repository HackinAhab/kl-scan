package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"kl-scan/internal/cli"
	"kl-scan/internal/detect"
	"kl-scan/internal/kube"
	"kl-scan/internal/logger"
	"kl-scan/internal/report"
	"kl-scan/internal/state"

	// Side-effect: registers the betterleaks detector.
	_ "kl-scan/internal/detect/betterleaks"
)

var version = "0.2.0"

func main() {
	os.Exit(run())
}

func run() int {
	var f cli.Flags

	root := &cobra.Command{
		Use:   "kl-scan",
		Short: "Scan Kubernetes pod logs for secrets and sensitive values",
		Long: `kl-scan is a Kubernetes pod log auditor for penetration testing.
By default it streams current logs from all matching pods once and detects
secrets, API keys, tokens, and other sensitive values.

Pass --watch to run continuously: kl-scan rotates through the pod set in
batches, observing each batch for a window before moving on. Findings are
deduped on disk so the same secret is not reported repeatedly within a run.`,
		Version:      version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), f)
		},
	}

	fl := root.Flags()

	// Pod selection
	fl.StringVarP(&f.Namespace, "namespace", "n", "", "target namespace (default: current context namespace)")
	fl.BoolVarP(&f.AllNamespaces, "all-namespaces", "A", false, "scan across all namespaces")
	fl.StringVarP(&f.Selector, "selector", "l", "", "label selector (e.g. app=api)")
	fl.StringVar(&f.FieldSelector, "field-selector", "", "field selector (e.g. status.phase=Running)")

	// Log scope
	fl.DurationVar(&f.Since, "since", time.Hour, "include logs since this duration ago (one-shot mode)")
	fl.Int64Var(&f.Tail, "tail", 100000, "maximum number of lines per container (0 = unlimited)")
	fl.IntVar(&f.MaxLineBytes, "max-line-bytes", 65536, "skip lines longer than this (bytes)")

	// Detection
	fl.StringSliceVar(&f.Detectors, "detectors", []string{"betterleaks"}, "comma-separated list of detectors to enable")
	fl.StringVar(&f.Rules, "rules", "", "path to custom rules TOML (replaces built-in ruleset)")

	// Concurrency
	fl.IntVar(&f.MaxStreams, "max-streams", 50, "maximum concurrent log streams")
	fl.IntVar(&f.MaxWorkers, "max-workers", runtime.NumCPU(), "detector worker goroutines")

	// Output
	fl.StringVar(&f.Output, "output", "console", "output format: console|json")
	fl.BoolVar(&f.Redacted, "redacted", false, "mask matched secret values in output")
	fl.StringVar(&f.Out, "out", "", "write output to this file path (in addition to stdout)")

	// Auth
	fl.StringVar(&f.Kubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	fl.StringVar(&f.Context, "context", "", "kubeconfig context to use")

	// Logging
	fl.StringVar(&f.LogLevel, "log", "error", "log level: error|info|debug")

	// Continuous (watch) mode
	fl.BoolVar(&f.Watch, "watch", false, "run continuously: rotate through pods in batches until cancelled")
	fl.IntVar(&f.WatchBatchSize, "watch-batch-size", 50, "targets streamed concurrently per batch (watch mode)")
	fl.DurationVar(&f.WatchWindow, "watch-window", 60*time.Second, "observation window per batch (watch mode)")
	fl.DurationVar(&f.WatchSince, "watch-since", 30*time.Second, "history fetched on first attach to a target (watch mode)")
	fl.DurationVar(&f.CyclePause, "cycle-pause", time.Second, "pause between batches (watch mode; 0 = no pause)")
	fl.DurationVar(&f.SummaryInterval, "summary-interval", 5*time.Minute, "heartbeat summary cadence on stderr (watch mode; 0 = off)")
	fl.StringVar(&f.StateFile, "state-file", "./kl-scan-state.ndjson", "persisted dedup file (watch mode)")
	fl.BoolVar(&f.StateDisabled, "state-disabled", false, "skip persistence; in-memory dedup only (watch mode)")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root.SetContext(ctx)

	if err := root.ExecuteContext(ctx); err != nil {
		return cli.ExitError
	}
	return cli.ExitClean
}

// runtime bundles the shared, mode-independent setup.
type runtimeCtx struct {
	flags     cli.Flags
	detectors []detect.Detector
	client    *kube.Client
	sink      outputSink
	closeSink func()
	pipeline  *detect.Pipeline
}

// setup performs the steps common to one-shot and watch modes.
func setup(f cli.Flags) (*runtimeCtx, error) {
	if err := logger.Init(f.LogLevel); err != nil {
		return nil, err
	}

	switch f.Output {
	case "console", "json":
	default:
		return nil, fmt.Errorf("unknown output format %q; valid values: console, json", f.Output)
	}

	detectors, err := detect.Build(f.Detectors, f.Rules)
	if err != nil {
		return nil, err
	}

	client, err := kube.NewClient(kube.Config{
		KubeconfigPath: f.Kubeconfig,
		ContextName:    f.Context,
		Namespace:      f.Namespace,
		AllNamespaces:  f.AllNamespaces,
	})
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}

	sink, closeSink, err := buildSink(f)
	if err != nil {
		return nil, err
	}

	pl := detect.NewPipeline(detectors, sink, f.Redacted, f.MaxWorkers)

	return &runtimeCtx{
		flags:     f,
		detectors: detectors,
		client:    client,
		sink:      sink,
		closeSink: closeSink,
		pipeline:  pl,
	}, nil
}

// runScan dispatches to one-shot or watch mode based on flags.
func runScan(ctx context.Context, f cli.Flags) error {
	rt, err := setup(f)
	if err != nil {
		return err
	}
	defer rt.closeSink()

	if f.Watch {
		return runWatch(ctx, rt)
	}
	return runOnce(ctx, rt)
}

// runOnce is the original one-shot scan path.
func runOnce(ctx context.Context, rt *runtimeCtx) error {
	start := time.Now()
	f := rt.flags

	targets, err := kube.DiscoverTargets(ctx, rt.client, kube.DiscoveryConfig{
		Namespace:     rt.client.Namespace,
		LabelSelector: f.Selector,
		FieldSelector: f.FieldSelector,
	})
	if err != nil {
		return fmt.Errorf("pod discovery: %w", err)
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "kl-scan: no running pods found\n")
		os.Exit(cli.ExitClean)
	}

	podCount := kube.CountPods(targets)
	containerCount := kube.CountContainers(targets)
	fmt.Fprintf(os.Stderr, "kl-scan: scanning %d pods / %d containers\n", podCount, containerCount)

	lineCh := make(chan detect.LogLine, 4096)
	streamErrCh := make(chan int, 1)
	go func() {
		errs := kube.StreamAll(ctx, rt.client, targets, kube.StreamConfig{
			SinceSeconds: kube.SinceToSeconds(f.Since),
			TailLines:    f.Tail,
			MaxLineBytes: f.MaxLineBytes,
			MaxStreams:   f.MaxStreams,
		}, lineCh)
		close(lineCh)
		streamErrCh <- errs
	}()

	rt.pipeline.Run(ctx, lineCh)
	streamErrs := <-streamErrCh

	elapsed := time.Since(start)
	total, bySev, podsWithFindings := rt.pipeline.Stats()

	rt.sink.WriteSummary(report.Summary{
		TotalFindings:     total,
		BySeverity:        bySev,
		PodsScanned:       podCount,
		ContainersScanned: containerCount,
		PodsWithFindings:  podsWithFindings,
		DurationSeconds:   elapsed.Seconds(),
		StreamErrors:      streamErrs,
	})

	exitCode := cli.ExitClean
	if total > 0 {
		exitCode = cli.ExitFindings
	}
	if streamErrs > 0 {
		exitCode = cli.ExitPartial
	}
	os.Exit(exitCode)
	return nil
}

// runWatch is the rotational continuous-watch path.
func runWatch(ctx context.Context, rt *runtimeCtx) error {
	start := time.Now()
	f := rt.flags

	// 1. State store with single-instance flock.
	store, err := state.Open(f.StateFile, f.StateDisabled)
	if err != nil {
		if errors.Is(err, state.ErrAlreadyRunning) {
			fmt.Fprintf(os.Stderr,
				"kl-scan: another kl-scan process is using state file %q; aborting.\n"+
					"Use --state-file to point at a different path, or stop the other process.\n",
				f.StateFile)
			os.Exit(cli.ExitError)
		}
		return fmt.Errorf("open state file: %w", err)
	}
	defer store.Close()
	rt.pipeline.SetStore(store)

	if !f.StateDisabled {
		fmt.Fprintf(os.Stderr,
			"kl-scan: watch mode  •  state=%s  •  seeded %d previously-seen findings\n",
			f.StateFile, store.SeenCount())
	} else {
		fmt.Fprintf(os.Stderr, "kl-scan: watch mode  •  state persistence DISABLED\n")
	}

	// 2. Build the informer-backed target index.
	idx, err := kube.NewTargetIndex(rt.client, kube.IndexConfig{
		Namespace:     rt.client.Namespace,
		LabelSelector: f.Selector,
		FieldSelector: f.FieldSelector,
	})
	if err != nil {
		return fmt.Errorf("build target index: %w", err)
	}

	// Run informer in its own goroutine.
	informerDone := make(chan struct{})
	go func() {
		defer close(informerDone)
		_ = idx.Run(ctx)
	}()

	// 3. Wait for cache sync (with sensible deadline).
	select {
	case <-idx.Synced():
	case <-ctx.Done():
		return nil
	case <-time.After(60 * time.Second):
		return fmt.Errorf("informer cache failed to sync within 60s")
	}

	initialTargets := idx.Snapshot()
	if len(initialTargets) == 0 {
		fmt.Fprintf(os.Stderr, "kl-scan: no running pods match selectors yet; will continue watching\n")
	} else {
		// Coverage prediction.
		batch := f.WatchBatchSize
		if batch > f.MaxStreams {
			fmt.Fprintf(os.Stderr,
				"kl-scan: warning: --watch-batch-size (%d) exceeds --max-streams (%d); clamping to %d\n",
				batch, f.MaxStreams, f.MaxStreams)
			batch = f.MaxStreams
		}
		if batch < 1 {
			batch = 1
		}
		nTargets := len(initialTargets)
		batches := int(math.Ceil(float64(nTargets) / float64(batch)))
		cycleDur := time.Duration(batches)*f.WatchWindow + time.Duration(batches)*f.CyclePause
		var coverage float64
		if cycleDur > 0 {
			coverage = float64(f.WatchWindow) / float64(cycleDur)
		}

		fmt.Fprintf(os.Stderr,
			"kl-scan: watching %d targets  •  batch=%d  window=%s  cycle≈%s  per-target coverage≈%.1f%%\n",
			nTargets, batch, f.WatchWindow.String(), cycleDur.Round(time.Second).String(), coverage*100)

		if coverage < 0.05 {
			fmt.Fprintf(os.Stderr,
				"kl-scan: WARN: per-target coverage is below 5%%. Consider scoping with "+
					"--namespace/--selector, raising --watch-batch-size, or lowering --watch-window.\n")
		}
	}

	// 4. Build rotator.
	clampedBatch := f.WatchBatchSize
	if clampedBatch > f.MaxStreams {
		clampedBatch = f.MaxStreams
	}
	if clampedBatch < 1 {
		clampedBatch = 1
	}
	lineCh := make(chan detect.LogLine, 4096)
	rotator := kube.NewRotator(rt.client, idx, kube.RotatorConfig{
		BatchSize:    clampedBatch,
		Window:       f.WatchWindow,
		CyclePause:   f.CyclePause,
		WatchSince:   f.WatchSince,
		MaxLineBytes: f.MaxLineBytes,
	}, lineCh)

	rotatorDone := make(chan struct{})
	go func() {
		defer close(rotatorDone)
		rotator.Run(ctx)
	}()

	// 5. Pipeline runs in its own goroutine so the main goroutine can drive
	// the heartbeat ticker and shutdown.
	pipelineDone := make(chan struct{})
	go func() {
		defer close(pipelineDone)
		rt.pipeline.Run(ctx, lineCh)
	}()

	// 6. Heartbeat summary ticker.
	emitHeartbeat := func() {
		total, bySev, podsWithFindings := rt.pipeline.Stats()
		snap := idx.Snapshot()
		rt.sink.WriteSummary(report.Summary{
			TotalFindings:     total,
			BySeverity:        bySev,
			PodsScanned:       kube.CountPods(snap),
			ContainersScanned: len(snap),
			PodsWithFindings:  podsWithFindings,
			DurationSeconds:   time.Since(start).Seconds(),
			StreamErrors:      rotator.StreamErrors(),
			Heartbeat:         true,
			Cycle:             rotator.Cycle(),
		})
	}

	var heartbeatStop func()
	if f.SummaryInterval > 0 {
		hbCtx, cancel := context.WithCancel(ctx)
		heartbeatStop = cancel
		go func() {
			t := time.NewTicker(f.SummaryInterval)
			defer t.Stop()
			for {
				select {
				case <-hbCtx.Done():
					return
				case <-t.C:
					emitHeartbeat()
				}
			}
		}()
	}

	// 7. Wait for ctx cancellation (signal handler).
	<-ctx.Done()
	if heartbeatStop != nil {
		heartbeatStop()
	}

	// Drain order:
	//  - rotator stops (ctx cancelled), closes its in-flight streams.
	//  - we close lineCh so pipeline workers can drain remaining lines.
	//  - pipeline finishes.
	<-rotatorDone
	close(lineCh)
	<-pipelineDone
	<-informerDone

	// 8. Final summary.
	total, bySev, podsWithFindings := rt.pipeline.Stats()
	snap := idx.Snapshot()
	rt.sink.WriteSummary(report.Summary{
		TotalFindings:     total,
		BySeverity:        bySev,
		PodsScanned:       kube.CountPods(snap),
		ContainersScanned: len(snap),
		PodsWithFindings:  podsWithFindings,
		DurationSeconds:   time.Since(start).Seconds(),
		StreamErrors:      rotator.StreamErrors(),
		Heartbeat:         false,
		Cycle:             rotator.Cycle(),
	})

	exitCode := cli.ExitClean
	if total > 0 {
		exitCode = cli.ExitFindings
	}
	if rotator.StreamErrors() > 0 {
		exitCode = cli.ExitPartial
	}
	os.Exit(exitCode)
	return nil
}

// --- sink adapters ----------------------------------------------------------

// outputSink combines detect.Sink with summary-writing so main.go can call
// WriteSummary without a type assertion.
type outputSink interface {
	detect.Sink
	WriteSummary(s report.Summary)
}

// consoleSink adapts ConsoleWriter to outputSink.
type consoleSink struct {
	w *report.ConsoleWriter
}

func (s *consoleSink) Emit(f report.Finding) {
	_ = s.w.Write(f)
}

func (s *consoleSink) WriteSummary(sum report.Summary) {
	_ = s.w.WriteSummary(sum)
}

// ndjsonSink adapts NDJSONWriter to outputSink.
// Summary is written to stderr so stdout stays clean NDJSON.
type ndjsonSink struct {
	w *report.NDJSONWriter
}

func (s *ndjsonSink) Emit(f report.Finding) {
	_ = s.w.Write(f)
}

func (s *ndjsonSink) WriteSummary(sum report.Summary) {
	parts := ""
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n, ok := sum.BySeverity[sev]; ok && n > 0 {
			if parts != "" {
				parts += ", "
			}
			parts += fmt.Sprintf("%d %s", n, sev)
		}
	}
	if parts == "" {
		parts = "0"
	}
	prefix := "kl-scan"
	if sum.Heartbeat {
		if sum.Cycle > 0 {
			prefix = fmt.Sprintf("kl-scan heartbeat cycle=%d", sum.Cycle)
		} else {
			prefix = "kl-scan heartbeat"
		}
	}
	fmt.Fprintf(os.Stderr,
		"%s: %d findings (%s) across %d pods  •  scanned %d pods / %d containers in %.1fs",
		prefix, sum.TotalFindings, parts, sum.PodsWithFindings,
		sum.PodsScanned, sum.ContainersScanned, sum.DurationSeconds,
	)
	if sum.StreamErrors > 0 {
		fmt.Fprintf(os.Stderr, "  •  %d stream error(s)", sum.StreamErrors)
	}
	fmt.Fprintln(os.Stderr)
}

func buildSink(f cli.Flags) (outputSink, func(), error) {
	var fileWriter io.WriteCloser
	if f.Out != "" {
		fh, err := os.Create(f.Out)
		if err != nil {
			return nil, nil, fmt.Errorf("create output file %q: %w", f.Out, err)
		}
		fileWriter = fh
		fmt.Fprintf(os.Stderr, "kl-scan: writing output to %s\n", f.Out)
	}

	closer := func() {
		if fileWriter != nil {
			_ = fileWriter.Close()
		}
	}

	switch f.Output {
	case "json":
		color.NoColor = true
		w := multiWriter(os.Stdout, fileWriter)
		return &ndjsonSink{w: report.NewNDJSONWriter(w)}, closer, nil
	default:
		cw := report.NewConsoleWriter(os.Stdout)
		if fileWriter != nil {
			return &teeConsoleSink{
				tty:  cw,
				file: report.NewConsoleWriter(fileWriter),
			}, closer, nil
		}
		return &consoleSink{w: cw}, closer, nil
	}
}

func multiWriter(stdout io.Writer, fw io.WriteCloser) io.Writer {
	if fw == nil {
		return stdout
	}
	return io.MultiWriter(stdout, fw)
}

// teeConsoleSink writes findings to both a tty ConsoleWriter and a plain-text
// file ConsoleWriter (no ANSI codes because the file is not a TTY).
type teeConsoleSink struct {
	tty  *report.ConsoleWriter
	file *report.ConsoleWriter
}

func (s *teeConsoleSink) Emit(f report.Finding) {
	_ = s.tty.Write(f)
	_ = s.file.Write(f)
}

func (s *teeConsoleSink) WriteSummary(sum report.Summary) {
	_ = s.tty.WriteSummary(sum)
	_ = s.file.WriteSummary(sum)
}
