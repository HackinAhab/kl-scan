package main

import (
	"context"
	"fmt"
	"io"
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

	// Side-effect: registers the betterleaks detector.
	_ "kl-scan/internal/detect/betterleaks"
)

var version = "0.1.0"

func main() {
	os.Exit(run())
}

func run() int {
	var f cli.Flags

	root := &cobra.Command{
		Use:   "kl-scan",
		Short: "Scan Kubernetes pod logs for secrets and sensitive values",
		Long: `kl-scan is a one-shot Kubernetes pod log auditor for penetration testing.
It streams current logs from all matching pods and detects secrets, API keys,
tokens, and other sensitive values using pluggable detection engines.`,
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
	fl.DurationVar(&f.Since, "since", time.Hour, "include logs since this duration ago (e.g. 30m, 2h)")
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
	fl.StringVar(&f.LogLevel, "log", "error", "log level: error|info|debug\n  error: silent (suppresses client-go noise)\n  info:  stream open/close per container\n  debug: full client-go request and throttle details")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root.SetContext(ctx)

	if err := root.ExecuteContext(ctx); err != nil {
		// cobra prints the error; we just set exit code.
		return cli.ExitError
	}

	// Exit code is set by runScan via os.Exit; reaching here means no RunE was
	// invoked (e.g. --help). Return clean.
	return cli.ExitClean
}

// runScan orchestrates the full scan and exits with the appropriate code.
func runScan(ctx context.Context, f cli.Flags) error {
	start := time.Now()

	// Initialise logging + klog verbosity before any kube calls.
	if err := logger.Init(f.LogLevel); err != nil {
		return err
	}

	// Validate output flag early.
	switch f.Output {
	case "console", "json":
	default:
		return fmt.Errorf("unknown output format %q; valid values: console, json", f.Output)
	}

	// Build detectors.
	detectors, err := detect.Build(f.Detectors, f.Rules)
	if err != nil {
		return err
	}

	// Build kube client.
	kubeClient, err := kube.NewClient(kube.Config{
		KubeconfigPath: f.Kubeconfig,
		ContextName:    f.Context,
		Namespace:      f.Namespace,
		AllNamespaces:  f.AllNamespaces,
	})
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	// Discover targets.
	targets, err := kube.DiscoverTargets(ctx, kubeClient, kube.DiscoveryConfig{
		Namespace:     kubeClient.Namespace,
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

	// Build output sink.
	sink, closeSink, err := buildSink(f)
	if err != nil {
		return err
	}
	defer closeSink()

	// Build pipeline.
	pl := detect.NewPipeline(detectors, sink, f.Redacted, f.MaxWorkers)

	// Start streamer and pipeline concurrently.
	lineCh := make(chan detect.LogLine, 4096)

	streamErrCh := make(chan int, 1)
	go func() {
		errs := kube.StreamAll(ctx, kubeClient, targets, kube.StreamConfig{
			SinceSeconds: kube.SinceToSeconds(f.Since),
			TailLines:    f.Tail,
			MaxLineBytes: f.MaxLineBytes,
			MaxStreams:    f.MaxStreams,
		}, lineCh)
		close(lineCh)
		streamErrCh <- errs
	}()

	// Pipeline blocks until lineCh is closed.
	pl.Run(ctx, lineCh)

	streamErrs := <-streamErrCh

	elapsed := time.Since(start)
	total, bySev, podsWithFindings := pl.Stats()

	sink.WriteSummary(report.Summary{
		TotalFindings:     total,
		BySeverity:        bySev,
		PodsScanned:       podCount,
		ContainersScanned: containerCount,
		PodsWithFindings:  podsWithFindings,
		DurationSeconds:   elapsed.Seconds(),
		StreamErrors:      streamErrs,
	})

	// Determine exit code.
	exitCode := cli.ExitClean
	if total > 0 {
		exitCode = cli.ExitFindings
	}
	if streamErrs > 0 && total == 0 {
		exitCode = cli.ExitPartial
	}
	if streamErrs > 0 && total > 0 {
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
	fmt.Fprintf(os.Stderr,
		"kl-scan: %d findings (%s) across %d pods  •  scanned %d pods / %d containers in %.1fs",
		sum.TotalFindings, parts, sum.PodsWithFindings,
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
				file: report.NewConsoleWriter(fileWriter), // non-TTY → no ANSI
			}, closer, nil
		}
		return &consoleSink{w: cw}, closer, nil
	}
}

// multiWriter returns a writer that copies to stdout and, if fw is non-nil,
// to the file as well.
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
