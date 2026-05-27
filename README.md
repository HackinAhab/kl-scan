# kl-scan

Kubernetes pod log auditor for penetration testing. Streams logs from matching pods and detects secrets, API keys, tokens, and other sensitive values using either the [betterleaks](https://github.com/) detection engine (the actively-maintained successor to gitleaks) or [Trufflehog](https://github.com/trufflesecurity/trufflehog), or both. Trufflehog runs with verification explicitly disabled — kl-scan never makes outbound API calls to validate live secrets.

By default kl-scan does a one-shot scan of historical logs. Pass `--watch` to keep it running continuously throughout an engagement, rotating through the pod set in batches so brief windows of secret exposure aren't missed.

> This tool was made with heavy usage of AI assistance. 

## Install

```bash
# Build locally
just build
# Binary at bin/kl-scan

# Or run directly
go run ./cmd/kl-scan [flags]
```

## Usage

```
kl-scan [flags]

Pod selection:
  -n, --namespace string       Target namespace (default: current context namespace)
  -A, --all-namespaces         Scan across all namespaces
  -l, --selector string        Label selector (e.g. app=api)
      --field-selector string  Field selector (e.g. status.phase=Running)

Log scope:
      --since duration         Include logs since this duration ago (default 1h)
      --tail int               Max lines per container (default 100000; 0=unlimited)
      --max-line-bytes int     Skip lines longer than this in bytes (default 65536)

Detection:
      --detectors strings      Detection engines to enable (default [betterleaks]; available: betterleaks,trufflehog)
      --rules string           Path to custom rules TOML (betterleaks only)

Concurrency:
      --max-streams int        Max concurrent log streams (default 50)
      --max-workers int        Detector worker goroutines (default: NumCPU)

Output:
      --output string          Output format: console|json (default console)
      --redacted               Mask matched secret values in output

Auth:
      --kubeconfig string      Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
      --context string         Kubeconfig context override

Continuous (watch) mode:
      --watch                       Run continuously until cancelled
      --watch-batch-size int        Targets streamed concurrently per batch (default 50)
      --watch-window duration       Observation window per batch (default 1m)
      --watch-since duration        History fetched on first attach to a target (default 30s)
      --cycle-pause duration        Pause between batches (default 1s)
      --summary-interval duration   Heartbeat summary cadence on stderr (default 5m; 0=off)
      --state-file string           Persisted dedup file (default ./kl-scan-state.ndjson)
      --state-disabled              Skip persistence; in-memory dedup only
```

## Examples

```bash
# Scan current namespace, last 1 hour of logs
kl-scan

# Scan all namespaces, last 30 minutes
kl-scan -A --since 30m

# Scan a specific namespace with a label filter, output as NDJSON
kl-scan -n prod -l app=api --output json

# Pipe JSON findings through jq
kl-scan -A --output json | jq 'select(.severity == "high")'

# Redact secret values in output
kl-scan -A --redacted

# Use a custom betterleaks rules file
kl-scan --rules ./my-rules.toml

# Run both detection engines (betterleaks + trufflehog, deduped per finding)
kl-scan -A --detectors betterleaks,trufflehog

# Trufflehog only
kl-scan -A --detectors trufflehog

# Scan with higher concurrency for large clusters
kl-scan -A --max-streams 100 --max-workers 16

# Continuous watch: rotate through all pods in prod, 50 at a time, 60s each
kl-scan -n prod --watch

# Tighter rotation for a small fleet (everything observed every minute)
kl-scan -l app=api --watch --watch-batch-size 20 --watch-window 30s

# Continuous run with NDJSON output to a file, heartbeat every 2 minutes
kl-scan -A --watch --output json --out findings.ndjson --summary-interval 2m
```

## Continuous (watch) mode

`--watch` keeps kl-scan running until you cancel it (Ctrl-C / SIGTERM). Instead of holding open a long-lived stream against every pod — which scales poorly past a few hundred pods — kl-scan rotates through the pod set:

1. A k8s informer maintains a live view of running pod containers (handles new pods and terminated pods automatically).
2. kl-scan picks `--watch-batch-size` uncovered targets (default 50).
3. It streams them with `follow=true` for `--watch-window` (default 60s).
4. The batch is closed; targets are marked covered for this cycle.
5. Repeat until every target has been covered, then reset and start the next cycle.

### Coverage tradeoff

Per-target observation per cycle is fixed at one `--watch-window`. The fraction of time any given target is being observed depends on the cluster size:

| Targets | Batch | Window | Cycle ≈ | Coverage |
|---|---|---|---|---|
| 50  | 50 | 60s | 60s  | 100% |
| 200 | 50 | 60s | ~4m  | 25%  |
| 1000| 50 | 60s | ~20m | 5%   |
| 5000| 50 | 60s | ~100m| 1%   |

A *recurring* leak (something that prints credentials repeatedly) is caught within at most one cycle. A *one-shot* leak is caught with probability ≈ coverage. To increase coverage: scope with `--namespace` / `--selector`, raise `--watch-batch-size`, or lower `--watch-window`.

kl-scan logs the predicted coverage at startup and warns if it falls below 5%.

### Dedup state

Findings are deduped using `<podUID>|<detector>|<rule>|sha256(value)`. In watch mode this set is persisted to `./kl-scan-state.ndjson` (configurable via `--state-file`) so the same secret in the same `(pod, container, rule)` is reported once and not re-flooded on every rotation. The state file is append-only — already-seen keys are never rewritten.

A pod restart produces a new `PodUID`, which legitimately re-fires findings (you want to know the secret is still present after a redeploy).

### Single instance

The state file is protected by an exclusive `flock`. Trying to start a second kl-scan against the same state file aborts with a clear error. Use `--state-file` to point at a different path or `--state-disabled` to skip persistence entirely.

### Heartbeat summaries

`--summary-interval` (default 5m, `0` to disable) prints an interim summary to **stderr** showing total findings, severity breakdown, current cycle, and target count. The final summary is emitted on shutdown.

### Pod lifecycle

The informer reacts to pod ADD / UPDATE / DELETE events:

- New pods that match the selectors are added to the rotation automatically.
- Terminated pods are removed; in-flight streams to them end naturally.
- Pods that fail to stream more than 3 times in a cycle are skipped for that cycle and retried on the next one.

### Exit codes (watch mode)

Same as one-shot mode (see [Exit Codes](#exit-codes) below). Watch mode exits only on signal, not after a single pass.

## Output

### Console (default)

```
prod/api-7d4f-x2k [api]  HIGH  betterleaks:aws-access-token  line 482
  AKIAIOSFODNN7EXAMPLE
  context: env AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

Summary: 3 findings across 2 pods (1 high, 2 medium)  •  scanned 47 pods / 51 containers in 12.3s
```

### JSON (NDJSON — one finding per line)

```json
{"detector":"betterleaks","rule_id":"aws-access-token","description":"AWS Access Key","severity":"high","namespace":"prod","pod":"api-7d4f-x2k","container":"api","node":"ip-10-0-1-23","timestamp":"2026-05-26T14:02:11Z","line_no":482,"match":"AKIAIOSFODNN7EXAMPLE","value_sha256":"a1b2...","context":"env AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE","entropy":4.82,"redacted":false}
```

Run-level summary is printed to **stderr** so `stdout` stays clean for piping.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No findings |
| `1`  | One or more findings present |
| `2`  | Runtime or configuration error |
| `3`  | Partial success (some streams failed) |

## Required RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kl-scan
rules:
- apiGroups: [""]
  resources: [pods]
  verbs: [get, list]
- apiGroups: [""]
  resources: [pods/log]
  verbs: [get]
```

## Detection

kl-scan ships with two detection engines. Either or both can be enabled per
run via `--detectors` (default: `betterleaks`).

### betterleaks (default)

The actively-maintained successor to gitleaks, written by the original
gitleaks author. The bundled default ruleset covers:

- AWS access/secret keys
- GCP service account JSON
- GitHub personal access tokens
- Slack tokens
- Stripe, Twilio, Sendgrid keys
- JWT tokens
- Generic `password=`, `secret=`, `apikey=` patterns
- Private key headers (RSA, EC, etc.)
- And 200+ more rules from the betterleaks default ruleset

To override the built-in ruleset, pass a custom betterleaks-format TOML file
via `--rules`. Note: betterleaks uses CEL expressions for allowlists/filters;
basic gitleaks v8 TOML rule blocks (`[[rules]]` with `id`, `regex`, `keywords`)
are still compatible, but `[[rules.allowlist]]` blocks are not.

### trufflehog

[Trufflehog](https://github.com/trufflesecurity/trufflehog)'s ~800 default
detectors are also bundled. Enable them with `--detectors trufflehog` or
run both engines simultaneously with `--detectors betterleaks,trufflehog`.

```bash
# trufflehog only
kl-scan -A --detectors trufflehog

# both engines, deduped per (pod, rule, secret)
kl-scan -A --detectors betterleaks,trufflehog
```

**Verification is permanently disabled.** Trufflehog's headline feature is
active credential validation against provider APIs (AWS, GitHub, Stripe,
etc.). kl-scan hardcodes `verify=false` on every detector call — the tool
will never make outbound API calls to validate live secrets, and there is
no flag to enable it. This is intentional for pentest engagements: outbound
validation creates audit trails on the target's third-party accounts and
may exceed engagement scope.

**Decoders.** Trufflehog also includes decoders that surface secrets buried
in encoded text. kl-scan applies the following per log line, single-pass
(no chaining):

- Base64 — catches secrets in `Authorization: Basic ...`, dumped k8s
  Secrets, encoded request/response bodies.
- UTF-16 — Windows containers and some .NET workloads emit UTF-16.
- Escaped Unicode (`\u00xx`) — common output from JSON loggers that
  escape non-ASCII bytes.

The HTML decoder is intentionally excluded; it is feature-gated off in
Trufflehog itself and adds no value for log streams.

**Caveats.**

- kl-scan is line-oriented. Multi-line secrets (e.g. a full PEM block
  spread across several log lines) will not reassemble across lines.
- The `--rules` flag applies only to betterleaks. Trufflehog uses its
  built-in detector set unconditionally; custom-detector YAML support is
  not exposed in the current adapter.
- Each line is run through a keyword pre-filter (Aho-Corasick) before
  detector regex evaluation, but per-line CPU cost is still meaningfully
  higher than betterleaks. For large clusters consider scoping with
  `--namespace` / `--selector`.

### Detector dedup

When both engines are enabled, the same secret found by both will appear
as two findings (one per detector). The dedup key is
`<podUID>|<detector>|<rule>|sha256(value)`, so an operator can compare
engine coverage without per-engine flooding.
