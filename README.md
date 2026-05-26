# kl-scan

One-shot Kubernetes pod log auditor for penetration testing. Streams current logs from all matching pods and detects secrets, API keys, tokens, and other sensitive values using pluggable detection engines. 

> This tool is almost entirely vibe coded, use at your own risk.

## Install

```bash
# Build locally
make build
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
      --detectors strings      Detectors to enable (default [betterleaks])
      --rules string           Path to custom rules TOML (replaces built-in ruleset)

Concurrency:
      --max-streams int        Max concurrent log streams (default 50)
      --max-workers int        Detector worker goroutines (default: NumCPU)

Output:
      --output string          Output format: console|json (default console)
      --redacted               Mask matched secret values in output

Auth:
      --kubeconfig string      Path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
      --context string         Kubeconfig context override
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

# Scan with higher concurrency for large clusters
kl-scan -A --max-streams 100 --max-workers 16
```

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

## Detectors

kl-scan uses a pluggable detector interface. The default detector is **betterleaks** (the actively-maintained successor to gitleaks, written by the original gitleaks author), which covers:

- AWS access/secret keys
- GCP service account JSON
- GitHub personal access tokens
- Slack tokens
- Stripe, Twilio, Sendgrid keys
- JWT tokens
- Generic `password=`, `secret=`, `apikey=` patterns
- Private key headers (RSA, EC, etc.)
- And 200+ more rules from the betterleaks default ruleset

To override the built-in ruleset, pass a custom betterleaks-format TOML file via `--rules`. Note: betterleaks uses CEL expressions for allowlists/filters; basic gitleaks v8 TOML rule blocks (`[[rules]]` with `id`, `regex`, `keywords`) are still compatible, but `[[rules.allowlist]]` blocks are not.

## Adding a Detector (v0.2+)

Implement the `detect.Detector` interface and register it:

```go
// In your detector package:
func init() {
    detect.Register("mydetector", func(rulesPath string) (detect.Detector, error) {
        return &MyDetector{}, nil
    })
}
```

Then enable it with `--detectors betterleaks,mydetector`.
