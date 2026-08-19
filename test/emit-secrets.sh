#!/usr/bin/env bash
# kl-scan detection test harness
# Run this script inside a pod in a local kind cluster.
# It emits lines to stdout that kl-scan should detect, covering the most
# common betterleaks rule categories. Each section notes the expected rule ID.
#
# Quickstart — run from your host:
#
#   # 1. Start the emitter pod
#   kubectl run kl-scan-test \
#     --image=busybox --restart=Never \
#     --command -- sh -c "$(cat test/emit-secrets.sh)"
#
#   # 2. Scan it (give the pod ~5s to start)
#   kl-scan -n default -l run=kl-scan-test --since 5m --log info
#
#   # Or scan and pipe to jq for easy reading
#   kl-scan -n default -l run=kl-scan-test --since 5m --output json | jq .
#
#   # 3. Clean up
#   kubectl delete pod kl-scan-test

set -euo pipefail

log() { echo "[kl-scan-test] $*" >&2; }

# ---------------------------------------------------------------------------
# 1. AWS
# Expected rule: aws-access-token
# Regex: (AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}   entropy >= 3
# ---------------------------------------------------------------------------
log "section: AWS"
echo "AWS_ACCESS_KEY_ID=AKIAI3QRMU4GQWDVF4XQ"
echo "export AWS_ACCESS_KEY_ID=AKIAI3QRMU4GQWDVF4XQ"
echo "Initialising client with key AKIAI3QRMU4GQWDVF4XQ and region us-east-1"
# STS temporary credential (ASIA prefix)
echo "Temporary STS credential: ASIAI3QRMU4GQWDVF4XQ region=us-east-1"

# ---------------------------------------------------------------------------
# 2. GitHub
# Expected rules: github-pat, github-fine-grained-pat, github-oauth
# ---------------------------------------------------------------------------
log "section: GitHub"
echo "GITHUB_TOKEN=ghp_xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2"
echo "Cloning repo with: ghp_xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2"
# Fine-grained PAT: github_pat_ + exactly 82 word chars
echo "fine-grained PAT: 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"
# OAuth token
echo "oauth: gho_xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2"

# ---------------------------------------------------------------------------
# 3. GitLab
# Expected rules: gitlab-pat, gitlab-cicd-job-token
# ---------------------------------------------------------------------------
log "section: GitLab"
echo "GITLAB_TOKEN=glpat-xK9mN2pQ7vR4wY1zA8bC"
echo "CI_JOB_TOKEN=glpat-xK9mN2pQ7vR4wY1zA8bC"
echo "CI job token: glcbt-01_xK9mN2pQ7vR4wY1zA8bC"

# ---------------------------------------------------------------------------
# 4. Stripe
# Expected rule: stripe-access-token
# Regex: (sk|rk)_(test|live|prod)_[a-zA-Z0-9]{10,99}
# ---------------------------------------------------------------------------
log "section: Stripe"
echo "STRIPE_SECRET_KEY=sk_live_xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
echo "test key: sk_test_xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
echo "restricted key: rk_live_xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"

# ---------------------------------------------------------------------------
# 5. Slack
# Expected rules: slack-bot-token, slack-webhook-url, slack-legacy-token
# ---------------------------------------------------------------------------
log "section: Slack"
echo "SLACK_BOT_TOKEN=xoxb-1234567890-1234567890-xK9mN2pQ7vR4wY1zA8bC"
echo "legacy token: xoxp-1234567890123-1234567890123-1234567890123-xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9m"
echo "Posting to webhook: https://hooks.slack.com/services/ABCDEFGHIJK/ABCDEFGHIJK/ABCDEFGHIJKabcdefghijklmn"

# ---------------------------------------------------------------------------
# 6. SendGrid
# Expected rule: sendgrid-api-token (or generic-api-key fallback)
# Regex: SG\.[a-z0-9=_\-\.]{66}  terminated by whitespace/EOL
# The specific rule requires no leading = sign; generic-api-key fires on KEY= prefix.
# ---------------------------------------------------------------------------
log "section: SendGrid"
# Standalone (hits sendgrid-api-token): exactly 66 chars after SG., newline-terminated
printf 'SG.5hfj3_pv59l4y9y791s=1hytl.rm5g3oroir7powk=l_y_dwb-9nis.0zn0u3ky_v9\n'
# With KEY= prefix (hits generic-api-key)
echo "SENDGRID_API_KEY=SG.xK9mN2pQ7v.xK9mN2pQ7v.xK9mN2pQ7v.xK9mN2pQ7v.xK9mN2pQ7v.xK9mN2pQ7v"

# ---------------------------------------------------------------------------
# 7. Twilio
# Expected rule: twilio-api-key
# Regex: SK[0-9a-fA-F]{32}
# ---------------------------------------------------------------------------
log "section: Twilio"
echo "TWILIO_API_KEY=SKabcdef1234567890abcdef1234567890"
echo "Twilio auth: SKabcdef1234567890abcdef1234567890"

# ---------------------------------------------------------------------------
# 8. OpenAI
# Expected rule: openai-api-key
# Regex: sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}
# ---------------------------------------------------------------------------
log "section: OpenAI"
echo "OPENAI_API_KEY=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"
echo "openai_key=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"

# ---------------------------------------------------------------------------
# 9. GCP
# Expected rule: gcp-api-key (or generic-api-key)
# Regex: AIza[\w-]{35}
# ---------------------------------------------------------------------------
log "section: GCP"
echo "GCP_API_KEY=AIzaSyxK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
echo "Initialised GCP client with key AIzaSyxK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"

# ---------------------------------------------------------------------------
# 10. JWT
# Expected rule: jwt
# Regex: ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.([a-zA-Z0-9\/\\_-]{10,}={0,2})?
# ---------------------------------------------------------------------------
log "section: JWT"
echo "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
echo "token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzAwMDAwMDAwfQ.xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
# Regression: low-entropy HS256 session token wrapped in single quotes.
# Previously missed because:
#   1. trufflehog's JWT detector intentionally skips HMAC-signed JWTs
#      (HS256/HS384/HS512) — see trufflehog/pkg/detectors/jwt/jwt.go.
#   2. betterleaks's default `jwt` rule has an entropy<=3.0 filter that
#      rejects JWTs with structured low-entropy payloads (human-readable
#      usernames, role names like "Guest", short org names).
# kl-scan now clears that betterleaks entropy filter via applyKLScanOverrides
# in internal/detect/betterleaks/detector.go.
echo "accesstoken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.XBbaOOjP86GJ1DKDzEykL8i13e6P_e7yaUA8WBfLAls'"

# ---------------------------------------------------------------------------
# 10b. JWT split across line boundary (cross-line detection regression)
#
# The kubelet's CRI log driver splits any single container stdout write
# that exceeds its internal buffer (commonly ~16 KiB) into consecutive
# log entries. The apiserver's pods/log endpoint emits these as separate
# newline-delimited lines. A JWT straddling that split is invisible to any
# strictly per-line detector.
#
# This fixture writes a line long enough that the JWT lands across the
# kubelet boundary. kl-scan's streamer sliding-window pass
# (internal/kube/window.go) concatenates adjacent lines and re-runs
# detection on the joined view to catch these cases.
#
# Note on the pad length: 16380 bytes places the mid-JWT split near the
# common 16384-byte kubelet boundary. The exact split point varies by
# runtime (some count the timestamp prefix toward the limit, some don't);
# ±64 bytes of adjustment may be needed when testing against a specific
# cluster runtime. The unit test in internal/kube/window_test.go uses a
# controlled split and does not depend on this approximation.
# ---------------------------------------------------------------------------
log "section: JWT (cross-line split regression)"
printf '%016380s%s\n' ' ' "accesstoken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NWZkMWU1NC0yZGE0LTRmYzUtODA4NS01ZDA4ZmFmZmQ3MjUiLCJzdWIiOiJTaHJhZGRoYS5QYXJpa2gxIiwiZW5kX3VzZXIiOiJTaHJhZGRoYS5QYXJpa2gxIiwib3JnX25hbWUiOiJHTTRDIiwiYWNjdE5hbWUiOiJ3M0lCTSIsInJvbGUiOiJHdWVzdCIsInR5cGUiOiJTU08iLCJleHAiOjE3ODAzMDI2MzEsImlhdCI6MTc4MDI5OTAzMX0.olVIiAsroMhXhSh8howvwsdkFTmrXnA2wckgUK4APog'"

# ---------------------------------------------------------------------------
# 11. Private key (PEM)
# Expected rule: private-key
# Regex matches across the full multi-line PEM block; kl-scan feeds one line
# at a time so the PEM header alone won't fire. Emit the entire block on one
# line (as it often appears in env vars / JSON logs) to guarantee detection.
# ---------------------------------------------------------------------------
log "section: Private Key"
# Single-line form (common in env vars, JSON, docker logs)
echo "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA\nxK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL\n-----END RSA PRIVATE KEY-----"
echo "key: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFxK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9m\n-----END PRIVATE KEY-----"

# ---------------------------------------------------------------------------
# 12. Shopify
# Expected rule: shopify-access-token
# Regex: shpat_[a-fA-F0-9]{32}
# ---------------------------------------------------------------------------
log "section: Shopify"
echo "SHOPIFY_TOKEN=shpat_abcdef1234567890abcdef1234567890"
echo "shopify_admin_api_access_token=shpat_ABCDEF1234567890ABCDEF1234567890"

# ---------------------------------------------------------------------------
# 13. HashiCorp Vault
# Expected rule: vault-service-token (or generic-api-key fallback)
# Regex: hvs\.[\w-]{90,120}  entropy >= 3.5
# ---------------------------------------------------------------------------
log "section: Vault"
echo "VAULT_TOKEN=hvs.xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA8bC5dE0f"
echo "vault_token: hvs.xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA8bC5dE0f"

# ---------------------------------------------------------------------------
# 14. DigitalOcean
# Expected rule: digitalocean-access-token
# Regex: doo_v1_[a-f0-9]{64}
# ---------------------------------------------------------------------------
log "section: DigitalOcean"
echo "DO_TOKEN=doo_v1_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
echo "digitalocean_token=doo_v1_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

# ---------------------------------------------------------------------------
# 15. Grafana
# Expected rule: grafana-api-key
# Regex: eyJrIjoi[A-Za-z0-9]{70,400}={0,3}
# ---------------------------------------------------------------------------
log "section: Grafana"
echo "GRAFANA_KEY=eyJrIjoixK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jLxK9mN2pQ="

# ---------------------------------------------------------------------------
# 16. npm
# Expected rule: npm-access-token
# Regex: npm_[a-z0-9]{36}  (lowercase only)
# ---------------------------------------------------------------------------
log "section: npm"
echo "NPM_TOKEN=npm_xk9mn2pq7vr4wy1za8bc5de0fg3hi6jl9mn2"
echo "//registry.npmjs.org/:_authToken=npm_xk9mn2pq7vr4wy1za8bc5de0fg3hi6jl9mn2"

# ---------------------------------------------------------------------------
# 17. Heroku
# Expected rule: heroku-api-key (generic match: "heroku" context + UUID value)
# ---------------------------------------------------------------------------
log "section: Heroku"
echo "HEROKU_API_KEY=xK9mN2pQ-7vR4-wY1z-A8bC-5dE0fG3hI6jL"
echo "heroku_token=xK9mN2pQ-7vR4-wY1z-A8bC-5dE0fG3hI6jL"

# ---------------------------------------------------------------------------
# 18. Generic API key / password patterns
# Expected rule: generic-api-key
# Triggers on keyword (key/secret/password/token) + high-entropy value
# ---------------------------------------------------------------------------
log "section: Generic"
echo "api_key=xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
echo "DB_PASSWORD=xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI"
echo "APP_SECRET=xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
echo "auth_token=xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL"
echo "secret_key=xK9mN2pQ7vR4wY1zA8bC5dE0fG3hI6jL9mN2"

# ---------------------------------------------------------------------------
# 19. Kubernetes Secret YAML embedded in log output
# Expected rule: kubernetes-secret-yaml
# ---------------------------------------------------------------------------
log "section: Kubernetes Secret YAML"
cat <<'EOF'
Applying manifest:
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
data:
  username: YWRtaW4=
  password: c3VwZXJzZWNyZXRwYXNzd29yZA==
EOF

# ---------------------------------------------------------------------------
# Done — sleep so kl-scan can stream logs before the pod exits.
# kl-scan default --since=1h will catch this regardless, but sleeping
# ensures the pod is still Running when discovery happens.
# ---------------------------------------------------------------------------
log "emission complete — sleeping 120s"
sleep 120
