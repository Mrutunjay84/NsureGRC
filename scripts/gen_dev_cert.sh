#!/usr/bin/env bash
# DEV ONLY (D-P6-001). Generates a self-signed TLS cert for the local HTTPS dev server
# (scripts/dev_run_https.py) into .dev-certs/ (gitignored, regenerate per machine - never commit).
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_DIR/.dev-certs"
mkdir -p "$OUT"
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -keyout "$OUT/localhost.key" -out "$OUT/localhost.crt" \
  -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "generated $OUT/localhost.crt + localhost.key"
