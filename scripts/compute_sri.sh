#!/usr/bin/env bash
# Compute Subresource Integrity (SRI) sha384 digests for the dashboard's
# pinned vendor assets. Run this once per dependency upgrade and paste
# the resulting "integrity=..." values into the dashboard templates.
#
# the dashboard
# now serves these assets from ``app/dashboard/static/vendor/`` rather
# than ``cdn.jsdelivr.net``. Pass ``--vendored`` to digest the local
# files; pass URLs explicitly to digest CDN copies (e.g. for upgrade
# verification before replacing the local file).
#
# Usage:
#   scripts/compute_sri.sh                    # digest the vendored files
#   scripts/compute_sri.sh --remote           # digest the upstream URLs
#   scripts/compute_sri.sh URL1 URL2 ...      # ad-hoc URLs / paths
#
# Requires: curl, openssl, base64.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR_DIR="$REPO_ROOT/app/dashboard/static/vendor"

DEFAULT_VENDORED=(
  "$VENDOR_DIR/alpinejs-csp-3.15.11.min.js"
  "$VENDOR_DIR/lucide-0.469.0.min.js"
  "$VENDOR_DIR/qrcode-1.4.4.min.js"
)

DEFAULT_REMOTE=(
  "https://cdn.jsdelivr.net/npm/@alpinejs/csp@3.15.11/dist/cdn.min.js"
  "https://cdn.jsdelivr.net/npm/lucide@0.469.0/dist/umd/lucide.min.js"
  "https://cdn.jsdelivr.net/npm/qrcode@1.4.4/build/qrcode.min.js"
)

mode="vendored"
if [[ ${1:-} == "--remote" ]]; then
  mode="remote"
  shift
fi

if [[ $# -gt 0 ]]; then
  inputs=("$@")
elif [[ "$mode" == "remote" ]]; then
  inputs=("${DEFAULT_REMOTE[@]}")
else
  inputs=("${DEFAULT_VENDORED[@]}")
fi

for input in "${inputs[@]}"; do
  if [[ "$input" =~ ^https?:// ]]; then
    digest=$(curl -fsSL "$input" | openssl dgst -sha384 -binary | base64 -w0 2>/dev/null || \
             curl -fsSL "$input" | openssl dgst -sha384 -binary | base64)
  else
    digest=$(openssl dgst -sha384 -binary "$input" | base64 -w0 2>/dev/null || \
             openssl dgst -sha384 -binary "$input" | base64)
  fi
  printf '%s\n  integrity="sha384-%s"\n\n' "$input" "$digest"
done
