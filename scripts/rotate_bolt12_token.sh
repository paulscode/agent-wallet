#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# rotate_bolt12_token.sh — rotate the BOLT 12 gateway bearer token.
#
# The wallet (api + celery-worker) and the bolt12-gateway sidecar
# share a single bearer token (``BOLT12_GATEWAY_TOKEN``) that
# authenticates every gRPC call from the wallet to the gateway.
# Docker Compose injects the same env var into both sides from
# ``.env``, so they always agree.
#
# WHY ROTATE
# ──────────
# The token is the only auth boundary on the gRPC surface; the
# bind address inside the private docker network is not the
# security boundary (see docker-compose.yml). Rotating limits the
# half-life of any leak — e.g. a transient log capture, an old
# ``.env`` snapshot in a backup, a compromised developer machine
# that briefly held the file.
#
# RECOMMENDED CADENCE
# ───────────────────
# * On every operator credential change (new admin, departure).
# * After any incident that may have exposed ``.env`` or container
#   memory (host root compromise, accidental upload to a paste
#   site, dumped core file, etc).
# * Otherwise: annually as routine hygiene.
#
# OPERATIONAL NOTES
# ─────────────────
# * The wallet and gateway must rotate together: the bearer is
#   pre-shared, so any window where their values disagree triggers
#   ``UNAUTHENTICATED`` and the wallet's BOLT 12 runtime fails its
#   health probe. This script enforces the lock-step by bouncing
#   both services in a single ``docker compose up -d`` after the
#   ``.env`` update.
# * In-flight BOLT 12 invoice_request flows (typically <1 s) may
#   land as transient errors and be retried by the orchestrator's
#   normal reconcile loop. No fund loss path — invreqs do not
#   commit anything to disk on the gateway.
#
# USAGE
# ─────
#     ./scripts/rotate_bolt12_token.sh         # prompts before applying
#     ./scripts/rotate_bolt12_token.sh --yes   # non-interactive
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
NON_INTERACTIVE="false"

for arg in "$@"; do
    case "$arg" in
        -y|--yes) NON_INTERACTIVE="true" ;;
        -h|--help)
            sed -n '1,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

if [[ ! -f "$ENV_FILE" ]]; then
    echo "error: $ENV_FILE not found. Run ./start.sh config first." >&2
    exit 1
fi

# Generate a fresh token. Same shape as start.sh's wizard: 32 bytes
# of cryptographic entropy, urlsafe-base64 encoded (~43 chars).
NEW_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
if [[ -z "$NEW_TOKEN" ]]; then
    echo "error: failed to generate a new token" >&2
    exit 1
fi

# Show the operator what's about to change. We deliberately do NOT
# print the OLD token; only confirm that a value exists.
if grep -q '^BOLT12_GATEWAY_TOKEN=' "$ENV_FILE"; then
    OLD_PRESENT="yes"
else
    OLD_PRESENT="no  (no existing line in .env — will be added)"
fi
echo "BOLT12_GATEWAY_TOKEN rotation"
echo "─────────────────────────────"
echo "  env file:          $ENV_FILE"
echo "  current token set: $OLD_PRESENT"
echo "  new token length:  ${#NEW_TOKEN} chars"
echo
echo "After update the wallet (api + celery-worker) and the"
echo "bolt12-gateway service will be restarted together so they"
echo "rotate in lock-step. A brief BOLT 12 outage (<5 s) is normal."

if [[ "$NON_INTERACTIVE" != "true" ]]; then
    read -r -p "Proceed? [y/N] " ans
    case "$ans" in
        y|Y|yes|YES) ;;
        *) echo "aborted."; exit 0 ;;
    esac
fi

# Update the .env line in-place. Two cases: the line exists (rotate),
# or it doesn't (add). We avoid ``sed -i`` portability quirks by
# writing to a sibling tempfile and renaming atomically.
TMP_FILE="$(mktemp "${ENV_FILE}.XXXXXX")"
# Preserve permissions of the original .env (typically 0600).
if command -v stat >/dev/null 2>&1; then
    chmod --reference="$ENV_FILE" "$TMP_FILE" 2>/dev/null || chmod 0600 "$TMP_FILE"
else
    chmod 0600 "$TMP_FILE"
fi
if grep -q '^BOLT12_GATEWAY_TOKEN=' "$ENV_FILE"; then
    # Replace existing line. Use awk so a token containing ``/``,
    # ``&``, etc. (unlikely with token_urlsafe but be defensive)
    # cannot break sed's substitution syntax.
    awk -v tok="$NEW_TOKEN" '
        BEGIN { replaced = 0 }
        /^BOLT12_GATEWAY_TOKEN=/ { print "BOLT12_GATEWAY_TOKEN=" tok; replaced = 1; next }
        { print }
        END { if (!replaced) print "BOLT12_GATEWAY_TOKEN=" tok }
    ' "$ENV_FILE" > "$TMP_FILE"
else
    cp "$ENV_FILE" "$TMP_FILE"
    printf '\n# Added by scripts/rotate_bolt12_token.sh\nBOLT12_GATEWAY_TOKEN=%s\n' "$NEW_TOKEN" >> "$TMP_FILE"
fi
mv "$TMP_FILE" "$ENV_FILE"

echo
echo "✓ .env updated."
echo
echo "Restarting bolt12-gateway, api, and celery-worker together so"
echo "they pick up the new token in lock-step..."
echo

# Re-deploy all three together. ``up -d`` recreates only containers
# whose effective config changed (i.e. those that read
# BOLT12_GATEWAY_TOKEN from .env via env_file). We list them
# explicitly so an unrelated service issue doesn't block the
# rotation.
(cd "$REPO_ROOT" && docker compose up -d bolt12-gateway api celery-worker)

echo
echo "✓ Rotation complete."
echo "  Verify with:  docker compose logs --since=30s api | grep -i bolt12"
echo "  Expected:     a 'BOLT 12 runtime started' line and no UNAUTHENTICATED."
