#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# Maintainer GPG signing ceremony for clock_skew_sources.json
# ══════════════════════════════════════════════════════════════════════
#
# Produces ``app/services/anonymize/clock_skew_sources.sig.asc`` — an
# armored OpenPGP detached signature over the canonical bytes of
# ``app/services/anonymize/clock_skew_sources.json``. The wallet's
# signed-load path verifies this signature at startup against the
# bundled ``app/services/anonymize/maintainer.asc`` and the
# fingerprint(s) pinned in
# ``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS`` (reused — same
# maintainer signs both registries).
#
# Workflow:
#   1. On first run: bootstrap ``clock_skew_sources.json`` from the
#      in-repo template ``clock_skew_sources.json.example``. Edit it
#      if you want a different source set.
#   2. Sign the canonical bytes with your air-gapped GPG key. Pass
#      the GPG identifier via ``--local-user`` (matches the form you
#      already use for project release signing).
#   3. Verify the round-trip via ``--verify``.
#
# Usage:
#   ./scripts/sign_clock_skew_sources.sh --sign <gpg-identifier>
#   ./scripts/sign_clock_skew_sources.sh --verify
#   ./scripts/sign_clock_skew_sources.sh --canonical-bytes   # write only, no sign
#
# Notes:
#   * Canonical bytes formula (must match clock_skew_sources.py:
#     ``_canonicalize_for_signing``): file content rstrip'd of
#     trailing whitespace + newlines, UTF-8 encoded.
#   * The signing key MUST have the [S] (or [SC]) usage flag. RSA and
#     EdDSA keys are both supported by the wallet's verifier.
#   * On an air-gapped workflow: run ``--canonical-bytes`` to produce
#     /tmp/clock_skew_sources.canonical.bin, transfer that one file to
#     the air-gapped machine, sign it there with
#     ``gpg --armor --detach-sign --local-user <id> /tmp/clock_skew_sources.canonical.bin``
#     to produce ``clock_skew_sources.canonical.bin.asc``, transfer
#     back, and rename to
#     ``app/services/anonymize/clock_skew_sources.sig.asc``.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REGISTRY="${REPO_ROOT}/app/services/anonymize/clock_skew_sources.json"
REGISTRY_TEMPLATE="${REGISTRY}.example"
SIG_FILE="${REPO_ROOT}/app/services/anonymize/clock_skew_sources.sig.asc"
CANONICAL="/tmp/clock_skew_sources.canonical.bin"

# Prefer the project's virtualenv interpreter so the verify path
# has access to the wallet's runtime deps. Falls back to system
# ``python3`` for plain canonical-bytes computation.
if [[ -x "${REPO_ROOT}/.venv/bin/python3" ]]; then
    PY="${REPO_ROOT}/.venv/bin/python3"
else
    PY="$(command -v python3 || true)"
    if [[ -z "$PY" ]]; then
        echo "ERROR: no python3 interpreter found" >&2
        exit 1
    fi
fi

# ── Helpers ──────────────────────────────────────────────────────────

ensure_registry() {
    if [[ ! -f "$REGISTRY" ]]; then
        if [[ -f "$REGISTRY_TEMPLATE" ]]; then
            cp "$REGISTRY_TEMPLATE" "$REGISTRY"
            echo "Initialised ${REGISTRY} from the in-repo template."
            echo "Edit it before signing if you want a different source set."
            echo ""
        else
            echo "ERROR: neither ${REGISTRY} nor ${REGISTRY_TEMPLATE} exist" >&2
            exit 1
        fi
    fi
}

compute_canonical_bytes() {
    # Mirrors clock_skew_sources.py:_canonicalize_for_signing:
    #   canonical = text.rstrip("\n ").encode("utf-8")
    "$PY" -c "
from pathlib import Path
src = Path('${REGISTRY}').read_text(encoding='utf-8')
canonical = src.rstrip('\n ').encode('utf-8')
Path('${CANONICAL}').write_bytes(canonical)
print(f'canonical bytes written: {len(canonical)} bytes -> ${CANONICAL}')
"
}

cmd_canonical_only() {
    ensure_registry
    compute_canonical_bytes
    echo ""
    echo "Next: transfer ${CANONICAL} to your air-gapped signing host"
    echo "and sign with:"
    echo ""
    echo "    gpg --armor --detach-sign --local-user <your-id> \\"
    echo "        --output clock_skew_sources.sig.asc \\"
    echo "        ${CANONICAL}"
    echo ""
    echo "Transfer clock_skew_sources.sig.asc back to ${SIG_FILE}"
    echo "and run \`./scripts/sign_clock_skew_sources.sh --verify\`."
}

cmd_sign() {
    local user_id="$1"
    if [[ -z "$user_id" ]]; then
        echo "ERROR: --sign requires a GPG identifier" >&2
        echo "Usage: $0 --sign <key-id-or-email>" >&2
        exit 1
    fi
    ensure_registry
    compute_canonical_bytes

    gpg --batch --yes --armor \
        --detach-sign \
        --local-user "$user_id" \
        --output "$SIG_FILE" \
        "$CANONICAL"

    echo ""
    echo "Wrote ${SIG_FILE}"
    echo ""
    cmd_verify
}

cmd_verify() {
    if [[ ! -f "$REGISTRY" ]]; then
        echo "ERROR: ${REGISTRY} does not exist — sign first" >&2
        exit 1
    fi
    if [[ ! -f "$SIG_FILE" ]]; then
        echo "ERROR: ${SIG_FILE} does not exist — sign first" >&2
        exit 1
    fi
    # Load .env so the wallet's signed-load path sees
    # ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS.
    if [[ -f "${REPO_ROOT}/.env" ]]; then
        # shellcheck disable=SC1091
        set -a; source "${REPO_ROOT}/.env"; set +a
    fi
    "$PY" <<PY
import sys
sys.path.insert(0, "${REPO_ROOT}")
from app.services.anonymize.clock_skew_sources import (
    load_signed_clock_skew_sources,
    ClockSkewSourcesSignatureError,
)
try:
    entries = load_signed_clock_skew_sources()
    print(f'OK — clock_skew_sources.sig.asc verifies against the bundled '
          f'maintainer.asc + a pinned fingerprint. '
          f'Registry loaded with {len(entries)} entries:')
    for e in entries:
        print(f'  - {e.source_id} @ {e.url}')
except ClockSkewSourcesSignatureError as exc:
    print(f'FAIL — {exc}', file=sys.stderr)
    sys.exit(2)
PY
}

# ── Dispatch ─────────────────────────────────────────────────────────

case "${1:-}" in
    --sign)
        cmd_sign "${2:-}"
        ;;
    --verify)
        cmd_verify
        ;;
    --canonical-bytes|"")
        cmd_canonical_only
        ;;
    *)
        echo "Usage: $0 [--canonical-bytes | --sign <gpg-id> | --verify]" >&2
        exit 1
        ;;
esac
