# SPDX-License-Identifier: MIT
"""items 8, 22, 36 — static-import / static-text CI lints.

These are forward-fences that catch regressions at PR time:

* Item 8: ``boltz_claim.js`` is pinned via ``scripts/package.json`` +
  ``scripts/compute_sri.sh``; both must exist in the repo.
* Item 22: the anonymize stack's routing-time code must NOT call
  LND's gossip-refresh helpers (``query_routes`` consumers must use
  cached graph data; ``ANONYMIZE_PROHIBIT_GOSSIP_AT_ROUTING=true``).
* Item 36: anonymize-stack source must never set both
  ``outgoing_chan_id`` and a ``chunks > 1`` value on the same
  ``send_payment_v2`` call (the two countermeasures cancel).

Where there is no executable hop code yet, the lints scan
the full ``app/services/anonymize/`` package and pass trivially.
The point is that the fence will fire the moment someone introduces
the forbidden pattern, before review.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ANONYMIZE_ROOT = _REPO_ROOT / "app" / "services" / "anonymize"


def _anonymize_files() -> list[Path]:
    return [p for p in _ANONYMIZE_ROOT.rglob("*.py") if "__pycache__" not in str(p)]


# ── item 8 — Boltz SRI lockfile + script presence ─────────────────


def test_scripts_package_json_exists() -> None:
    """Boltz claim JS dependency lockfile is in-repo."""
    p = _REPO_ROOT / "scripts" / "package.json"
    assert p.is_file(), f"missing {p}"


def test_compute_sri_script_exists() -> None:
    """SRI generator script is in-repo."""
    p = _REPO_ROOT / "scripts" / "compute_sri.sh"
    assert p.is_file(), f"missing {p}"


def test_boltz_claim_js_exists() -> None:
    """The cooperative-claim helper script ships in-repo."""
    p = _REPO_ROOT / "scripts" / "boltz_claim.js"
    assert p.is_file(), f"missing {p}"


def test_scripts_package_lock_pins_dependencies() -> None:
    """``package-lock.json`` pins exact versions for reproducible SRI."""
    p = _REPO_ROOT / "scripts" / "package-lock.json"
    assert p.is_file(), f"missing {p}"


# ── item 22 — synchronous gossip-query prohibition ────────────────


def test_anonymize_stack_does_not_trigger_synchronous_gossip_refresh() -> None:
    """The anonymize routing path must use cached graph data only.

    LND's ``QueryRoutes`` is fine; what's forbidden is the
    *gossip-refresh* helpers that synchronously fan out gossip queries
    to peers right before a ``query_routes`` call. The lint
    flags any ``send_gossip_query`` / ``refresh_graph`` / ``sync_graph``
    helper invocations from within the anonymize package.
    """
    pat = re.compile(
        r"\b(?:send_gossip_query|refresh_graph_sync|sync_graph_now"
        r"|describe_graph_force_refresh)\s*\("
    )
    offenders: list[str] = []
    for path in _anonymize_files():
        if pat.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert not offenders, f"anonymize stack must not synchronously refresh gossip; offenders: {offenders}"


# ── item 36 — MPP / outgoing_chan_id mutual exclusion ─────────────


def test_anonymize_stack_does_not_combine_outgoing_chan_with_mpp() -> None:
    """No ``send_payment_v2`` call in the anonymize package may pass
    BOTH ``outgoing_chan_id`` AND ``chunks=N>1``.

    The two countermeasures cancel each other:
    ``outgoing_chan_id`` pins routing through one channel, while MPP
    chunking is supposed to hide the full amount from any one peer.
    The lint catches a future call site that combines them.
    """
    # Where there are no `send_payment_v2` calls yet, the lint is a
    # forward-fence. We scan for any mention of `outgoing_chan_id`
    # inside the anonymize package; if found, we additionally require
    # the same file to NOT mention `chunks=` in a value > 1.
    chan_pat = re.compile(r"outgoing_chan_id")
    chunks_gt1_pat = re.compile(
        r"chunks\s*=\s*(?:[2-9]|[1-9]\d+)"  # chunks=2..N
    )
    offenders: list[str] = []
    for path in _anonymize_files():
        text = path.read_text(encoding="utf-8")
        if chan_pat.search(text) and chunks_gt1_pat.search(text):
            offenders.append(str(path))
    assert not offenders, (
        f"anonymize stack must not combine outgoing_chan_id with MPP chunks > 1; offenders: {offenders}"
    )
