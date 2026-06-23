# SPDX-License-Identifier: MIT
"""BOLT 12 blinded-path diagnostics: htlc_max vs live remote_balance.

Two surfaces:

* :func:`collect_channel_drift_snapshot` — one-shot snapshot of every
  open channel's ``(capacity, local_balance, remote_balance,
  gossiped_inbound_max_htlc_msat, ratio)``. Used by the diagnostic
  endpoint at ``GET /v1/bolt12/diagnostics/path-snapshot`` and by
  the periodic Celery check.

* :func:`run_drift_check` — runs the snapshot, emits a structured
  WARN log line + an audit row when any channel's ratio exceeds
  ``BOLT12_HTLC_MAX_DRIFT_RATIO_ALERT``. Bounded best-effort: a
  per-channel LND error is logged and the row is skipped, not
  raised.

Why this matters: LND's blinded-path ``max_htlc_msat`` derives
from the gossiped channel ``max_htlc`` policy, which is typically
set ~99% of capacity at channel-open and never recomputed against
the live ``remote_balance``. The 2026-06-05 Ocean payout failure
showed our Megalithic-backup channel advertising 60,000 sat
``max_htlc`` against a 20,000 sat live ``remote_balance`` — a
3.0x over-claim. Payers' pathfinders pick the over-claimed
path preferentially, then the HTLC fails mid-route at the
under-funded hop.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any

from app.services.lnd_service import LNDService

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ChannelDriftRow:
    """Snapshot of one channel's policy-vs-balance state."""

    chan_id: str
    peer_pubkey: str
    peer_alias: str
    active: bool
    capacity_sat: int
    local_balance_sat: int
    remote_balance_sat: int
    """Live ``remote_balance`` — what a payer can currently push
    to us via this channel (modulo reserve)."""

    gossiped_inbound_max_htlc_sat: int | None
    """Gossiped ``max_htlc_msat`` (converted to sat) on the
    direction from our peer to us. ``None`` when the graph has no
    edge entry for this channel (private channels without
    ``-option_scid_alias`` advertised, or recently-opened
    channels not yet gossiped)."""

    ratio_advertised_to_receivable: float | None
    """``gossiped_inbound_max_htlc_sat / remote_balance_sat``.
    ``None`` when the gossiped value is missing, or when
    ``remote_balance_sat == 0`` (channel fully spent). Values >1.0
    indicate over-claim; values >>1.0 are the failure-mode
    signal."""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def collect_channel_drift_snapshot(
    lnd: LNDService,
) -> list[ChannelDriftRow]:
    """One-shot snapshot of every active channel's drift state.

    Returns rows sorted by ``ratio_advertised_to_receivable``
    descending (worst offender first). Best-effort: a per-channel
    graph-edge lookup failure surfaces as
    ``gossiped_inbound_max_htlc_sat=None`` rather than raising.
    """
    channels, err = await lnd.get_channels()
    if err is not None or channels is None:
        logger.warning("bolt12 path diagnostics: list_channels failed: %s", err)
        return []

    info, info_err = await lnd.get_info()
    if info_err is not None or info is None:
        logger.warning("bolt12 path diagnostics: get_info failed: %s", info_err)
        return []
    our_pubkey = info.get("identity_pubkey", "") if isinstance(info, dict) else ""

    rows: list[ChannelDriftRow] = []
    for ch in channels:
        chan_id = ch.get("chan_id", "")
        if not chan_id:
            continue
        peer_pubkey = ch.get("remote_pubkey", "")
        edge, edge_err = await lnd.get_channel_edge(chan_id)
        gossiped_max_msat = (
            _extract_inbound_max_htlc(
                edge,
                our_pubkey=our_pubkey,
                peer_pubkey=peer_pubkey,
            )
            if edge_err is None
            else None
        )
        gossiped_max_sat = gossiped_max_msat // 1000 if gossiped_max_msat is not None else None
        remote_balance = int(ch.get("remote_balance", 0))
        ratio: float | None
        if gossiped_max_sat is None or remote_balance <= 0:
            ratio = None
        else:
            ratio = round(gossiped_max_sat / remote_balance, 3)
        rows.append(
            ChannelDriftRow(
                chan_id=chan_id,
                peer_pubkey=peer_pubkey,
                peer_alias=ch.get("peer_alias", ""),
                active=bool(ch.get("active", False)),
                capacity_sat=int(ch.get("capacity", 0)),
                local_balance_sat=int(ch.get("local_balance", 0)),
                remote_balance_sat=remote_balance,
                gossiped_inbound_max_htlc_sat=gossiped_max_sat,
                ratio_advertised_to_receivable=ratio,
            )
        )

    rows.sort(
        key=lambda r: r.ratio_advertised_to_receivable if r.ratio_advertised_to_receivable is not None else -1.0,
        reverse=True,
    )
    return rows


def _extract_inbound_max_htlc(
    edge: dict | None,
    *,
    our_pubkey: str,
    peer_pubkey: str,
) -> int | None:
    """Pull ``max_htlc_msat`` from the policy advertised by the
    peer (the side forwarding TO us) inside an LND graph-edge dict.

    LND's ``/v1/graph/edge/{chan_id}`` returns ``node1_pub`` /
    ``node2_pub`` sorted lexicographically with ``node1_policy``
    / ``node2_policy`` describing the OUTGOING policy of each
    node. The policy we care about is the one whose owner is
    ``peer_pubkey`` (the peer forwards TO us along this channel).
    """
    if not isinstance(edge, dict):
        return None
    node1 = edge.get("node1_pub", "")
    node2 = edge.get("node2_pub", "")
    policy = None
    if node1 == peer_pubkey and node2 == our_pubkey:
        policy = edge.get("node1_policy")
    elif node2 == peer_pubkey and node1 == our_pubkey:
        policy = edge.get("node2_policy")
    if not isinstance(policy, dict):
        return None
    raw = policy.get("max_htlc_msat")
    if raw is None or raw in ("", "0"):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


async def run_drift_check(
    lnd: LNDService,
    *,
    alert_ratio: float,
) -> dict[str, Any]:
    """Run :func:`collect_channel_drift_snapshot` and surface any
    over-claim above ``alert_ratio`` via WARN log + audit row.

    Returns a summary dict for caller logging:
    ``{"scanned": N, "alerted": K, "max_ratio": f}``.

    Audit-row contract:
        * ``action="bolt12_htlc_max_drift_detected"``
        * ``success=False``
        * ``details`` includes the offending channel snapshot

    Idempotent across runs — emits one audit row per channel per
    check above the threshold; the audit log itself is the
    persistence layer for the alert state.
    """
    rows = await collect_channel_drift_snapshot(lnd)

    alerted = 0
    max_ratio = 0.0
    for row in rows:
        r = row.ratio_advertised_to_receivable
        if r is None:
            continue
        if r > max_ratio:
            max_ratio = r
        if r >= alert_ratio:
            alerted += 1
            # Log the actionable drift ratio (the operator signal) but keep the
            # privacy-sensitive specifics — peer alias and the exact live
            # remote_balance — out of the durable log line. The exact figures
            # are a who-paid-whom / balance trail; the ratio + chan_id are
            # enough to act on.
            logger.warning(
                "bolt12 path drift: channel %s (peer=%s) advertised inbound "
                "max_htlc drifted to ratio=%.2fx of live remote_balance "
                "(threshold=%.2fx) — payers may pick this channel "
                "preferentially and the HTLC will fail at the under-funded hop",
                row.chan_id,
                row.peer_pubkey[:16] + "…" if row.peer_pubkey else "?",
                r,
                alert_ratio,
            )
            try:
                from app.core.database import get_db_context
                from app.services.bolt12.responder import _audit_inbound

                await _audit_inbound(
                    get_db_context,
                    action="bolt12_htlc_max_drift_detected",
                    success=False,
                    error_message="htlc_max_over_claims_receivable",
                    details={
                        "chan_id": row.chan_id,
                        "peer_pubkey": row.peer_pubkey,
                        "peer_alias": row.peer_alias,
                        "active": row.active,
                        "capacity_sat": row.capacity_sat,
                        "local_balance_sat": row.local_balance_sat,
                        "remote_balance_sat": row.remote_balance_sat,
                        "gossiped_inbound_max_htlc_sat": (row.gossiped_inbound_max_htlc_sat),
                        "ratio": r,
                        "threshold": alert_ratio,
                    },
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "bolt12 path drift: audit emit failed for %s",
                    row.chan_id,
                )

    return {
        "scanned": len(rows),
        "alerted": alerted,
        "max_ratio": round(max_ratio, 3),
    }


async def capture_mint_time_channel_snapshot(
    lnd: LNDService,
) -> dict[str, Any] | None:
    """Telemetry #2: snapshot for embedding in
    ``Bolt12Invoice.channel_state_snapshot``.

    Wraps :func:`collect_channel_drift_snapshot` into a JSON-safe
    dict shape:

    .. code-block:: json

        {
          "captured_at": "2026-06-05T10:15:45Z",
          "channels": [
            {"chan_id":"…", "capacity_sat":…, "remote_balance_sat":…,
             "gossiped_inbound_max_htlc_sat":…, "ratio":3.0, …}
          ]
        }

    Returns ``None`` on any failure so the mint hot path is never
    blocked — telemetry must never break a payment flow.
    """
    from datetime import datetime, timezone

    try:
        rows = await collect_channel_drift_snapshot(lnd)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "bolt12 channel snapshot: capture failed (%s) — proceeding without snapshot",
            exc,
        )
        return None
    if not rows:
        return None
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "channels": [r.to_dict() for r in rows],
    }


__all__ = [
    "ChannelDriftRow",
    "capture_mint_time_channel_snapshot",
    "collect_channel_drift_snapshot",
    "run_drift_check",
]
