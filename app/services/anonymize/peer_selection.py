# SPDX-License-Identifier: MIT
"""Auto peer-selection randomization.

When the wizard's ``priv_channel`` hop is configured with
``peer_pubkey: "auto"``, the orchestrator must NOT pick the
top-1-betweenness candidate deterministically — that would let an
attacker who positions their own node as the dominant betweenness
peer become our pinned peer for every anonymize session that uses
auto-select.

Mitigation:
* Sample weighted-random over the top
  ``ANONYMIZE_AUTO_PEER_TOP_K`` betweenness candidates.
* Apply the auto-blocklist before sampling.
* Apply a per-peer cooldown of
  ``ANONYMIZE_AUTO_PEER_COOLDOWN_S`` so a recently-picked peer is
  excluded regardless of its centrality score.

This module exposes the pure-helper layer: filter + weighted sample.
The actual betweenness scoring + recent-peer query lives in the LND-
graph reader the ``priv_channel`` hop uses.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class PeerCandidate:
    """One peer in the LND graph eligible for auto-selection."""

    pubkey: str
    centrality_score: float
    outbound_capacity_sat: int


def select_eligible_candidates(
    candidates: list[PeerCandidate],
    *,
    blocklist: frozenset[str],
    recent_pubkeys: frozenset[str],
    min_outbound_capacity_sat: int,
    top_k: int,
) -> list[PeerCandidate]:
    """Apply the filter chain and return the top-K survivors.

    The filter order is:
    1. Drop peers in the blocklist (auto-populated top-N
       gossipy peers + the operator's manual entries).
    2. Drop peers whose outbound capacity is below the binned amount.
    3. Drop peers chosen as auto-peer within the last
       ``ANONYMIZE_AUTO_PEER_COOLDOWN_S``.
    4. Sort by centrality descending and slice to ``top_k``.

    Pure / no I/O — the caller passes resolved sets so the function
    is trivially testable.
    """
    if top_k <= 0:
        return []

    eligible: list[PeerCandidate] = []
    for c in candidates:
        if c.pubkey in blocklist:
            continue
        if c.outbound_capacity_sat < min_outbound_capacity_sat:
            continue
        if c.pubkey in recent_pubkeys:
            continue
        eligible.append(c)

    eligible.sort(key=lambda c: c.centrality_score, reverse=True)
    return eligible[:top_k]


def weighted_random_choice(
    candidates: list[PeerCandidate],
    *,
    rng: secrets.SystemRandom | None = None,
) -> PeerCandidate | None:
    """Weighted-random pick over ``candidates`` using centrality as weight.

    Returns ``None`` when ``candidates`` is empty. Uses
    :class:`secrets.SystemRandom` so the orchestrator's choice is
    unpredictable to anyone not running our process — denying a
    "predict the next auto-peer" attack against an adversary who
    correlates our outbound LN activity with our local graph.
    """
    if not candidates:
        return None
    rng = rng or secrets.SystemRandom()
    weights = [max(0.0, c.centrality_score) for c in candidates]
    total = sum(weights)
    if total <= 0:
        # All candidates have zero/negative centrality — fall back to
        # uniform-random rather than returning None.
        return rng.choice(candidates)
    target = rng.uniform(0.0, total)
    cumulative = 0.0
    for c, w in zip(candidates, weights):
        cumulative += w
        if cumulative >= target:
            return c
    # Floating-point edge case: return the last candidate.
    return candidates[-1]


def select_auto_peer(
    candidates: list[PeerCandidate],
    *,
    blocklist: frozenset[str],
    recent_pubkeys: frozenset[str],
    min_outbound_capacity_sat: int,
    top_k: int,
    rng: secrets.SystemRandom | None = None,
) -> PeerCandidate | None:
    """End-to-end ``priv_channel`` auto-peer selection.

    Composes :func:`select_eligible_candidates` and
    :func:`weighted_random_choice`. Returns ``None`` when no peer
    survives the filter chain — the caller falls back to manual
    selection or aborts with ``no_eligible_peers``.
    """
    eligible = select_eligible_candidates(
        candidates,
        blocklist=blocklist,
        recent_pubkeys=recent_pubkeys,
        min_outbound_capacity_sat=min_outbound_capacity_sat,
        top_k=top_k,
    )
    return weighted_random_choice(eligible, rng=rng)


# --------------------------------------------------------------------
# LND graph-snapshot adapter.
# --------------------------------------------------------------------


def candidates_from_lnd_graph(
    *,
    nodes: list[dict],
    channels: list[dict],
    our_node_pubkey: str | None = None,
) -> list[PeerCandidate]:
    """Adapt LND's ``describe_graph`` snapshot into :class:`PeerCandidate`s.

    ``nodes`` is the list of node dicts from LND's
    ``describe_graph.nodes``. ``channels`` is the corresponding
    ``edges`` list; the helper computes a per-node centrality
    approximation as the *sum of channel capacities the node
    participates in*. This is a coarse betweenness substitute that
    avoids expensive graph algorithms — fine for the priv_channel
    hop's peer selection where we want a "well-connected non-LSP"
    peer rather
    than the absolute betweenness leader.

    ``our_node_pubkey`` is excluded from the output (we don't open a
    channel to ourselves).

    Pure / no I/O — the orchestrator passes pre-fetched LND data so
    this helper has no LND-RPC coupling.
    """
    capacity_by_node: dict[str, int] = {}
    for ch in channels:
        capacity = int(ch.get("capacity", 0))
        for side in ("node1_pub", "node2_pub"):
            pk = ch.get(side)
            if not pk:
                continue
            capacity_by_node[pk] = capacity_by_node.get(pk, 0) + capacity

    out: list[PeerCandidate] = []
    for node in nodes:
        pk = node.get("pub_key") or node.get("pubkey")
        if not pk:
            continue
        if our_node_pubkey and pk == our_node_pubkey:
            continue
        cap = capacity_by_node.get(pk, 0)
        # Centrality proxy: log-scale capacity. We don't want a
        # 100-BTC hub to dominate the weighted draw; the log smooths
        # the distribution while still preferring the well-connected
        # majority.
        import math

        centrality = math.log1p(max(0, cap))
        out.append(
            PeerCandidate(
                pubkey=pk,
                centrality_score=centrality,
                outbound_capacity_sat=cap,
            )
        )
    return out


async def record_auto_peer_chosen(
    db: AsyncSession,
    *,
    session_id: UUID,
    chosen_pubkey: str,
    candidates_size: int,
) -> None:
    """Emit the ``auto_peer_chosen`` event row.

    The event records the chosen peer pubkey + the eligible-candidates
    pool size so the audit chain can later answer "did this session
    have a real selection or was it a forced single-candidate pick?".
    Caller is responsible for committing.
    """
    from datetime import datetime, timezone

    from app.models.anonymize_session import AnonymizeSessionEvent

    db.add(
        AnonymizeSessionEvent(
            session_id=session_id,
            ts=datetime.now(timezone.utc),
            kind="auto_peer_chosen",
            detail_json={
                "chosen_pubkey": chosen_pubkey,
                "candidates_size": int(candidates_size),
            },
        )
    )


__all__ = [
    "PeerCandidate",
    "select_eligible_candidates",
    "weighted_random_choice",
    "select_auto_peer",
    "candidates_from_lnd_graph",
    "record_auto_peer_chosen",
]
