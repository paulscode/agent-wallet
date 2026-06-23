# SPDX-License-Identifier: MIT
"""Reorg-aware completion (/ items 27 + 55).

The exit reverse-claim transitions through three states once
broadcast:

* ``confirming`` — broadcast observed; waiting for
  ``ANONYMIZE_CLAIM_MIN_CONFIRMATIONS`` confirmations.
* ``completed`` — depth threshold reached; ``completed_at`` populated.
* ``completed_with_reorg_uncertainty`` — the claim tx was observed
  mined at depth ≥ 1 at some point, but reorg churn (≥
  ``ANONYMIZE_CLAIM_REORG_GIVEUP_BLOCKS``) prevented reaching the
  depth threshold. Funds are at the destination at the last-known
  depth; this is **not** ``failed`` (no refund needed).

This module ships the pure-helper layer that decides which terminal
state a (current_depth, max_depth_seen, reorg_count) tuple maps to.
The actual electrs subscription + chain reading lands alongside the
``broadcast.py`` self-broadcast fallback — both share a chain client.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.core.config import settings
from app.models.anonymize_session import AnonymizeStatus


@dataclass(frozen=True)
class ConfirmationObservation:
    """One snapshot of the chain's view of the claim tx.

    ``current_depth`` is the present confirmation depth (-1 if not in
    a block right now, e.g., reorged out and not yet re-mined).
    ``max_depth_seen`` is the deepest confirmation depth we have ever
    observed for this txid (monotonic across observations).
    ``reorg_count`` is the number of times we have seen a previously
    confirmed depth roll back to a lower depth.
    """

    current_depth: int
    max_depth_seen: int
    reorg_count: int


ReorgDecision = Literal[
    "stay_confirming",  # keep waiting; no transition.
    "completed",  # depth threshold reached.
    "completed_with_reorg_uncertainty",  # gave up after churn.
    "failed_no_chain_record",  # we never saw the tx mine; abort.
]


def decide_terminal_state(obs: ConfirmationObservation) -> ReorgDecision:
    """Map a confirmation observation to a state-machine decision.

    Pure / no I/O: the orchestrator pulls the observation from the
    chain client and feeds it here. The decision space matches.
    """
    min_confirmations = int(settings.anonymize_claim_min_confirmations)
    giveup_blocks = int(settings.anonymize_claim_reorg_giveup_blocks)

    if obs.current_depth >= min_confirmations:
        return "completed"

    # If we've never seen the tx mine and reorg churn is high, the
    # broadcast probably never made it (e.g., dropped from mempool).
    # The orchestrator may want to re-broadcast; we don't decide that
    # here, but we do flag the "no chain record at all" branch
    # distinctly from the reorg-uncertainty branch.
    if obs.max_depth_seen == 0 and obs.reorg_count >= giveup_blocks:
        return "failed_no_chain_record"

    if obs.reorg_count >= giveup_blocks and obs.max_depth_seen >= 1:
        # We did see it mine at some point; the destination has the
        # output at the last-known depth. Do NOT route to ``failed`` —
        # there is no refund to issue.
        return "completed_with_reorg_uncertainty"

    return "stay_confirming"


def map_decision_to_status(decision: ReorgDecision) -> str | None:
    """Map a :class:`ReorgDecision` to an :class:`AnonymizeStatus` value.

    Returns ``None`` for ``stay_confirming`` (caller stays put).
    ``failed_no_chain_record`` maps to ``failed`` (the orchestrator
    handles the refund / re-broadcast routing separately).
    """
    if decision == "stay_confirming":
        return None
    if decision == "completed":
        return AnonymizeStatus.COMPLETED.value
    if decision == "completed_with_reorg_uncertainty":
        return AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value
    if decision == "failed_no_chain_record":
        return AnonymizeStatus.FAILED.value
    raise ValueError(f"unknown ReorgDecision: {decision!r}")


__all__ = [
    "ConfirmationObservation",
    "ReorgDecision",
    "decide_terminal_state",
    "map_decision_to_status",
]
