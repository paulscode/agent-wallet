# SPDX-License-Identifier: MIT
"""Onboarding funding recommender.

Maps a new user's *intent* (how they'll use the wallet + a rough scale) to a
concrete deposit recommendation, so the very first screen can answer "how much
should I deposit?" before they fund.

This module is the **pure** part: the use-case → liquidity-target numeric
mapping, the receive efficient-vs-fast decision, and the card serializers that
turn a :class:`~app.services.channel_mix_planner.Plan` /
:class:`~app.services.channel_mix_planner.BootstrapPlan` into the response shape.
The dashboard endpoint does the I/O (running the planners via the shared
``_build_plan`` / ``_build_bootstrap_plan`` helpers) and hands the results here,
so the numbers always match what the executor will actually do.

See ``internal_docs/onboarding_funding_ux_plan.md``.
"""

from __future__ import annotations

import math
from dataclasses import asdict
from typing import Any, Literal, Optional

from app.services.channel_mix_planner import (
    PER_CHANNEL_FLOOR_SATS,
    BootstrapPlan,
    Plan,
)

UseCase = Literal["spend", "receive", "both", "explore"]

# A small, low-commitment first channel for the "just exploring" path.
EXPLORE_STARTER_SATS = 300_000

# Receive defaults to the capital-efficient bootstrap only once the target is
# large enough that the savings are material; below this, the direct/fast path
# is simpler and the bootstrap's multi-hour wait isn't worth it.
RECEIVE_EFFICIENT_MIN_TARGET_SATS = 1_000_000

# Inbound share of a receive-heavy channel — used to size the *fast* (direct)
# receive capacity so the channel ends with ~target inbound.
RECEIVE_HEAVY_INBOUND_FRACTION = 0.75


def clamp_to_floor(scale_sats: Optional[int]) -> tuple[int, bool]:
    """Clamp a requested target up to the one-channel floor.

    Returns ``(value, was_bumped)``. A target below ``PER_CHANNEL_FLOOR_SATS``
    can't open even a single channel, so we raise it and tell the user."""
    value = int(scale_sats or 0)
    if value < PER_CHANNEL_FLOOR_SATS:
        return PER_CHANNEL_FLOOR_SATS, value > 0
    return value, False


def receive_fast_capacity(target_inbound_sats: int) -> int:
    """Channel capacity needed so a receive-heavy open ends with ~target
    inbound (the direct/fast path)."""
    return int(math.ceil(target_inbound_sats / RECEIVE_HEAVY_INBOUND_FRACTION))


def receive_default_is_efficient(target_inbound_sats: int, boltz_available: bool) -> bool:
    """Whether the receive recommendation should lead with the efficient
    (bootstrap) path rather than the fast (direct) one."""
    return bool(boltz_available) and target_inbound_sats >= RECEIVE_EFFICIENT_MIN_TARGET_SATS


# ─── Rationale copy (plain, honest, audience-neutral) ─────────────


def spend_rationale(target_capacity_sats: int) -> str:
    return (
        f"Enough to open a channel and be able to spend about "
        f"{target_capacity_sats:,} sats, with a small reserve for fees. "
        "Want to receive too? Choose “Both”."
    )


def both_rationale(target_capacity_sats: int) -> str:
    return (
        f"A balanced channel (~{target_capacity_sats:,} sats) so you can send "
        "and receive, plus a small reserve for fees."
    )


def explore_rationale(target_capacity_sats: int) -> str:
    return (
        f"A small starter channel (~{target_capacity_sats:,} sats) to learn the "
        "ropes — you can add more anytime."
    )


def receive_efficient_rationale(plan: BootstrapPlan) -> str:
    hrs = max(1, round(plan.est_duration_minutes / 60))
    return (
        f"Deposit ~{plan.initial_deposit_sats:,} sats and we'll build about "
        f"{plan.expected_total_inbound_sats:,} sats of receiving capacity over "
        f"~{hrs} hour(s) by recycling the funds — runs in the background."
    )


def receive_fast_rationale(target_inbound_sats: int) -> str:
    return (
        f"Deposit up front for ~{target_inbound_sats:,} sats of receiving "
        "capacity that's ready as soon as the channel opens."
    )


# ─── Card serializers ─────────────────────────────────────────────


def parallel_card(
    plan: Plan,
    *,
    target_capacity_sats: int,
    outbound_option: str,
    rationale: str,
) -> Optional[dict[str, Any]]:
    """Serialize a parallel :class:`Plan` into a recommendation card, or
    ``None`` when the planner produced nothing usable (catalog empty,
    below floor, non-mainnet) so the caller can surface the error state."""
    if not plan.per_channel:
        return None
    return {
        "strategy": "parallel",
        "deposit_sats": int(plan.recommended_sats),
        "minimum_deposit_sats": int(plan.minimum_sats),
        "target_capacity_sats": int(target_capacity_sats),
        "target_inbound_sats": None,
        "outbound_option": outbound_option,
        "rationale": rationale,
        "estimate": None,
        "breakdown": asdict(plan.breakdown),
        "warnings": list(plan.diagnostics.warnings),
    }


def bootstrap_card(plan: BootstrapPlan, *, rationale: str) -> Optional[dict[str, Any]]:
    """Serialize a :class:`BootstrapPlan` into a recommendation card, or
    ``None`` when no schedule was produced (Boltz down, below floor)."""
    if not plan.rounds:
        return None
    return {
        "strategy": "bootstrap",
        "deposit_sats": int(plan.initial_deposit_sats),
        "minimum_deposit_sats": int(plan.initial_deposit_sats),
        "target_capacity_sats": None,
        "target_inbound_sats": (
            int(plan.target_inbound_sats) if plan.target_inbound_sats is not None else None
        ),
        "outbound_option": None,
        "rationale": rationale,
        "estimate": {
            "rounds": int(plan.expected_rounds),
            "est_duration_minutes": int(plan.est_duration_minutes),
            "total_fees_sats": int(plan.expected_total_fees_sats),
            "expected_total_inbound_sats": int(plan.expected_total_inbound_sats),
            "residual_outbound_sats": int(plan.residual_outbound_sats),
        },
        "breakdown": None,
        "warnings": list(plan.diagnostics.warnings),
    }


__all__ = [
    "UseCase",
    "EXPLORE_STARTER_SATS",
    "RECEIVE_EFFICIENT_MIN_TARGET_SATS",
    "RECEIVE_HEAVY_INBOUND_FRACTION",
    "clamp_to_floor",
    "receive_fast_capacity",
    "receive_default_is_efficient",
    "spend_rationale",
    "both_rationale",
    "explore_rationale",
    "receive_efficient_rationale",
    "receive_fast_rationale",
    "parallel_card",
    "bootstrap_card",
]
