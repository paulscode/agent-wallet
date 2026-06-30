# SPDX-License-Identifier: MIT
"""Persistent per-channel state for a channel-mix executor run.

The channel-mix planner (:mod:`app.services.channel_mix_planner`)
produces a :class:`Plan` describing one or more channels to open + seed.
The executor walks the plan one channel at a time, persisting state to
this table so a Celery-worker restart mid-run can resume without
losing track of which opens succeeded and which haven't.

Per-channel state lives in a JSON column rather than a separate child
table because every column on a child would carry the same parent
``mix_run_id`` foreign key and the executor never queries one channel
across runs — the access pattern is always "load the whole run."
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Index,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ChannelMixRunState(str, enum.Enum):
    """Top-level lifecycle of a channel-mix executor run.

    The granular per-channel state lives in ``channels`` (the JSON
    column). This enum is the run-wide rollup the dashboard polls.
    """

    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    # Bootstrap-only: the recyclable on-chain balance is temporarily
    # below what the next round needs to open. Transient — the prior
    # round's reverse-swap claim may still be confirming, or the user
    # may top the wallet back up. Non-terminal; the recover beat keeps
    # re-driving it until funds return or it ages out to
    # ``STOPPED_INSUFFICIENT``.
    AWAITING_FUNDS = "awaiting_funds"
    COMPLETE = "complete"
    PARTIAL_FAILURE = "partial_failure"
    # Bootstrap-only terminal: ran out of recyclable capital before the
    # target (or the awaiting-funds wait elapsed). Channels opened so
    # far are intact and seeded; the user can deposit more and start a
    # fresh run.
    STOPPED_INSUFFICIENT = "stopped_insufficient"
    CANCELLED = "cancelled"


# Run-wide states that mean "no further work" — the executor short-
# circuits these and the recover scan skips them.
TERMINAL_RUN_STATES = (
    ChannelMixRunState.COMPLETE,
    ChannelMixRunState.PARTIAL_FAILURE,
    ChannelMixRunState.STOPPED_INSUFFICIENT,
    ChannelMixRunState.CANCELLED,
)


# Per-round sub-states for the bootstrap executor (``mode="bootstrap"``).
# Like the parallel path's open/seed states these live as strings inside
# the ``channels`` JSON list (one entry per round, appended as rounds
# run). The sequential round driver walks them in order.
BOOTSTRAP_ROUND_STATES = (
    "opening",        # connect_peer + open_channel (idempotent on open_txid)
    "open_pending",   # funding tx broadcast; waiting for the channel to go active
    "open_active",    # channel usable; size + create the drain swap next
    "swapping",       # reverse swap created; LN payment + claim in flight
    "swap_pending",   # waiting for the Boltz claim tx to confirm (the recycle gate)
    "settled",        # claim confirmed; recycled capital available — round done
    "open_failed",    # terminal for the round (no funds moved)
    "swap_failed",    # terminal for the round (channel opened but not drained)
)

# Bootstrap round sub-states that mean the round is finished (one way or
# another) and the loop may consider starting the next round.
BOOTSTRAP_ROUND_TERMINAL_STATES = ("settled", "open_failed", "swap_failed")


# Per-channel sub-states. These are emitted into the ``channels`` JSON
# blob; they're not SQLAlchemy enums because the dashboard reads them as
# strings and they live alongside the channel's other fields.
CHANNEL_OPEN_STATES = (
    "queued",
    "opening",
    "open_pending",
    "open_active",
    "open_failed",
)

CHANNEL_SEED_STATES = (
    "skipped",       # the plan had no seed step for this channel
    "queued",
    "swapping",
    "seeded",
    "seed_failed",
)


class ChannelMixRun(Base):
    """One executor run for a channel-mix plan.

    The row is created on ``POST /v1/wallet/channel-mix/execute`` with
    one entry per channel in ``channels``. The Celery executor task
    advances each channel's ``open_state`` and ``seed_state`` and re-
    commits the row after every transition. A worker crash resumes by
    loading the row and re-driving any channel still in a non-terminal
    state.
    """

    __tablename__ = "channel_mix_runs"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    # The API key that submitted the execute call.
    api_key_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # SHA-256 of the plan token that authorised this run. UNIQUE so a
    # double-submitted execute call (e.g. the dashboard's request
    # retrying after a transient timeout) hits the unique constraint
    # and is mapped to the existing run instead of opening every
    # channel twice. The token itself isn't stored — only its digest,
    # so an attacker reading this column can't replay the token.
    plan_token_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )

    # Overall lifecycle state — drives the polling endpoint's
    # ``summary.overall_state`` field.
    state: Mapped[ChannelMixRunState] = mapped_column(
        Enum(
            ChannelMixRunState,
            name="channel_mix_run_state",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=ChannelMixRunState.QUEUED,
        server_default=ChannelMixRunState.QUEUED.value,
        index=True,
    )

    # Execution strategy. ``"parallel"`` (default) is the original
    # open-all-channels-at-once executor; ``"bootstrap"`` is the
    # sequential open→drain→recycle loop. The executor branches on this
    # so existing parallel runs are untouched.
    mode: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="parallel",
        server_default="parallel",
    )

    # Snapshot of the funding numbers the planner produced, so a
    # post-execute lookup can show them without re-running the planner.
    # For a bootstrap run, ``minimum_sats`` is the initial deposit the
    # plan was sized for and ``recommended_sats`` mirrors it (the loop
    # recomputes capacity from live balance each round regardless).
    minimum_sats: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recommended_sats: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # ── Bootstrap-only run-level fields (NULL / 0 for parallel runs) ──
    #
    # Target inbound the user asked for (target-inbound framing); NULL
    # for a budget-framed bootstrap run or any parallel run. When set,
    # the loop stops once ``realized_inbound_sats`` reaches it.
    target_inbound_sats: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    # Running totals the loop updates as rounds settle.
    realized_inbound_sats: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    total_fees_sats: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default="0",
    )
    # Cooperative "stop after this round" flag (the dashboard's stop
    # control). The loop lets the in-flight round settle, then finalizes
    # instead of starting a new round.
    stop_requested: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    # Peer-selection + option inputs the bootstrap loop needs to re-pick
    # peers and recompute the schedule at runtime (the schedule is not
    # pre-materialized — rounds are appended as they run). Shape::
    #
    #   {
    #     "peer_mix_mode": str,
    #     "manual_picks": list[str],
    #     "include_marginal_routing": bool,
    #     "network": str,
    #     "final_push_round": bool,
    #     "deposit_sats": int,            # the plan estimate, for reference
    #     "expected_total_inbound_sats": int,
    #     "expected_rounds": int,
    #     "expected_total_fees_sats": int,
    #     "est_duration_minutes": int,
    #   }
    #
    # NULL for parallel runs.
    bootstrap_params: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )

    # Per-channel state — list of dicts, each shaped like::
    #
    #   {
    #     "peer_alias": str,
    #     "peer_pubkey": str,
    #     "peer_host": str,
    #     "capacity_sats": int,
    #     "push_sat": int,
    #     "expected_inbound_seed_sats": int,
    #     "inbound_seed_strategy": "boltz_reverse" | "push_only" | "rebalance_from",
    #     "open_state": one-of CHANNEL_OPEN_STATES,
    #     "open_txid": Optional[str],
    #     "open_error": Optional[str],
    #     "seed_state": one-of CHANNEL_SEED_STATES,
    #     "seed_swap_id": Optional[str],
    #     "seed_error": Optional[str],
    #   }
    #
    # Mutable so an in-place update on a list element flushes correctly.
    channels: Mapped[list[dict[str, Any]]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )

    # Free-form diagnostics surface — the warnings from
    # :class:`PlanDiagnostics` plus any executor-side incidents.
    warnings: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )

    # Latest user-visible error string, when the run failed entirely
    # before any per-channel work could begin (e.g. plan-stale).
    error_message: Mapped[Optional[str]] = mapped_column(
        String(1024),
        nullable=True,
    )

    # Timestamps.
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("idx_channel_mix_runs_state", "state"),
        Index("idx_channel_mix_runs_api_key", "api_key_id"),
    )


def finalize_run(run: "ChannelMixRun", state: ChannelMixRunState) -> None:
    """Move a run to a terminal ``state`` and stamp ``completed_at``.

    The single audit point for every terminal transition — the parallel
    ``_rollup_state`` path, the bootstrap finalizers, the force-cancel
    endpoint, and the auto-resolution backstops all route through here so
    no path can forget to set ``completed_at`` (recovery plan §3.3). A
    no-op if the run is already terminal, so racing callers (an executor
    tick finishing as a force-cancel lands) settle on the first writer's
    state rather than overwriting it.
    """
    if run.state in TERMINAL_RUN_STATES:
        return
    run.state = state
    run.completed_at = _utc_now()


# Helpers for callers building / mutating ``channels`` entries — kept
# next to the model so the schema and helpers stay in lockstep.


def make_channel_entry(
    *,
    peer_alias: str,
    peer_pubkey: str,
    peer_host: str,
    capacity_sats: int,
    push_sat: int,
    expected_inbound_seed_sats: int,
    inbound_seed_strategy: str,
) -> dict[str, Any]:
    """Construct one ``channels`` JSON entry in the documented shape.

    The channel-mix pipeline carries two related but distinct shapes for
    a single channel slot, and the wizard template touches both. Keeping
    them straight matters when the template or executor is edited:

    * **Plan-time shape** (planner output, used in the *Plan preview*
      panel): a :class:`~app.services.channel_mix_planner.ChannelOpen`
      dataclass with a nested :class:`~app.services.small_channel_peers.SmallChannelPeer`.
      The template reads ``ch.peer.alias``, ``ch.peer.location``, etc. —
      dotted access against the dataclass projection.

    * **Run-time shape** (executor row entries, used in the *executing /
      done* panel): the flat dict this function returns. The template
      reads ``ch.peer_alias``, ``ch.capacity_sats``, etc. — flat keys.

    The two shapes deliberately diverge because the persisted row needs
    the per-slot state machine (``open_state``, ``open_txid``,
    ``open_error``, ``seed_state``, ``seed_swap_id``, ``seed_error``),
    none of which exist at plan time, while the plan-preview surface
    needs the full :class:`SmallChannelPeer` (with ``summary``, ``tags``,
    ``caveats`` etc.) that the executor row doesn't carry.
    """
    seed_state = (
        "skipped"
        if expected_inbound_seed_sats <= 0 or inbound_seed_strategy == "push_only"
        else "queued"
    )
    return {
        "peer_alias": peer_alias,
        "peer_pubkey": peer_pubkey,
        "peer_host": peer_host,
        "capacity_sats": int(capacity_sats),
        "push_sat": int(push_sat),
        "expected_inbound_seed_sats": int(expected_inbound_seed_sats),
        "inbound_seed_strategy": inbound_seed_strategy,
        "open_state": "queued",
        "open_txid": None,
        # Funding vout + per-wait timestamp, populated when the open is
        # broadcast (open_state → open_pending). Drive the auto-resolution
        # backstops (recovery plan §3): the vout lets the executor build a
        # channel point for confirmed-dead matching, and the timestamp
        # bounds a single open wait. JSON fields → no migration.
        "open_output_index": None,
        "open_pending_since": None,
        "open_error": None,
        "seed_state": seed_state,
        "seed_swap_id": None,
        "seed_error": None,
    }


def make_bootstrap_round_entry(
    *,
    round_index: int,
    peer_alias: str,
    peer_pubkey: str,
    peer_host: str,
    capacity_sats: int,
    drain_target_sats: int,
    spendable_before_sats: int,
    state: str = "opening",
) -> dict[str, Any]:
    """Construct one bootstrap-round ``channels`` JSON entry.

    Mirrors :func:`make_channel_entry` but for the sequential
    open→drain→recycle loop. The entry is appended when the round
    *starts* (so the persisted list records the actual schedule, which
    diverges from the plan estimate when fees move or the user spends
    mid-run). ``capacity_sats`` / ``drain_target_sats`` are the live
    values computed at round start; ``drain_target_sats`` is refined
    from the active channel before the swap (see the executor).

    The fields beyond the open/swap state machine:

    * ``swap_id`` — the linked :class:`~app.models.boltz_swap.BoltzSwap`
      row id once the drain swap is created (idempotency guard).
    * ``swap_claim_txid`` — the Boltz claim tx, recorded at settle.
    * ``recycled_sats`` — what actually landed back on-chain (the claim
      output), used for honest accounting; the next round sizes from
      live balance regardless.
    * ``expected_inbound_sats`` — the drain amount ≈ inbound created.
    * ``spendable_before_sats`` — confirmed on-chain balance snapshot at
      round start, for audit/debug.
    * ``open_output_index`` — funding output vout, so the executor can
      build the ``txid:vout`` channel point for ``channel_is_active``.
    """
    return {
        "round_index": int(round_index),
        "state": state,
        "peer_alias": peer_alias,
        "peer_pubkey": peer_pubkey,
        "peer_host": peer_host,
        "capacity_sats": int(capacity_sats),
        "drain_target_sats": int(drain_target_sats),
        "expected_inbound_sats": 0,
        "spendable_before_sats": int(spendable_before_sats),
        "open_txid": None,
        "open_output_index": None,
        "open_error": None,
        "swap_id": None,
        "swap_claim_txid": None,
        "recycled_sats": None,
        "swap_error": None,
    }


__all__ = [
    "BOOTSTRAP_ROUND_STATES",
    "BOOTSTRAP_ROUND_TERMINAL_STATES",
    "CHANNEL_OPEN_STATES",
    "CHANNEL_SEED_STATES",
    "TERMINAL_RUN_STATES",
    "ChannelMixRun",
    "ChannelMixRunState",
    "finalize_run",
    "make_bootstrap_round_entry",
    "make_channel_entry",
]
