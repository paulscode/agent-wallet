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
    DateTime,
    Enum,
    Index,
    String,
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
    COMPLETE = "complete"
    PARTIAL_FAILURE = "partial_failure"
    CANCELLED = "cancelled"


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

    # Snapshot of the funding numbers the planner produced, so a
    # post-execute lookup can show them without re-running the planner.
    minimum_sats: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recommended_sats: Mapped[int] = mapped_column(BigInteger, nullable=False)

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
        "open_error": None,
        "seed_state": seed_state,
        "seed_swap_id": None,
        "seed_error": None,
    }


__all__ = [
    "CHANNEL_OPEN_STATES",
    "CHANNEL_SEED_STATES",
    "ChannelMixRun",
    "ChannelMixRunState",
    "make_channel_entry",
]
