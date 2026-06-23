# SPDX-License-Identifier: MIT
"""Multi-output session orchestration (state-machine fan-out).

The dashboard `POST /anonymize/sessions/multi` endpoint persists one
:class:`AnonymizeSessionOutput` row per destination. This module
exposes the per-output state the orchestrator's per-session loop
reads to dispatch the egress.

Layering:

* :func:`select_ready_outputs` — given a session and current time,
  returns the outputs that are *due* (``scheduled_at_unix_s <= now``)
  and *not yet completed*, sorted by output_index. The per-session
  task iterates these and dispatches the egress (reverse swap →
  claim → broadcast → confirm) for each.
* :func:`mark_output_completed` — called once an output's claim tx
  has confirmed; records the txid + vout + ``completed_at``.
* :func:`is_session_fully_complete` — true iff every output for the
  session has ``completed_at`` set. The orchestrator uses this as
  the gate for the parent session's COMPLETED transition.
* :func:`count_pending_outputs` — for dashboard / observability.

Single-output sessions (no rows in ``anonymize_session_output``)
keep using the existing single-output completion path; the
orchestrator detects multi-output via ``pipeline_json["multi_output"]``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSessionOutput


@dataclass(frozen=True)
class ReadyOutput:
    """One output ready for egress dispatch.

    The orchestrator pulls the destination + amount from this and
    composes the per-output egress (reverse swap, claim, broadcast,
    confirm) without needing to re-read the row.
    """

    session_id: UUID
    output_index: int
    destination_address_enc: bytes
    destination_script_type: str
    bin_amount_sat: int
    scheduled_at_unix_s: Optional[float]


async def select_ready_outputs(
    db: AsyncSession,
    *,
    session_id: UUID,
    now_unix_s: Optional[float] = None,
) -> list[ReadyOutput]:
    """Return the outputs ready for egress in ``output_index`` order.

    A ready output:
    * has ``completed_at`` NULL (not yet egressed), AND
    * has ``scheduled_at_unix_s <= now`` (or NULL — admit immediately).
    """
    now = now_unix_s if now_unix_s is not None else datetime.now(timezone.utc).timestamp()
    stmt = (
        select(AnonymizeSessionOutput)
        .where(AnonymizeSessionOutput.session_id == session_id)
        .where(AnonymizeSessionOutput.completed_at.is_(None))
        .order_by(AnonymizeSessionOutput.output_index)
    )
    rows = (await db.execute(stmt)).scalars().all()
    ready: list[ReadyOutput] = []
    for r in rows:
        # Treat NULL scheduled_at as "egress immediately" — the
        # endpoint always sets it, so this is a safety fallback for
        # operator-injected rows.
        if r.scheduled_at_unix_s is not None and r.scheduled_at_unix_s > now:
            continue
        ready.append(
            ReadyOutput(
                session_id=r.session_id,
                output_index=r.output_index,
                destination_address_enc=r.destination_address_enc,
                destination_script_type=r.destination_script_type,
                bin_amount_sat=int(r.bin_amount_sat),
                scheduled_at_unix_s=r.scheduled_at_unix_s,
            )
        )
    return ready


async def mark_output_completed(
    db: AsyncSession,
    *,
    session_id: UUID,
    output_index: int,
    output_txid: str,
    output_vout: int,
    completed_at: Optional[datetime] = None,
) -> bool:
    """Mark a single output as completed.

    Returns True when the row was updated, False when no matching
    row was found (e.g., wrong session_id / output_index). Idempotent:
    re-marking an already-completed output updates ``output_txid`` /
    ``output_vout`` in place (the WHERE clause does NOT filter on
    completed_at).

    The caller commits.
    """
    if not output_txid:
        raise ValueError("output_txid must be non-empty")
    if output_vout < 0:
        raise ValueError("output_vout must be non-negative")
    when = completed_at or datetime.now(timezone.utc)
    stmt = (
        update(AnonymizeSessionOutput)
        .where(AnonymizeSessionOutput.session_id == session_id)
        .where(AnonymizeSessionOutput.output_index == output_index)
        .values(
            output_txid=output_txid,
            output_vout=int(output_vout),
            completed_at=when,
        )
    )
    result = await db.execute(stmt)
    return (result.rowcount or 0) > 0  # type: ignore[attr-defined]


async def is_session_fully_complete(
    db: AsyncSession,
    *,
    session_id: UUID,
) -> bool:
    """True iff every output for ``session_id`` has ``completed_at`` set.

    Returns False for sessions with zero output rows — multi-output
    sessions always have ≥ 1 row, so a zero-row count indicates the
    session was created via the single-output path and should use
    the existing completion gate.
    """
    total = (
        await db.execute(
            select(func.count())
            .select_from(AnonymizeSessionOutput)
            .where(AnonymizeSessionOutput.session_id == session_id)
        )
    ).scalar_one()
    if total == 0:
        return False
    pending = (
        await db.execute(
            select(func.count())
            .select_from(AnonymizeSessionOutput)
            .where(AnonymizeSessionOutput.session_id == session_id)
            .where(AnonymizeSessionOutput.completed_at.is_(None))
        )
    ).scalar_one()
    return pending == 0


async def count_pending_outputs(
    db: AsyncSession,
    *,
    session_id: UUID,
) -> int:
    """How many outputs of ``session_id`` haven't completed yet."""
    return (
        await db.execute(
            select(func.count())
            .select_from(AnonymizeSessionOutput)
            .where(AnonymizeSessionOutput.session_id == session_id)
            .where(AnonymizeSessionOutput.completed_at.is_(None))
        )
    ).scalar_one()


__all__ = [
    "ReadyOutput",
    "count_pending_outputs",
    "is_session_fully_complete",
    "mark_output_completed",
    "select_ready_outputs",
]
