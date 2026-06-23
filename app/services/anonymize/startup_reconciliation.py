# SPDX-License-Identifier: MIT
"""startup reconciliation pass.

Every boot, before the orchestrator schedules any per-session task,
it walks the non-terminal sessions in the DB and classifies each as:

* **resume** — the session is healthy and the per-session task can
  pick up where it left off. Most rows fall into this bucket.
* **reconcile** — the session is stuck (e.g., crashed mid-broadcast,
  exceeded a wall-clock budget while the host was down, or was last
  observed under a pipeline_schema_version the running code can no
  longer execute). The orchestrator routes these to
  ``awaiting_reconciliation`` and emits an audit event; the actual
  recovery walks each row through a bounded-retry loop.

This module ships the *query* + *classifier*; the side-effects
(spawning the per-session task, writing the transition) live on
:class:`AnonymizeService`.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import (
    ANONYMIZE_TERMINAL_STATUSES,
    AnonymizeSession,
    AnonymizeStatus,
)

if TYPE_CHECKING:
    from .per_session_loop import HopStepFn, ObservationFn
    from .service import AnonymizeService
    from .tick import TickObservations

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

ReconciliationDisposition = Literal["resume", "reconcile"]


@dataclass(frozen=True)
class ReconciliationOutcome:
    """One per-session classification result."""

    session_id: str
    disposition: ReconciliationDisposition
    reason: str


def _max_wallclock_budget_s() -> float:
    """Wall-clock budget after which a stuck session reconciles.

    A session whose ``updated_at`` (or ``created_at`` for sessions that
    have never advanced) lies further in the past than the longest-
    possible legitimate idle interval is classified ``reconcile`` so
    a stale row from a crashed previous boot can't get re-armed as
    if nothing had happened.

    Default: twice the longest configured inter-leg delay so a single
    long delay window is tolerated, but two stacked windows escalate.
    """
    inter_leg_max = int(settings.anonymize_onchain_max_interleg_delay_s)
    return float(2 * max(inter_leg_max, 86_400))  # ≥ 1 day


def _is_below_min_supported_schema(session: AnonymizeSession) -> bool:
    """The running code can't execute the schema."""
    running_min = int(settings.anonymize_pipeline_schema_version_min_supported)
    return int(session.pipeline_schema_version or 0) < running_min


def classify_session(
    session: AnonymizeSession,
    *,
    now: datetime | None = None,
) -> ReconciliationOutcome:
    """Decide what to do with a non-terminal session on boot.

    Pure function — caller is responsible for the actual transition
    and audit-event writes.
    """
    sid = str(session.id)

    # Terminal rows should never have reached this helper, but guard
    # anyway so a regression in the query path doesn't silently
    # re-arm a terminal row.
    if session.status in ANONYMIZE_TERMINAL_STATUSES:
        return ReconciliationOutcome(
            session_id=sid,
            disposition="resume",
            reason="terminal_already_no_op",
        )

    if _is_below_min_supported_schema(session):
        return ReconciliationOutcome(
            session_id=sid,
            disposition="reconcile",
            reason="pipeline_schema_below_min_supported",
        )

    n = now or datetime.now(timezone.utc)
    last_advance = session.updated_at or session.created_at
    if last_advance is not None:
        if last_advance.tzinfo is None:
            last_advance = last_advance.replace(tzinfo=timezone.utc)
        idle_s = (n - last_advance).total_seconds()
        if idle_s > _max_wallclock_budget_s():
            return ReconciliationOutcome(
                session_id=sid,
                disposition="reconcile",
                reason="wall_clock_budget_exceeded",
            )

    # AWAITING_RECONCILIATION rows stay where they are — they need
    # the per-state recovery path, not the resume path.
    if session.status == AnonymizeStatus.AWAITING_RECONCILIATION.value:
        return ReconciliationOutcome(
            session_id=sid,
            disposition="reconcile",
            reason="already_awaiting_reconciliation",
        )

    return ReconciliationOutcome(
        session_id=sid,
        disposition="resume",
        reason="healthy",
    )


async def fetch_non_terminal_sessions(
    db: AsyncSession,
    *,
    limit: int = 1000,
) -> list[AnonymizeSession]:
    """Return every non-terminal session on boot.

    The orchestrator's startup pass walks this batch and calls
    :func:`classify_session` for each row. ``limit`` is a safety
    cap — production deployments are unlikely to hit it; if they do,
    the orchestrator pages through.
    """
    stmt = (
        select(AnonymizeSession)
        .where(AnonymizeSession.status.notin_(list(ANONYMIZE_TERMINAL_STATUSES)))
        .where(AnonymizeSession.deleted_at.is_(None))
        .order_by(AnonymizeSession.created_at.asc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def classify_all_non_terminal(
    db: AsyncSession,
    *,
    now: datetime | None = None,
) -> list[ReconciliationOutcome]:
    """Convenience wrapper for tests and the orchestrator entry point."""
    sessions = await fetch_non_terminal_sessions(db)
    return [classify_session(s, now=now) for s in sessions]


@dataclass(frozen=True)
class ReconciliationSummary:
    """Per-boot reconciliation outcome the orchestrator records.

    Returned by :func:`run_startup_reconciliation` so the lifespan
    caller can stash counts on app state for the health endpoint.
    """

    resumed_count: int
    reconciled_count: int
    outcomes: list[ReconciliationOutcome]


async def run_startup_reconciliation(
    *,
    service: "AnonymizeService",
    session_factory: "SessionFactory",
    observation_fn: "ObservationFn",
    hop_step_fn: "HopStepFn | None" = None,
) -> ReconciliationSummary:
    """Run the startup reconciliation pass once per boot.

    Walks every non-terminal session. For each row:

    * ``disposition == "resume"`` → spawn a per-session task that
      drives the row through the tick loop.
    * ``disposition == "reconcile"`` → transition to
      ``AWAITING_RECONCILIATION`` so the bounded-retry path
      picks it up.

    The function does not raise on per-row errors — it logs and moves
    on so a single corrupted row can't deny-of-service the orchestrator
    boot. Returns counts + per-row outcomes so the caller can stash
    them on app state for health-card reporting.
    """
    from app.models.anonymize_session import AnonymizeStatus

    outcomes: list[ReconciliationOutcome] = []
    resumed = 0
    reconciled = 0

    async with session_factory() as db:
        sessions = await fetch_non_terminal_sessions(db)
        for sess in sessions:
            try:
                outcome = classify_session(sess)
                outcomes.append(outcome)
                if outcome.disposition == "reconcile":
                    if sess.status != AnonymizeStatus.AWAITING_RECONCILIATION.value:
                        await service.transition_to_awaiting_reconciliation(
                            db,
                            sess,
                            reason=outcome.reason,
                        )
                    reconciled += 1
                else:
                    service.spawn_session_task(
                        session_id=sess.id,
                        session_factory=session_factory,
                        observation_fn=observation_fn,
                        hop_step_fn=hop_step_fn,
                    )
                    resumed += 1
            except Exception:  # noqa: BLE001
                # Log + continue — one bad row must not deny the boot.
                import logging

                from .metadata import ANONYMIZE_LOGGER_NAME

                logging.getLogger(ANONYMIZE_LOGGER_NAME).exception(
                    "startup reconciliation failed for session %s",
                    sess.id,
                )
        await db.commit()

    return ReconciliationSummary(
        resumed_count=resumed,
        reconciled_count=reconciled,
        outcomes=outcomes,
    )


async def no_op_observation_fn(_db: AsyncSession, _session: AnonymizeSession) -> "TickObservations":
    """Default LN-source observation collector.

    Returns an empty :class:`TickObservations` so the per-session
    loop ticks (and exits if the row reaches a terminal status via
    a user-initiated cancel/refund endpoint) but does not advance
    on its own. Replaced by hop-specific collectors.
    """
    from .tick import TickObservations

    return TickObservations()


__all__ = [
    "ReconciliationDisposition",
    "ReconciliationOutcome",
    "ReconciliationSummary",
    "classify_session",
    "fetch_non_terminal_sessions",
    "classify_all_non_terminal",
    "run_startup_reconciliation",
    "no_op_observation_fn",
]
