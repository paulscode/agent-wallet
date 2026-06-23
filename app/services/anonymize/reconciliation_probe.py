# SPDX-License-Identifier: MIT
"""Auto-retry probe + wedge detector + startup heuristic.

This module ships the **pure** decision helpers + **DB-driven**
side-effect functions that auto-retry sessions stuck awaiting
reconciliation and detect wedged sessions at startup. The recurring
tick runner that wires these into the orchestrator lives in
:mod:`app.services.anonymize.tick_runners`.

Three concerns separated:

1. **Backoff math** — pure functions for exponential backoff with
   the configured envelope (``compute_backoff_s`` /
   ``is_in_cooldown``).
2. **Per-session attempt** — given an ``AWAITING_RECONCILIATION``
   row, decide whether to retry (resume to
   ``pre_reconciliation_status``), escalate (transition to a
   terminal status), or defer (Class C; operator must act).
3. **Wedge detector + startup heuristic** — sweep functions that
   flip wedged active rows into AR and backfill missing
   ``pre_reconciliation_status`` on legacy rows.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import (
    ANONYMIZE_TERMINAL_STATUSES,
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)

from .concurrency import lock_session_for_update
from .metadata import ANONYMIZE_LOGGER_NAME
from .reconciliation_classify import (
    CLASS_SEMI,
    CLASS_TERMINAL,
    CLASS_TRANSIENT,
    MAX_RETRIES_SEMI,
    classify_reason,
)
from .state_machine import is_legal_transition

if TYPE_CHECKING:
    # Imported for typing only — the runtime import is lazy to avoid a
    # service↔probe cycle.
    from .service import AnonymizeService

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# ── Backoff math (pure) ──────────────────────────────────────────────


def compute_backoff_s(
    attempts: int,
    *,
    base_s: float | None = None,
    max_s: float | None = None,
) -> float:
    """Exponential backoff with a configured envelope.

    ``attempts`` is the **completed** attempt count (1 after the
    first auto-retry tick consumes a budget). Returns the seconds
    the next retry should wait. ``base_s * 2^(attempts-1)``, clamped
    at ``max_s``. For ``attempts<=0`` returns 0 so a freshly-parked
    session is eligible immediately on the next tick.
    """
    if attempts <= 0:
        return 0.0
    if base_s is None:
        base_s = float(settings.anonymize_reconciliation_backoff_base_s)
    if max_s is None:
        max_s = float(settings.anonymize_reconciliation_backoff_max_s)
    # 2^(attempts-1) — cap the exponent so we don't overflow on
    # pathological ``attempts`` values.
    exp = min(int(attempts) - 1, 30)
    return float(min(max_s, base_s * (2**exp)))


def is_in_cooldown(
    session: AnonymizeSession,
    *,
    now: datetime,
    base_s: float | None = None,
    max_s: float | None = None,
) -> bool:
    """True iff the session is still inside the backoff window.

    A row that's never been auto-attempted (``attempts==0`` and
    ``last_reconciliation_attempt_ts is None``) is **not** in cooldown
    — the probe can attempt immediately. A row that was just attempted
    is in cooldown until ``last_reconciliation_attempt_ts + backoff_s``.
    """
    attempts = int(session.reconciliation_attempts or 0)
    if attempts <= 0:
        return False
    last = session.last_reconciliation_attempt_ts
    if last is None:
        # Inconsistent state — treat as out of cooldown so the next
        # tick re-attempts and persists a fresh timestamp.
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    backoff = compute_backoff_s(attempts, base_s=base_s, max_s=max_s)
    elapsed = (now - last).total_seconds()
    return elapsed < backoff


def compute_next_retry_at_unix_s(
    session: AnonymizeSession,
    *,
    base_s: float | None = None,
    max_s: float | None = None,
) -> Optional[float]:
    """Return the Unix timestamp of the next retry, or ``None`` when
    not applicable (no auto-retry class, no last-try timestamp,
    or already in the past).

    Surfaced on the session-summary projection so the SPA can
    render the countdown caption.
    """
    if session.status != AnonymizeStatus.AWAITING_RECONCILIATION.value:
        return None
    cls = classify_reason(session.awaiting_reconciliation_reason)
    if cls == CLASS_TERMINAL:
        return None
    last = session.last_reconciliation_attempt_ts
    if last is None:
        return None
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    attempts = int(session.reconciliation_attempts or 0)
    if attempts <= 0:
        return None
    backoff = compute_backoff_s(attempts, base_s=base_s, max_s=max_s)
    next_at = last.timestamp() + backoff
    now_unix = datetime.now(timezone.utc).timestamp()
    if next_at <= now_unix:
        return None
    return float(next_at)


# ── Per-session attempt decision ─────────────────────────────────────


@dataclass(frozen=True)
class AttemptOutcome:
    """Result of one auto-retry attempt on a single AR row."""

    kind: str  # "retried" | "escalated" | "deferred" | "noop"
    target_status: Optional[str] = None  # set for "retried" / "escalated"
    reason: str = ""  # operator-readable description


def max_retries_for_class(cls: str) -> int:
    """Per-class retry budget. Class A is configurable;
    Class B is the code constant ``MAX_RETRIES_SEMI``; Class C
    has zero auto-retries."""
    if cls == CLASS_TRANSIENT:
        return int(settings.anonymize_reconciliation_max_retries_transient)
    if cls == CLASS_SEMI:
        return int(MAX_RETRIES_SEMI)
    return 0


async def attempt_reconciliation(
    db: AsyncSession,
    session: AnonymizeSession,
    *,
    service: AnonymizeService,
    now: datetime,
) -> AttemptOutcome:
    """Run one probe tick against a single AR row.

    Decision tree:

    1. Class C (terminal / unknown): defer — no automated action.
       Touch the timestamp so the UI shows "last seen" but don't
       consume an attempt budget.
    2. Attempts past class budget: escalate to FAILED.
    3. Missing or illegal ``pre_reconciliation_status``: escalate to
       FAILED (back-compat path for legacy rows without the helper).
    4. Otherwise: resume to ``pre_reconciliation_status`` via
       ``service.transition_session``.

    Emits ``reconciliation_attempt_started`` + either
    ``reconciliation_attempt_completed`` / ``reconciliation_escalated``.
    Caller commits.
    """
    reason = (session.awaiting_reconciliation_reason or "").strip()
    cls = classify_reason(reason)

    # Class C: defer, just touch the timestamp.
    if cls == CLASS_TERMINAL:
        # Refresh last-try so the operator-facing "last seen" works,
        # but do NOT bump attempts (Class C doesn't consume budget).
        session.last_reconciliation_attempt_ts = now
        db.add(
            AnonymizeSessionEvent(
                session_id=session.id,
                ts=now,
                kind="reconciliation_attempt_started",
                detail_json={
                    "attempts": int(session.reconciliation_attempts or 0),
                    "reason": reason,
                    "class": cls,
                    "target_status": None,
                },
            )
        )
        db.add(
            AnonymizeSessionEvent(
                session_id=session.id,
                ts=now,
                kind="reconciliation_attempt_completed",
                detail_json={
                    "attempts": int(session.reconciliation_attempts or 0),
                    "outcome": "deferred",
                },
            )
        )
        return AttemptOutcome(kind="deferred", reason="class_c_operator_action")

    # Bump the counter + timestamp BEFORE the side-effect attempt
    # so a crash mid-transition still records the attempt budget.
    next_attempts = int(session.reconciliation_attempts or 0) + 1
    session.reconciliation_attempts = next_attempts
    session.last_reconciliation_attempt_ts = now

    target = session.pre_reconciliation_status
    budget = max_retries_for_class(cls)

    db.add(
        AnonymizeSessionEvent(
            session_id=session.id,
            ts=now,
            kind="reconciliation_attempt_started",
            detail_json={
                "attempts": next_attempts,
                "reason": reason,
                "class": cls,
                "target_status": target,
            },
        )
    )

    # Budget exhausted?
    if next_attempts > budget:
        return await _escalate(
            db,
            session,
            cls=cls,
            reason=reason,
            now=now,
            why="budget_exhausted",
        )

    # Missing or illegal target?
    if not target or not is_legal_transition(
        from_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        to_status=target,
    ):
        return await _escalate(
            db,
            session,
            cls=cls,
            reason=reason,
            now=now,
            why="no_pre_reconciliation_status",
        )

    # Class A or B with budget remaining and a legal target: resume.
    await service.transition_session(
        db,
        session,
        to_status=target,
        reason=f"reconciliation_retry:{reason}",
    )
    db.add(
        AnonymizeSessionEvent(
            session_id=session.id,
            ts=now,
            kind="reconciliation_attempt_completed",
            detail_json={
                "attempts": next_attempts,
                "outcome": "retried",
            },
        )
    )
    return AttemptOutcome(
        kind="retried",
        target_status=target,
        reason=reason,
    )


async def _escalate(
    db: AsyncSession,
    session: AnonymizeSession,
    *,
    cls: str,
    reason: str,
    now: datetime,
    why: str,
) -> AttemptOutcome:
    """Transition a session out of AR after auto-retry exhaustion.

    :
    * Class A exhausted → FAILED.
    * Class B exhausted, funds may be at stake → REFUNDING when
      legal, else FAILED. The LN-source reasons that flow through
      here are pre-payment (``mpp_k_floor_exhausted``) so FAILED is
      the right call; on-chain reasons like ``claim_feerate_outlier``
      / ``stuck_htlc_alarm`` will need their own classification when
      they're wired in.
    * Class C never auto-escalates — those rows take the defer
      branch and live or die by operator action.

    Conservative posture: escalate everything (Class A + B
    auto-retry exhaustion, missing pre_status) to FAILED. The
    `→ REFUNDING` branch can be enabled once a Class B reason that
    actually has funds-in-flight semantics ships.

    Emits ``reconciliation_escalated``. Caller commits.
    """
    # Lazy import to avoid a service↔probe cycle.
    from .service import get_anonymize_service

    svc = get_anonymize_service()
    to_status = AnonymizeStatus.FAILED.value
    try:
        await svc.transition_session(
            db,
            session,
            to_status=to_status,
            reason=f"reconciliation_escalated:{why}",
        )
    except Exception:  # noqa: BLE001
        # Illegal transition (shouldn't happen — AR→FAILED is legal)
        # — log + leave the row where it is. Operator can intervene.
        logger.exception(
            "reconciliation escalate failed for session %s",
            session.id,
        )
        return AttemptOutcome(
            kind="noop",
            reason=f"escalate_illegal_transition:{why}",
        )

    db.add(
        AnonymizeSessionEvent(
            session_id=session.id,
            ts=now,
            kind="reconciliation_escalated",
            detail_json={
                "final_attempts": int(session.reconciliation_attempts or 0),
                "from_class": cls,
                "to_status": to_status,
                "why": why,
                "reason": reason,
            },
        )
    )
    db.add(
        AnonymizeSessionEvent(
            session_id=session.id,
            ts=now,
            kind="reconciliation_attempt_completed",
            detail_json={
                "attempts": int(session.reconciliation_attempts or 0),
                "outcome": "escalated",
            },
        )
    )
    return AttemptOutcome(
        kind="escalated",
        target_status=to_status,
        reason=why,
    )


# ── DB queries ───────────────────────────────────────────────────────


async def fetch_awaiting_reconciliation_sessions(
    db: AsyncSession,
    *,
    limit: int,
) -> list[AnonymizeSession]:
    """Return AR rows in ``last_attempt_ts`` ascending order — least-
    recently-attempted first so a backlog is worked off evenly."""
    stmt = lock_session_for_update(
        select(AnonymizeSession)
        .where(AnonymizeSession.status == AnonymizeStatus.AWAITING_RECONCILIATION.value)
        .where(AnonymizeSession.deleted_at.is_(None))
        .order_by(
            AnonymizeSession.last_reconciliation_attempt_ts.asc().nullsfirst(),
        )
        .limit(int(limit))
    )
    return list((await db.execute(stmt)).scalars().all())


async def fetch_wedged_active_sessions(
    db: AsyncSession,
    *,
    now: datetime,
    budget_s: float,
    limit: int,
) -> list[AnonymizeSession]:
    """Find active sessions idle past the runtime budget.

    Excludes terminals and AWAITING_RECONCILIATION (those are owned
    by the auto-retry path). Compares against ``updated_at``.
    """
    cutoff = now.timestamp() - float(budget_s)
    # Use a Unix-timestamp compare via Python: filter in-Python rather
    # than emit a backend-specific interval expression. The wedged
    # set is small in normal operation so the over-fetch is fine.
    #
    # ``SKIP LOCKED`` keeps the probe off any session a per-session loop
    # is actively driving (it holds the row's ``FOR UPDATE`` lock across
    # its tick), so the probe never transitions a row out from under a
    # live hop. A genuinely wedged session has no live loop, so its row
    # is unlocked and the probe sees it.
    stmt = lock_session_for_update(
        select(AnonymizeSession)
        .where(
            AnonymizeSession.status.notin_(
                list(ANONYMIZE_TERMINAL_STATUSES)
                + [
                    AnonymizeStatus.AWAITING_RECONCILIATION.value,
                ],
            )
        )
        .where(AnonymizeSession.deleted_at.is_(None))
        .where(
            or_(
                AnonymizeSession.updated_at.is_(None),
                AnonymizeSession.updated_at < datetime.fromtimestamp(cutoff, tz=timezone.utc),
            )
        )
        .order_by(AnonymizeSession.updated_at.asc().nullsfirst())
        .limit(int(limit))
    )
    return list((await db.execute(stmt)).scalars().all())


async def fetch_legacy_ar_rows_missing_pre_status(
    db: AsyncSession,
    *,
    limit: int,
) -> list[AnonymizeSession]:
    """startup-heuristic input: AR rows with NULL pre-status."""
    stmt = (
        select(AnonymizeSession)
        .where(AnonymizeSession.status == AnonymizeStatus.AWAITING_RECONCILIATION.value)
        .where(AnonymizeSession.deleted_at.is_(None))
        .where(AnonymizeSession.pre_reconciliation_status.is_(None))
        .order_by(AnonymizeSession.created_at.asc())
        .limit(int(limit))
    )
    return list((await db.execute(stmt)).scalars().all())


# ── Wedge detector + startup heuristic ──────────────────────────────


# When ``pre_reconciliation_status`` is NULL on a legacy row,
# infer the target from the reason. Reasons whose emit-site lives in
# a single state can be inferred reliably:
#
#   mpp_k_floor_exhausted → EXITING (reverse-hop pay-invoice path)
#
# Reasons whose emit-site could be in many states (circuit_rebuild_throttled,
# bounded_retry_exhausted, wall_clock_budget_exceeded) are NOT inferred —
# the auto-retry probe's "missing target → escalate" branch handles them.
_PRE_STATUS_HEURISTIC: dict[str, str] = {
    "mpp_k_floor_exhausted": AnonymizeStatus.EXITING.value,
}


def heuristic_pre_status_for(reason: str | None) -> Optional[str]:
    """Return the inferred ``pre_reconciliation_status`` for a reason,
    or ``None`` when there's no safe inference."""
    if not reason:
        return None
    return _PRE_STATUS_HEURISTIC.get(str(reason).strip())


async def apply_startup_pre_status_heuristic(
    db: AsyncSession,
    *,
    now: datetime,
    limit: int = 100,
) -> int:
    """One-shot backfill of ``pre_reconciliation_status`` for legacy
    AR rows. Called at orchestrator boot. Returns the number of rows
    whose pre-status was populated.

    Emits ``reconciliation_pre_status_heuristic_applied`` per row.
    Caller commits.
    """
    rows = await fetch_legacy_ar_rows_missing_pre_status(db, limit=limit)
    count = 0
    for sess in rows:
        target = heuristic_pre_status_for(sess.awaiting_reconciliation_reason)
        if target is None:
            continue
        # Don't write if the target wouldn't be a legal resume edge.
        if not is_legal_transition(
            from_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
            to_status=target,
        ):
            continue
        sess.pre_reconciliation_status = target
        db.add(
            AnonymizeSessionEvent(
                session_id=sess.id,
                ts=now,
                kind="reconciliation_pre_status_heuristic_applied",
                detail_json={
                    "reason": sess.awaiting_reconciliation_reason or "",
                    "inferred_pre_status": target,
                },
            )
        )
        count += 1
    return count


async def apply_wedge_detector(
    db: AsyncSession,
    *,
    service: AnonymizeService,
    now: datetime,
    budget_s: float | None = None,
    limit: int = 50,
) -> int:
    """Flip wedged active rows into AR.

    Walks non-terminal, non-AR sessions whose ``updated_at`` is older
    than the runtime budget and routes each through
    ``transition_to_awaiting_reconciliation`` with reason
    ``wall_clock_budget_exceeded``. The auto-retry probe picks them
    up as Class A on the next tick.

    Emits ``reconciliation_wall_clock_flipped`` per row. Caller commits.
    """
    if budget_s is None:
        budget_s = float(
            settings.anonymize_reconciliation_runtime_wall_clock_budget_s,
        )
    rows = await fetch_wedged_active_sessions(
        db,
        now=now,
        budget_s=budget_s,
        limit=limit,
    )
    count = 0
    for sess in rows:
        from_status = sess.status
        # Capture the idle duration BEFORE the transition. The
        # subsequent ``transition_to_awaiting_reconciliation`` flushes,
        # which triggers SQLAlchemy's ``onupdate=now()`` on
        # ``updated_at`` and would otherwise zero this out.
        last_advance = sess.updated_at or sess.created_at
        idle_s = 0.0
        if last_advance is not None:
            if last_advance.tzinfo is None:
                last_advance = last_advance.replace(tzinfo=timezone.utc)
            idle_s = max(0.0, (now - last_advance).total_seconds())
        try:
            await service.transition_to_awaiting_reconciliation(
                db,
                sess,
                reason="wall_clock_budget_exceeded",
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "wedge detector: transition failed for %s",
                sess.id,
            )
            continue
        db.add(
            AnonymizeSessionEvent(
                session_id=sess.id,
                ts=now,
                kind="reconciliation_wall_clock_flipped",
                detail_json={
                    "from_status": from_status,
                    "idle_s": int(idle_s),
                },
            )
        )
        count += 1
    return count


__all__ = [
    "AttemptOutcome",
    "apply_startup_pre_status_heuristic",
    "apply_wedge_detector",
    "attempt_reconciliation",
    "compute_backoff_s",
    "compute_next_retry_at_unix_s",
    "fetch_awaiting_reconciliation_sessions",
    "fetch_legacy_ar_rows_missing_pre_status",
    "fetch_wedged_active_sessions",
    "heuristic_pre_status_for",
    "is_in_cooldown",
    "max_retries_for_class",
]
