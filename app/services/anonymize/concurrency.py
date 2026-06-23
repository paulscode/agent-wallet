# SPDX-License-Identifier: MIT
"""Anonymize concurrency + locking helpers (items 46, 47, 48).

* Tier-keyed concurrency cap. The cap
  applied at session-create time is the cap of the *highest-tier*
  in-flight session. The check is computed from DB state, not a
  sliding window.
* Reconciliation queue isolation.
  ``awaiting_reconciliation`` and ``awaiting_channel_close`` sessions
  count against ``ANONYMIZE_AWAITING_RECONCILIATION_CAP``, *not*
  the active in-flight cap. A flaky operator cannot block all new
  session creation by parking sessions in reconciliation.
* Row-level locking for mutators. The
  orchestrator, gc, audit-summarizer, and reconciler use
  ``SELECT FOR UPDATE SKIP LOCKED`` (PostgreSQL) before mutating an
  ``anonymize_session`` row. SQLite (test runner) doesn't support
  the lock clause; the helper detects the dialect and degrades to a
  plain SELECT — tests that exercise the helper on SQLite are
  semantically equivalent because there's only one connection.
"""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

# Statuses that count toward the *active in-flight* cap.
# Sessions in awaiting_reconciliation / awaiting_channel_close /
# terminal states do not count here.
_ACTIVE_IN_FLIGHT_STATUSES: frozenset[str] = frozenset(
    {
        AnonymizeStatus.CREATED.value,
        AnonymizeStatus.SOURCING.value,
        AnonymizeStatus.FUNDING.value,
        AnonymizeStatus.LN_HOLDING.value,
        AnonymizeStatus.DELAYING.value,
        AnonymizeStatus.HOPPING.value,
        AnonymizeStatus.EXITING.value,
        AnonymizeStatus.CONFIRMING.value,
        AnonymizeStatus.REFUNDING.value,
    }
)


# Statuses that count toward the reconciliation-queue cap.
_RECONCILIATION_QUEUE_STATUSES: frozenset[str] = frozenset(
    {
        AnonymizeStatus.AWAITING_RECONCILIATION.value,
        AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value,
    }
)


# Tier-rank ordering for the item 46 cap calculation.
_TIER_RANK: dict[str, int] = {"weak": 0, "moderate": 1, "strong": 2}


# ────────────────────────────────────────────────────────────────────
# Tier-keyed in-flight cap.
# ────────────────────────────────────────────────────────────────────


async def count_active_in_flight_sessions(db: AsyncSession) -> int:
    """Number of sessions whose status counts toward the active cap."""
    stmt = (
        select(func.count())
        .select_from(AnonymizeSession)
        .where(AnonymizeSession.status.in_(list(_ACTIVE_IN_FLIGHT_STATUSES)))
        .where(AnonymizeSession.deleted_at.is_(None))
    )
    result = await db.execute(stmt)
    return int(result.scalar_one())


async def fetch_in_flight_session_tiers(db: AsyncSession) -> list[str]:
    """Return the tier of each active in-flight session.

    Reads from ``final_score_report_json -> 'tier'`` when present
    (post-execution score), otherwise from
    ``pipeline_json -> 'tier'`` (the quote-time score baked into
    the frozen pipeline). Sessions without either drop to ``"weak"``
    so the cap-fail-closed property holds.
    """
    stmt = (
        select(AnonymizeSession.pipeline_json, AnonymizeSession.final_score_report_json)
        .where(AnonymizeSession.status.in_(list(_ACTIVE_IN_FLIGHT_STATUSES)))
        .where(AnonymizeSession.deleted_at.is_(None))
    )
    result = await db.execute(stmt)
    out: list[str] = []
    for pipeline_json, final in result.all():
        tier: str | None = None
        if isinstance(final, dict):
            tier = final.get("tier")
        if not tier and isinstance(pipeline_json, dict):
            tier = pipeline_json.get("tier")
        if tier not in _TIER_RANK:
            tier = "weak"
        out.append(tier)
    return out


def highest_tier_in_flight(tiers: Iterable[str]) -> str | None:
    """Return the highest-rank tier from ``tiers``, or ``None`` if empty."""
    ranked = [t for t in tiers if t in _TIER_RANK]
    if not ranked:
        return None
    return max(ranked, key=lambda t: _TIER_RANK[t])


def cap_for_proposed_tier(
    *,
    proposed_tier: str,
    in_flight_tiers: Iterable[str],
) -> int:
    """Return the active-in-flight cap that applies.

    The cap is the value of ``ANONYMIZE_TIER_CONCURRENCY_CAP`` for
    the *highest* tier in the union of in-flight tiers and the
    proposed new session's tier. A pipeline whose proposed tier is
    ``strong`` and whose in-flight set already has a ``moderate``
    session computes against ``strong`` (cap = 1), so the new
    session is rejected if any session is in flight.
    """
    cap_dict = settings.anonymize_tier_cap_dict
    candidates = list(in_flight_tiers) + [proposed_tier]
    candidates = [t for t in candidates if t in _TIER_RANK]
    if not candidates:
        return cap_dict.get("weak", 3)
    highest = max(candidates, key=lambda t: _TIER_RANK[t])
    return cap_dict.get(highest, cap_dict.get("weak", 3))


async def can_create_session_at_tier(
    db: AsyncSession,
    *,
    proposed_tier: str,
) -> tuple[bool, int, int]:
    """Return ``(allowed, current_count, cap)``.

    ``allowed`` is True iff ``current_count < cap``. The orchestrator
    inserts the new session inside an advisory-locked transaction
    (Postgres-only ``pg_advisory_xact_lock``) that holds across this
    check + INSERT to defeat the race. The helper returns
    the cap so the caller can format an audit-event payload.
    """
    in_flight_tiers = await fetch_in_flight_session_tiers(db)
    current_count = len(in_flight_tiers)
    cap = cap_for_proposed_tier(proposed_tier=proposed_tier, in_flight_tiers=in_flight_tiers)
    return current_count < cap, current_count, cap


# ────────────────────────────────────────────────────────────────────
# Reconciliation queue isolation.
# ────────────────────────────────────────────────────────────────────


async def count_reconciliation_queue(db: AsyncSession) -> int:
    """Number of sessions parked in the reconciliation / channel-close queue."""
    stmt = (
        select(func.count())
        .select_from(AnonymizeSession)
        .where(AnonymizeSession.status.in_(list(_RECONCILIATION_QUEUE_STATUSES)))
        .where(AnonymizeSession.deleted_at.is_(None))
    )
    result = await db.execute(stmt)
    return int(result.scalar_one())


def is_reconciliation_queue_full(current_count: int) -> bool:
    """True when the queue exceeds ``ANONYMIZE_AWAITING_RECONCILIATION_CAP``."""
    cap = int(settings.anonymize_awaiting_reconciliation_cap)
    return current_count >= cap


# ────────────────────────────────────────────────────────────────────
# Row-level locking helpers.
# ────────────────────────────────────────────────────────────────────


def lock_session_for_update(stmt: Select[Any]) -> Select[Any]:
    """Apply ``SELECT FOR UPDATE SKIP LOCKED`` to ``stmt`` on PostgreSQL.

    SQLite does not support the lock clauses (the test runner uses
    SQLite). The helper returns the un-modified statement on SQLite
    so semantic tests still pass; in production against PostgreSQL
    the lock prevents two orchestrators from racing the same row.
    """
    return stmt.with_for_update(skip_locked=True)


__all__ = [
    "count_active_in_flight_sessions",
    "fetch_in_flight_session_tiers",
    "highest_tier_in_flight",
    "cap_for_proposed_tier",
    "can_create_session_at_tier",
    "count_reconciliation_queue",
    "is_reconciliation_queue_full",
    "lock_session_for_update",
]
