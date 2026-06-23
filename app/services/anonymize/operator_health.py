# SPDX-License-Identifier: MIT
"""Persistent operator-health row writer.

Tracks per-operator misbehaviour over a 24-hour rolling window:

* Every cooperative-claim feerate outlier
  bumps the per-operator counter; once the count crosses
  ``ANONYMIZE_OPERATOR_DEGRADE_OUTLIER_THRESHOLD``, the operator is
  marked ``degraded`` and excluded from pair sampling until
  the auto-clear window elapses without further outliers.
* Operator-signature mismatch counts share the same
  bookkeeping; both surfaces feed the same ``outlier_count_24h``
  column (the ``degraded_reason`` text records which class of
  outlier triggered the flip).

The orchestrator calls :func:`record_operator_outlier` from inside
the row-locked transaction; the helper handles the
upsert + auto-clear + flip-to-degraded decision in a single round
trip.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeOperatorHealth


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(ts: datetime | None) -> datetime | None:
    """Coerce a naive timestamp to UTC.

    SQLite (test runner) round-trips ``DateTime(timezone=True)`` columns
    without their tzinfo; PostgreSQL preserves it. The helpers below
    must work in both cases.
    """
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


async def get_operator_health(
    db: AsyncSession,
    operator_id: str,
    *,
    for_update: bool = False,
) -> AnonymizeOperatorHealth | None:
    """Read the current health row, or ``None`` when no record exists.

    Pass ``for_update=True`` from the increment path to hold the row under
    ``FOR UPDATE`` so concurrent outliers for the same operator serialize and
    no increment is lost (the count is a read-modify-write). SQLite (tests)
    cannot lock rows, so it falls back to a plain read.
    """
    stmt = select(AnonymizeOperatorHealth).where(AnonymizeOperatorHealth.operator_id == operator_id)
    if for_update:
        try:
            result = await db.execute(stmt.with_for_update())
            return result.scalar_one_or_none()
        except Exception:  # noqa: BLE001 — dialect without row locking (SQLite)
            pass
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def record_operator_outlier(
    db: AsyncSession,
    *,
    operator_id: str,
    reason: str,
    now: datetime | None = None,
) -> AnonymizeOperatorHealth:
    """Increment the operator's 24h outlier counter; flip ``degraded`` on threshold.

    Auto-clear: when the *previous* outlier is older than
    ``ANONYMIZE_OPERATOR_DEGRADE_AUTOCLEAR_S``, the counter resets to
    1 and ``degraded`` flips back to False before the new outlier
    increments.

    Returns the updated row. The caller is expected to commit; this
    helper does NOT commit so it can compose with the orchestrator's
    own transaction.
    """
    n = now or _utc_now()
    threshold = max(1, int(settings.anonymize_operator_degrade_outlier_threshold))
    autoclear_s = int(settings.anonymize_operator_degrade_autoclear_s)
    rolling_window_s = 24 * 3600

    row = await get_operator_health(db, operator_id, for_update=True)
    if row is None:
        row = AnonymizeOperatorHealth(
            operator_id=operator_id,
            outlier_count_24h=1,
            last_outlier_ts=n,
            degraded=False,
        )
        db.add(row)
    else:
        last = _ensure_aware(row.last_outlier_ts)
        # Auto-clear if the most-recent outlier is past the auto-clear
        # window — the operator gets a fresh slate.
        if last is not None and (n - last).total_seconds() >= autoclear_s:
            row.outlier_count_24h = 0
            row.degraded = False
            row.degraded_at = None
            row.degraded_reason = None
        # Reset the rolling 24h count if the most-recent outlier is
        # older than the rolling window (e.g., 25h ago).
        elif last is not None and (n - last).total_seconds() >= rolling_window_s:
            row.outlier_count_24h = 0
        row.outlier_count_24h += 1
        row.last_outlier_ts = n

    if row.outlier_count_24h >= threshold and not row.degraded:
        row.degraded = True
        row.degraded_at = n
        row.degraded_reason = reason

    # Flush
    # the probe-result cache and any quote-cache entries that priced
    # through this operator. A real degradation event must bypass
    # stale "reachable" / "valid quote" entries.
    try:
        from .operator_selection import invalidate_probe_cache

        invalidate_probe_cache(operator_id)
    except Exception:  # noqa: BLE001
        # Selection module is optional during early bootstrap; do
        # not block the health-record update on a transient import error.
        pass
    try:
        from .quote_cache import invalidate_quote_cache_for_operator

        invalidate_quote_cache_for_operator(operator_id)
    except Exception:  # noqa: BLE001
        pass

    return row


async def is_operator_degraded(db: AsyncSession, operator_id: str) -> bool:
    """True iff the operator is currently flagged ``degraded``.

    The pair sampler consults this predicate via
    ``operators.sample_operator_pair(... excluded_ids=...)`` to skip
    degraded operators.
    """
    row = await get_operator_health(db, operator_id)
    return bool(row and row.degraded)


async def all_degraded_operator_ids(db: AsyncSession) -> frozenset[str]:
    """Return the set of currently-degraded operator_ids."""
    stmt = select(AnonymizeOperatorHealth.operator_id).where(AnonymizeOperatorHealth.degraded.is_(True))
    result = await db.execute(stmt)
    return frozenset(row[0] for row in result.all())


__all__ = [
    "get_operator_health",
    "record_operator_outlier",
    "is_operator_degraded",
    "all_degraded_operator_ids",
]
