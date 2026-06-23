# SPDX-License-Identifier: MIT
"""Session-create admission control.

The create endpoint applies two gates *before* persisting a session:

1. **Sliding-window rate limit** (max 10 sessions/h, computed from
   session-creation timestamps).
2. **Tier-keyed in-flight cap** — the cap applied at create-time is
   ``ANONYMIZE_TIER_CONCURRENCY_CAP[max_in_flight_tier]``. Defaults:
   ``strong=1, moderate=2, weak=3``. The cap is computed from DB
   state (count of non-terminal sessions), not from a sliding window.

This module ships the *pure decision helpers* — the orchestrator
wraps them with the actual DB / Redis primitives.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

if TYPE_CHECKING:
    from datetime import datetime

AdmissionDecision = Literal[
    "admit",
    "rate_limited",  # 429 — sliding-window budget exhausted.
    "tier_cap_exhausted",  # 429 — concurrent in-flight cap hit.
]


@dataclass(frozen=True)
class AdmissionInputs:
    """Inputs the gate consults; no I/O at this layer."""

    requested_tier: str  # "weak" | "moderate" | "strong"
    in_flight_count_by_tier: dict[str, int]
    sessions_created_in_window_count: int
    window_max: int = 10  # item 3: 10 sessions/h


def _tier_cap(tier: str) -> int:
    """Look up the configured cap for ``tier`` with a conservative default."""
    caps = settings.anonymize_tier_cap_dict
    if tier in caps:
        return int(caps[tier])
    # Unknown tier — refuse with the lowest reasonable cap.
    return 1


def decide_session_create_admission(
    inputs: AdmissionInputs,
) -> AdmissionDecision:
    """Pure decision for the session-create endpoint.

    Order of checks:
    1. Sliding-window rate limit (covers the volumetric DoS class).
    2. Tier-keyed concurrency cap (covers the structural in-flight
       class — a sticky session that never terminates would otherwise
       leak the slot indefinitely).

    Returns ``"admit"`` only when both gates pass.
    """
    if inputs.sessions_created_in_window_count >= inputs.window_max:
        return "rate_limited"

    cap = _tier_cap(inputs.requested_tier)
    in_flight = int(inputs.in_flight_count_by_tier.get(inputs.requested_tier, 0))
    if in_flight >= cap:
        return "tier_cap_exhausted"

    return "admit"


# Distinct advisory-lock key from the audit chain's (42) so the two
# critical sections don't needlessly serialize against each other.
_ADMISSION_LOCK_KEY = 43


async def acquire_admission_lock(db: AsyncSession) -> None:
    """Serialize concurrent session-create admission decisions.

    The in-flight / rate-limit counts are read and then a session row is
    inserted; without serialization N concurrent creates all observe the
    same pre-insert count and all admit, bypassing the tier cap and the
    rolling-window budget (TOCTOU). On PostgreSQL we take a
    transaction-scoped advisory lock so the count→insert critical section
    runs one request at a time and releases on commit/rollback. On other
    backends (SQLite in tests) it is a graceful no-op. Call this *before*
    the admission counts, inside the same transaction that inserts the
    session.
    """
    from sqlalchemy import text

    # Only PostgreSQL has advisory locks. Detect the dialect first and
    # skip entirely on others (e.g. SQLite in tests) — executing the
    # unknown function would raise and poison the session transaction,
    # breaking the very count queries this lock is meant to guard.
    try:
        dialect_name = db.get_bind().dialect.name
    except Exception:
        dialect_name = ""
    if dialect_name != "postgresql":
        return
    try:
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADMISSION_LOCK_KEY})
    except Exception:
        pass


async def count_in_flight_sessions(db: AsyncSession) -> int:
    """DB-state-based count of non-terminal sessions.

    Returns the total number of rows in non-terminal status. The
    create endpoint uses this as the tier-cap input under the
    "every active session is at least ``weak``" assumption that
    holds for single-operator LN-source deployments (no scorer-cached
    tier column yet). The on-chain self-source in-flight tier
    breakdown reads from a per-session tier column populated by the
    scorer at create-time.
    """
    from app.models.anonymize_session import (
        ANONYMIZE_TERMINAL_STATUSES,
        AnonymizeSession,
    )

    stmt = (
        select(func.count())
        .select_from(AnonymizeSession)
        .where(AnonymizeSession.deleted_at.is_(None))
        .where(AnonymizeSession.status.notin_(list(ANONYMIZE_TERMINAL_STATUSES)))
    )
    result = await db.execute(stmt)
    n = result.scalar_one()
    return int(n)


async def count_sessions_created_in_window(
    db: AsyncSession,
    *,
    window_seconds: int = 3600,
    now: datetime | None = None,
) -> int:
    """Sessions created within the rolling rate-limit window.

    The Lightning self-source path uses a coarse global counter (every
    cookie shares the same budget). The on-chain self-source path refines
    via the three-budget limiter for per-cookie / per-user / per-IP isolation.
    """
    from datetime import datetime, timedelta, timezone

    from app.models.anonymize_session import AnonymizeSession

    n = now or datetime.now(timezone.utc)
    cutoff = n - timedelta(seconds=int(window_seconds))
    stmt = (
        select(func.count())
        .select_from(AnonymizeSession)
        .where(AnonymizeSession.created_at >= cutoff)
        .where(AnonymizeSession.deleted_at.is_(None))
    )
    result = await db.execute(stmt)
    return int(result.scalar_one())


__all__ = [
    "AdmissionDecision",
    "AdmissionInputs",
    "count_in_flight_sessions",
    "count_sessions_created_in_window",
    "decide_session_create_admission",
]
