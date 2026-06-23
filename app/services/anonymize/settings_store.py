# SPDX-License-Identifier: MIT
"""DB-backed singleton settings.

The ``anonymize_settings`` table stores durable knobs that must
survive backup-restore: most importantly ``feature_enabled_at_day``
, the UTC-day-quantized timestamp recording when this
wallet first ran an anonymize session.

 mandates that all reads go through a single
application-boundary helper that uses ``datetime.now(timezone.utc).date()``
— never ``datetime.utcnow()`` or ``datetime.now().date()``. A CI lint
reads this module as the only legitimate site for the value.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSettings

_FEATURE_ENABLED_AT_DAY_KEY = "feature_enabled_at_day"


async def get_feature_enabled_at_day(db: AsyncSession) -> date | None:
    """Return the day the anonymize feature was first enabled, or None."""
    result = await db.execute(select(AnonymizeSettings).where(AnonymizeSettings.key == _FEATURE_ENABLED_AT_DAY_KEY))
    row = result.scalar_one_or_none()
    if row is None:
        return None
    raw: object = row.value
    if isinstance(raw, dict):
        raw = raw.get("date") or raw.get("day")
    if isinstance(raw, str):
        try:
            return date.fromisoformat(raw)
        except ValueError:
            return None
    return None


async def set_feature_enabled_at_day_if_unset(
    db: AsyncSession,
    *,
    today: date | None = None,
) -> date:
    """First-session-create writes the row with today's UTC-day.

    Idempotent: a second call returns the existing value. ``today``
    defaults to ``datetime.now(timezone.utc).date()`` — never use
    ``datetime.utcnow()`` (CI lint).
    """
    existing = await get_feature_enabled_at_day(db)
    if existing is not None:
        return existing
    if today is None:
        today = datetime.now(timezone.utc).date()
    new_row = AnonymizeSettings(
        key=_FEATURE_ENABLED_AT_DAY_KEY,
        value={"date": today.isoformat()},
        # Migration 017 trigger truncates set_at to UTC-day for this
        # key; but we set it explicitly here for SQLite test runs that
        # don't carry the trigger.
        set_at=datetime.combine(today, datetime.min.time(), tzinfo=timezone.utc),
    )
    db.add(new_row)
    await db.commit()
    return today


__all__ = [
    "get_feature_enabled_at_day",
    "set_feature_enabled_at_day_if_unset",
]
