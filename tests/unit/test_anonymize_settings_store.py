# SPDX-License-Identifier: MIT
"""Feature_enabled_at_day storage.

Idempotent set-once helper writing the UTC-day-quantized row.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from app.services.anonymize.settings_store import (
    get_feature_enabled_at_day,
    set_feature_enabled_at_day_if_unset,
)


@pytest.mark.asyncio
async def test_get_returns_none_when_unset(db_session) -> None:
    assert await get_feature_enabled_at_day(db_session) is None


@pytest.mark.asyncio
async def test_set_then_get_returns_the_day(db_session) -> None:
    today = date(2026, 5, 10)
    out = await set_feature_enabled_at_day_if_unset(db_session, today=today)
    assert out == today
    assert await get_feature_enabled_at_day(db_session) == today


@pytest.mark.asyncio
async def test_set_is_idempotent(db_session) -> None:
    """Subsequent calls preserve the original day."""
    first = date(2026, 5, 10)
    second = date(2026, 6, 1)
    await set_feature_enabled_at_day_if_unset(db_session, today=first)
    out = await set_feature_enabled_at_day_if_unset(db_session, today=second)
    assert out == first  # second call MUST NOT overwrite


@pytest.mark.asyncio
async def test_default_today_is_utc(db_session) -> None:
    """When no ``today`` is passed, the helper uses ``datetime.now(timezone.utc).date()``."""
    expected = datetime.now(timezone.utc).date()
    out = await set_feature_enabled_at_day_if_unset(db_session)
    # The day rolling over mid-test would make this flaky; we accept
    # either the expected value or one day off.
    assert out in (expected, date.fromordinal(expected.toordinal() + 1)), f"unexpected day {out!r}"
