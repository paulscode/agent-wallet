# SPDX-License-Identifier: MIT
"""Persistent operator-health row writer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.config import settings
from app.services.anonymize.operator_health import (
    all_degraded_operator_ids,
    get_operator_health,
    is_operator_degraded,
    record_operator_outlier,
)


@pytest.mark.asyncio
async def test_first_outlier_creates_row_below_threshold(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 3)
    row = await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="claim_feerate_outlier",
    )
    await db_session.commit()
    assert row.outlier_count_24h == 1
    assert row.degraded is False


@pytest.mark.asyncio
async def test_outlier_increments_existing_row(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 3)
    await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="claim_feerate_outlier",
    )
    await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="claim_feerate_outlier",
    )
    await db_session.commit()
    row = await get_operator_health(db_session, "op-a")
    assert row is not None
    assert row.outlier_count_24h == 2
    assert row.degraded is False


@pytest.mark.asyncio
async def test_threshold_flips_degraded(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 3)
    for _ in range(3):
        await record_operator_outlier(
            db_session,
            operator_id="op-a",
            reason="signature_mismatch",
        )
    await db_session.commit()
    row = await get_operator_health(db_session, "op-a")
    assert row is not None
    assert row.outlier_count_24h == 3
    assert row.degraded is True
    assert row.degraded_reason == "signature_mismatch"
    assert row.degraded_at is not None


@pytest.mark.asyncio
async def test_autoclear_resets_counter_after_window(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 3)
    monkeypatch.setattr(settings, "anonymize_operator_degrade_autoclear_s", 7 * 24 * 3600)
    # First outlier 8 days ago.
    long_ago = datetime.now(timezone.utc) - timedelta(days=8)
    await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="x",
        now=long_ago,
    )
    # New outlier today: counter should reset to 1.
    fresh = await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="x",
    )
    await db_session.commit()
    assert fresh.outlier_count_24h == 1
    assert fresh.degraded is False


@pytest.mark.asyncio
async def test_rolling_24h_window_resets_counter(db_session, monkeypatch) -> None:
    """Outliers older than 24h but younger than the auto-clear window
    still reset the rolling count to 1."""
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 3)
    monkeypatch.setattr(settings, "anonymize_operator_degrade_autoclear_s", 30 * 24 * 3600)
    yesterday_plus = datetime.now(timezone.utc) - timedelta(hours=25)
    await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="x",
        now=yesterday_plus,
    )
    fresh = await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="x",
    )
    await db_session.commit()
    assert fresh.outlier_count_24h == 1


@pytest.mark.asyncio
async def test_is_operator_degraded_helper(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 1)
    assert await is_operator_degraded(db_session, "op-a") is False
    await record_operator_outlier(
        db_session,
        operator_id="op-a",
        reason="claim_feerate_outlier",
    )
    await db_session.commit()
    assert await is_operator_degraded(db_session, "op-a") is True


@pytest.mark.asyncio
async def test_all_degraded_operator_ids_returns_set(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 1)
    await record_operator_outlier(db_session, operator_id="op-a", reason="x")
    await record_operator_outlier(db_session, operator_id="op-b", reason="x")
    await db_session.commit()
    out = await all_degraded_operator_ids(db_session)
    assert out == frozenset({"op-a", "op-b"})


@pytest.mark.asyncio
async def test_degraded_does_not_double_flip(db_session, monkeypatch) -> None:
    """Subsequent outliers past threshold leave ``degraded_at`` unchanged."""
    monkeypatch.setattr(settings, "anonymize_operator_degrade_outlier_threshold", 1)
    first = await record_operator_outlier(db_session, operator_id="op-a", reason="r1")
    first_degraded_at = first.degraded_at
    second = await record_operator_outlier(db_session, operator_id="op-a", reason="r2")
    assert second.degraded_at == first_degraded_at  # unchanged
    assert second.degraded_reason == "r1"  # original reason preserved
