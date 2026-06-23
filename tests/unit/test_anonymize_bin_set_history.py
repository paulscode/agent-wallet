# SPDX-License-Identifier: MIT
"""/ items 66 + 90 — bin-set history."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.services.anonymize.bin_set_history import (
    IMPLICIT_BIN_SET_SENTINEL,
    get_active_bin_set_at_height,
    get_bin_set_by_id,
    record_bin_set_change,
    seed_initial_bin_set_history,
)


@pytest.mark.asyncio
async def test_seed_writes_first_row_when_table_empty(db_session, monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000,1000000",
    )
    row = await seed_initial_bin_set_history(db_session)
    await db_session.commit()
    assert row.id is not None
    assert row.bin_set_json["bins_sat"] == [50_000, 100_000, 250_000, 500_000, 1_000_000]


@pytest.mark.asyncio
async def test_seed_is_idempotent(db_session) -> None:
    first = await seed_initial_bin_set_history(db_session)
    await db_session.commit()
    second = await seed_initial_bin_set_history(db_session)
    assert second.id == first.id  # same row, no second insert


@pytest.mark.asyncio
async def test_get_bin_set_by_id_sentinel_returns_current(db_session, monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000",
    )
    out = await get_bin_set_by_id(db_session, IMPLICIT_BIN_SET_SENTINEL)
    assert out == [50_000, 100_000, 250_000]


@pytest.mark.asyncio
async def test_get_bin_set_by_id_returns_history_row(db_session) -> None:
    row = await record_bin_set_change(
        db_session,
        bin_set=[100_000, 200_000],
        schema_version=2,
    )
    await db_session.commit()
    out = await get_bin_set_by_id(db_session, row.id)
    assert out == [100_000, 200_000]


@pytest.mark.asyncio
async def test_get_bin_set_by_id_returns_none_for_missing(db_session) -> None:
    out = await get_bin_set_by_id(db_session, 99_999)
    assert out is None


@pytest.mark.asyncio
async def test_get_active_at_height_falls_back_to_sentinel_when_empty(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000",
    )
    when = datetime(2026, 5, 10, tzinfo=timezone.utc)
    bin_set_id, bins = await get_active_bin_set_at_height(
        db_session,
        confirmed_at=when,
    )
    assert bin_set_id == IMPLICIT_BIN_SET_SENTINEL
    assert bins == [50_000, 100_000]


@pytest.mark.asyncio
async def test_get_active_at_height_returns_most_recent_history(
    db_session,
) -> None:
    """Multiple rows ⇒ pick the most-recent one whose activated_at ≤ confirmed_at."""
    early = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later = datetime(2026, 4, 1, tzinfo=timezone.utc)

    await record_bin_set_change(
        db_session,
        bin_set=[100_000],
        schema_version=1,
        activated_at=early,
    )
    await record_bin_set_change(
        db_session,
        bin_set=[100_000, 250_000],
        schema_version=2,
        activated_at=later,
    )
    await db_session.commit()

    # Confirmed before the second row → first row's set.
    bin_set_id, bins = await get_active_bin_set_at_height(
        db_session,
        confirmed_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )
    assert bins == [100_000]

    # Confirmed after both → second row's set.
    bin_set_id, bins = await get_active_bin_set_at_height(
        db_session,
        confirmed_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    assert bins == [100_000, 250_000]


@pytest.mark.asyncio
async def test_get_active_at_height_handles_naive_input(db_session) -> None:
    """A naive datetime input is treated as UTC."""
    await record_bin_set_change(
        db_session,
        bin_set=[1_000],
        schema_version=1,
        activated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    await db_session.commit()
    naive = datetime(2026, 5, 1)  # no tzinfo
    _, bins = await get_active_bin_set_at_height(db_session, confirmed_at=naive)
    assert bins == [1_000]
