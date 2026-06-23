# SPDX-License-Identifier: MIT
"""Refund-label backfill HWM."""

from __future__ import annotations

import time

import pytest

from app.services.anonymize.refund_backfill import (
    HighWaterMark,
    read_high_water_mark,
    update_high_water_mark,
)


@pytest.mark.asyncio
async def test_read_returns_empty_on_fresh_deploy(db_session) -> None:
    out = await read_high_water_mark(db_session)
    assert out.backfilled_through_boltz_swap_id_ordering == 0
    assert out.backfilled_at_unix_s == 0.0


@pytest.mark.asyncio
async def test_update_persists_value(db_session) -> None:
    await update_high_water_mark(
        db_session,
        new_ordering=42,
        now_unix_s=1_000_000.0,
    )
    await db_session.commit()
    out = await read_high_water_mark(db_session)
    assert out.backfilled_through_boltz_swap_id_ordering == 42
    assert out.backfilled_at_unix_s == 1_000_000.0


@pytest.mark.asyncio
async def test_update_is_monotonic(db_session) -> None:
    """A lower-ordering write must NOT regress the HWM."""
    await update_high_water_mark(db_session, new_ordering=100)
    await db_session.commit()
    # Try to roll back to 50 — should be a no-op.
    await update_high_water_mark(db_session, new_ordering=50)
    await db_session.commit()
    out = await read_high_water_mark(db_session)
    assert out.backfilled_through_boltz_swap_id_ordering == 100


@pytest.mark.asyncio
async def test_update_admits_strictly_greater_ordering(db_session) -> None:
    await update_high_water_mark(db_session, new_ordering=10)
    await db_session.commit()
    await update_high_water_mark(db_session, new_ordering=20)
    await db_session.commit()
    out = await read_high_water_mark(db_session)
    assert out.backfilled_through_boltz_swap_id_ordering == 20


@pytest.mark.asyncio
async def test_update_uses_current_time_by_default(db_session) -> None:
    before = time.time()
    await update_high_water_mark(db_session, new_ordering=1)
    after = time.time()
    out = await read_high_water_mark(db_session)
    assert before <= out.backfilled_at_unix_s <= after


@pytest.mark.asyncio
async def test_empty_classmethod_returns_zero_state() -> None:
    e = HighWaterMark.empty()
    assert e.backfilled_through_boltz_swap_id_ordering == 0
    assert e.backfilled_at_unix_s == 0.0


# ── Sequence regression + anti-orphan scan ──────────────────────


def test_sequence_regression_passes_when_max_id_matches_or_exceeds_hwm() -> None:
    from app.services.anonymize.refund_backfill import (
        HighWaterMark,
        assert_no_sequence_regression,
    )

    hwm = HighWaterMark(
        backfilled_through_boltz_swap_id_ordering=1000,
        backfilled_at_unix_s=1.0,
        max_processed_created_at_day=20260510,
    )
    # No-raise.
    assert_no_sequence_regression(
        current_max_boltz_swap_id=1000,
        hwm=hwm,
        override_allowed=False,
    )
    assert_no_sequence_regression(
        current_max_boltz_swap_id=2000,
        hwm=hwm,
        override_allowed=False,
    )


def test_sequence_regression_raises_when_max_id_below_hwm() -> None:
    import pytest

    from app.services.anonymize.refund_backfill import (
        BoltzSwapSequenceRegressionError,
        HighWaterMark,
        assert_no_sequence_regression,
    )

    hwm = HighWaterMark(
        backfilled_through_boltz_swap_id_ordering=1000,
        backfilled_at_unix_s=1.0,
        max_processed_created_at_day=20260510,
    )
    with pytest.raises(BoltzSwapSequenceRegressionError, match="sequence regression"):
        assert_no_sequence_regression(
            current_max_boltz_swap_id=500,
            hwm=hwm,
            override_allowed=False,
        )


def test_sequence_regression_override_admits_rewound_state() -> None:
    """One-shot override admits a rewound DB so the orchestrator can rewrite HWM."""
    from app.services.anonymize.refund_backfill import (
        HighWaterMark,
        assert_no_sequence_regression,
    )

    hwm = HighWaterMark(
        backfilled_through_boltz_swap_id_ordering=1000,
        backfilled_at_unix_s=1.0,
        max_processed_created_at_day=20260510,
    )
    # No-raise under operator-acknowledged override.
    assert_no_sequence_regression(
        current_max_boltz_swap_id=500,
        hwm=hwm,
        override_allowed=True,
    )


def test_anti_orphan_scan_window_includes_slack_day() -> None:
    from app.services.anonymize.refund_backfill import (
        AntiOrphanScanWindow,
        HighWaterMark,
        build_anti_orphan_scan_window,
    )

    hwm = HighWaterMark(
        backfilled_through_boltz_swap_id_ordering=1000,
        backfilled_at_unix_s=1.0,
        max_processed_created_at_day=20260510,
    )
    out = build_anti_orphan_scan_window(hwm, slack_days=1)
    assert isinstance(out, AntiOrphanScanWindow)
    assert out.max_processed_id == 1000
    assert out.earliest_created_at_day == 20260509


def test_anti_orphan_scan_window_zero_on_fresh_deployment() -> None:
    from app.services.anonymize.refund_backfill import (
        HighWaterMark,
        build_anti_orphan_scan_window,
    )

    out = build_anti_orphan_scan_window(HighWaterMark.empty(), slack_days=1)
    assert out.max_processed_id == 0
    assert out.earliest_created_at_day == 0
