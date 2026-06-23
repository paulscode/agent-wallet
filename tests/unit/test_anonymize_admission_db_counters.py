# SPDX-License-Identifier: MIT
"""/ #3 — DB-state-based admission counters."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.admission import (
    count_in_flight_sessions,
    count_sessions_created_in_window,
)


def _session(
    *,
    status: str,
    created_offset_s: float = 60,
    deleted: bool = False,
) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        created_at=now - timedelta(seconds=created_offset_s),
        deleted_at=now if deleted else None,
    )


# ── count_in_flight_sessions ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_count_in_flight_excludes_terminal(db_session) -> None:
    db_session.add_all(
        [
            _session(status=AnonymizeStatus.HOPPING.value),
            _session(status=AnonymizeStatus.LN_HOLDING.value),
            _session(status=AnonymizeStatus.COMPLETED.value),
            _session(status=AnonymizeStatus.FAILED.value),
            _session(status=AnonymizeStatus.CANCELLED.value),
        ]
    )
    await db_session.commit()
    n = await count_in_flight_sessions(db_session)
    assert n == 2


@pytest.mark.asyncio
async def test_count_in_flight_excludes_soft_deleted(db_session) -> None:
    db_session.add_all(
        [
            _session(status=AnonymizeStatus.HOPPING.value),
            _session(status=AnonymizeStatus.HOPPING.value, deleted=True),
        ]
    )
    await db_session.commit()
    n = await count_in_flight_sessions(db_session)
    assert n == 1


@pytest.mark.asyncio
async def test_count_in_flight_zero_on_empty_db(db_session) -> None:
    n = await count_in_flight_sessions(db_session)
    assert n == 0


# ── count_sessions_created_in_window ─────────────────────────────────


@pytest.mark.asyncio
async def test_count_window_returns_rows_inside(db_session) -> None:
    """Rows created inside the rolling window count; older ones don't."""
    db_session.add_all(
        [
            _session(status=AnonymizeStatus.HOPPING.value, created_offset_s=60),
            _session(status=AnonymizeStatus.HOPPING.value, created_offset_s=300),
            _session(status=AnonymizeStatus.HOPPING.value, created_offset_s=5000),  # outside
        ]
    )
    await db_session.commit()
    n = await count_sessions_created_in_window(db_session, window_seconds=3600)
    assert n == 2


@pytest.mark.asyncio
async def test_count_window_excludes_soft_deleted(db_session) -> None:
    db_session.add_all(
        [
            _session(status=AnonymizeStatus.HOPPING.value, created_offset_s=60),
            _session(
                status=AnonymizeStatus.HOPPING.value,
                created_offset_s=60,
                deleted=True,
            ),
        ]
    )
    await db_session.commit()
    n = await count_sessions_created_in_window(db_session, window_seconds=3600)
    assert n == 1


@pytest.mark.asyncio
async def test_count_window_includes_terminal_rows_inside(db_session) -> None:
    """Terminal rows still count toward the create-rate budget."""
    db_session.add_all(
        [
            _session(status=AnonymizeStatus.COMPLETED.value, created_offset_s=60),
            _session(status=AnonymizeStatus.FAILED.value, created_offset_s=120),
        ]
    )
    await db_session.commit()
    n = await count_sessions_created_in_window(db_session, window_seconds=3600)
    assert n == 2


# ── decide_session_create_admission ─────────────────────────────


def test_admission_admits_under_both_gates(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.admission import (
        AdmissionInputs,
        decide_session_create_admission,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_tier_concurrency_cap",
        "weak=3,moderate=2,strong=1",
    )
    out = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="moderate",
            in_flight_count_by_tier={"moderate": 1},
            sessions_created_in_window_count=5,
        )
    )
    assert out == "admit"


def test_admission_rate_limited_when_window_full() -> None:
    from app.services.anonymize.admission import (
        AdmissionInputs,
        decide_session_create_admission,
    )

    out = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="weak",
            in_flight_count_by_tier={"weak": 0},
            sessions_created_in_window_count=10,
        )
    )
    assert out == "rate_limited"


def test_admission_window_max_is_configurable() -> None:
    # The create endpoint passes ``window_max`` from
    # ANONYMIZE_CREATE_WINDOW_MAX_PER_HOUR so testers can raise the
    # default-10 rolling-window cap. A higher window admits beyond 10.
    from app.services.anonymize.admission import (
        AdmissionInputs,
        decide_session_create_admission,
    )

    out = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="weak",
            in_flight_count_by_tier={"weak": 0},
            sessions_created_in_window_count=15,
            window_max=50,
        )
    )
    assert out == "admit"


def test_admission_tier_cap_exhausted(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.admission import (
        AdmissionInputs,
        decide_session_create_admission,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_tier_concurrency_cap",
        "strong=1",
    )
    out = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="strong",
            in_flight_count_by_tier={"strong": 1},
            sessions_created_in_window_count=1,
        )
    )
    assert out == "tier_cap_exhausted"


def test_admission_rate_limit_takes_priority_over_tier_cap() -> None:
    """When both gates would reject, the volumetric DoS class wins."""
    from app.services.anonymize.admission import (
        AdmissionInputs,
        decide_session_create_admission,
    )

    out = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="weak",
            in_flight_count_by_tier={"weak": 100},  # cap exhausted
            sessions_created_in_window_count=10,  # window exhausted
        )
    )
    assert out == "rate_limited"


def test_admission_unknown_tier_refuses_with_lowest_cap() -> None:
    """An unknown tier name is treated conservatively."""
    from app.services.anonymize.admission import (
        AdmissionInputs,
        decide_session_create_admission,
    )

    out = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="custom-tier",
            in_flight_count_by_tier={"custom-tier": 1},
            sessions_created_in_window_count=0,
        )
    )
    assert out == "tier_cap_exhausted"
