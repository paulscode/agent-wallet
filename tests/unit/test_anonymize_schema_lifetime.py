# SPDX-License-Identifier: MIT
"""Pipeline schema forward-compat lifetime."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.startup import (
    AnonymizeStartupError,
    assert_pipeline_schema_forward_compat,
)


def _row(*, schema_version: int, status: str = AnonymizeStatus.LN_HOLDING.value) -> AnonymizeSession:
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
        pipeline_schema_version=schema_version,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_passes_when_no_in_flight_sessions(db_session) -> None:
    """Empty DB → no offenders → no raise."""
    await assert_pipeline_schema_forward_compat(db_session)


@pytest.mark.asyncio
async def test_passes_when_in_flight_at_or_above_minimum(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 10)
    db_session.add(_row(schema_version=10))
    db_session.add(_row(schema_version=11))
    await db_session.commit()
    await assert_pipeline_schema_forward_compat(db_session)


@pytest.mark.asyncio
async def test_passes_when_low_schema_session_is_terminal(db_session, monkeypatch) -> None:
    """Terminal sessions (completed/failed/cancelled) don't block startup."""
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 20)
    db_session.add(_row(schema_version=10, status=AnonymizeStatus.COMPLETED.value))
    db_session.add(_row(schema_version=10, status=AnonymizeStatus.FAILED.value))
    await db_session.commit()
    await assert_pipeline_schema_forward_compat(db_session)


@pytest.mark.asyncio
async def test_refuses_to_start_with_old_in_flight_session(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 20)
    db_session.add(_row(schema_version=10))
    await db_session.commit()
    with pytest.raises(AnonymizeStartupError, match="pipeline_schema_version"):
        await assert_pipeline_schema_forward_compat(db_session)


@pytest.mark.asyncio
async def test_error_message_caps_offender_count(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 20)
    for _ in range(8):
        db_session.add(_row(schema_version=10))
    await db_session.commit()
    with pytest.raises(AnonymizeStartupError) as excinfo:
        await assert_pipeline_schema_forward_compat(db_session)
    # The error message includes a short id list capped at 5.
    assert "first 5 ids" in str(excinfo.value)
