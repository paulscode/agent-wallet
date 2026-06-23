# SPDX-License-Identifier: MIT
"""Recurring decoy-retention catch-up pass."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeStatus,
)
from app.services.anonymize.gc import (
    ALL_PASSES_MASK,
    GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    fetch_decoy_catchup_sessions,
)


def _session(*, status, completed_offset_days: float, gc_bits: int = 0) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="onchain-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=now - timedelta(days=completed_offset_days),
        gc_passes_completed=gc_bits,
    )


@pytest.mark.asyncio
async def test_catchup_returns_session_past_horizon_missing_decoy_bit(
    db_session,
    monkeypatch,
) -> None:
    """A session past retention with non-zero passes but no decoy pass is included."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    # 30 days old, completed, has SOME pass bits set but not the decoy pass.
    sess = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_offset_days=30,
        gc_bits=ALL_PASSES_MASK & ~GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    )
    db_session.add(sess)
    await db_session.commit()

    rows = await fetch_decoy_catchup_sessions(db_session)
    assert any(r.id == sess.id for r in rows)


@pytest.mark.asyncio
async def test_catchup_excludes_session_inside_horizon(
    db_session,
    monkeypatch,
) -> None:
    """Sessions completed inside the retention horizon are skipped."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    sess = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_offset_days=2,  # well inside 7-day horizon
        gc_bits=ALL_PASSES_MASK & ~GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    )
    db_session.add(sess)
    await db_session.commit()
    rows = await fetch_decoy_catchup_sessions(db_session)
    assert all(r.id != sess.id for r in rows)


@pytest.mark.asyncio
async def test_catchup_excludes_session_with_no_passes_started(
    db_session,
    monkeypatch,
) -> None:
    """A session that has not started any retention pass is not a catchup target."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    sess = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_offset_days=30,
        gc_bits=0,  # no retention started — picked up by the regular pass
    )
    db_session.add(sess)
    await db_session.commit()
    rows = await fetch_decoy_catchup_sessions(db_session)
    assert all(r.id != sess.id for r in rows)


@pytest.mark.asyncio
async def test_catchup_excludes_session_with_decoy_pass_already_done(
    db_session,
    monkeypatch,
) -> None:
    """A row whose decoy pass already completed is not re-enqueued."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    sess = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_offset_days=30,
        gc_bits=ALL_PASSES_MASK,  # everything done
    )
    db_session.add(sess)
    await db_session.commit()
    rows = await fetch_decoy_catchup_sessions(db_session)
    assert all(r.id != sess.id for r in rows)


@pytest.mark.asyncio
async def test_catchup_respects_limit(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    for _ in range(5):
        sess = _session(
            status=AnonymizeStatus.COMPLETED.value,
            completed_offset_days=30,
            gc_bits=ALL_PASSES_MASK & ~GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
        )
        db_session.add(sess)
    await db_session.commit()
    rows = await fetch_decoy_catchup_sessions(db_session, limit=3)
    assert len(rows) == 3
