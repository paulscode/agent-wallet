# SPDX-License-Identifier: MIT
"""Hop-idempotency-key purge ordering."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.hop_idempotency import (
    can_purge_hop_idempotency_key_generation,
)


def _session(*, status: str, completed_at: datetime) -> AnonymizeSession:
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
        destination_address_blake2b_keyed=uuid4().bytes + uuid4().bytes,
        destination_reuse_key_generation=0,
        completed_at=completed_at,
    )


def _event(*, sid, generation: int) -> AnonymizeSessionEvent:
    return AnonymizeSessionEvent(
        session_id=sid,
        ts=datetime.now(timezone.utc),
        kind="hop_attempt_started",
        detail_json={},
        hop_idempotency_key=f"deadbeef-{generation}-{uuid4().hex[:8]}",
        hop_idempotency_key_generation=generation,
        hop_idempotency_nonce_enc=b"\x10" * 16,
    )


@pytest.mark.asyncio
async def test_refuses_purge_within_retention_horizon(db_session) -> None:
    now = time.time()
    rotated_out = now - 86400  # 1 day ago
    can, reason = await can_purge_hop_idempotency_key_generation(
        db_session,
        generation=5,
        rotated_out_at_unix_s=rotated_out,
        retention_days=14,  # 14-day retention not yet elapsed
        destination_retention_days=7,
        now_unix_s=now,
    )
    assert can is False
    assert "retention horizon" in (reason or "")


@pytest.mark.asyncio
async def test_admits_purge_when_horizon_clear_and_no_references(db_session) -> None:
    now = time.time()
    rotated_out = now - (30 * 86400)  # well past retention
    can, reason = await can_purge_hop_idempotency_key_generation(
        db_session,
        generation=5,
        rotated_out_at_unix_s=rotated_out,
        retention_days=14,
        destination_retention_days=7,
        now_unix_s=now,
    )
    assert can is True
    assert reason is None


@pytest.mark.asyncio
async def test_refuses_purge_when_non_terminal_session_references(
    db_session,
) -> None:
    now = time.time()
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(sess)
    await db_session.flush()
    db_session.add(_event(sid=sess.id, generation=5))
    await db_session.commit()

    can, reason = await can_purge_hop_idempotency_key_generation(
        db_session,
        generation=5,
        rotated_out_at_unix_s=now - (30 * 86400),
        retention_days=14,
        destination_retention_days=7,
        now_unix_s=now,
    )
    assert can is False
    assert "non-terminal" in (reason or "")


@pytest.mark.asyncio
async def test_refuses_purge_when_recent_terminal_session_references(
    db_session,
) -> None:
    """Terminal session inside the destination-retention window blocks the purge."""
    now = time.time()
    completed_at = datetime.now(timezone.utc) - timedelta(days=2)
    sess = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_at=completed_at,
    )
    db_session.add(sess)
    await db_session.flush()
    db_session.add(_event(sid=sess.id, generation=5))
    await db_session.commit()

    can, reason = await can_purge_hop_idempotency_key_generation(
        db_session,
        generation=5,
        rotated_out_at_unix_s=now - (30 * 86400),
        retention_days=14,
        destination_retention_days=7,
        now_unix_s=now,
    )
    assert can is False
    assert "destination-retention window" in (reason or "")


@pytest.mark.asyncio
async def test_admits_purge_when_only_old_terminal_references(db_session) -> None:
    """Terminal session past destination retention does NOT block the purge."""
    now = time.time()
    completed_at = datetime.now(timezone.utc) - timedelta(days=30)
    sess = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_at=completed_at,
    )
    db_session.add(sess)
    await db_session.flush()
    db_session.add(_event(sid=sess.id, generation=5))
    await db_session.commit()

    can, _reason = await can_purge_hop_idempotency_key_generation(
        db_session,
        generation=5,
        rotated_out_at_unix_s=now - (30 * 86400),
        retention_days=14,
        destination_retention_days=7,
        now_unix_s=now,
    )
    assert can is True
