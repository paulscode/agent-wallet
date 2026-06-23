# SPDX-License-Identifier: MIT
"""Reuse_key_purge + hop_idempotency_key_null GC passes."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.gc import (
    GC_PASS_HOP_IDEMPOTENCY_KEY_NULL,
    GC_PASS_REUSE_KEY_PURGE,
    is_pass_complete,
    run_hop_idempotency_key_null_pass,
    run_reuse_key_purge_pass,
)
from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL


def _session(*, gc_bits: int = 0, reuse_hash: bytes = b"\xab" * 32) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=reuse_hash,
        destination_reuse_key_generation=0,
        gc_passes_completed=gc_bits,
        completed_at=datetime.now(timezone.utc),
    )


# ── reuse_key_purge ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_reuse_key_purge_overwrites_hash_with_sentinel(db_session) -> None:
    s = _session(reuse_hash=b"\x77" * 32)
    db_session.add(s)
    await db_session.commit()

    out = await run_reuse_key_purge_pass(db_session, s)
    assert out is True
    assert s.destination_address_blake2b_keyed == REUSE_DETECTION_SENTINEL
    assert is_pass_complete(s.gc_passes_completed, GC_PASS_REUSE_KEY_PURGE)


@pytest.mark.asyncio
async def test_reuse_key_purge_is_idempotent(db_session) -> None:
    s = _session(gc_bits=GC_PASS_REUSE_KEY_PURGE)
    db_session.add(s)
    await db_session.commit()

    out = await run_reuse_key_purge_pass(db_session, s)
    assert out is False
    # Hash unchanged on re-run.
    assert s.destination_address_blake2b_keyed == b"\xab" * 32


# ── hop_idempotency_key_null ─────────────────────────────────


@pytest.mark.asyncio
async def test_hop_idempotency_key_null_clears_event_columns(db_session) -> None:
    s = _session()
    db_session.add(s)
    await db_session.flush()

    ev = AnonymizeSessionEvent(
        session_id=s.id,
        ts=datetime.now(timezone.utc),
        kind="hop_attempt_started",
        detail_json={},
        hop_idempotency_key="abc123",
        hop_idempotency_key_generation=0,
        hop_idempotency_nonce_enc=b"\xff" * 16,
    )
    db_session.add(ev)
    await db_session.commit()

    out = await run_hop_idempotency_key_null_pass(db_session, s)
    assert out is True
    assert is_pass_complete(
        s.gc_passes_completed,
        GC_PASS_HOP_IDEMPOTENCY_KEY_NULL,
    )
    await db_session.refresh(ev)
    assert ev.hop_idempotency_key is None
    assert ev.hop_idempotency_key_generation is None
    assert ev.hop_idempotency_nonce_enc is None


@pytest.mark.asyncio
async def test_hop_idempotency_key_null_is_idempotent(db_session) -> None:
    s = _session(gc_bits=GC_PASS_HOP_IDEMPOTENCY_KEY_NULL)
    db_session.add(s)
    await db_session.commit()
    out = await run_hop_idempotency_key_null_pass(db_session, s)
    assert out is False


@pytest.mark.asyncio
async def test_hop_idempotency_key_null_skips_events_for_other_sessions(
    db_session,
) -> None:
    """Only THIS session's event rows are nulled."""
    s1 = _session()
    s2 = _session()
    db_session.add_all([s1, s2])
    await db_session.flush()

    ev_other = AnonymizeSessionEvent(
        session_id=s2.id,
        ts=datetime.now(timezone.utc),
        kind="hop_attempt_started",
        detail_json={},
        hop_idempotency_key="other-key",
        hop_idempotency_key_generation=0,
    )
    db_session.add(ev_other)
    await db_session.commit()

    await run_hop_idempotency_key_null_pass(db_session, s1)
    await db_session.refresh(ev_other)
    # The other session's event is untouched.
    assert ev_other.hop_idempotency_key == "other-key"
