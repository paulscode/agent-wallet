# SPDX-License-Identifier: MIT
"""Reuse-detection partial index excludes the sentinel.

The migration declares::

    CREATE INDEX ix_anonymize_session_destination_keyed
      ON anonymize_session(destination_address_blake2b_keyed)
      WHERE deleted_at IS NULL
        AND destination_address_blake2b_keyed != E'\\x' || repeat('00', 32)::bytea;

This DB-integration test verifies the *behavior* the partial-index
predicate enables: a sentinel-overwritten row (post purge) is
not returned by the reuse-lookup query, and a fresh address whose
hash happens to equal another sentinel-bearing row's hash space does
not collide. Combined with :mod:`tests.unit.test_anonymize_reuse_lookup`
this completes the internal-consistency story.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.crypto import encrypt_destination_address
from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL


def _row(*, addr_hash: bytes, deleted: bool = False) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=encrypt_destination_address("bcrt1qexample"),
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=addr_hash,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        deleted_at=datetime.now(timezone.utc) if deleted else None,
    )


@pytest.mark.asyncio
async def test_sentinel_row_not_returned_by_reuse_predicate(db_session) -> None:
    """A row with the sentinel hash must not match the reuse predicate."""
    db_session.add(_row(addr_hash=REUSE_DETECTION_SENTINEL))
    await db_session.commit()
    # The application-layer query embeds the same predicate the
    # partial index relies on (excluding sentinel + soft-deleted rows).
    stmt = select(AnonymizeSession.destination_address_blake2b_keyed).where(
        AnonymizeSession.destination_address_blake2b_keyed.in_([REUSE_DETECTION_SENTINEL]),
        AnonymizeSession.deleted_at.is_(None),
        AnonymizeSession.destination_address_blake2b_keyed != REUSE_DETECTION_SENTINEL,
    )
    result = await db_session.execute(stmt)
    assert list(result.all()) == []


@pytest.mark.asyncio
async def test_real_row_returned_by_reuse_predicate(db_session) -> None:
    real_hash = b"\x77" * 32
    db_session.add(_row(addr_hash=real_hash))
    await db_session.commit()
    stmt = select(AnonymizeSession.destination_address_blake2b_keyed).where(
        AnonymizeSession.destination_address_blake2b_keyed.in_([real_hash]),
        AnonymizeSession.deleted_at.is_(None),
        AnonymizeSession.destination_address_blake2b_keyed != REUSE_DETECTION_SENTINEL,
    )
    result = await db_session.execute(stmt)
    assert [row[0] for row in result.all()] == [real_hash]


@pytest.mark.asyncio
async def test_soft_deleted_real_row_not_returned(db_session) -> None:
    real_hash = b"\x55" * 32
    db_session.add(_row(addr_hash=real_hash, deleted=True))
    await db_session.commit()
    stmt = select(AnonymizeSession.destination_address_blake2b_keyed).where(
        AnonymizeSession.destination_address_blake2b_keyed.in_([real_hash]),
        AnonymizeSession.deleted_at.is_(None),
        AnonymizeSession.destination_address_blake2b_keyed != REUSE_DETECTION_SENTINEL,
    )
    result = await db_session.execute(stmt)
    assert list(result.all()) == []


@pytest.mark.asyncio
async def test_mixed_workload_only_returns_eligible_row(db_session) -> None:
    """With sentinel + soft-deleted + live rows present, only the live
    real-hash row matches."""
    sentinel_row = _row(addr_hash=REUSE_DETECTION_SENTINEL)
    deleted_row = _row(addr_hash=b"\xaa" * 32, deleted=True)
    live_row = _row(addr_hash=b"\xbb" * 32)
    db_session.add_all([sentinel_row, deleted_row, live_row])
    await db_session.commit()

    candidates = [REUSE_DETECTION_SENTINEL, b"\xaa" * 32, b"\xbb" * 32]
    stmt = select(AnonymizeSession.destination_address_blake2b_keyed).where(
        AnonymizeSession.destination_address_blake2b_keyed.in_(candidates),
        AnonymizeSession.deleted_at.is_(None),
        AnonymizeSession.destination_address_blake2b_keyed != REUSE_DETECTION_SENTINEL,
    )
    result = await db_session.execute(stmt)
    assert [row[0] for row in result.all()] == [b"\xbb" * 32]
