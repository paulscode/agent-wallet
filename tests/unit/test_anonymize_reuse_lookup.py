# SPDX-License-Identifier: MIT
"""Destination-reuse hard-block DB lookup.

DB-integration test (uses the in-memory SQLite test fixture). The
lookup must:
* Return False for fresh addresses.
* Return True after a session with that address has been recorded.
* Skip the all-zeros sentinel (purged-key rows).
* Skip soft-deleted rows.
* Match historical hashes generated under any loaded key generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.crypto import encrypt_destination_address
from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL
from app.services.anonymize.reuse_detection import (
    ReuseDetectionKeySet,
    fetch_reuse_hashes_for_destination,
    is_destination_reused,
)

_KEY_A = b"\xaa" * 32
_KEY_B = b"\xbb" * 32

_ADDR_PASTED = "bcrt1qexampleexampleexampleexampleexampleexample"
_ADDR_OTHER = "bcrt1qotherotherotherotherotherotherotherotherother"


def _insert_session(db, *, addr_hash: bytes, deleted: bool = False) -> AnonymizeSession:
    sess = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=encrypt_destination_address(_ADDR_PASTED),
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=addr_hash,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        deleted_at=datetime.now(timezone.utc) if deleted else None,
    )
    db.add(sess)
    return sess


@pytest.mark.asyncio
async def test_no_match_for_unseen_address(db_session) -> None:
    keyset = ReuseDetectionKeySet([_KEY_A], active_generation=0)
    out = await fetch_reuse_hashes_for_destination(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)
    assert out == []
    assert (await is_destination_reused(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)) is False


@pytest.mark.asyncio
async def test_match_when_address_was_used(db_session) -> None:
    keyset = ReuseDetectionKeySet([_KEY_A], active_generation=0)
    h = keyset.hash_active(_ADDR_PASTED)
    _insert_session(db_session, addr_hash=h)
    await db_session.commit()

    out = await fetch_reuse_hashes_for_destination(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)
    assert out == [h]
    assert (await is_destination_reused(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)) is True


@pytest.mark.asyncio
async def test_lookup_only_returns_matching_address(db_session) -> None:
    keyset = ReuseDetectionKeySet([_KEY_A], active_generation=0)
    h_other = keyset.hash_active(_ADDR_OTHER)
    _insert_session(db_session, addr_hash=h_other)
    await db_session.commit()
    out = await fetch_reuse_hashes_for_destination(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)
    assert out == []
    assert (await is_destination_reused(db_session, candidate_address=_ADDR_OTHER, keyset=keyset)) is True


@pytest.mark.asyncio
async def test_sentinel_rows_are_ignored(db_session) -> None:
    """A row whose hash is the sentinel must NOT match anything.

    Matching against the sentinel hash would re-introduce false-
    positive reuse hits for every sentinel-overwritten row.
    """
    keyset = ReuseDetectionKeySet([_KEY_A], active_generation=0)
    _insert_session(db_session, addr_hash=REUSE_DETECTION_SENTINEL)
    await db_session.commit()
    # Hash an address; it should not match the sentinel even by accident.
    out = await fetch_reuse_hashes_for_destination(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)
    assert out == []


@pytest.mark.asyncio
async def test_soft_deleted_rows_are_ignored(db_session) -> None:
    keyset = ReuseDetectionKeySet([_KEY_A], active_generation=0)
    h = keyset.hash_active(_ADDR_PASTED)
    _insert_session(db_session, addr_hash=h, deleted=True)
    await db_session.commit()
    out = await fetch_reuse_hashes_for_destination(db_session, candidate_address=_ADDR_PASTED, keyset=keyset)
    assert out == []


@pytest.mark.asyncio
async def test_lookup_works_across_key_generations(db_session) -> None:
    """A row hashed under the previous key still matches after rotation."""
    # Insert a row hashed under the *old* key.
    old_keyset = ReuseDetectionKeySet([_KEY_B], active_generation=0)
    old_hash = old_keyset.hash_active(_ADDR_PASTED)
    _insert_session(db_session, addr_hash=old_hash)
    await db_session.commit()

    # Now run the lookup under the post-rotation key set: index 0 is
    # the new active key, index 1 is the rotated-out one.
    new_keyset = ReuseDetectionKeySet([_KEY_A, _KEY_B], active_generation=0)
    out = await fetch_reuse_hashes_for_destination(db_session, candidate_address=_ADDR_PASTED, keyset=new_keyset)
    assert out == [old_hash]
