# SPDX-License-Identifier: MIT
"""Row-locked cascade-redaction predicate.

The predicate is True iff no other anonymize session references the
same ``boltz_swap`` row. The orchestrator takes a row-level lock on
the swap row before checking; this test verifies the *predicate*
correctness — the lock is exercised at the DB layer in production.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.gc import is_boltz_swap_safe_to_cascade_redact


def _row(*, submarine_swap_id=None, reverse_swap_id=None, deleted: bool = False) -> AnonymizeSession:
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
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        submarine_swap_id=submarine_swap_id,
        reverse_swap_id=reverse_swap_id,
        deleted_at=datetime.now(timezone.utc) if deleted else None,
    )


@pytest.mark.asyncio
async def test_safe_to_cascade_when_no_references(db_session) -> None:
    swap_id = uuid4()
    out = await is_boltz_swap_safe_to_cascade_redact(db_session, boltz_swap_id=swap_id)
    assert out is True


@pytest.mark.asyncio
async def test_unsafe_when_another_session_references_swap(db_session) -> None:
    swap_id = uuid4()
    db_session.add(_row(submarine_swap_id=swap_id))
    await db_session.commit()
    out = await is_boltz_swap_safe_to_cascade_redact(db_session, boltz_swap_id=swap_id)
    assert out is False


@pytest.mark.asyncio
async def test_safe_when_only_excluded_session_references(db_session) -> None:
    """The session being redacted itself doesn't count against the predicate."""
    swap_id = uuid4()
    sess = _row(reverse_swap_id=swap_id)
    db_session.add(sess)
    await db_session.commit()
    out = await is_boltz_swap_safe_to_cascade_redact(
        db_session,
        boltz_swap_id=swap_id,
        excluding_session_id=sess.id,
    )
    assert out is True


@pytest.mark.asyncio
async def test_safe_when_other_reference_is_soft_deleted(db_session) -> None:
    """Soft-deleted rows don't block the cascade."""
    swap_id = uuid4()
    db_session.add(_row(submarine_swap_id=swap_id, deleted=True))
    await db_session.commit()
    out = await is_boltz_swap_safe_to_cascade_redact(db_session, boltz_swap_id=swap_id)
    assert out is True


@pytest.mark.asyncio
async def test_predicate_handles_either_swap_id_column(db_session) -> None:
    """A swap_id referenced as ``reverse_swap_id`` blocks the cascade
    just as one referenced as ``submarine_swap_id`` does."""
    swap_id = uuid4()
    db_session.add(_row(reverse_swap_id=swap_id))
    await db_session.commit()
    out = await is_boltz_swap_safe_to_cascade_redact(db_session, boltz_swap_id=swap_id)
    assert out is False


@pytest.mark.asyncio
async def test_predicate_with_none_swap_id_returns_false(db_session) -> None:
    """A null swap_id is never safe — it's a programming bug."""
    out = await is_boltz_swap_safe_to_cascade_redact(db_session, boltz_swap_id=None)
    assert out is False
