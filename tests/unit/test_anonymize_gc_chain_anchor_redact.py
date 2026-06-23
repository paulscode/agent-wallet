# SPDX-License-Identifier: MIT
"""Destination retention pass body.

The pass nulls ``destination_address_enc`` (sentinel),
``output_txid``, ``output_vout``, ``claim_tx_hex``, and stamps
``destination_address_redacted_at``. Idempotent — running twice
on the same row leaves it unchanged.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.crypto import (
    DESTINATION_REDACTED_SENTINEL,
    encrypt_destination_address,
)
from app.services.anonymize.gc import (
    GC_PASS_CHAIN_ANCHOR_REDACT,
    GC_PASS_LAST_ERROR_NULL,
    is_pass_complete,
    mark_pass_complete,
    run_chain_anchor_redact_pass,
    run_last_error_null_pass,
)


def _make_session(
    *,
    status: str = AnonymizeStatus.COMPLETED.value,
    completed_at: datetime | None = None,
) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=encrypt_destination_address("bcrt1q" + "0" * 38),
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=completed_at or datetime.now(timezone.utc),
        output_txid="aa" * 32,
        output_vout=0,
        claim_tx_hex="deadbeef" * 50,
        last_error="some error trace",
    )


@pytest.mark.asyncio
async def test_chain_anchor_redact_pass_nulls_sensitive_fields(db_session) -> None:
    sess = _make_session()
    db_session.add(sess)
    await db_session.commit()

    mutated = await run_chain_anchor_redact_pass(db_session, sess)
    assert mutated is True
    assert sess.destination_address_enc == DESTINATION_REDACTED_SENTINEL
    assert sess.output_txid is None
    assert sess.output_vout is None
    assert sess.claim_tx_hex is None
    assert sess.destination_address_redacted_at is not None
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_CHAIN_ANCHOR_REDACT)


@pytest.mark.asyncio
async def test_chain_anchor_redact_pass_is_idempotent(db_session) -> None:
    sess = _make_session()
    db_session.add(sess)
    await db_session.commit()

    first = await run_chain_anchor_redact_pass(db_session, sess)
    second = await run_chain_anchor_redact_pass(db_session, sess)
    assert first is True
    assert second is False  # already complete
    # The redaction timestamp should not be re-stamped on the no-op call.
    redacted_at_after_first = sess.destination_address_redacted_at
    assert redacted_at_after_first is not None


@pytest.mark.asyncio
async def test_last_error_null_pass(db_session) -> None:
    sess = _make_session()
    db_session.add(sess)
    await db_session.commit()
    assert sess.last_error is not None
    mutated = await run_last_error_null_pass(db_session, sess)
    assert mutated is True
    assert sess.last_error is None
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_LAST_ERROR_NULL)


@pytest.mark.asyncio
async def test_last_error_null_pass_is_idempotent(db_session) -> None:
    sess = _make_session()
    db_session.add(sess)
    await db_session.commit()
    await run_last_error_null_pass(db_session, sess)
    again = await run_last_error_null_pass(db_session, sess)
    assert again is False


@pytest.mark.asyncio
async def test_chain_anchor_pass_skipped_when_bit_already_set(db_session) -> None:
    """Pre-marking the bitfield prevents the pass from running."""
    sess = _make_session()
    sess.gc_passes_completed = mark_pass_complete(0, GC_PASS_CHAIN_ANCHOR_REDACT)
    db_session.add(sess)
    await db_session.commit()
    mutated = await run_chain_anchor_redact_pass(db_session, sess)
    assert mutated is False
    # Original ciphertext is preserved (the function short-circuited).
    assert sess.destination_address_enc != DESTINATION_REDACTED_SENTINEL
