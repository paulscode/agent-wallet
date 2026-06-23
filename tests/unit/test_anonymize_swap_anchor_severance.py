# SPDX-License-Identifier: MIT
"""Gc swap-anchor severance pass."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
from app.services.anonymize.gc import (
    GC_PASS_CHAIN_ANCHOR_REDACT,
    GC_PASS_SWAP_ANCHOR_SEVER,
    is_pass_complete,
    mark_pass_complete,
    run_swap_anchor_severance_pass,
    swap_anchor_sentinel_uuid,
)


def _session(*, submarine_swap_id=None, reverse_swap_id=None) -> AnonymizeSession:
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
        # Pre-condition: chain-anchor pass already ran.
        gc_passes_completed=mark_pass_complete(0, GC_PASS_CHAIN_ANCHOR_REDACT),
    )


def _swap() -> BoltzSwap:
    return BoltzSwap(
        id=uuid4(),
        boltz_swap_id="boltz-id-" + uuid4().hex[:8],
        direction=BoltzSwapDirection.REVERSE,
        api_key_id=uuid4(),
        invoice_amount_sats=250_000,
        destination_address="bcrt1qexample",
        status=SwapStatus.COMPLETED,
    )


def test_sentinel_uuid_is_all_zeros() -> None:
    assert str(swap_anchor_sentinel_uuid()) == "00000000-0000-0000-0000-000000000000"


@pytest.mark.asyncio
async def test_severance_replaces_swap_ids_with_sentinel(db_session) -> None:
    swap_a = _swap()
    swap_b = _swap()
    sess = _session(submarine_swap_id=swap_a.id, reverse_swap_id=swap_b.id)
    db_session.add_all([swap_a, swap_b, sess])
    await db_session.commit()

    sentinel = swap_anchor_sentinel_uuid()
    out = await run_swap_anchor_severance_pass(db_session, sess)
    assert out is True
    assert sess.submarine_swap_id == sentinel
    assert sess.reverse_swap_id == sentinel
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_SWAP_ANCHOR_SEVER)


@pytest.mark.asyncio
async def test_severance_skipped_when_chain_anchor_pass_not_run(db_session) -> None:
    """Pre-condition: chain-anchor pass (bit 3) must be set first."""
    swap_a = _swap()
    sess = _session(submarine_swap_id=swap_a.id)
    sess.gc_passes_completed = 0  # chain-anchor bit NOT set
    db_session.add_all([swap_a, sess])
    await db_session.commit()

    out = await run_swap_anchor_severance_pass(db_session, sess)
    assert out is False
    assert not is_pass_complete(sess.gc_passes_completed, GC_PASS_SWAP_ANCHOR_SEVER)


@pytest.mark.asyncio
async def test_severance_skipped_when_other_session_references_swap(
    db_session,
) -> None:
    """Pre-condition: live cross-references block the sentinel write."""
    swap_a = _swap()
    sess = _session(submarine_swap_id=swap_a.id)
    other = _session(submarine_swap_id=swap_a.id)  # live reference
    db_session.add_all([swap_a, sess, other])
    await db_session.commit()

    await run_swap_anchor_severance_pass(db_session, sess)
    # Still set the bit so retention can advance, but the swap_id
    # column is preserved (the cross-reference predicate failed).
    assert sess.submarine_swap_id == swap_a.id


@pytest.mark.asyncio
async def test_severance_idempotent(db_session) -> None:
    swap_a = _swap()
    sess = _session(submarine_swap_id=swap_a.id)
    db_session.add_all([swap_a, sess])
    await db_session.commit()
    first = await run_swap_anchor_severance_pass(db_session, sess)
    second = await run_swap_anchor_severance_pass(db_session, sess)
    assert first is True
    assert second is False  # already complete


@pytest.mark.asyncio
async def test_severance_is_a_noop_when_swap_ids_already_null(db_session) -> None:
    """LN-source sessions have no swap_id columns; the pass
    still records completion so retention advances."""
    sess = _session(submarine_swap_id=None, reverse_swap_id=None)
    db_session.add(sess)
    await db_session.commit()
    out = await run_swap_anchor_severance_pass(db_session, sess)
    assert out is True
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_SWAP_ANCHOR_SEVER)
