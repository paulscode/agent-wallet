# SPDX-License-Identifier: MIT
"""Decoy-output retention pass."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.anonymize_session import (
    AnonymizeDecoyOutput,
    AnonymizeSession,
    AnonymizeStatus,
)
from app.services.anonymize.gc import (
    GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    is_pass_complete,
    run_decoy_chain_anchor_redact_pass,
    swap_anchor_sentinel_uuid,
)


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
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
        completed_at=datetime.now(timezone.utc),
    )


def _decoy(*, sid, spent: bool = False, value: int = 50_000) -> AnonymizeDecoyOutput:
    return AnonymizeDecoyOutput(
        session_id=sid,
        session_account=42,
        derivation_index=0,
        address="bcrt1qexample",
        value_sat=value,
        outpoint=("aa" * 32) + ":0",
        spent_at=(datetime.now(timezone.utc) if spent else None),
    )


@pytest.mark.asyncio
async def test_pass_is_noop_when_no_decoy_rows(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.commit()
    out = await run_decoy_chain_anchor_redact_pass(db_session, sess)
    assert out is True  # bit set so retention can advance
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_DECOY_CHAIN_ANCHOR_REDACT)


@pytest.mark.asyncio
async def test_pass_nulls_chain_anchors_for_unspent_decoy(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    decoy = _decoy(sid=sess.id, spent=False)
    db_session.add(decoy)
    await db_session.commit()

    await run_decoy_chain_anchor_redact_pass(db_session, sess)
    # In-memory mutations show:
    assert decoy.address is None
    assert decoy.value_sat is None
    assert decoy.session_account is None
    assert decoy.derivation_index is None
    # Unspent decoy: outpoint preserved (residual #34).
    assert decoy.outpoint is not None
    # session_id replaced with sentinel.
    assert decoy.session_id == swap_anchor_sentinel_uuid()


@pytest.mark.asyncio
async def test_pass_nulls_outpoint_for_spent_decoy(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    decoy = _decoy(sid=sess.id, spent=True)
    db_session.add(decoy)
    await db_session.commit()

    await run_decoy_chain_anchor_redact_pass(db_session, sess)
    assert decoy.outpoint is None  # spent ⇒ outpoint null


@pytest.mark.asyncio
async def test_pass_handles_multiple_decoys(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    db_session.add_all(
        [
            _decoy(sid=sess.id, value=10_000),
            _decoy(sid=sess.id, value=20_000),
            _decoy(sid=sess.id, value=30_000),
        ]
    )
    await db_session.commit()
    await run_decoy_chain_anchor_redact_pass(db_session, sess)

    rows = (
        (
            await db_session.execute(
                select(AnonymizeDecoyOutput).where(AnonymizeDecoyOutput.session_id == swap_anchor_sentinel_uuid())
            )
        )
        .scalars()
        .all()
    )
    assert len(list(rows)) == 3


@pytest.mark.asyncio
async def test_pass_is_idempotent(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.commit()
    first = await run_decoy_chain_anchor_redact_pass(db_session, sess)
    second = await run_decoy_chain_anchor_redact_pass(db_session, sess)
    assert first is True
    assert second is False


@pytest.mark.asyncio
async def test_pass_does_not_touch_other_session_decoys(db_session) -> None:
    sess_a = _session()
    sess_b = _session()
    db_session.add_all([sess_a, sess_b])
    await db_session.flush()
    decoy_a = _decoy(sid=sess_a.id)
    decoy_b = _decoy(sid=sess_b.id)
    db_session.add_all([decoy_a, decoy_b])
    await db_session.commit()

    await run_decoy_chain_anchor_redact_pass(db_session, sess_a)
    # sess_b's decoy is untouched.
    assert decoy_b.address == "bcrt1qexample"
    assert decoy_b.session_id == sess_b.id
