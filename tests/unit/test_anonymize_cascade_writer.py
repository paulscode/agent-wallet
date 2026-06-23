# SPDX-License-Identifier: MIT
"""Chain-anchor cascade onto boltz_swap.

The cascade writer is gated by both the live-reference
predicate and the
``ANONYMIZE_BOLTZ_SWAP_REDACT_ON_ANONYMIZE_RETENTION`` feature flag.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
from app.services.anonymize.gc import cascade_redact_boltz_swap_anchors


def _swap() -> BoltzSwap:
    return BoltzSwap(
        id=uuid4(),
        boltz_swap_id="boltz-id-" + uuid4().hex[:8],
        direction=BoltzSwapDirection.REVERSE,
        api_key_id=uuid4(),
        invoice_amount_sats=250_000,
        destination_address="bcrt1qexample",
        claim_txid="aa" * 32,
        status=SwapStatus.COMPLETED,
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
    )


@pytest.mark.asyncio
async def test_cascade_nulls_claim_txid_when_safe(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_swap_redact_on_anonymize_retention", True)
    swap = _swap()
    db_session.add(swap)
    await db_session.commit()

    out = await cascade_redact_boltz_swap_anchors(db_session, boltz_swap_id=swap.id)
    assert out is True
    # The cascade mutates the in-memory instance; flush so the UPDATE
    # is sent to the DB. The in-memory ``claim_txid`` reflects the
    # mutation directly without a refresh.
    await db_session.flush()
    assert swap.claim_txid is None


@pytest.mark.asyncio
async def test_cascade_skipped_when_feature_flag_off(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_swap_redact_on_anonymize_retention", False)
    swap = _swap()
    db_session.add(swap)
    await db_session.commit()
    out = await cascade_redact_boltz_swap_anchors(db_session, boltz_swap_id=swap.id)
    assert out is False
    # No mutation expected — the original ciphertext is still in place.
    assert swap.claim_txid is not None


@pytest.mark.asyncio
async def test_cascade_skipped_when_other_session_still_references(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_swap_redact_on_anonymize_retention", True)
    swap = _swap()
    sess = _session(reverse_swap_id=swap.id)  # live reference
    db_session.add_all([swap, sess])
    await db_session.commit()
    # Cascade attempted by another session ⇒ predicate fails ⇒ no-op.
    out = await cascade_redact_boltz_swap_anchors(db_session, boltz_swap_id=swap.id)
    assert out is False
    assert swap.claim_txid is not None


@pytest.mark.asyncio
async def test_cascade_runs_when_excluding_session_was_only_reference(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_swap_redact_on_anonymize_retention", True)
    swap = _swap()
    sess = _session(reverse_swap_id=swap.id)
    db_session.add_all([swap, sess])
    await db_session.commit()
    out = await cascade_redact_boltz_swap_anchors(
        db_session,
        boltz_swap_id=swap.id,
        excluding_session_id=sess.id,
    )
    assert out is True
    await db_session.flush()
    assert swap.claim_txid is None


@pytest.mark.asyncio
async def test_cascade_returns_false_for_missing_swap(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_swap_redact_on_anonymize_retention", True)
    out = await cascade_redact_boltz_swap_anchors(
        db_session,
        boltz_swap_id=uuid4(),
    )
    assert out is False
