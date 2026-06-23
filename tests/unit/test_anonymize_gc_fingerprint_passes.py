# SPDX-License-Identifier: MIT
"""/ items 79 + 82 — gc fingerprint passes."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.gc import (
    GC_PASS_FINGERPRINT_COLUMNS,
    is_pass_complete,
    mark_pass_complete,
    run_fingerprint_coarsen_pass,
    run_fingerprint_columns_pass,
)


def _row(**kwargs) -> AnonymizeSession:
    base = dict(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={"tier": "moderate", "bin_amount_sat": 250_000},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        used_preconsolidation=False,
        broadcast_deadline_unix_s=1_700_000_000,
        self_broadcast_attempted_at_ts=datetime.now(timezone.utc),
        reverse_payment_chunks_k=3,
        delay_until_ts=datetime.now(timezone.utc),
        inter_leg_delay_until_ts=datetime.now(timezone.utc),
        submarine_operator_id="boltz-a",
        reverse_operator_id="boltz-b",
        awaiting_reconciliation_reason="some reason",
        pre_reconciliation_status="ln_holding",
        last_reconciliation_attempt_ts=datetime.now(timezone.utc),
        claim_broadcast_at_ts=datetime.now(timezone.utc),
        funding_has_change=True,
        reconciliation_attempts=3,
    )
    base.update(kwargs)
    return AnonymizeSession(**base)


# ── item 79 — fingerprint columns pass ────────────────────────────


@pytest.mark.asyncio
async def test_fingerprint_columns_pass_nulls_widened_set(db_session) -> None:
    sess = _row()
    db_session.add(sess)
    await db_session.commit()

    mutated = await run_fingerprint_columns_pass(db_session, sess)
    assert mutated is True
    # set.
    assert sess.used_preconsolidation is None
    assert sess.broadcast_deadline_unix_s is None
    assert sess.self_broadcast_attempted_at_ts is None
    assert sess.reverse_payment_chunks_k is None
    assert sess.delay_until_ts is None
    assert sess.inter_leg_delay_until_ts is None
    # widened set.
    assert sess.submarine_operator_id is None
    assert sess.reverse_operator_id is None
    assert sess.awaiting_reconciliation_reason is None
    assert sess.pre_reconciliation_status is None
    assert sess.last_reconciliation_attempt_ts is None
    assert sess.claim_broadcast_at_ts is None
    assert sess.funding_has_change is None
    assert sess.reconciliation_attempts == 0
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_FINGERPRINT_COLUMNS)


@pytest.mark.asyncio
async def test_fingerprint_columns_pass_quantizes_pipeline_schema_version(
    db_session,
) -> None:
    """Pipeline_schema_version → // 10 (major-generation only)."""
    sess = _row(pipeline_schema_version=23)  # MAJOR=2, MINOR=3
    db_session.add(sess)
    await db_session.commit()
    await run_fingerprint_columns_pass(db_session, sess)
    # 23 // 10 = 2 → 2 * 10 = 20 (preserves major generation).
    assert sess.pipeline_schema_version == 20


@pytest.mark.asyncio
async def test_fingerprint_columns_pass_idempotent(db_session) -> None:
    sess = _row()
    db_session.add(sess)
    await db_session.commit()
    first = await run_fingerprint_columns_pass(db_session, sess)
    second = await run_fingerprint_columns_pass(db_session, sess)
    assert first is True
    assert second is False


@pytest.mark.asyncio
async def test_fingerprint_columns_pass_skipped_when_bit_already_set(
    db_session,
) -> None:
    sess = _row()
    sess.gc_passes_completed = mark_pass_complete(0, GC_PASS_FINGERPRINT_COLUMNS)
    db_session.add(sess)
    await db_session.commit()
    out = await run_fingerprint_columns_pass(db_session, sess)
    assert out is False
    # Originals preserved.
    assert sess.submarine_operator_id == "boltz-a"


# ── item 82 — fingerprint coarsen pass ────────────────────────────


@pytest.mark.asyncio
async def test_fingerprint_coarsen_pass_rounds_completed_at_to_bucket(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    # 14:32 UTC on a fictional day.
    completed = datetime(2026, 5, 10, 14, 32, 17, tzinfo=timezone.utc)
    sess = _row(completed_at=completed)
    db_session.add(sess)
    await db_session.commit()

    mutated = await run_fingerprint_coarsen_pass(db_session, sess)
    assert mutated is True
    # Bucket-quantized to 14:00 UTC.
    assert sess.completed_at == datetime(2026, 5, 10, 14, 0, 0, tzinfo=timezone.utc)
    assert sess.destination_script_type == "redacted"


@pytest.mark.asyncio
async def test_fingerprint_coarsen_replaces_bin_amount_with_index(
    db_session,
    monkeypatch,
) -> None:
    """Bin_amount_sat → index in published bin set."""
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000,1000000,2000000,5000000",
    )
    sess = _row(bin_amount_sat=250_000)
    db_session.add(sess)
    await db_session.commit()
    await run_fingerprint_coarsen_pass(db_session, sess)
    # 250_000 is bins[2].
    assert sess.bin_amount_sat == 2
    assert sess.pipeline_json.get("bin_index") == 2
    assert "bin_amount_sat" not in sess.pipeline_json


@pytest.mark.asyncio
async def test_fingerprint_coarsen_unknown_bin_uses_minus_one(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000",
    )
    sess = _row(bin_amount_sat=999_999)  # not in published set
    db_session.add(sess)
    await db_session.commit()
    await run_fingerprint_coarsen_pass(db_session, sess)
    assert sess.bin_amount_sat == -1
    assert sess.pipeline_json.get("bin_index") == -1


@pytest.mark.asyncio
async def test_fingerprint_coarsen_idempotent(db_session) -> None:
    sess = _row(bin_amount_sat=250_000)
    db_session.add(sess)
    await db_session.commit()
    first = await run_fingerprint_coarsen_pass(db_session, sess)
    second = await run_fingerprint_coarsen_pass(db_session, sess)
    assert first is True
    assert second is False
