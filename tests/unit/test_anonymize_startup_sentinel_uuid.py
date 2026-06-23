# SPDX-License-Identifier: MIT
"""Sentinel-UUID safety + FK-validity drift."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
from app.services.anonymize.gc import swap_anchor_sentinel_uuid
from app.services.anonymize.startup import (
    AnonymizeStartupError,
    assert_pipeline_schema_version_check_invariant,
    assert_sentinel_uuid_fk_integrity,
)


def _swap() -> BoltzSwap:
    return BoltzSwap(
        id=uuid4(),
        boltz_swap_id="b-" + uuid4().hex[:8],
        direction=BoltzSwapDirection.REVERSE,
        api_key_id=uuid4(),
        invoice_amount_sats=250_000,
        destination_address="bcrt1qexample",
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
async def test_passes_when_no_sessions_exist(db_session) -> None:
    await assert_sentinel_uuid_fk_integrity(db_session)


@pytest.mark.asyncio
async def test_passes_for_session_with_valid_swap_reference(db_session) -> None:
    swap = _swap()
    sess = _session(submarine_swap_id=swap.id)
    db_session.add_all([swap, sess])
    await db_session.commit()
    await assert_sentinel_uuid_fk_integrity(db_session)  # no raise


@pytest.mark.asyncio
async def test_passes_for_session_with_sentinel_swap_id(db_session) -> None:
    """A sentinel-UUID swap-id is not a drift — it's the gc-pass-8 marker."""
    sess = _session(reverse_swap_id=swap_anchor_sentinel_uuid())
    db_session.add(sess)
    await db_session.commit()
    await assert_sentinel_uuid_fk_integrity(db_session)


@pytest.mark.asyncio
async def test_raises_when_session_references_missing_swap(db_session) -> None:
    """A session whose swap-id points at a non-existent boltz_swaps row
    must trip the integrity check."""
    sess = _session(submarine_swap_id=uuid4())  # never inserted
    db_session.add(sess)
    await db_session.commit()
    with pytest.raises(AnonymizeStartupError, match="dangling swap-id"):
        await assert_sentinel_uuid_fk_integrity(db_session)


@pytest.mark.asyncio
async def test_skips_soft_deleted_sessions(db_session) -> None:
    """Soft-deleted sessions are exempt from the integrity check."""
    sess = _session(submarine_swap_id=uuid4())
    sess.deleted_at = datetime.now(timezone.utc)
    db_session.add(sess)
    await db_session.commit()
    await assert_sentinel_uuid_fk_integrity(db_session)  # no raise


# ── pipeline_schema_version invariant ────────────────────────────────


def test_schema_version_invariant_passes_with_documented_defaults(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_current", 10)
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 10)
    assert_pipeline_schema_version_check_invariant()  # no raise


def test_schema_version_invariant_rejects_below_10_current(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_current", 9)
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 9)
    with pytest.raises(AnonymizeStartupError, match="must be >= 10"):
        assert_pipeline_schema_version_check_invariant()


def test_schema_version_invariant_rejects_min_above_current(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_current", 10)
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 20)
    with pytest.raises(AnonymizeStartupError, match="greater than CURRENT"):
        assert_pipeline_schema_version_check_invariant()
