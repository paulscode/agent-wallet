# SPDX-License-Identifier: MIT
"""/ items 75 + 89 — retention bitfield + active-session safety.

Pure-helper tests for the bitfield manipulation. The
DB-integration test (real session row, retention pass actually
running) lives next to the orchestrator code that fills in each
pass body.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.gc import (
    ALL_PASSES_MASK,
    GC_PASS_EVENT_COLLAPSE,
    GC_PASS_PIPELINE_TRUNCATE,
    GC_PASSES_ORDERED,
    RetentionWindow,
    all_passes_complete,
    fetch_retention_eligible_sessions,
    is_pass_complete,
    mark_pass_complete,
    remaining_passes,
    select_next_pass_for_session,
)


def test_bit_layout_is_contiguous_and_ordered() -> None:
    """Pass bits must form a contiguous run starting at bit 0."""
    expected_bits = [1 << i for i in range(10)]
    actual_bits = [bit for _, bit in GC_PASSES_ORDERED]
    assert actual_bits == expected_bits


def test_all_passes_mask_covers_every_ordered_pass() -> None:
    union = 0
    for _, bit in GC_PASSES_ORDERED:
        union |= bit
    assert union == ALL_PASSES_MASK


def test_pass_bit_helpers() -> None:
    bf = 0
    assert not is_pass_complete(bf, GC_PASS_PIPELINE_TRUNCATE)
    bf = mark_pass_complete(bf, GC_PASS_PIPELINE_TRUNCATE)
    assert is_pass_complete(bf, GC_PASS_PIPELINE_TRUNCATE)
    # Marking the same pass twice is idempotent.
    assert mark_pass_complete(bf, GC_PASS_PIPELINE_TRUNCATE) == bf
    assert not all_passes_complete(bf)
    # Set every pass.
    for _, bit in GC_PASSES_ORDERED:
        bf = mark_pass_complete(bf, bit)
    assert all_passes_complete(bf)


def test_remaining_passes_lists_unfinished_only() -> None:
    bf = mark_pass_complete(0, GC_PASS_PIPELINE_TRUNCATE)
    bf = mark_pass_complete(bf, GC_PASS_EVENT_COLLAPSE)
    remaining = [label for label, _ in remaining_passes(bf)]
    assert "pipeline_truncate" not in remaining
    assert "event_collapse" not in remaining
    assert "reuse_key_purge" in remaining
    assert len(remaining) == 8


# ── transactional-multi-pass crash recovery semantics ───────


def test_select_next_pass_returns_first_pass_on_fresh_session() -> None:
    """A row with bitfield=0 selects the first pass in
    ``GC_PASSES_ORDERED`` so a fresh retention sweep starts from
    pipeline_truncate."""
    first_name, first_bit = GC_PASSES_ORDERED[0]
    out = select_next_pass_for_session(0)
    assert out == (first_name, first_bit)


def test_select_next_pass_returns_first_unset_bit() -> None:
    """A row that completed pass N selects pass N+1 — the bitfield
    layout is the durable resume marker for."""
    bf = mark_pass_complete(0, GC_PASSES_ORDERED[0][1])
    bf = mark_pass_complete(bf, GC_PASSES_ORDERED[1][1])
    next_name, next_bit = GC_PASSES_ORDERED[2]
    assert select_next_pass_for_session(bf) == (next_name, next_bit)


def test_select_next_pass_returns_none_when_all_complete() -> None:
    """A fully-walked session has no more work — the scheduler skips it."""
    assert select_next_pass_for_session(ALL_PASSES_MASK) is None


def test_select_next_pass_walks_holes_in_order() -> None:
    """Crash mid-sweep: only pass 0 and pass 3 completed. The next
    pass returned is pass 1 (the *first* unset bit), not pass 4.

    This is the contract: the scheduler always retries the
    lowest unset bit, so an out-of-order completion can't cause the
    sweep to skip earlier passes silently.
    """
    bf = mark_pass_complete(0, GC_PASSES_ORDERED[0][1])
    bf = mark_pass_complete(bf, GC_PASSES_ORDERED[3][1])
    name, bit = select_next_pass_for_session(bf)
    assert (name, bit) == GC_PASSES_ORDERED[1]


def test_pass_bit_marking_is_independent_per_pass() -> None:
    """Marking pass N does NOT mark pass N+1 — each pass owns its bit.

    Guards against a bug where ``mark_pass_complete`` would shift past
    the desired bit and corrupt the bitfield.
    """
    bf = 0
    for name, bit in GC_PASSES_ORDERED:
        bf_before = bf
        bf = mark_pass_complete(bf, bit)
        assert is_pass_complete(bf, bit), name
        # No OTHER bit got flipped by this mark.
        flipped = bf ^ bf_before
        assert flipped == bit, name


def test_retention_window_from_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    now = datetime(2026, 5, 10, tzinfo=timezone.utc)
    window = RetentionWindow.from_settings(now=now)
    assert window.retention_days == 7
    assert window.cutoff == datetime(2026, 5, 3, tzinfo=timezone.utc)


# ── DB-backed safety filter tests ────────────────────────────────────


@pytest.mark.asyncio
async def test_active_session_safety_filter_excludes_active_session(
    db_session,
    monkeypatch,
) -> None:
    """A non-terminal session past retention age is NOT eligible."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    old_active = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.LN_HOLDING.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\x01" * 32,
        destination_reuse_key_generation=0,
        completed_at=None,
        created_at=datetime.now(timezone.utc) - timedelta(days=14),
    )
    db_session.add(old_active)
    await db_session.commit()
    eligible = await fetch_retention_eligible_sessions(db_session)
    assert old_active.id not in {s.id for s in eligible}


@pytest.mark.asyncio
async def test_active_session_safety_filter_includes_old_completed(
    db_session,
    monkeypatch,
) -> None:
    """A terminal session past retention age IS eligible."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    completed_at = datetime.now(timezone.utc) - timedelta(days=14)
    old_completed = AnonymizeSession(
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
        destination_address_blake2b_keyed=b"\x02" * 32,
        destination_reuse_key_generation=0,
        completed_at=completed_at,
    )
    db_session.add(old_completed)
    await db_session.commit()
    eligible = await fetch_retention_eligible_sessions(db_session)
    assert old_completed.id in {s.id for s in eligible}


@pytest.mark.asyncio
async def test_active_session_safety_filter_excludes_recent_completed(
    db_session,
    monkeypatch,
) -> None:
    """A terminal session within the retention window is NOT eligible."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    recent = AnonymizeSession(
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
        destination_address_blake2b_keyed=b"\x03" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    db_session.add(recent)
    await db_session.commit()
    eligible = await fetch_retention_eligible_sessions(db_session)
    assert recent.id not in {s.id for s in eligible}


@pytest.mark.asyncio
async def test_already_redacted_session_not_returned(db_session, monkeypatch) -> None:
    """A session whose bitfield equals ALL_PASSES_MASK is excluded."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    completed_at = datetime.now(timezone.utc) - timedelta(days=14)
    redacted = AnonymizeSession(
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
        destination_address_blake2b_keyed=b"\x04" * 32,
        destination_reuse_key_generation=0,
        completed_at=completed_at,
        gc_passes_completed=ALL_PASSES_MASK,
    )
    db_session.add(redacted)
    await db_session.commit()
    eligible = await fetch_retention_eligible_sessions(db_session)
    assert redacted.id not in {s.id for s in eligible}
