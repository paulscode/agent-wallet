# SPDX-License-Identifier: MIT
"""+ items 61 + 62 — event-collapse + pipeline-truncate."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.gc import (
    GC_PASS_EVENT_COLLAPSE,
    is_pass_complete,
    run_event_collapse_pass,
    run_pipeline_json_truncate_pass,
)


def _row(**kwargs) -> AnonymizeSession:
    base = dict(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={
            "schema_version": 10,
            "source": {"kind": "ext-lightning"},
            "bin_amount_sat": 250_000,
            "hops": [{"kind": "ln_self_pay"}],
            "delay_policy": {"min_seconds": 3600, "max_seconds": 21600},
        },
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        bin_set_id=0,
        final_score_report_json={
            "tier": "moderate",
            "cap": "moderate",
            "points": 5,
            "breakdown": ["source: ext-lightning +3"],
            "notes": [],
        },
    )
    base.update(kwargs)
    return AnonymizeSession(**base)


# ── item 61 ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_event_collapse_default_deletes_rows(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_retain_redacted_history_rows", False)
    sess = _row()
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        AnonymizeSessionEvent(
            session_id=sess.id,
            ts=datetime.now(timezone.utc),
            kind="hop_started",
            detail_json={},
        )
    )
    db_session.add(
        AnonymizeSessionEvent(
            session_id=sess.id,
            ts=datetime.now(timezone.utc),
            kind="state_change",
            detail_json={"to": "ln_holding"},
        )
    )
    await db_session.commit()

    mutated = await run_event_collapse_pass(db_session, sess)
    assert mutated is True
    # All event rows are gone.
    result = await db_session.execute(select(AnonymizeSessionEvent).where(AnonymizeSessionEvent.session_id == sess.id))
    assert list(result.scalars().all()) == []
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_EVENT_COLLAPSE)


@pytest.mark.asyncio
async def test_event_collapse_retained_mode_inserts_marker(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_retain_redacted_history_rows", True)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    sess = _row(
        completed_at=datetime(2026, 5, 10, 14, 32, 0, tzinfo=timezone.utc),
    )
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        AnonymizeSessionEvent(
            session_id=sess.id,
            ts=datetime.now(timezone.utc),
            kind="hop_started",
            detail_json={"hop_index": 0},
        )
    )
    await db_session.commit()

    await run_event_collapse_pass(db_session, sess)
    result = await db_session.execute(select(AnonymizeSessionEvent).where(AnonymizeSessionEvent.session_id == sess.id))
    rows = list(result.scalars().all())
    assert len(rows) == 1
    marker = rows[0]
    assert marker.kind == "redacted_history"
    assert marker.detail_json == {}
    assert marker.hop_idempotency_key is None
    # Bucket-quantized to 14:00 UTC.
    ts = marker.ts.replace(tzinfo=timezone.utc) if marker.ts.tzinfo is None else marker.ts
    assert ts == datetime(2026, 5, 10, 14, 0, 0, tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_event_collapse_idempotent(db_session) -> None:
    sess = _row()
    db_session.add(sess)
    await db_session.commit()
    await run_event_collapse_pass(db_session, sess)
    second = await run_event_collapse_pass(db_session, sess)
    assert second is False


# ── item 62 ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pipeline_truncate_keeps_minimal_shape(db_session) -> None:
    sess = _row(bin_set_id=1)
    db_session.add(sess)
    await db_session.commit()

    mutated = await run_pipeline_json_truncate_pass(db_session, sess)
    assert mutated is True
    keys = sorted(sess.pipeline_json.keys())
    # Must contain only the documented minimal shape (+ bin_set_id).
    assert set(keys) <= {
        "schema_version",
        "source_kind",
        "bin_amount_sat",
        "bin_index",
        "bin_set_id",
    }
    assert "hops" not in sess.pipeline_json
    assert "delay_policy" not in sess.pipeline_json
    # bin_set_id propagated.
    assert sess.pipeline_json.get("bin_set_id") == 1


@pytest.mark.asyncio
async def test_pipeline_truncate_reduces_final_score_to_tier_cap(db_session) -> None:
    sess = _row()
    db_session.add(sess)
    await db_session.commit()
    await run_pipeline_json_truncate_pass(db_session, sess)
    assert sess.final_score_report_json == {"tier": "moderate", "cap": "moderate"}


@pytest.mark.asyncio
async def test_pipeline_truncate_handles_missing_source_dict(db_session) -> None:
    """A pipeline_json without a nested ``source`` dict still gets a
    ``source_kind`` from the row column."""
    sess = _row(
        pipeline_json={
            "schema_version": 10,
            "bin_amount_sat": 250_000,
            "hops": [],
        },
    )
    db_session.add(sess)
    await db_session.commit()
    await run_pipeline_json_truncate_pass(db_session, sess)
    assert sess.pipeline_json["source_kind"] == "ext-lightning"


@pytest.mark.asyncio
async def test_pipeline_truncate_idempotent(db_session) -> None:
    sess = _row()
    db_session.add(sess)
    await db_session.commit()
    await run_pipeline_json_truncate_pass(db_session, sess)
    second = await run_pipeline_json_truncate_pass(db_session, sess)
    assert second is False
