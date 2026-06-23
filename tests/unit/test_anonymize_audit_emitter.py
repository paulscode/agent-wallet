# SPDX-License-Identifier: MIT
"""Audit-bucket emitter."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.audit_summary import (
    aggregate_window_emission,
    build_audit_payload,
    build_bucket_summary,
    collect_session_counts_for_bucket,
)


def _row(
    *,
    status: str,
    completed_at: datetime,
    source_kind: str = "ext-lightning",
) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind=source_kind,
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=uuid4().bytes + uuid4().bytes,
        destination_reuse_key_generation=0,
        completed_at=completed_at,
    )


@pytest.mark.asyncio
async def test_collect_counts_returns_terminal_status_buckets(db_session) -> None:
    bucket_start = 1_715_000_000
    bucket_seconds = 3600
    inside = datetime.fromtimestamp(bucket_start + 1000, tz=timezone.utc)
    outside_before = datetime.fromtimestamp(bucket_start - 100, tz=timezone.utc)

    db_session.add(_row(status=AnonymizeStatus.COMPLETED.value, completed_at=inside))
    db_session.add(_row(status=AnonymizeStatus.COMPLETED.value, completed_at=inside))
    db_session.add(_row(status=AnonymizeStatus.FAILED.value, completed_at=inside))
    # Out-of-window row must NOT count.
    db_session.add(_row(status=AnonymizeStatus.COMPLETED.value, completed_at=outside_before))
    # Active rows have completed_at=None implicitly — but our model
    # requires it; use a row with completed_at outside the window
    # under a non-terminal status to verify it's still excluded.
    db_session.add(_row(status=AnonymizeStatus.LN_HOLDING.value, completed_at=inside))
    await db_session.commit()

    by_status, by_source = await collect_session_counts_for_bucket(
        db_session,
        bucket_start_unix_s=bucket_start,
        bucket_seconds=bucket_seconds,
    )
    assert by_status == {"completed": 2, "failed": 1}
    # All in-window rows are ext-lightning by default.
    assert by_source.get("ext-lightning") == 3


@pytest.mark.asyncio
async def test_collect_counts_groups_by_source_kind(db_session) -> None:
    bucket_start = 1_715_010_000
    bucket_seconds = 3600
    inside = datetime.fromtimestamp(bucket_start + 100, tz=timezone.utc)
    db_session.add(
        _row(
            status=AnonymizeStatus.COMPLETED.value,
            completed_at=inside,
            source_kind="ext-lightning",
        )
    )
    db_session.add(
        _row(
            status=AnonymizeStatus.COMPLETED.value,
            completed_at=inside,
            source_kind="lightning-self",
        )
    )
    await db_session.commit()
    _, by_source = await collect_session_counts_for_bucket(
        db_session,
        bucket_start_unix_s=bucket_start,
        bucket_seconds=bucket_seconds,
    )
    assert by_source == {"ext-lightning": 1, "lightning-self": 1}


def test_build_audit_payload_window_shape(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_min_bucket_count", 5)
    s_above = build_bucket_summary(
        bucket_start_unix_s=1_715_000_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7},
        counts_by_source_kind={"ext-lightning": 7},
    )
    s_below = build_bucket_summary(
        bucket_start_unix_s=1_715_003_600,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 1},
        counts_by_source_kind={"ext-lightning": 1},
    )
    win = aggregate_window_emission(
        [s_above, s_below],
        window_start_unix_s=1_715_000_000,
        window_end_unix_s=1_715_086_400,
    )
    payload = build_audit_payload(win)
    assert payload["window_start_unix_s"] == 1_715_000_000
    assert payload["window_end_unix_s"] == 1_715_086_400
    assert payload["had_suppressed_buckets"] is True  # the below-threshold one
    assert len(payload["buckets"]) == 1  # the suppressed one is excluded
    bucket = payload["buckets"][0]
    assert bucket["counts_by_terminal_state"] == {"completed": "4-10"}
    assert bucket["counts_by_source_kind"] == {"ext-lightning": "4-10"}


# ── recurring-emitter pure helpers (audit_emitter.py) ────────────────


from app.services.anonymize.audit_emitter import (  # noqa: E402
    AuditEmitOutcome,
    audit_emit_tick_due,
    build_emission_window_for_buckets,
    enumerate_pending_buckets,
)
from app.services.anonymize.audit_summary import WindowEmission  # noqa: E402


def test_emit_tick_due_on_fresh_deployment() -> None:
    assert audit_emit_tick_due(last_emit_at_unix_s=None) is True


def test_emit_tick_due_after_cadence_elapsed(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    assert (
        audit_emit_tick_due(
            last_emit_at_unix_s=1_000.0,
            now_unix_s=5_000.0,
        )
        is True
    )


def test_emit_tick_not_due_inside_cadence(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    assert (
        audit_emit_tick_due(
            last_emit_at_unix_s=1_000.0,
            now_unix_s=2_000.0,
        )
        is False
    )


def test_emit_tick_due_with_explicit_interval() -> None:
    assert (
        audit_emit_tick_due(
            last_emit_at_unix_s=1_000.0,
            interval_s=60,
            now_unix_s=1_061.0,
        )
        is True
    )


def test_emit_tick_due_zero_cadence_always_fires() -> None:
    """A misconfigured zero cadence degrades to always-fire."""
    assert (
        audit_emit_tick_due(
            last_emit_at_unix_s=1_000.0,
            interval_s=0,
            now_unix_s=1_000.5,
        )
        is True
    )


def test_enumerate_empty_when_fresh_and_jitter_unblocked(monkeypatch) -> None:
    """A bucket whose end is inside the jitter buffer is not yet eligible."""
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 900)
    out = enumerate_pending_buckets(
        last_emitted_bucket_start_unix_s=None,
        now_unix_s=3700,
    )
    assert out == []


def test_enumerate_returns_latest_bucket_on_fresh_deploy(monkeypatch) -> None:
    """Fresh deployment emits only the latest completed bucket, not history."""
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 0)
    out = enumerate_pending_buckets(
        last_emitted_bucket_start_unix_s=None,
        now_unix_s=7300,
    )
    assert out == [3600]


def test_enumerate_walks_from_high_water_mark(monkeypatch) -> None:
    """Returning emitter resumes from last_emitted + bucket_seconds."""
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 0)
    out = enumerate_pending_buckets(
        last_emitted_bucket_start_unix_s=0,
        now_unix_s=14_400,
    )
    assert out == [3600, 7200, 10_800]


def test_enumerate_respects_jitter_buffer(monkeypatch) -> None:
    """A bucket end inside the jitter buffer is held back."""
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 900)
    out = enumerate_pending_buckets(
        last_emitted_bucket_start_unix_s=None,
        now_unix_s=4200,
    )
    assert out == []


def test_enumerate_handles_zero_bucket_seconds() -> None:
    out = enumerate_pending_buckets(
        last_emitted_bucket_start_unix_s=None,
        now_unix_s=10_000,
        bucket_seconds=0,
    )
    assert out == []


def test_enumerate_explicit_overrides_settings() -> None:
    out = enumerate_pending_buckets(
        last_emitted_bucket_start_unix_s=0,
        now_unix_s=300,
        bucket_seconds=60,
        emit_jitter_s=0,
    )
    assert out == [60, 120, 180, 240]


def test_build_window_aggregates_summaries() -> None:
    a = build_bucket_summary(
        bucket_start_unix_s=0,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7},
        counts_by_source_kind={"ext-lightning": 7},
        min_bucket_count=5,
    )
    b = build_bucket_summary(
        bucket_start_unix_s=3600,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 6},
        counts_by_source_kind={"ext-lightning": 6},
        min_bucket_count=5,
    )
    out = build_emission_window_for_buckets(
        [a, b],
        window_start_unix_s=0,
        window_end_unix_s=7200,
    )
    assert isinstance(out, WindowEmission)
    assert len(out.summaries) == 2
    assert out.had_suppressed_buckets is False


def test_build_window_marks_suppressed_buckets() -> None:
    """A bucket below the k-anonymity threshold drops out + flag flips."""
    healthy = build_bucket_summary(
        bucket_start_unix_s=0,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7},
        counts_by_source_kind={"ext-lightning": 7},
        min_bucket_count=5,
    )
    suppressed = build_bucket_summary(
        bucket_start_unix_s=3600,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 1},
        counts_by_source_kind={"ext-lightning": 1},
        min_bucket_count=5,
    )
    out = build_emission_window_for_buckets(
        [healthy, suppressed],
        window_start_unix_s=0,
        window_end_unix_s=7200,
    )
    assert out.had_suppressed_buckets is True
    assert len(out.summaries) == 1


def test_audit_emit_outcome_empty_shape() -> None:
    out = AuditEmitOutcome(pending_bucket_starts=[], emitted_window=None)
    assert out.pending_bucket_starts == []
    assert out.emitted_window is None


def test_audit_emit_outcome_with_window() -> None:
    window = WindowEmission(
        window_start_unix_s=0,
        window_end_unix_s=3600,
        summaries=[],
        had_suppressed_buckets=False,
    )
    out = AuditEmitOutcome(pending_bucket_starts=[0], emitted_window=window)
    assert out.emitted_window is window
