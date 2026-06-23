# SPDX-License-Identifier: MIT
"""Per-tick run-fn adapters wiring pure helpers to the scheduler."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeStatus,
)
from app.services.anonymize.gc import (
    ALL_PASSES_MASK,
    GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    is_pass_complete,
)
from app.services.anonymize.tick_runners import (
    make_audit_emit_run_fn,
    make_decoy_catchup_run_fn,
    make_gc_sweep_run_fn,
)


def _session(
    *,
    status: str = AnonymizeStatus.COMPLETED.value,
    completed_offset_days: float = 30,
    gc_bits: int = 0,
    source_kind: str = "ext-lightning",
) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
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
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=now - timedelta(days=completed_offset_days),
        gc_passes_completed=gc_bits,
    )


def _factory(db_session):
    """Build a SessionFactory that always yields the test's db_session.

    Real production code instantiates a session per run; tests reuse
    the fixture so the assertions can read the state the run wrote.
    """

    @asynccontextmanager
    async def _make():
        yield db_session

    return _make


# ── make_audit_emit_run_fn ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_emit_no_pending_buckets_is_noop(
    db_session,
    monkeypatch,
) -> None:
    """Inside the jitter buffer ⇒ nothing to emit; audit_writer never fires."""
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 900)
    monkeypatch.setattr(settings, "anonymize_audit_min_bucket_count", 5)

    emitted: list[dict] = []

    async def _writer(payload: dict) -> None:
        emitted.append(payload)

    run_fn = make_audit_emit_run_fn(
        session_factory=_factory(db_session),
        audit_writer=_writer,
        now_fn=lambda: 3700.0,  # well inside the first bucket's jitter
    )
    await run_fn()
    assert emitted == []


@pytest.mark.asyncio
async def test_audit_emit_writes_payload_and_bumps_hwm(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 0)
    monkeypatch.setattr(settings, "anonymize_audit_min_bucket_count", 1)

    # Fresh-deploy emits the latest completed bucket only (no
    # backfill across history). Latest = (14_400/3600 - 1) * 3600
    # = 10_800. Add rows inside [10_800, 14_400).
    inside = datetime.fromtimestamp(11_000, tz=timezone.utc)
    for _ in range(3):
        s = _session(completed_offset_days=0)
        s.completed_at = inside
        db_session.add(s)
    await db_session.commit()

    emitted: list[dict] = []

    async def _writer(payload: dict) -> None:
        emitted.append(payload)

    run_fn = make_audit_emit_run_fn(
        session_factory=_factory(db_session),
        audit_writer=_writer,
        now_fn=lambda: 14_400.0,
    )
    await run_fn()
    assert len(emitted) == 1
    assert emitted[0]["window_start_unix_s"] == 10_800
    assert emitted[0]["had_suppressed_buckets"] is False

    # HWM persisted.
    from app.services.anonymize.runtime_state import read_runtime_state

    raw = await read_runtime_state(
        db_session,
        key="audit_chain_last_emitted_bucket_start_unix_s",
    )
    assert raw == {"value": 10_800}


@pytest.mark.asyncio
async def test_audit_emit_resumes_from_persisted_hwm(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 3600)
    monkeypatch.setattr(settings, "anonymize_audit_bucket_emit_jitter_s", 0)

    from app.services.anonymize.runtime_state import write_runtime_state

    await write_runtime_state(
        db_session,
        key="audit_chain_last_emitted_bucket_start_unix_s",
        payload={"value": 7200},
    )
    await db_session.commit()

    emitted: list[dict] = []

    async def _writer(payload: dict) -> None:
        emitted.append(payload)

    run_fn = make_audit_emit_run_fn(
        session_factory=_factory(db_session),
        audit_writer=_writer,
        now_fn=lambda: 18_000.0,  # cutoff 18_000 → latest 14_400
    )
    await run_fn()
    assert len(emitted) == 1
    # Walked from 7200+3600 → 14_400.
    assert emitted[0]["window_start_unix_s"] == 10_800
    assert emitted[0]["window_end_unix_s"] == 18_000


# ── make_decoy_catchup_run_fn ────────────────────────────────────────


@pytest.mark.asyncio
async def test_decoy_catchup_runs_pass_for_eligible_sessions(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)

    # Past horizon, started retention but missed pass 10.
    s = _session(
        completed_offset_days=30,
        gc_bits=ALL_PASSES_MASK & ~GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    )
    db_session.add(s)
    await db_session.commit()

    run_fn = make_decoy_catchup_run_fn(session_factory=_factory(db_session))
    await run_fn()

    await db_session.refresh(s)
    assert is_pass_complete(s.gc_passes_completed, GC_PASS_DECOY_CHAIN_ANCHOR_REDACT)


@pytest.mark.asyncio
async def test_decoy_catchup_is_noop_when_nothing_eligible(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    # Inside retention window — not eligible.
    s = _session(
        completed_offset_days=2,
        gc_bits=ALL_PASSES_MASK & ~GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    )
    db_session.add(s)
    await db_session.commit()

    run_fn = make_decoy_catchup_run_fn(session_factory=_factory(db_session))
    await run_fn()  # no-raise

    await db_session.refresh(s)
    # Bit unchanged.
    assert not is_pass_complete(
        s.gc_passes_completed,
        GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    )


# ── make_gc_sweep_run_fn ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_gc_sweep_dispatches_to_first_unset_pass(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    monkeypatch.setattr(settings, "anonymize_gc_tick_interval_s", 1)

    s = _session(completed_offset_days=30, gc_bits=0)
    db_session.add(s)
    await db_session.commit()

    called: list[str] = []

    async def _pipeline_truncate(db, sess) -> bool:
        called.append("pipeline_truncate")
        return True

    run_fn = make_gc_sweep_run_fn(
        session_factory=_factory(db_session),
        pass_runners={"pipeline_truncate": _pipeline_truncate},
    )
    await run_fn()
    assert called == ["pipeline_truncate"]


@pytest.mark.asyncio
async def test_gc_sweep_respects_cadence(db_session, monkeypatch) -> None:
    """A recent ``last_successful_gc_at`` defers the sweep entirely."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    monkeypatch.setattr(settings, "anonymize_gc_tick_interval_s", 600)

    from app.services.anonymize.runtime_state import write_runtime_state

    await write_runtime_state(
        db_session,
        key="last_successful_gc_at",
        payload={"value": 1_000.0},
    )
    await db_session.commit()

    s = _session(completed_offset_days=30, gc_bits=0)
    db_session.add(s)
    await db_session.commit()

    called: list[str] = []

    async def _pipeline_truncate(db, sess) -> bool:
        called.append("pipeline_truncate")
        return True

    run_fn = make_gc_sweep_run_fn(
        session_factory=_factory(db_session),
        pass_runners={"pipeline_truncate": _pipeline_truncate},
        now_fn=lambda: 1_100.0,  # 100s elapsed < 600s interval
    )
    await run_fn()
    assert called == []  # cadence not yet up


@pytest.mark.asyncio
async def test_gc_sweep_unknown_pass_runner_is_skipped(
    db_session,
    monkeypatch,
) -> None:
    """An eligible session whose next pass has no runner is silently
    skipped — the next pass's runner will catch it on a later tick."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    monkeypatch.setattr(settings, "anonymize_gc_tick_interval_s", 1)

    s = _session(completed_offset_days=30, gc_bits=0)
    db_session.add(s)
    await db_session.commit()

    run_fn = make_gc_sweep_run_fn(
        session_factory=_factory(db_session),
        pass_runners={},  # no runners
    )
    await run_fn()  # no-raise
    await db_session.refresh(s)
    assert s.gc_passes_completed == 0  # nothing changed
