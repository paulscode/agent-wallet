# SPDX-License-Identifier: MIT
"""Per-session orchestrator loop."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.per_session_loop import (
    PerSessionLoopConfig,
    default_loop_config,
    make_per_session_loop_run_fn,
    sample_jittered_poll_sleep_s,
)
from app.services.anonymize.service import (
    AnonymizeService,
    reset_anonymize_service,
)
from app.services.anonymize.tick import TickObservations


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _session(*, status: str = AnonymizeStatus.FUNDING.value) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
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
    )


def _factory(db_session):
    @asynccontextmanager
    async def _make():
        yield db_session

    return _make


# ── sample_jittered_poll_sleep_s ─────────────────────────────────────


def test_jittered_sleep_in_expected_range(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_poll_interval_s", 30)
    cfg = PerSessionLoopConfig(
        poll_interval_s=30.0,
        poll_jitter_min_s=1.0,
        poll_jitter_max_s=5.0,
    )
    for _ in range(50):
        v = sample_jittered_poll_sleep_s(cfg)
        assert 31.0 <= v <= 35.0


def test_jittered_sleep_uses_default_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_poll_interval_s", 7)
    v = sample_jittered_poll_sleep_s()
    # default jitter 0.5..5.0 → 7.5..12.0.
    assert 7.5 <= v <= 12.0


def test_default_loop_config_reads_setting(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_poll_interval_s", 42)
    cfg = default_loop_config()
    assert cfg.poll_interval_s == 42.0


# ── make_per_session_loop_run_fn ─────────────────────────────────────


@pytest.mark.asyncio
async def test_loop_advances_session_and_exits_on_terminal(db_session) -> None:
    """A single tick can drive a session through to a terminal state."""
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.CREATED.value)
    db_session.add(sess)
    await db_session.commit()
    sid = sess.id

    obs_calls = {"n": 0}

    async def _observe(db, s) -> TickObservations:
        # First tick: signal user cancel — CANCELLED is terminal.
        obs_calls["n"] += 1
        return TickObservations(user_cancel_requested=True)

    sleep_calls: list[float] = []

    async def _sleep(s):
        sleep_calls.append(s)

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=_factory(db_session),
        observation_fn=_observe,
        session_id=sid,
        sleep_fn=_sleep,
    )
    await run_fn()  # should terminate within one iteration

    await db_session.refresh(sess)
    assert sess.status == AnonymizeStatus.CANCELLED.value
    assert obs_calls["n"] == 1
    # No sleep — terminal exit short-circuits before the jitter.
    assert sleep_calls == []
    await svc.stop()


@pytest.mark.asyncio
async def test_loop_surfaces_hop_error_to_last_error(db_session) -> None:
    """A hop step that returns an error outcome records the detail on
    ``last_error`` so a wedged session shows *why* in the UI, instead of
    retrying silently with the outcome discarded."""
    from types import SimpleNamespace

    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.SOURCING.value)
    db_session.add(sess)
    await db_session.commit()
    sid = sess.id

    async def _hop(db, s):
        return SimpleNamespace(
            kind="error",
            detail="submarine swap create failed: 400 amount too low",
        )

    async def _observe(db, s) -> TickObservations:
        # Cancel so the loop exits after one tick (CANCELLED is terminal).
        return TickObservations(user_cancel_requested=True)

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=_factory(db_session),
        observation_fn=_observe,
        session_id=sid,
        sleep_fn=lambda _s: asyncio.sleep(0),
        hop_step_fn=_hop,
    )
    await run_fn()

    await db_session.refresh(sess)
    assert sess.last_error is not None
    assert "400" in sess.last_error
    await svc.stop()


@pytest.mark.asyncio
async def test_loop_clears_last_error_on_progress(db_session) -> None:
    """A hop step that makes progress clears a stale ``last_error`` so a
    recovered session doesn't keep showing an old failure."""
    from types import SimpleNamespace

    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.SOURCING.value)
    sess.last_error = "previous failure"
    db_session.add(sess)
    await db_session.commit()
    sid = sess.id

    async def _hop(db, s):
        return SimpleNamespace(kind="issued_swap", detail="swap-123")

    async def _observe(db, s) -> TickObservations:
        return TickObservations(user_cancel_requested=True)

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=_factory(db_session),
        observation_fn=_observe,
        session_id=sid,
        sleep_fn=lambda _s: asyncio.sleep(0),
        hop_step_fn=_hop,
    )
    await run_fn()

    await db_session.refresh(sess)
    assert sess.last_error is None
    await svc.stop()


@pytest.mark.asyncio
async def test_loop_exits_when_session_missing(db_session) -> None:
    """A deleted-since-spawn session row triggers a clean exit."""
    svc = AnonymizeService()
    await svc.start()

    obs_called = False

    async def _observe(db, s) -> TickObservations:
        nonlocal obs_called
        obs_called = True
        return TickObservations()

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=_factory(db_session),
        observation_fn=_observe,
        session_id=uuid4(),  # unknown id
        sleep_fn=lambda _s: asyncio.sleep(0),
    )
    await run_fn()
    assert obs_called is False
    await svc.stop()


@pytest.mark.asyncio
async def test_loop_exits_immediately_for_terminal_row(db_session) -> None:
    """A row that is already terminal exits without calling observe."""
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.COMPLETED.value)
    db_session.add(sess)
    await db_session.commit()

    obs_called = False

    async def _observe(db, s) -> TickObservations:
        nonlocal obs_called
        obs_called = True
        return TickObservations()

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=_factory(db_session),
        observation_fn=_observe,
        session_id=sess.id,
        sleep_fn=lambda _s: asyncio.sleep(0),
    )
    await run_fn()
    assert obs_called is False
    await svc.stop()


@pytest.mark.asyncio
async def test_loop_routes_to_reconciliation_after_bounded_retries(
    db_engine,
    monkeypatch,
) -> None:
    """N consecutive observation failures route to
    ``awaiting_reconciliation`` instead of looping forever.

    Per recovery the transition must go through the
    ``transition_to_awaiting_reconciliation`` helper so all four AR
    columns are populated atomically (reason +
    pre_reconciliation_status snapshotted from the pre-failure
    status).
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker

    monkeypatch.setattr(settings, "anonymize_health_flip_threshold", 1)
    # Threshold = max(2, 1*3) = 3. Three failures should route.
    svc = AnonymizeService()
    await svc.start()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as db:
        sess = _session(status=AnonymizeStatus.HOPPING.value)
        db.add(sess)
        await db.commit()
        sid = sess.id

    fails = {"n": 0}

    async def _always_raise(db, s):
        fails["n"] += 1
        raise RuntimeError("simulated wedge")

    sleeps: list[float] = []

    async def _sleep(s):
        sleeps.append(s)

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=factory,
        observation_fn=_always_raise,
        session_id=sid,
        sleep_fn=_sleep,
    )
    await run_fn()
    # The loop bailed before infinite retries.
    assert fails["n"] >= 3
    async with factory() as fresh:
        from sqlalchemy import select

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == sid))).scalar_one()
        # contract: helper populates all four columns.
        assert row.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
        assert row.awaiting_reconciliation_reason == "bounded_retry_exhausted"
        assert row.pre_reconciliation_status == AnonymizeStatus.HOPPING.value
    await svc.stop()


@pytest.mark.asyncio
async def test_loop_recovers_from_observation_error(db_session) -> None:
    """A raise in observation_fn is logged + the loop backs off + retries."""
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.commit()

    calls = {"n": 0}

    async def _flaky(db, s) -> TickObservations:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("simulated transient error")
        # On the second call, drive to a terminal status so the loop exits.
        return TickObservations(user_cancel_requested=False, fatal_error_kind="x")

    sleeps: list[float] = []

    async def _sleep(s):
        sleeps.append(s)

    run_fn = make_per_session_loop_run_fn(
        service=svc,
        session_factory=_factory(db_session),
        observation_fn=_flaky,
        session_id=sess.id,
        sleep_fn=_sleep,
    )
    await run_fn()
    assert calls["n"] == 2
    # First call raised, so a sleep MUST have happened before the retry.
    assert len(sleeps) >= 1
    await db_session.refresh(sess)
    assert sess.status == AnonymizeStatus.FAILED.value
    await svc.stop()


# ── AnonymizeService.spawn_session_task ──────────────────────────────


@pytest.mark.asyncio
async def test_spawn_session_task_runs_to_terminal(db_engine, db_session) -> None:
    """Spawn task uses a real per-task session factory to avoid sharing
    a single AsyncSession across concurrent tasks."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.CREATED.value)
    db_session.add(sess)
    await db_session.commit()

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _observe(db, s) -> TickObservations:
        return TickObservations(user_cancel_requested=True)

    svc.spawn_session_task(
        session_id=sess.id,
        session_factory=factory,
        observation_fn=_observe,
    )
    # Wait for the task to settle (terminal transition exits the loop).
    for _ in range(50):
        if not svc.is_session_task_running(str(sess.id)):
            break
        await asyncio.sleep(0.01)

    # Re-read from a fresh session because the spawn task wrote on its own.
    async with factory() as fresh:
        from sqlalchemy import select

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == sess.id))).scalar_one()
        assert row.status == AnonymizeStatus.CANCELLED.value

    await svc.stop()


@pytest.mark.asyncio
async def test_spawn_session_task_cancels_on_stop(db_engine, db_session) -> None:
    """Calling service.stop() cancels a live per-session loop cleanly."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.commit()
    sid_str = str(sess.id)

    factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def _hold(db, s) -> TickObservations:
        return TickObservations()

    svc.spawn_session_task(
        session_id=sess.id,
        session_factory=factory,
        observation_fn=_hold,
    )
    # Let it tick once before cancelling.
    await asyncio.sleep(0)
    await svc.stop()
    assert not svc.is_session_task_running(sid_str)


@pytest.mark.asyncio
async def test_load_for_update_takes_row_lock() -> None:
    """The per-session tick loads its row ``FOR UPDATE`` so a second
    driver of the same session (a duplicate loop or the reconciliation
    probe) serializes behind the live tick instead of racing the same
    fund-moving hop. The clause is a no-op on SQLite, so the lock is
    asserted at the statement level."""
    from app.services.anonymize.per_session_loop import _load

    captured = {}

    class _FakeResult:
        def scalar_one_or_none(self):
            return None

    class _FakeDb:
        async def execute(self, stmt):
            captured["stmt"] = stmt
            return _FakeResult()

    await _load(_FakeDb(), uuid4(), for_update=True)
    assert captured["stmt"]._for_update_arg is not None

    await _load(_FakeDb(), uuid4(), for_update=False)
    assert captured["stmt"]._for_update_arg is None
