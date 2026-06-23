# SPDX-License-Identifier: MIT
"""Startup reconciliation pass (the integration body)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.service import (
    AnonymizeService,
    reset_anonymize_service,
)
from app.services.anonymize.startup_reconciliation import (
    ReconciliationSummary,
    no_op_observation_fn,
    run_startup_reconciliation,
)


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _session(
    *,
    status: str,
    updated_offset_s: float = 60,
    schema: int = 10,
) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
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
        pipeline_schema_version=schema,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        updated_at=now - timedelta(seconds=updated_offset_s),
    )


@pytest.mark.asyncio
async def test_run_reconciliation_returns_summary_shape(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 10)
    monkeypatch.setattr(settings, "anonymize_onchain_max_interleg_delay_s", 172_800)

    svc = AnonymizeService()
    await svc.start()

    healthy = _session(
        status=AnonymizeStatus.HOPPING.value,
        updated_offset_s=60,
    )
    stuck = _session(
        status=AnonymizeStatus.HOPPING.value,
        updated_offset_s=400_000,
    )
    db_session.add_all([healthy, stuck])
    await db_session.commit()

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    summary = await run_startup_reconciliation(
        service=svc,
        session_factory=factory,
        observation_fn=no_op_observation_fn,
    )
    assert isinstance(summary, ReconciliationSummary)
    assert summary.resumed_count == 1
    assert summary.reconciled_count == 1
    assert len(summary.outcomes) == 2
    await svc.stop()


@pytest.mark.asyncio
async def test_stuck_session_transitions_to_awaiting_reconciliation(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """A wall-clock-exceeded session is routed to AWAITING_RECONCILIATION
    via the helper so all four AR columns are populated
    (recovery write-site contract for startup_reconciliation).
    """
    monkeypatch.setattr(settings, "anonymize_onchain_max_interleg_delay_s", 86_400)

    svc = AnonymizeService()
    await svc.start()
    stuck = _session(
        status=AnonymizeStatus.HOPPING.value,
        updated_offset_s=500_000,  # well past 2x86400 budget
    )
    db_session.add(stuck)
    await db_session.commit()

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    summary = await run_startup_reconciliation(
        service=svc,
        session_factory=factory,
        observation_fn=no_op_observation_fn,
    )
    assert summary.reconciled_count == 1

    # Re-read to verify the contract: status + reason +
    # pre_reconciliation_status all populated atomically.
    async with factory() as fresh:
        from sqlalchemy import select

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == stuck.id))).scalar_one()
        assert row.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
        assert row.awaiting_reconciliation_reason == "wall_clock_budget_exceeded"
        assert row.pre_reconciliation_status == AnonymizeStatus.HOPPING.value
        # DB defaults on first AR entry.
        assert row.reconciliation_attempts == 0
        assert row.last_reconciliation_attempt_ts is None
    await svc.stop()


@pytest.mark.asyncio
async def test_schema_below_min_supported_routes_to_ar_with_reason(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """A session with ``pipeline_schema_version`` below the
    running floor must route to AR via the helper so the
    ``pipeline_schema_below_min_supported`` reason is set on the row.
    Tests the second startup_reconciliation write-site.
    """
    monkeypatch.setattr(
        settings,
        "anonymize_pipeline_schema_version_min_supported",
        20,
    )
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    # schema_version 10 is below the configured min 20.
    sess.pipeline_schema_version = 10
    db_session.add(sess)
    await db_session.commit()

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    summary = await run_startup_reconciliation(
        service=svc,
        session_factory=factory,
        observation_fn=no_op_observation_fn,
    )
    assert summary.reconciled_count == 1

    async with factory() as fresh:
        from sqlalchemy import select

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == sess.id))).scalar_one()
        assert row.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
        assert row.awaiting_reconciliation_reason == ("pipeline_schema_below_min_supported")
        assert row.pre_reconciliation_status == AnonymizeStatus.HOPPING.value
    await svc.stop()


@pytest.mark.asyncio
async def test_healthy_session_gets_spawned_task(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_pipeline_schema_version_min_supported", 10)
    monkeypatch.setattr(settings, "anonymize_onchain_max_interleg_delay_s", 172_800)

    svc = AnonymizeService()
    await svc.start()
    healthy = _session(
        status=AnonymizeStatus.HOPPING.value,
        updated_offset_s=60,
    )
    db_session.add(healthy)
    await db_session.commit()

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    await run_startup_reconciliation(
        service=svc,
        session_factory=factory,
        observation_fn=no_op_observation_fn,
    )
    # Per-session task is registered on the service.
    assert svc.in_flight_count() == 1
    await svc.stop()


@pytest.mark.asyncio
async def test_already_reconciling_session_stays_put(
    db_engine,
    db_session,
) -> None:
    """A session already in AWAITING_RECONCILIATION isn't re-transitioned."""
    svc = AnonymizeService()
    await svc.start()
    sess = _session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        updated_offset_s=60,
    )
    db_session.add(sess)
    await db_session.commit()

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    summary = await run_startup_reconciliation(
        service=svc,
        session_factory=factory,
        observation_fn=no_op_observation_fn,
    )
    assert summary.reconciled_count == 1
    # Row is unchanged.
    async with factory() as fresh:
        from sqlalchemy import select

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == sess.id))).scalar_one()
        assert row.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    await svc.stop()


@pytest.mark.asyncio
async def test_reconciliation_empty_db_returns_zero_counts(
    db_engine,
) -> None:
    svc = AnonymizeService()
    await svc.start()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    summary = await run_startup_reconciliation(
        service=svc,
        session_factory=factory,
        observation_fn=no_op_observation_fn,
    )
    assert summary.resumed_count == 0
    assert summary.reconciled_count == 0
    assert summary.outcomes == []
    await svc.stop()


@pytest.mark.asyncio
async def test_no_op_observation_returns_empty_tick_obs() -> None:
    """The default observation collector yields no signals."""
    from app.services.anonymize.tick import TickObservations

    obs = await no_op_observation_fn(None, None)
    assert isinstance(obs, TickObservations)
    # Every field defaults to None — the dispatcher will return "wait".
    assert obs.funding_invoice_settled is None
    assert obs.delay_window_elapsed is None


# ── classify_session decision matrix ────────────────────────────


def _make_test_session(
    *,
    status: str | None = None,
    created_offset_s: float = 0,
    updated_offset_s: float | None = 0,
    schema: int = 10,
):
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

    now = datetime.now(timezone.utc)
    return AnonymizeSession(
        id=uuid4(),
        status=status or AnonymizeStatus.HOPPING.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=schema,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        created_at=now - timedelta(seconds=created_offset_s),
        updated_at=(None if updated_offset_s is None else now - timedelta(seconds=updated_offset_s)),
    )


def test_classify_healthy_session_resumes(monkeypatch) -> None:
    from app.services.anonymize.startup_reconciliation import classify_session

    monkeypatch.setattr(
        settings,
        "anonymize_onchain_max_interleg_delay_s",
        172_800,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_pipeline_schema_version_min_supported",
        10,
    )
    sess = _make_test_session(updated_offset_s=300)  # 5 min ago
    out = classify_session(sess)
    assert out.disposition == "resume"
    assert out.reason == "healthy"


def test_classify_below_min_schema_reconciles(monkeypatch) -> None:
    from app.services.anonymize.startup_reconciliation import classify_session

    monkeypatch.setattr(
        settings,
        "anonymize_pipeline_schema_version_min_supported",
        20,
    )
    sess = _make_test_session(schema=10)  # below 20
    out = classify_session(sess)
    assert out.disposition == "reconcile"
    assert out.reason == "pipeline_schema_below_min_supported"


def test_classify_wall_clock_exceeded_reconciles(monkeypatch) -> None:
    from app.services.anonymize.startup_reconciliation import classify_session

    monkeypatch.setattr(
        settings,
        "anonymize_onchain_max_interleg_delay_s",
        86_400,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_pipeline_schema_version_min_supported",
        10,
    )
    # Budget is 2x86400 = 172800 s; updated 200000s ago > budget.
    sess = _make_test_session(updated_offset_s=200_000)
    out = classify_session(sess)
    assert out.disposition == "reconcile"
    assert out.reason == "wall_clock_budget_exceeded"


def test_classify_awaiting_reconciliation_stays_reconcile(monkeypatch) -> None:
    from app.models.anonymize_session import AnonymizeStatus
    from app.services.anonymize.startup_reconciliation import classify_session

    monkeypatch.setattr(
        settings,
        "anonymize_onchain_max_interleg_delay_s",
        172_800,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_pipeline_schema_version_min_supported",
        10,
    )
    sess = _make_test_session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        updated_offset_s=10,
    )
    out = classify_session(sess)
    assert out.disposition == "reconcile"
    assert out.reason == "already_awaiting_reconciliation"


def test_classify_terminal_is_noop_safety_guard() -> None:
    """A terminal row that leaks through the query is no-op'd, not re-armed."""
    from app.models.anonymize_session import AnonymizeStatus
    from app.services.anonymize.startup_reconciliation import classify_session

    sess = _make_test_session(status=AnonymizeStatus.COMPLETED.value)
    out = classify_session(sess)
    assert out.disposition == "resume"
    assert out.reason == "terminal_already_no_op"


@pytest.mark.asyncio
async def test_fetch_non_terminal_excludes_completed(db_session) -> None:
    from app.models.anonymize_session import AnonymizeStatus
    from app.services.anonymize.startup_reconciliation import (
        fetch_non_terminal_sessions,
    )

    live = _make_test_session(status=AnonymizeStatus.HOPPING.value)
    done = _make_test_session(status=AnonymizeStatus.COMPLETED.value)
    db_session.add_all([live, done])
    await db_session.commit()
    rows = await fetch_non_terminal_sessions(db_session)
    ids = {r.id for r in rows}
    assert live.id in ids
    assert done.id not in ids


@pytest.mark.asyncio
async def test_classify_all_non_terminal_walks_each_row(
    db_session,
    monkeypatch,
) -> None:
    from app.services.anonymize.startup_reconciliation import (
        classify_all_non_terminal,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_pipeline_schema_version_min_supported",
        20,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_onchain_max_interleg_delay_s",
        172_800,
    )
    a = _make_test_session(schema=10)  # below min
    b = _make_test_session(schema=20, updated_offset_s=10)
    db_session.add_all([a, b])
    await db_session.commit()
    outs = await classify_all_non_terminal(db_session)
    reasons = {o.reason for o in outs}
    assert "pipeline_schema_below_min_supported" in reasons
    assert "healthy" in reasons
