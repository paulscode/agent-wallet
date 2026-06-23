# SPDX-License-Identifier: MIT
"""Orchestrator bootstrap in app/main.py lifespan.

Covers ``bootstrap_anonymize_orchestrator()``: the wiring that
registers the three recurring tick adapters (audit emit / GC sweep /
decoy catchup) on the module-level :class:`AnonymizeService` and
calls :meth:`AnonymizeService.start`.

The bootstrap uses :func:`app.core.database.get_session_maker` for
its production session factory. The tests patch that to return a
factory bound to the in-memory test engine.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.service import (
    bootstrap_anonymize_orchestrator,
    reset_anonymize_service,
)


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


@pytest.fixture
def _quote_keyset(monkeypatch):
    """Seed a Fernet quote-token key so the bootstrap canary passes."""
    from cryptography.fernet import Fernet

    from app.core.config import settings

    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.mark.asyncio
async def test_bootstrap_registers_three_recurring_tasks(
    db_engine,
    monkeypatch,
    _quote_keyset,
) -> None:
    """The bootstrap wires audit-emit, GC sweep, and decoy catchup."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    svc = await bootstrap_anonymize_orchestrator()
    try:
        scheduler = svc._state.scheduler  # type: ignore[attr-defined]
        assert scheduler is not None
        names = {t.name for t in scheduler.tasks()}
        assert names == {
            "audit_emit",
            "gc_sweep",
            "decoy_catchup",
            "clock_skew_probe",
            "tor_bootstrap_recheck",
            "rotation_tick",
            "chain_poll",
            "self_broadcast_fallback",
            "quote_cache_refresh",
            # The reconciliation auto-retry probe + wedge detector.
            "reconciliation_probe",
        }
    finally:
        await svc.stop()


@pytest.mark.asyncio
async def test_bootstrap_is_idempotent(
    db_engine,
    monkeypatch,
    _quote_keyset,
) -> None:
    """Calling bootstrap twice does not duplicate tasks."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    svc1 = await bootstrap_anonymize_orchestrator()
    svc2 = await bootstrap_anonymize_orchestrator()
    try:
        assert svc1 is svc2
        scheduler = svc1._state.scheduler  # type: ignore[attr-defined]
        names = {t.name for t in scheduler.tasks()}
        # Register-by-name replaces, so we still have the same set.
        assert names == {
            "audit_emit",
            "gc_sweep",
            "decoy_catchup",
            "clock_skew_probe",
            "tor_bootstrap_recheck",
            "rotation_tick",
            "chain_poll",
            "self_broadcast_fallback",
            "quote_cache_refresh",
            # The reconciliation auto-retry probe + wedge detector.
            "reconciliation_probe",
        }
    finally:
        await svc1.stop()


@pytest.mark.asyncio
async def test_bootstrap_started_service_can_be_stopped(
    db_engine,
    monkeypatch,
    _quote_keyset,
) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    svc = await bootstrap_anonymize_orchestrator()
    await svc.stop()
    # State flips back to "not started" so a re-bootstrap is clean.
    assert svc._state.started is False  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_bootstrap_refuses_without_quote_token_keyset(
    db_engine,
    monkeypatch,
) -> None:
    """Missing keyset raises at the bootstrap canary."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core.config import settings
    from app.services.anonymize.quote_token import QuoteTokenKeysetUnconfiguredError

    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_fernet", "")
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    with pytest.raises(QuoteTokenKeysetUnconfiguredError):
        await bootstrap_anonymize_orchestrator()
