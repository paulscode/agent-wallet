# SPDX-License-Identifier: MIT
"""Tests for the LND keepalive task's active-recovery path.

Pins the 2026-06-02 wedge postmortem: after the configured failure
threshold, the keepalive must drop the wedged httpx pool AND
force-close the LND breaker, then keep probing on its normal
cadence. After the hard-alarm ceiling it must stop bouncing the
pool (handing off to ``/livez`` + Docker).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _reset_keepalive_state():
    """Each test starts with a fresh module-level ``_STATE``. The
    keepalive task mutates module globals; without this fixture,
    test order would matter."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE = lnd_keepalive._KeepaliveState()
    yield
    lnd_keepalive._STATE = lnd_keepalive._KeepaliveState()


# ── State tracking ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_successful_probe_updates_last_success_at() -> None:
    """A single successful probe records ``last_success_at`` so
    ``/livez`` can read it."""
    from app.services import lnd_keepalive

    fake_lnd = MagicMock()
    fake_lnd.get_info = AsyncMock(return_value=({"alias": "x"}, None))
    fake_settings = MagicMock(lnd_keepalive_interval_s=0.05)
    stop = asyncio.Event()

    with patch("app.services.lnd_service.lnd_service", fake_lnd), patch("app.core.config.settings", fake_settings):
        # Run until the first probe records success, then stop — no reliance
        # on a fixed sleep landing after the probe interval.
        task = asyncio.create_task(lnd_keepalive.run_lnd_keepalive(stop))
        loop = asyncio.get_event_loop()
        deadline = loop.time() + 5.0
        while lnd_keepalive.get_state().last_success_at is None and loop.time() < deadline:
            await asyncio.sleep(0.01)
        stop.set()
        await asyncio.wait_for(task, timeout=2.0)

    state = lnd_keepalive.get_state()
    assert state.last_success_at is not None
    assert state.consecutive_failures == 0


# ── Active recovery: drops pool + resets breaker ───────────────────


@pytest.mark.asyncio
async def test_active_recovery_fires_after_threshold(monkeypatch) -> None:
    """After ``_RECOVERY_TRIGGER_FAILURES`` consecutive failures,
    keepalive must call ``lnd_service.close()`` AND reset
    ``_LND_BREAKER``. This is the canonical unwedge for a stale
    httpx connection pool."""
    from app.core.resilience import CircuitBreaker
    from app.services import lnd_keepalive

    # Synthetic always-failing get_info.
    fake_lnd = MagicMock()
    fake_lnd.get_info = AsyncMock(return_value=(None, "boom"))
    fake_lnd.close = AsyncMock()

    fake_breaker = CircuitBreaker(name="lnd-test")
    # Pre-open the breaker so reset() has visible effect.
    for _ in range(fake_breaker.failure_threshold):
        fake_breaker.record_failure("synthetic")
    assert fake_breaker.state == "open"

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service",
        fake_lnd,
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.lnd_service._LND_BREAKER",
        fake_breaker,
        raising=False,
    )

    # Trigger N failures via the module-level _STATE to skip the
    # slow loop. We call _attempt_active_recovery directly.
    lnd_keepalive._STATE.consecutive_failures = lnd_keepalive._RECOVERY_TRIGGER_FAILURES
    await lnd_keepalive._attempt_active_recovery()

    fake_lnd.close.assert_awaited_once()
    assert fake_breaker.state == "closed"
    assert fake_breaker.consecutive_failures == 0
    assert lnd_keepalive._STATE.recoveries_attempted_total == 1
    assert lnd_keepalive._STATE.last_recovery_at is not None


@pytest.mark.asyncio
async def test_active_recovery_survives_close_raising(monkeypatch) -> None:
    """If ``lnd_service.close()`` raises (e.g. httpx surfacing an
    AnyIO cancellation during pool teardown), the breaker reset
    must still happen — that's the load-bearing half."""
    from app.core.resilience import CircuitBreaker
    from app.services import lnd_keepalive

    fake_lnd = MagicMock()
    fake_lnd.close = AsyncMock(side_effect=RuntimeError("synthetic teardown"))

    fake_breaker = CircuitBreaker(name="lnd-test")
    for _ in range(fake_breaker.failure_threshold):
        fake_breaker.record_failure("synthetic")
    assert fake_breaker.state == "open"

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service",
        fake_lnd,
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.lnd_service._LND_BREAKER",
        fake_breaker,
        raising=False,
    )

    await lnd_keepalive._attempt_active_recovery()
    assert fake_breaker.state == "closed"
    assert lnd_keepalive._STATE.recoveries_attempted_total == 1
