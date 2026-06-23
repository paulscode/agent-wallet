# SPDX-License-Identifier: MIT
"""Full recovery story integration test.

This test ties together today's three layers of recovery and pins
the contract that each layer holds up its end:

  Layer 1 (today's patches): `Connection failed:` keeps state
    recoverable (BoltzSwap stays in PAYING_INVOICE / Liquid hop
    returns noop / reverse hop returns noop).
  Layer 2 (watchdog): notices the Tor breaker open, fires NEWNYM
    after the in-flight check passes. State invalidation hooks
    fire.
  Layer 3 (healthcheck): if NEWNYM + SIGHUP don't recover within
    the threshold, Docker restarts the container.

The fully end-to-end test (real Tor + iptables-driven flap) lives
in `tests/integration/test_tor_real_recovery.py` marked
`@pytest.mark.integration_tor`. This unit-level pin uses mocks at
the seams and asserts the orchestration is correct.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.tor_inflight import InFlightResult


@pytest.mark.asyncio
async def test_full_recovery_orchestration(monkeypatch) -> None:
    """Drive the canonical 2026-05-21 incident scenario:

    1. Tor SOCKS goes flaky → LND streaming pay-invoice gets
       `Connection failed:` from httpx.
    2. The boltz_tasks patch keeps the swap in PAYING_INVOICE
       (verified by the existing test_boltz_tasks suite — not
       re-driven here).
    3. The Tor breaker opens after N classified failures.
    4. After the threshold, the watchdog's tier-2 check
       fires NEWNYM (in-flight check passes because the swap is
       not in the live LookupPayment set — it's in our DB at
       PAYING_INVOICE).
    5. The anonymize exit-diversity cache invalidates so future
       sessions re-evaluate.
    6. Once new circuits work, the breaker closes; the watchdog
       goes quiet.
    """
    # ── Reset state ──
    from app.services.tor_watchdog import _STATE, WatchdogState

    fresh = WatchdogState()
    for k, v in fresh.__dict__.items():
        setattr(_STATE, k, v)

    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER

    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    while _LND_BREAKER.state != "closed":
        _LND_BREAKER.record_success()

    # ── Step 1: Tor wedges. Simulate by directly bumping the Tor
    # breaker as the lnd_service catch-site would do. This matches
    # the real-world flow tested in test_tor_two_tier_breaker.py.
    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("ProxyError: General SOCKS server failure")
    assert _TOR_BREAKER.state == "open"

    # ── Step 2: backdate the open timestamp past tier-2 threshold
    # to simulate "60+ seconds elapsed since the breaker opened."
    _STATE.tor_breaker_opened_at_ts = time.monotonic() - 90

    # ── Step 3: watchdog tick. Mock the LND probe to report no
    # in-flight HTLCs (the swap is in our DB but not yet in LND).
    nn = AsyncMock(return_value=(True, None))
    fake_svc = MagicMock()
    fake_svc.invalidate_exit_diversity_cache = AsyncMock()

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _null_db():
        yield MagicMock()

    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(return_value=InFlightResult(in_flight=False, surfaces=[])),
        ),
        patch(
            "app.services.anonymize.service.get_anonymize_service",
            return_value=fake_svc,
        ),
        patch(
            "app.core.database.get_db_context",
            _null_db,
        ),
    ):
        from app.services.tor_watchdog import _watchdog_tick

        await _watchdog_tick()

    # ── Assertions ──
    # NEWNYM fired.
    nn.assert_awaited_once()
    # State recorded the action.
    assert _STATE.last_newnym_ts > 0
    # cache invalidation hook fired.
    fake_svc.invalidate_exit_diversity_cache.assert_awaited_once()

    # ── Step 4: simulate the breaker recovering (new circuits work)
    # ── by closing it and re-running the watchdog. Escalation state
    # ── should fully reset.
    _TOR_BREAKER.record_success()
    assert _TOR_BREAKER.state == "closed"

    with patch("app.core.database.get_db_context", _null_db):
        await _watchdog_tick()

    assert _STATE.tor_breaker_opened_at_ts == 0.0
    assert _STATE.consecutive_tier_3_fires == 0


@pytest.mark.asyncio
async def test_in_flight_blocks_recovery_during_active_payment(
    monkeypatch,
) -> None:
    """If an LN payment is genuinely in flight when the breaker
    opens (e.g. mid-payment Tor flap), the watchdog must NOT fire
    NEWNYM — fail-closed defer is the correct behaviour. This is
    the explicit funds-safety guarantee."""
    from app.services.tor_watchdog import _STATE, WatchdogState

    fresh = WatchdogState()
    for k, v in fresh.__dict__.items():
        setattr(_STATE, k, v)

    from app.services.lnd_service import _TOR_BREAKER

    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("ProxyError: synthetic")
    _STATE.tor_breaker_opened_at_ts = time.monotonic() - 90

    nn = AsyncMock(return_value=(True, None))

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _null_db():
        yield MagicMock()

    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(
                return_value=InFlightResult(
                    in_flight=True,
                    surfaces=["lnd_htlc"],
                )
            ),
        ),
        patch(
            "app.core.database.get_db_context",
            _null_db,
        ),
    ):
        from app.services.tor_watchdog import _watchdog_tick

        await _watchdog_tick()

    # NEWNYM must NOT have fired — funds safety invariant.
    nn.assert_not_called()
    assert _STATE.last_newnym_ts == 0
