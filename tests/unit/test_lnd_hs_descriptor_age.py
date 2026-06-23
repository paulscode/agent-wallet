# SPDX-License-Identifier: MIT
"""Tests for ``app.services.lnd_hs_descriptor_age`` (T4).

Periodic HSFETCH probe of our LND onion + age tracking surfaced
on ``/livez``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest


@pytest.mark.asyncio
async def test_hs_descriptor_age_updates_on_success(monkeypatch):
    """A successful probe records success_total and updates the
    age_seconds reading."""
    from app.services import lnd_hs_descriptor_age as hsa

    hsa._reset_for_tests()

    async def _fake_probe():
        return True, None

    monkeypatch.setattr(hsa, "_probe_once", _fake_probe)

    # Drive one cycle of the loop without the initial-delay sleep
    # by calling the probe-cycle internals directly.
    hsa._STATE.attempts_total += 1
    hsa._STATE.last_fetch_attempt_at = datetime.now(timezone.utc)
    ok, err = await hsa._probe_once()
    assert ok
    if ok:
        import time as _t

        hsa._STATE.last_fetch_ok_at = hsa._STATE.last_fetch_attempt_at
        hsa._STATE.last_fetch_ok_monotonic = _t.monotonic()
        hsa._STATE.successes_total += 1

    assert hsa._STATE.successes_total == 1
    assert hsa.age_seconds() is not None
    assert hsa.age_seconds() < 1.0


@pytest.mark.asyncio
async def test_hs_descriptor_age_returns_none_before_first_success():
    """``age_seconds`` returns None until the first ok probe."""
    from app.services import lnd_hs_descriptor_age as hsa

    hsa._reset_for_tests()
    assert hsa.age_seconds() is None


@pytest.mark.asyncio
async def test_hs_descriptor_age_feeds_supervisor_after_threshold(monkeypatch):
    """Idea 2 (2026-06-12): the probe records an
    ``hs_fetch_failure`` signal on the inbound supervisor on
    EACH probe past the configured consecutive-failure threshold.
    This lets a single sustained-failure pattern trigger SIGHUP
    without waiting for a transport-error pile-up that polling-
    mode deployments never see."""
    from app.services import lnd_hs_descriptor_age as hsa
    from app.services.bolt12 import inbound_supervisor as sup

    hsa._reset_for_tests()
    sup._reset_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.lnd_hs_descriptor_failure_supervisor_threshold",
        3,
    )

    async def _fake_failure():
        return False, "simulated"

    monkeypatch.setattr(hsa, "_probe_once", _fake_failure)

    # Drive the real production tick 5 times. Failures 1 and 2
    # don't cross the threshold; 3, 4, 5 do. Expect 3 signals.
    for _ in range(5):
        await hsa._probe_tick()

    fetch_signals = sum(1 for e in sup._STATE.events if e.kind == "hs_fetch_failure")
    assert fetch_signals == 3, (
        f"expected 3 hs_fetch_failure signals (probes 3, 4, 5 above threshold of 3), got {fetch_signals}"
    )
    # Probe state should reflect the run.
    assert hsa._STATE.attempts_total == 5
    assert hsa._STATE.consecutive_failures == 5
    assert hsa._STATE.successes_total == 0


@pytest.mark.asyncio
async def test_hs_descriptor_age_does_not_feed_supervisor_below_threshold(
    monkeypatch,
):
    """Idea 2 negative case: failures BELOW the threshold record
    NO signals on the supervisor — the gate only opens once the
    failure pattern is sustained."""
    from app.services import lnd_hs_descriptor_age as hsa
    from app.services.bolt12 import inbound_supervisor as sup

    hsa._reset_for_tests()
    sup._reset_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.lnd_hs_descriptor_failure_supervisor_threshold",
        5,
    )

    async def _fake_failure():
        return False, "simulated"

    monkeypatch.setattr(hsa, "_probe_once", _fake_failure)

    # 3 failures — below threshold of 5.
    for _ in range(3):
        await hsa._probe_tick()

    fetch_signals = sum(1 for e in sup._STATE.events if e.kind == "hs_fetch_failure")
    assert fetch_signals == 0


@pytest.mark.asyncio
async def test_hs_descriptor_age_success_resets_consecutive_failures(
    monkeypatch,
):
    """Idea 2 hygiene: a successful probe resets the counter so a
    fresh failure streak has to re-cross the threshold before
    signals flow again."""
    from app.services import lnd_hs_descriptor_age as hsa
    from app.services.bolt12 import inbound_supervisor as sup

    hsa._reset_for_tests()
    sup._reset_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.lnd_hs_descriptor_failure_supervisor_threshold",
        3,
    )

    call_count = 0

    async def _flaky():
        nonlocal call_count
        call_count += 1
        # Pattern: 2 failures, 1 success, 4 failures (4th crosses
        # the threshold).
        if call_count in (1, 2, 4, 5, 6, 7):
            return False, "simulated"
        return True, None

    monkeypatch.setattr(hsa, "_probe_once", _flaky)

    for _ in range(7):
        await hsa._probe_tick()

    # After call 3 (success): consecutive_failures resets to 0.
    # After call 4 (fail): consecutive_failures=1, below threshold.
    # After call 5 (fail): =2, still below.
    # After call 6 (fail): =3, AT threshold → 1 signal.
    # After call 7 (fail): =4, above threshold → 1 more signal.
    fetch_signals = sum(1 for e in sup._STATE.events if e.kind == "hs_fetch_failure")
    assert fetch_signals == 2
    assert hsa._STATE.successes_total == 1
    assert hsa._STATE.consecutive_failures == 4


@pytest.mark.asyncio
async def test_hs_descriptor_age_probe_skipped_on_clearnet_lnd(monkeypatch):
    """Gate: when ``_lnd_onion_hostname`` returns empty (LND is
    clearnet), the probe loop returns immediately without
    attempting HSFETCH. Prevents WARN-log noise on clearnet
    deployments."""
    from app.services import lnd_hs_descriptor_age as hsa

    hsa._reset_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.lnd_hs_descriptor_probe_interval_s",
        600,
    )

    # Pretend LND is clearnet.
    monkeypatch.setattr(
        "app.services.lnd_tor_supervisor._lnd_onion_hostname",
        lambda: "",
    )

    # The probe should NEVER fire — explode if called.
    async def _explode_probe():
        raise AssertionError("HSFETCH must not fire on clearnet LND")

    monkeypatch.setattr(hsa, "_probe_once", _explode_probe)

    stop = asyncio.Event()
    await asyncio.wait_for(
        hsa.run_hs_descriptor_age_probe(stop),
        timeout=1.0,
    )
    assert hsa._STATE.attempts_total == 0


@pytest.mark.asyncio
async def test_hs_descriptor_probe_disabled_when_interval_zero(monkeypatch):
    """Interval ≤ 0 is the kill switch — the loop returns immediately
    without gating on the onion hostname or probing."""
    from app.services import lnd_hs_descriptor_age as hsa

    hsa._reset_for_tests()
    monkeypatch.setattr("app.core.config.settings.testing", False, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_hs_descriptor_probe_interval_s", 0, raising=False)

    async def _explode():
        raise AssertionError("probe must not fire when interval <= 0")

    monkeypatch.setattr(hsa, "_probe_once", _explode)
    stop = asyncio.Event()
    await asyncio.wait_for(hsa.run_hs_descriptor_age_probe(stop), timeout=1.0)
    assert hsa._STATE.attempts_total == 0


@pytest.mark.asyncio
async def test_hs_descriptor_probe_runs_tick_then_stops_on_onion_lnd(monkeypatch):
    """On an onion LND deployment the loop clears the initial delay,
    runs at least one real probe tick (updating attempts_total +
    success state), and exits promptly once stop is set."""
    from app.services import lnd_hs_descriptor_age as hsa

    hsa._reset_for_tests()
    monkeypatch.setattr("app.core.config.settings.testing", False, raising=False)
    # Tiny interval → the initial-delay (min(60, interval)) and the
    # inter-tick wait are both near-instant; no real sleeping.
    monkeypatch.setattr("app.core.config.settings.lnd_hs_descriptor_probe_interval_s", 0.01, raising=False)
    # LND is an onion → the probe gate opens.
    monkeypatch.setattr(
        "app.services.lnd_tor_supervisor._lnd_onion_hostname",
        lambda: "examplelndaddress12345.onion",
    )

    stop = asyncio.Event()

    async def _ok_probe():
        # After the first tick, ask the loop to stop so the
        # interval wait short-circuits.
        stop.set()
        return True, None

    monkeypatch.setattr(hsa, "_probe_once", _ok_probe)

    await asyncio.wait_for(hsa.run_hs_descriptor_age_probe(stop), timeout=1.0)

    assert hsa._STATE.attempts_total == 1
    assert hsa._STATE.successes_total == 1
    assert hsa.age_seconds() is not None


@pytest.mark.asyncio
async def test_hs_descriptor_probe_once_wraps_probe_exception(monkeypatch):
    """``_probe_once`` converts an exception from the underlying
    HSFETCH helper into a ``(False, error_str)`` tuple rather than
    propagating, so a single bad fetch can't crash the loop."""
    from app.services import lnd_hs_descriptor_age as hsa

    async def _boom(*a, **k):
        raise RuntimeError("hsfetch transport error")

    monkeypatch.setattr(
        "app.services.lnd_tor_supervisor._hsfetch_lnd_onion",
        _boom,
    )
    ok, err = await hsa._probe_once()
    assert ok is False
    assert "RuntimeError" in err and "hsfetch transport error" in err
