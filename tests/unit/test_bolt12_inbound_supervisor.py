# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.inbound_supervisor`` (S1).

Inbound-symptom HS supervisor that fires SIGHUP Tor when
subscribers can't keep streams alive long enough. Parallels
``lnd_tor_supervisor`` but triggered by INBOUND signals (peer
forward failures observable as subscriber transport errors) so
the outbound LND breaker staying closed doesn't mask the problem.
"""

from __future__ import annotations

import asyncio

import pytest

# ── _should_sighup decision matrix ──────────────────────────────


def test_inbound_supervisor_should_sighup_below_threshold():
    """Fewer transport events than the threshold → no SIGHUP."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    sup.record_subscriber_event(transport=True, lifetime_s=1.0)
    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is False
    assert diag["decision"] == "below_failure_threshold"


def test_inbound_supervisor_should_sighup_fires_when_conditions_met():
    """≥ threshold transport events AND no healthy stream → fire."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(15):
        sup.record_subscriber_event(transport=True, lifetime_s=2.0)
    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is True
    assert diag["decision"] == "fire"
    assert diag["transport_count"] >= 10


def test_inbound_supervisor_skips_when_stream_recovered():
    """If a stream in the window lived past the healthy
    threshold, don't SIGHUP — Tor is at least intermittently
    working."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(15):
        sup.record_subscriber_event(transport=True, lifetime_s=2.0)
    # One successful long-lived stream → reason to wait.
    sup.record_subscriber_event(transport=False, lifetime_s=120.0)
    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is False
    assert diag["decision"] == "stream_recovered_recently"


def test_inbound_supervisor_throttle_blocks_consecutive_sighups():
    """After firing once, a second evaluation within the throttle
    window declines."""
    import time

    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(15):
        sup.record_subscriber_event(transport=True, lifetime_s=2.0)

    # Simulate a previous fire 10 s ago; throttle is 3600 s.
    sup._STATE.last_sighup_monotonic = time.monotonic() - 10.0
    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is False
    assert diag["decision"] == "throttled"


# ── Multi-kind signal sources (idea 1 + 2, 2026-06-12) ───────────


def test_inbound_supervisor_fires_on_flap_threshold_alone():
    """Channel-flap-only deployments (polling mode) still trigger
    SIGHUP when 3 flaps land in the window — without any
    subscriber transport errors at all."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(3):
        sup.record_channel_flap()

    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,  # transport never reaches this
        flap_threshold=3,
        hs_fetch_failure_threshold=99,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is True
    assert diag["decision"] == "fire"
    assert "channel_flap" in diag["triggered_by"]
    assert diag["flap_count"] == 3


def test_inbound_supervisor_fires_on_single_hs_fetch_failure_signal():
    """A single HSFETCH-failure signal trips SIGHUP because the
    HS-descriptor probe only emits one signal per probe past its
    own consecutive-failure threshold — that's already a
    sustained pattern."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    sup.record_hs_fetch_failure()

    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        flap_threshold=99,
        hs_fetch_failure_threshold=1,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is True
    assert "hs_fetch_failure" in diag["triggered_by"]
    assert diag["hs_fetch_failure_count"] == 1


def test_inbound_supervisor_records_all_three_kinds_separately():
    """A mixed window (some transport errors, some flaps, some
    HSFETCH failures) reports separate counts so operators can
    see which source dominated when reading audit rows."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(5):
        sup.record_subscriber_event(transport=True, lifetime_s=2.0)
    sup.record_channel_flap()
    sup.record_channel_flap()
    sup.record_hs_fetch_failure()

    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=99,
        flap_threshold=99,
        hs_fetch_failure_threshold=99,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert diag["transport_count"] == 5
    assert diag["flap_count"] == 2
    assert diag["hs_fetch_failure_count"] == 1
    assert fire is False  # all below thresholds


def test_inbound_supervisor_healthy_stream_blocks_flap_triggered_sighup():
    """The "stream recovered recently" gate applies to channel-
    flap-triggered SIGHUPs: if our outbound stream is healthy,
    flaps are likely peer-side issues that SIGHUP wouldn't help."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(3):
        sup.record_channel_flap()
    # A clean stream lifetime in the same window.
    sup.record_subscriber_event(transport=False, lifetime_s=120.0)

    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        flap_threshold=3,
        hs_fetch_failure_threshold=99,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is False
    assert diag["decision"] == "stream_recovered_recently"


def test_inbound_supervisor_healthy_stream_does_not_block_hs_fetch_trigger():
    """The "stream recovered recently" gate is BYPASSED when an
    HSFETCH-failure signal triggers the threshold. A healthy
    outbound stream proves Tor's transport is working — it says
    nothing about HS-descriptor publication, which is exactly
    what SIGHUP refreshes. So HSFETCH triggers fire SIGHUP even
    with a healthy stream in the window."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    sup.record_hs_fetch_failure()
    # A clean long stream in the same window — should NOT block.
    sup.record_subscriber_event(transport=False, lifetime_s=300.0)

    fire, diag = sup._should_sighup(
        window_s=300,
        failure_threshold=10,
        flap_threshold=99,
        hs_fetch_failure_threshold=1,
        healthy_lifetime_s=30.0,
        sighup_throttle_s=3600,
    )
    assert fire is True
    assert diag["decision"] == "fire"
    assert "hs_fetch_failure" in diag["triggered_by"]


# ── _tick end-to-end ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inbound_supervisor_full_tick_fires_sighup_and_audits(
    monkeypatch,
):
    """End-to-end: a tick with the failure signature triggers
    SIGHUP, increments the counter, AND emits both ``armed`` and
    ``sighup_fired`` audit rows."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    # Set up enough transport events to trip the threshold.
    for _ in range(15):
        sup.record_subscriber_event(transport=True, lifetime_s=2.0)

    sighup_called = False

    async def _fake_sighup():
        nonlocal sighup_called
        sighup_called = True
        return True

    monkeypatch.setattr(sup, "_fire_sighup", _fake_sighup)

    audit_events: list[str] = []

    async def _capture_audit(action, details):
        audit_events.append(action)

    monkeypatch.setattr(sup, "_emit_supervisor_audit", _capture_audit)

    await sup._tick()

    assert sighup_called is True
    assert sup._STATE.sighups_fired_total == 1
    assert "bolt12_inbound_supervisor_armed" in audit_events
    assert "bolt12_inbound_supervisor_sighup_fired" in audit_events


@pytest.mark.asyncio
async def test_inbound_supervisor_full_tick_below_threshold_no_action(
    monkeypatch,
):
    """When the signature isn't matched, the tick does NOTHING
    visible — no SIGHUP, no audit row, no counter bump."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    # Only ONE event — well below the threshold.
    sup.record_subscriber_event(transport=True, lifetime_s=2.0)

    sighup_called = False

    async def _fake_sighup():
        nonlocal sighup_called
        sighup_called = True
        return True

    monkeypatch.setattr(sup, "_fire_sighup", _fake_sighup)

    audit_events: list[str] = []

    async def _capture_audit(action, details):
        audit_events.append(action)

    monkeypatch.setattr(sup, "_emit_supervisor_audit", _capture_audit)

    await sup._tick()

    assert sighup_called is False
    assert sup._STATE.sighups_fired_total == 0
    assert audit_events == []
    # Last decision recorded for /livez surface.
    assert sup._STATE.last_decision == "below_failure_threshold"


@pytest.mark.asyncio
async def test_inbound_supervisor_sighup_failure_does_not_increment_counter(
    monkeypatch,
):
    """If SIGHUP itself fails (Tor unreachable), we emit the
    ``armed`` row but NOT ``sighup_fired``, and the counter
    stays put. Operators can grep the missing fire row to spot
    "supervisor wanted to act but Tor was unreachable" events."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    for _ in range(15):
        sup.record_subscriber_event(transport=True, lifetime_s=2.0)

    async def _failing_sighup():
        return False

    monkeypatch.setattr(sup, "_fire_sighup", _failing_sighup)

    audit_events: list[str] = []

    async def _capture_audit(action, details):
        audit_events.append(action)

    monkeypatch.setattr(sup, "_emit_supervisor_audit", _capture_audit)

    await sup._tick()

    assert sup._STATE.sighups_fired_total == 0
    assert "bolt12_inbound_supervisor_armed" in audit_events
    assert "bolt12_inbound_supervisor_sighup_fired" not in audit_events


# ── Lifecycle hygiene ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_inbound_supervisor_disabled_setting_returns_early(monkeypatch):
    """Kill switch: ``bolt12_inbound_supervisor_enabled=false``
    returns immediately and never ticks. Operators must be able
    to fully disable SIGHUP behaviour."""
    from app.services.bolt12 import inbound_supervisor as sup

    sup._reset_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_inbound_supervisor_enabled",
        False,
    )

    tick_called = False

    async def _explode_if_called():
        nonlocal tick_called
        tick_called = True
        raise AssertionError("tick must not run when supervisor disabled")

    monkeypatch.setattr(sup, "_tick", _explode_if_called)

    stop = asyncio.Event()
    await asyncio.wait_for(sup.run_inbound_supervisor(stop), timeout=1.0)
    assert tick_called is False


@pytest.mark.asyncio
async def test_inbound_supervisor_clears_trace_id_at_entry(monkeypatch):
    """Hygiene: when the supervisor task starts, it must clear the
    trace_id contextvar so any inherited id from a parent flow
    doesn't taint the supervisor's audit rows. Verified by
    seeding a stale trace_id, running the supervisor briefly via
    stop_event, and checking the contextvar reads None at the
    point the loop's tick would emit an audit row."""
    from app.services.bolt12 import inbound_supervisor as sup
    from app.services.bolt12 import trace

    sup._reset_for_tests()
    # This test drives the real supervisor loop, so it must opt out of
    # the global ``settings.testing`` short-circuit that conftest sets.
    monkeypatch.setattr("app.core.config.settings.testing", False)
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_inbound_supervisor_enabled",
        True,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_inbound_supervisor_tick_interval_s",
        0.01,
    )

    # Seed a stale trace_id from a hypothetical parent flow.
    trace.set_current_trace_id("LEAKED_FROM_PARENT")

    observed: list[str | None] = []

    stop = asyncio.Event()

    async def _tick_then_stop():
        observed.append(trace.get_current_trace_id())
        stop.set()

    monkeypatch.setattr(sup, "_tick", _tick_then_stop)

    await asyncio.wait_for(sup.run_inbound_supervisor(stop), timeout=2.0)

    # Inside the supervisor's loop, trace_id MUST be None — the
    # supervisor cleared its inherited value at task entry.
    assert observed, "tick should have been called at least once"
    assert observed[0] is None, f"supervisor must clear contextvar at entry; saw {observed[0]!r}"

    trace.set_current_trace_id(None)
