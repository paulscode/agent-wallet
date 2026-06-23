# SPDX-License-Identifier: MIT
"""Tests for ``app.services.lnd_channel_flap_detector`` (S3).

Tighter-cadence polling (default 15 s) that catches sub-minute
``active → inactive`` transitions the 60 s keepalive misses; feeds
the same NEWNYM-burst trigger as the keepalive's own detector.
"""

from __future__ import annotations

import asyncio

import pytest


@pytest.mark.asyncio
async def test_channel_flap_detector_records_active_to_inactive(monkeypatch):
    """An ``active → inactive`` transition lands on the shared
    keepalive burst event ring."""
    from app.services import lnd_channel_flap_detector as flap
    from app.services import lnd_keepalive as ka

    flap._reset_for_tests()
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])

    # First poll: channel active.
    async def _ch_active(*args, **kwargs):
        return [{"chan_id": "1", "active": True}], None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_channels",
        _ch_active,
    )
    await flap._poll_and_detect()
    assert flap._STATE.transitions_total == 0
    assert ka._STATE.inbound_inactivity_events == []

    # Second poll: channel went inactive → record one transition.
    async def _ch_inactive(*args, **kwargs):
        return [{"chan_id": "1", "active": False}], None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_channels",
        _ch_inactive,
    )
    await flap._poll_and_detect()
    assert flap._STATE.transitions_total == 1
    assert len(ka._STATE.inbound_inactivity_events) == 1


@pytest.mark.asyncio
async def test_channel_flap_detector_feeds_inbound_supervisor(monkeypatch):
    """Idea 1 (2026-06-12): each detected ``active→inactive``
    transition also records a ``channel_flap`` signal on the
    inbound supervisor. This is the supervisor's primary signal
    source in polling-mode deployments where subscriber
    transport-error events never fire."""
    from app.services import lnd_channel_flap_detector as flap
    from app.services import lnd_keepalive as ka
    from app.services.bolt12 import inbound_supervisor as sup

    flap._reset_for_tests()
    sup._reset_for_tests()
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])

    async def _ch_active(*args, **kwargs):
        return [{"chan_id": "1", "active": True}], None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_channels",
        _ch_active,
    )
    await flap._poll_and_detect()
    assert len(sup._STATE.events) == 0

    async def _ch_inactive(*args, **kwargs):
        return [{"chan_id": "1", "active": False}], None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_channels",
        _ch_inactive,
    )
    await flap._poll_and_detect()
    # Exactly one signal — and it's a channel_flap kind.
    assert len(sup._STATE.events) == 1
    assert sup._STATE.events[0].kind == "channel_flap"


@pytest.mark.asyncio
async def test_channel_flap_detector_no_transition_no_event(monkeypatch):
    """Two consecutive polls with the same state record no
    transition."""
    from app.services import lnd_channel_flap_detector as flap
    from app.services import lnd_keepalive as ka

    flap._reset_for_tests()
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])

    async def _stable(*args, **kwargs):
        return [{"chan_id": "1", "active": True}], None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_channels",
        _stable,
    )
    await flap._poll_and_detect()
    await flap._poll_and_detect()
    assert flap._STATE.transitions_total == 0
    assert ka._STATE.inbound_inactivity_events == []


@pytest.mark.asyncio
async def test_channel_flap_detector_fires_newnym_at_threshold(monkeypatch):
    """When the count of active→inactive transitions inside the burst
    window reaches the configured threshold, the detector fires the
    shared throttled NEWNYM, bumps the burst counter, and CLEARS the
    event ring so the next burst must re-accumulate from scratch."""
    from app.services import lnd_channel_flap_detector as flap
    from app.services import lnd_keepalive as ka

    flap._reset_for_tests()
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])
    monkeypatch.setattr(ka._STATE, "inbound_burst_newnyms_total", 0)
    monkeypatch.setattr("app.core.config.settings.lnd_inbound_burst_newnym_threshold", 2, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_inbound_burst_window_s", 300, raising=False)

    fired = {"n": 0}

    async def _fake_newnym():
        fired["n"] += 1
        return True

    monkeypatch.setattr("app.services.bolt12.subscriber_recovery.try_newnym_throttled", _fake_newnym)

    # Prime two channels as active.
    async def _two_active(*a, **k):
        return [{"chan_id": "1", "active": True}, {"chan_id": "2", "active": True}], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _two_active)
    await flap._poll_and_detect()

    # Both go inactive in one tick → 2 transitions, hits threshold of 2.
    async def _two_inactive(*a, **k):
        return [{"chan_id": "1", "active": False}, {"chan_id": "2", "active": False}], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _two_inactive)
    await flap._poll_and_detect()

    assert fired["n"] == 1
    assert ka._STATE.inbound_burst_newnyms_total == 1
    # Ring cleared after a successful NEWNYM.
    assert ka._STATE.inbound_inactivity_events == []
    assert ka._STATE.last_inbound_burst_newnym_at is not None


@pytest.mark.asyncio
async def test_channel_flap_detector_no_newnym_when_throttled(monkeypatch):
    """If the throttle declines (``try_newnym_throttled`` returns
    False), the burst counter is NOT bumped and the event ring is
    NOT cleared — the accumulated flaps stay so a later tick can
    retry once the throttle clears."""
    from app.services import lnd_channel_flap_detector as flap
    from app.services import lnd_keepalive as ka

    flap._reset_for_tests()
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])
    monkeypatch.setattr(ka._STATE, "inbound_burst_newnyms_total", 0)
    monkeypatch.setattr("app.core.config.settings.lnd_inbound_burst_newnym_threshold", 2, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_inbound_burst_window_s", 300, raising=False)

    async def _throttled():
        return False

    monkeypatch.setattr("app.services.bolt12.subscriber_recovery.try_newnym_throttled", _throttled)

    async def _two_active(*a, **k):
        return [{"chan_id": "1", "active": True}, {"chan_id": "2", "active": True}], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _two_active)
    await flap._poll_and_detect()

    async def _two_inactive(*a, **k):
        return [{"chan_id": "1", "active": False}, {"chan_id": "2", "active": False}], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _two_inactive)
    await flap._poll_and_detect()

    assert ka._STATE.inbound_burst_newnyms_total == 0
    # Two transitions remain queued (within window) — not cleared.
    assert len(ka._STATE.inbound_inactivity_events) == 2


@pytest.mark.asyncio
async def test_channel_flap_detector_below_threshold_does_not_fire(monkeypatch):
    """A single flap with a threshold of 2 must NOT fire NEWNYM —
    one transition stays in the ring awaiting a second."""
    from app.services import lnd_channel_flap_detector as flap
    from app.services import lnd_keepalive as ka

    flap._reset_for_tests()
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])
    monkeypatch.setattr(ka._STATE, "inbound_burst_newnyms_total", 0)
    monkeypatch.setattr("app.core.config.settings.lnd_inbound_burst_newnym_threshold", 2, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_inbound_burst_window_s", 300, raising=False)

    async def _explode():
        raise AssertionError("NEWNYM must not fire below threshold")

    monkeypatch.setattr("app.services.bolt12.subscriber_recovery.try_newnym_throttled", _explode)

    async def _active(*a, **k):
        return [{"chan_id": "1", "active": True}], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _active)
    await flap._poll_and_detect()

    async def _inactive(*a, **k):
        return [{"chan_id": "1", "active": False}], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _inactive)
    await flap._poll_and_detect()

    assert ka._STATE.inbound_burst_newnyms_total == 0
    assert len(ka._STATE.inbound_inactivity_events) == 1


@pytest.mark.asyncio
async def test_channel_flap_detector_disabled_when_interval_zero(monkeypatch):
    """Interval ≤ 0 disables the detector loop — it returns without
    ever polling."""
    from app.services import lnd_channel_flap_detector as flap

    monkeypatch.setattr("app.core.config.settings.testing", False, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_channel_flap_detect_interval_s", 0, raising=False)

    async def _explode(*a, **k):
        raise AssertionError("poll must not run when disabled")

    monkeypatch.setattr(flap, "_poll_and_detect", _explode)
    stop = asyncio.Event()
    await asyncio.wait_for(flap.run_channel_flap_detector(stop), timeout=1.0)


@pytest.mark.asyncio
async def test_channel_flap_detector_loop_polls_then_stops(monkeypatch):
    """The loop runs a poll and then exits when stop is set during
    the inter-tick wait."""
    from app.services import lnd_channel_flap_detector as flap

    monkeypatch.setattr("app.core.config.settings.testing", False, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_channel_flap_detect_interval_s", 15, raising=False)

    stop = asyncio.Event()
    polls = 0

    async def _poll():
        nonlocal polls
        polls += 1
        stop.set()

    monkeypatch.setattr(flap, "_poll_and_detect", _poll)
    await asyncio.wait_for(flap.run_channel_flap_detector(stop), timeout=1.0)
    assert polls == 1
