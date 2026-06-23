# SPDX-License-Identifier: MIT
"""Tests for ``app.services.lnd_channel_uptime`` (T6).

Per-channel active/inactive duration tracker with rolling 24 h /
7 d windows surfaced on ``/livez``.
"""

from __future__ import annotations

import asyncio
import time

import pytest


def test_channel_uptime_first_observation_does_not_record():
    """First time we see a channel we initialise but don't add a
    sample (we have no prior interval)."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()
    import time

    now = time.monotonic()
    snap = cu._ChannelSnapshot(chan_id="abc")
    cu._record_sample(snap, now_monotonic=now, active_now=True)
    assert snap.active is True
    assert snap.state_started_monotonic == now
    assert len(snap.samples) == 0


def test_channel_uptime_records_active_interval():
    """A second observation with the same active state records
    an active-interval sample."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()
    import time

    now = time.monotonic()
    snap = cu._ChannelSnapshot(chan_id="abc")
    cu._record_sample(snap, now_monotonic=now, active_now=True)
    cu._record_sample(snap, now_monotonic=now + 5.0, active_now=True)
    assert len(snap.samples) == 1
    ts, was_active, dt = snap.samples[0]
    assert was_active is True
    assert abs(dt - 5.0) < 0.001


def test_channel_uptime_ratio_zero_for_no_samples():
    """A channel we've never sampled is reported at 0.0 uptime."""
    from app.services import lnd_channel_uptime as cu

    snap = cu._ChannelSnapshot(chan_id="abc")
    assert cu._ratio_over_window(snap, 3600) == 0.0


def test_channel_uptime_ratio_computes_correctly():
    """Half active, half inactive over the window → 0.5 ratio."""
    from app.services import lnd_channel_uptime as cu

    snap = cu._ChannelSnapshot(chan_id="abc")
    import time

    now = time.monotonic()
    # Two intervals of 10 s each — one active, one inactive.
    snap.samples.append((now - 5, True, 10.0))
    snap.samples.append((now, False, 10.0))
    ratio = cu._ratio_over_window(snap, 60.0)
    assert abs(ratio - 0.5) < 0.001


def test_channel_uptime_ratio_excludes_samples_before_cutoff():
    """Samples older than the window cutoff are not counted — a
    channel that was active long ago but has only inactive recent
    samples reports 0.0 over a short window."""
    from app.services import lnd_channel_uptime as cu

    snap = cu._ChannelSnapshot(chan_id="abc")
    now = time.monotonic()
    # Active sample well outside a 30 s window.
    snap.samples.append((now - 1000.0, True, 10.0))
    # Recent inactive sample inside the window.
    snap.samples.append((now, False, 10.0))
    assert cu._ratio_over_window(snap, 30.0) == 0.0


def test_channel_uptime_transition_starts_new_interval():
    """An active→inactive transition records the prior interval as
    active and resets ``state_started`` so the next sample measures
    only the new (inactive) interval — the integration the dashboard
    ratio depends on."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()
    now = time.monotonic()
    snap = cu._ChannelSnapshot(chan_id="abc")
    cu._record_sample(snap, now_monotonic=now, active_now=True)
    # 8 s active, then it goes inactive.
    cu._record_sample(snap, now_monotonic=now + 8.0, active_now=False)
    assert snap.active is False
    assert snap.state_started_monotonic == now + 8.0
    ts, was_active, dt = snap.samples[-1]
    # The recorded interval was the ACTIVE one preceding the flip.
    assert was_active is True
    assert abs(dt - 8.0) < 0.001


@pytest.mark.asyncio
async def test_channel_uptime_summary_reports_per_channel(monkeypatch):
    """``summary`` projects each tracked channel into a dashboard row
    with the current active flag, peer metadata, and both rolling
    ratios."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()
    now = time.monotonic()
    snap = cu._ChannelSnapshot(chan_id="c1")
    snap.peer_alias = "ACINQ"
    snap.peer_pubkey = "03abc"
    snap.active = True
    snap.samples.append((now, True, 10.0))
    cu._STATE.channels["c1"] = snap

    out = cu.summary()
    row = out["channels"]["c1"]
    assert row["peer_alias"] == "ACINQ"
    assert row["peer_pubkey"] == "03abc"
    assert row["currently_active"] is True
    assert row["uptime_ratio_24h"] == 1.0
    assert row["sample_count"] == 1


@pytest.mark.asyncio
async def test_channel_uptime_poll_projects_channels(monkeypatch):
    """``_poll_once`` ingests ``get_channels`` rows, creating a
    per-channel snapshot keyed by chan_id and recording peer
    metadata. Rows with no chan_id are skipped."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()

    async def _channels(*a, **k):
        return [
            {"chan_id": "100", "active": True, "remote_pubkey": "02dead", "peer_alias": "peerA"},
            {"chan_id": "", "active": True},  # skipped — no chan_id
        ], None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _channels)
    await cu._poll_once()
    assert "100" in cu._STATE.channels
    assert "" not in cu._STATE.channels
    assert cu._STATE.channels["100"].peer_alias == "peerA"
    assert cu._STATE.last_poll_at is not None


@pytest.mark.asyncio
async def test_channel_uptime_poll_swallows_get_channels_error(monkeypatch):
    """A raising ``get_channels`` must not propagate — the tracker is
    advisory and the tick logs+continues, leaving state untouched."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()

    async def _boom(*a, **k):
        raise RuntimeError("lnd unreachable")

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _boom)
    await cu._poll_once()
    assert cu._STATE.channels == {}


@pytest.mark.asyncio
async def test_channel_uptime_poll_ignores_error_tuple(monkeypatch):
    """When ``get_channels`` returns ``(None, error)``, the poll
    returns without recording — no snapshot is created from a failed
    fetch."""
    from app.services import lnd_channel_uptime as cu

    cu._reset_for_tests()

    async def _err(*a, **k):
        return None, "rpc error"

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_channels", _err)
    await cu._poll_once()
    assert cu._STATE.channels == {}


@pytest.mark.asyncio
async def test_channel_uptime_tracker_disabled_when_interval_zero(monkeypatch):
    """Interval ≤ 0 is the kill switch — the loop returns immediately
    without ever polling."""
    from app.services import lnd_channel_uptime as cu

    monkeypatch.setattr("app.core.config.settings.testing", False, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_channel_uptime_track_interval_s", 0, raising=False)

    async def _explode(*a, **k):
        raise AssertionError("poll must not run when disabled")

    monkeypatch.setattr(cu, "_poll_once", _explode)
    stop = asyncio.Event()
    await asyncio.wait_for(cu.run_channel_uptime_tracker(stop), timeout=1.0)


@pytest.mark.asyncio
async def test_channel_uptime_tracker_polls_then_stops(monkeypatch):
    """The loop polls at least once and then exits promptly when
    stop_event is set during the inter-tick wait."""
    from app.services import lnd_channel_uptime as cu

    monkeypatch.setattr("app.core.config.settings.testing", False, raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_channel_uptime_track_interval_s", 30, raising=False)

    stop = asyncio.Event()
    polls = 0

    async def _poll():
        nonlocal polls
        polls += 1
        stop.set()  # ask the loop to exit after the first poll

    monkeypatch.setattr(cu, "_poll_once", _poll)
    await asyncio.wait_for(cu.run_channel_uptime_tracker(stop), timeout=1.0)
    assert polls == 1
