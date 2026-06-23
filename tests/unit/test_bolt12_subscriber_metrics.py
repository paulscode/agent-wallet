# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.subscriber_metrics``.

Covers the stream-lifetime histogram (T1) and subscriber-heartbeat
audit row (T5) used by both BOLT 12 subscribers.
"""

from __future__ import annotations

import asyncio

import pytest

# ── Stream-lifetime histogram ───────────────────────────────────


def test_subscriber_metrics_records_lifetime():
    """record_stream_started + _ended round-trip stores one
    sample in the per-subscriber histogram and increments the
    monotonic counters."""
    from app.services.bolt12 import subscriber_metrics as sm

    sm._reset_for_tests()
    start = sm.record_stream_started("settlement")
    # Simulate a stream that lived ≥ 0 s. Don't sleep — we only
    # need the call sequence to land in the histogram.
    sm.record_stream_ended("settlement", start)

    s = sm.summary("settlement")
    assert s["settlement"]["sample_count"] == 1
    assert s["settlement"]["stream_starts_total"] == 1
    assert s["settlement"]["stream_ends_total"] == 1
    # Histogram fields should be float (allowed to be 0.0 on a
    # near-instant test loop).
    assert isinstance(s["settlement"]["lifetime_s_p50"], float)


def test_subscriber_metrics_ring_evicts_oldest(monkeypatch):
    """Ring capacity is bounded; appending beyond it drops oldest."""
    from app.services.bolt12 import subscriber_metrics as sm

    sm._reset_for_tests()
    # Force capacity to a tiny value — monkeypatch auto-reverts so
    # we don't leak the modified constant into subsequent tests.
    cap = 5
    monkeypatch.setattr(sm, "_LIFETIME_RING_CAPACITY", cap)
    for _ in range(cap + 3):
        st = sm.record_stream_started("settlement")
        sm.record_stream_ended("settlement", st)
    s = sm.summary("settlement")
    assert s["settlement"]["sample_count"] == cap
    # Counters track ALL events, not just retained samples.
    assert s["settlement"]["stream_starts_total"] == cap + 3


# ── Subscriber heartbeat ────────────────────────────────────────


@pytest.mark.asyncio
async def test_subscriber_heartbeat_emits_audit_row(monkeypatch):
    """``emit_heartbeat`` writes an audit row via ``_audit_inbound``
    with the subscriber name in the details."""
    from app.services.bolt12 import subscriber_metrics as sm

    sm._reset_for_tests()
    captured: list[dict] = []

    async def _fake_audit(*args, **kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _fake_audit,
    )
    await sm.emit_heartbeat("settlement", extra_details={"foo": "bar"})

    assert captured
    kw = captured[0]
    assert kw["action"] == "bolt12_subscriber_heartbeat"
    assert kw["success"] is True
    assert kw["details"]["subscriber"] == "settlement"
    assert kw["details"]["foo"] == "bar"


@pytest.mark.asyncio
async def test_subscriber_heartbeat_loop_respects_stop(monkeypatch):
    """``run_heartbeat_loop`` exits cleanly when stop_event fires."""
    from app.services.bolt12 import subscriber_metrics as sm

    sm._reset_for_tests()

    async def _fake_audit(*args, **kwargs):
        pass

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _fake_audit,
    )

    stop = asyncio.Event()

    async def _stopper():
        await asyncio.sleep(0.05)
        stop.set()

    await asyncio.gather(
        sm.run_heartbeat_loop(
            stop,
            subscriber_name="settlement",
            interval_s=0.02,
        ),
        _stopper(),
    )
