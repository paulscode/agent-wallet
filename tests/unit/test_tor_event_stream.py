# SPDX-License-Identifier: MIT
"""Tor control-port event stream dispatch + reconnect tests.

Exercises the event dispatcher in isolation (line → counter delta),
then verifies the reconnect loop's backoff + counter persistence
across drops.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from app.services.tor_event_stream import (
    EventCounters,
    _dispatch_event,
    get_counters,
)


@pytest.fixture(autouse=True)
def _fresh_counters() -> None:
    """Counters are process-global; reset between tests."""
    import app.services.tor_event_stream as mod

    mod._COUNTERS = EventCounters()


# ── Dispatch: per-event-type counter mapping ───────────────────────


def test_circ_failed_increments_circ_counter() -> None:
    _dispatch_event("650 CIRC 42 FAILED $FP1,$FP2,$FP3 REASON=TIMEOUT")
    c = get_counters()
    assert c.circ_failed == 1
    assert c.events_total == 1


def test_circ_built_does_not_count_as_failure() -> None:
    _dispatch_event("650 CIRC 42 BUILT $FP1,$FP2,$FP3")
    c = get_counters()
    assert c.circ_failed == 0
    # But it still counts as an event-stream pulse.
    assert c.events_total == 1


def test_hs_desc_failed_increments() -> None:
    _dispatch_event("650 HS_DESC FAILED abcdefg0123456789.onion NO_AUTH $HSDIR REASON=NOT_FOUND")
    assert get_counters().hs_desc_failed == 1


def test_guard_down_increments() -> None:
    _dispatch_event("650 GUARD ENTRY $FINGERPRINT DOWN")
    assert get_counters().guard_down == 1


def test_guard_dropped_also_counted() -> None:
    _dispatch_event("650 GUARD ENTRY $FP DROPPED")
    assert get_counters().guard_down == 1


def test_network_liveness_down_increments() -> None:
    _dispatch_event("650 NETWORK_LIVENESS DOWN")
    assert get_counters().network_liveness_down_total == 1


def test_warn_and_err_count_separately() -> None:
    _dispatch_event("650 WARN something warned")
    _dispatch_event("650 ERR something broke")
    c = get_counters()
    assert c.warn_total == 1
    assert c.err_total == 1


# ── log-pattern matchers ─────────────────────────────────────


def test_guard_excluded_pattern_matches_warn() -> None:
    """The 2026-05-21 smoking gun must be picked up from the
    control-port WARN payload."""
    _dispatch_event("650 WARN All current guards excluded by path restriction type 2; using an additional guard")
    c = get_counters()
    assert c.guard_excluded_total == 1
    assert c.warn_total == 1


def test_guard_excluded_pattern_also_matches_err() -> None:
    """A future Tor that promotes the guard-exclusion message to
    ERR must still be picked up."""
    _dispatch_event("650 ERR All current guards excluded by path restriction")
    assert get_counters().guard_excluded_total == 1


def test_circuit_stuck_pattern_matches_seconds_form() -> None:
    """``Tried for N seconds to get a connection`` is the stuck-
    circuit signal; the matcher must accept any integer N."""
    _dispatch_event("650 WARN Tried for 120 seconds to get a connection to [scrubbed]")
    assert get_counters().circuit_stuck_total == 1


def test_unrelated_warn_does_not_match_patterns() -> None:
    """A WARN that mentions neither pattern must NOT bump the
    pattern counters — false positives would mislead the operator."""
    _dispatch_event("650 WARN something else entirely happened here")
    c = get_counters()
    assert c.warn_total == 1
    assert c.guard_excluded_total == 0
    assert c.circuit_stuck_total == 0


def test_pattern_matcher_is_case_insensitive() -> None:
    """If Tor capitalizes differently in a future release, detection
    must survive the change."""
    _dispatch_event("650 WARN ALL CURRENT GUARDS EXCLUDED BY PATH RESTRICTION")
    assert get_counters().guard_excluded_total == 1


def test_unrecognized_event_still_bumps_events_total() -> None:
    """events_total is the keep-alive counter — any 650-prefixed line
    counts toward it, even if we don't recognize the event TYPE.
    Without this the dashboard's "stream is alive" signal would
    silently regress when Tor introduces a new event type."""
    _dispatch_event("650 BUILDTIMEOUT_SET 60 COMPUTED 42")
    assert get_counters().events_total == 1


def test_malformed_line_does_not_crash() -> None:
    """A line that doesn't match the ``650 <type>`` shape must not
    raise — Tor occasionally writes status lines that look adjacent
    (e.g. ``250 OK``) and the read loop forwards anything starting
    with 650 to the dispatcher.

    NOTE: this exercises the regex-mismatch path inside _dispatch_event,
    not the read loop's filter.
    """
    _dispatch_event("not-an-event-line")
    # events_total still bumped because the dispatcher counts every
    # call (the read-loop only forwards 650-prefixed lines; the
    # counter is a "dispatch attempts" gauge).
    assert get_counters().events_total == 1


# ── Reconnect loop: backoff progression + counter persistence ──────


@pytest.mark.asyncio
async def test_reconnect_loop_resets_after_clean_exit() -> None:
    """If ``_subscribe_once`` returns cleanly (because stop_event was
    set), the reconnect counter does NOT bump — that path is reserved
    for unexpected errors."""
    import app.services.tor_event_stream as mod

    async def _clean(_stop: asyncio.Event, *, pool: str = "unified") -> None:
        # Set stop_event immediately so the outer loop exits.
        _stop.set()

    stop_event = asyncio.Event()
    with patch.object(mod, "_subscribe_once", _clean):
        await mod._run_subscription(stop_event)
    c = get_counters()
    assert c.stream_reconnect_total == 0
    assert c.stream_connected is False


@pytest.mark.asyncio
async def test_reconnect_loop_increments_on_error() -> None:
    """A raised exception inside _subscribe_once must bump the
    reconnect counter and stash the error in ``last_reconnect_error``."""
    import app.services.tor_event_stream as mod

    call_count = {"n": 0}

    async def _flaky(_stop: asyncio.Event, *, pool: str = "unified") -> None:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionError("simulated drop")
        # Second call: clean exit.
        _stop.set()

    stop_event = asyncio.Event()
    # Shrink the backoff schedule so the test runs fast.
    with patch.object(mod, "_RECONNECT_BACKOFFS_S", (0.01,)), patch.object(mod, "_subscribe_once", _flaky):
        await mod._run_subscription(stop_event)

    c = get_counters()
    assert c.stream_reconnect_total == 1
    assert c.last_reconnect_error is not None
    assert "simulated drop" in c.last_reconnect_error
    assert c.stream_connected is False


@pytest.mark.asyncio
async def test_counters_persist_across_reconnect() -> None:
    """Dispatched events recorded before a drop must remain after
    the reconnect."""
    import app.services.tor_event_stream as mod

    _dispatch_event("650 CIRC 1 FAILED reason=foo")
    _dispatch_event("650 GUARD ENTRY $FP DOWN")
    before = get_counters()
    assert before.circ_failed == 1
    assert before.guard_down == 1

    async def _one_shot(_stop: asyncio.Event, *, pool: str = "unified") -> None:
        # Drop once, then clean exit.
        if not getattr(_one_shot, "did_drop", False):
            _one_shot.did_drop = True  # type: ignore[attr-defined]
            raise ConnectionError("drop")
        _stop.set()

    stop_event = asyncio.Event()
    with patch.object(mod, "_RECONNECT_BACKOFFS_S", (0.01,)), patch.object(mod, "_subscribe_once", _one_shot):
        await mod._run_subscription(stop_event)

    after = get_counters()
    # Counters survived the reconnect.
    assert after.circ_failed == 1
    assert after.guard_down == 1
    assert after.stream_reconnect_total == 1


# ── Control-endpoint resolution per pool ───────────────────────────


def test_resolve_control_endpoint_lnd_vs_anonymize(monkeypatch) -> None:
    """The 'lnd' pool resolves to the LND control endpoint and any
    other pool to the anonymize endpoint — split-mode must never
    point both tasks at the same control port."""
    import app.services.tor_event_stream as mod

    monkeypatch.setattr("app.core.config.settings.lnd_tor_control_host", "tor-lnd", raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_tor_control_port", 9100, raising=False)
    monkeypatch.setattr("app.core.config.settings.anonymize_tor_control_host", "127.0.0.1", raising=False)
    monkeypatch.setattr("app.core.config.settings.anonymize_tor_control_port", 9051, raising=False)

    assert mod._resolve_control_endpoint("lnd") == ("tor-lnd", 9100)
    assert mod._resolve_control_endpoint("anonymize") == ("127.0.0.1", 9051)


# ── Full subscription session over the control-port mock ───────────


@pytest.mark.asyncio
async def test_subscribe_once_no_control_port_parks_until_stop(monkeypatch) -> None:
    """With no control host/port configured, the session must not
    open a connection — it waits on stop_event and returns, so a
    clearnet/misconfigured deployment doesn't spin the reconnect
    loop opening doomed sockets."""
    import app.services.tor_event_stream as mod

    monkeypatch.setattr(mod, "_resolve_control_endpoint", lambda pool: ("", 0))
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(mod._subscribe_once(stop, pool="unified"), timeout=1.0)


@pytest.mark.asyncio
async def test_subscribe_once_handshake_marks_connected(monkeypatch) -> None:
    """A successful AUTHENTICATE + SETEVENTS marks the pool counters
    ``stream_connected`` and sends both protocol commands. The read
    loop then blocks on the (quiet) control port; cancelling the task
    must run the ``finally`` that closes the writer — the clean
    teardown the reconnect loop relies on."""
    import app.services.tor_event_stream as mod
    from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control

    counters = mod.EventCounters()
    monkeypatch.setattr(mod, "get_pool_counters", lambda pool: counters)
    monkeypatch.setattr(mod, "_resolve_control_endpoint", lambda pool: ("127.0.0.1", 9051))

    mock = TorControlPortMock()
    mock.set_response(f"SETEVENTS {mod._EVENT_TYPES}", "250 OK\r\n")

    stop = asyncio.Event()
    with mock_tor_control(monkeypatch, mock):
        task = asyncio.create_task(mod._subscribe_once(stop, pool="unified"))
        for _ in range(100):
            await asyncio.sleep(0)
            if counters.stream_connected:
                break
        assert counters.stream_connected is True
        # The session is parked in readline() on a quiet control port;
        # cancel to exercise the teardown finally deterministically.
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert mock.closed is True
    assert any(c.startswith("AUTHENTICATE") for c in mock.commands)
    assert f"SETEVENTS {mod._EVENT_TYPES}" in mock.commands


@pytest.mark.asyncio
async def test_subscribe_once_raises_when_setevents_rejected(monkeypatch) -> None:
    """A non-250 SETEVENTS reply must raise so the reconnect loop
    treats it as a failed session and backs off — never silently
    sits on a control port that refused the subscription."""
    import app.services.tor_event_stream as mod
    from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control

    counters = mod.EventCounters()
    monkeypatch.setattr(mod, "get_pool_counters", lambda pool: counters)
    monkeypatch.setattr(mod, "_resolve_control_endpoint", lambda pool: ("127.0.0.1", 9051))

    mock = TorControlPortMock()
    mock.set_response(f"SETEVENTS {mod._EVENT_TYPES}", "552 Unrecognized event\r\n")

    stop = asyncio.Event()
    with mock_tor_control(monkeypatch, mock):
        with pytest.raises(RuntimeError, match="SETEVENTS rejected"):
            await asyncio.wait_for(mod._subscribe_once(stop, pool="unified"), timeout=1.0)
    assert counters.stream_connected is False


@pytest.mark.asyncio
async def test_subscribe_once_raises_when_auth_rejected(monkeypatch) -> None:
    """A rejected AUTHENTICATE must raise (failed session → backoff),
    not proceed to SETEVENTS on an unauthenticated control link."""
    import app.services.tor_event_stream as mod
    from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control

    counters = mod.EventCounters()
    monkeypatch.setattr(mod, "get_pool_counters", lambda pool: counters)
    monkeypatch.setattr(mod, "_resolve_control_endpoint", lambda pool: ("127.0.0.1", 9051))

    mock = TorControlPortMock(accept_auth=False)

    stop = asyncio.Event()
    with mock_tor_control(monkeypatch, mock):
        with pytest.raises(RuntimeError, match="AUTHENTICATE rejected"):
            await asyncio.wait_for(mod._subscribe_once(stop, pool="unified"), timeout=1.0)
    # SETEVENTS must never have been attempted.
    assert all(not c.startswith("SETEVENTS") for c in mock.commands)
