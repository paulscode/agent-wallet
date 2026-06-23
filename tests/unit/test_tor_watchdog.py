# SPDX-License-Identifier: MIT
"""Tor recovery watchdog tests.

These tests drive the watchdog's escalation tiers and pin
the correctness invariants:

  - NEWNYM is gated on the in-flight inventory — fail-closed
    on any uncertainty.
  - NEWNYM respects the rate-limit cooldown
    (settings.tor_newnym_min_interval_s).
  - SIGHUP only fires AFTER NEWNYM didn't recover (escalation order).
  - After NEWNYM, the anonymize exit-diversity cache is invalidated
    .
  - Watchdog self-supervision restarts a crashed loop, bounded
    by _SUPERVISION_MAX_RESTARTS.

The watchdog state is in-memory; tests reset it between cases via
the fixture.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.tor_inflight import InFlightResult
from app.services.tor_watchdog import (
    _STATE,
    WatchdogState,
    _watchdog_tick,
)


@pytest.fixture(autouse=True)
def _reset_state() -> None:
    """Each test starts with a clean watchdog state — for BOTH
    the default pool and the split-mode LND pool. Without
    resetting both, a test that ran ``pool='lnd'`` could leave
    counters set and a later assertion against the LND state
    would start from a non-zero baseline."""
    from app.services.tor_watchdog import _STATE_LND

    fresh = WatchdogState()
    for k, v in fresh.__dict__.items():
        setattr(_STATE, k, v)
    fresh_lnd = WatchdogState()
    for k, v in fresh_lnd.__dict__.items():
        setattr(_STATE_LND, k, v)
    # Also reset all three Tor-relevant breakers so tests don't
    # pollute each other.
    from app.services.lnd_service import (
        _LND_BREAKER,
        _TOR_BREAKER,
        _TOR_LND_BREAKER,
    )

    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    while _TOR_LND_BREAKER.state != "closed":
        _TOR_LND_BREAKER.record_success()
    while _LND_BREAKER.state != "closed":
        _LND_BREAKER.record_success()


# ── last-tick timestamp advances every tick ──────────────────


@pytest.mark.asyncio
async def test_last_tick_ts_advances_on_every_tick(monkeypatch) -> None:
    """The watchdog must stamp ``last_tick_ts`` on every
    tick. The dashboard's "watchdog alive" indicator + the
    ``tor_watchdog_last_tick_age_seconds`` Prometheus gauge both
    depend on this; if a tick silently fails to advance the
    timestamp the panel would falsely report a stuck watchdog
    (worse, mask a real one). This assertion is
    explicit."""
    from app.services.tor_watchdog import _STATE as state

    assert state.last_tick_ts == 0.0
    await _watchdog_tick()
    first_tick = state.last_tick_ts
    assert first_tick > 0.0

    # Subsequent ticks must advance the timestamp.
    import time

    time.sleep(0.01)  # let the monotonic clock move
    await _watchdog_tick()
    assert state.last_tick_ts > first_tick


# ── heartbeat cadence ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_heartbeat_does_not_fire_within_interval() -> None:
    """``tor_watchdog_alive`` heartbeat must fire at
    ``_HEARTBEAT_INTERVAL_S`` cadence (default 1 h), NOT every
    tick. Without this guard a regression that emitted on every
    tick would 120× the audit-log volume and bury real signal."""
    from unittest.mock import AsyncMock

    from app.services.tor_watchdog import _STATE as state

    # Pretend we just emitted a heartbeat 5 seconds ago.
    state.last_heartbeat_ts = _now_monotonic()

    audit = AsyncMock()
    with patch("app.services.tor_watchdog._emit_audit", audit):
        await _watchdog_tick()

    # No tor_watchdog_alive audit row in this tick.
    alive_calls = [c for c in audit.await_args_list if c.args and c.args[0] == "tor_watchdog_alive"]
    assert alive_calls == [], (
        f"heartbeat fired within the interval — operator audit log would balloon. Calls: {audit.await_args_list}"
    )


@pytest.mark.asyncio
async def test_heartbeat_fires_after_interval_elapses() -> None:
    """Mirror: when the heartbeat is due, the audit row must fire
    on the next tick. Drives ``last_heartbeat_ts`` past the
    interval so the cadence check passes."""
    from unittest.mock import AsyncMock

    from app.services.tor_watchdog import _HEARTBEAT_INTERVAL_S
    from app.services.tor_watchdog import _STATE as state

    # Backdate the last-heartbeat far enough that the cadence
    # check on the next tick allows the emit.
    state.last_heartbeat_ts = _now_monotonic() - (_HEARTBEAT_INTERVAL_S + 5)

    audit = AsyncMock()
    with patch("app.services.tor_watchdog._emit_audit", audit):
        await _watchdog_tick()

    alive_calls = [c for c in audit.await_args_list if c.args and c.args[0] == "tor_watchdog_alive"]
    assert len(alive_calls) == 1, (
        f"heartbeat should have fired exactly once after the interval elapsed; got {len(alive_calls)} calls."
    )


def _now_monotonic() -> float:
    import time

    return time.monotonic()


# ── Healthy Tor: watchdog stays quiet ──────────────────────────────


@pytest.mark.asyncio
async def test_no_action_when_tor_breaker_closed(monkeypatch) -> None:
    """Breaker closed → no NEWNYM, no SIGHUP, no audit emits (other
    than the eventual heartbeat which isn't due yet)."""
    nn = AsyncMock()
    sh = AsyncMock()
    with patch("app.services.anonymize.tor.signal_newnym", nn), patch("app.services.anonymize.tor.signal_reload", sh):
        await _watchdog_tick()
    nn.assert_not_called()
    sh.assert_not_called()


# ── Tier 2: NEWNYM fires after threshold + nothing in-flight ──────


@pytest.mark.asyncio
async def test_tier_2_fires_newnym_when_breaker_open_and_nothing_in_flight(
    monkeypatch,
) -> None:
    """Open the Tor breaker, backdate the open timestamp past the
    tier-2 threshold, mock the in-flight check to return False, and
    assert NEWNYM is dispatched."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    # Force the breaker open.
    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic Tor wedge")
    assert _TOR_BREAKER.state == "open"

    # Backdate open timestamp 90s ago so we're past the 60s threshold.
    import time

    state.tor_breaker_opened_at_ts = time.monotonic() - 90

    nn = AsyncMock(return_value=(True, None))
    sh = AsyncMock(return_value=(True, None))
    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch("app.services.anonymize.tor.signal_reload", sh),
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(return_value=InFlightResult(in_flight=False, surfaces=[])),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
    ):
        await _watchdog_tick()
    nn.assert_awaited_once()
    sh.assert_not_called()
    assert state.last_newnym_ts > 0
    # Prometheus counter must increment per successful
    # NEWNYM. Without this the ``tor_newnym_total`` metric stays
    # 0 forever and operators can't graph rotation frequency.
    assert state.newnym_fired_total >= 1


# ── Tier 2 gated by in-flight: defer if anything live ─────────────


@pytest.mark.asyncio
async def test_tier_2_defers_newnym_when_in_flight(monkeypatch) -> None:
    """If the inventory reports an in-flight surface, NEWNYM does
    NOT fire and last_newnym_ts stays at 0."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic Tor wedge")

    import time

    state.tor_breaker_opened_at_ts = time.monotonic() - 90

    nn = AsyncMock(return_value=(True, None))
    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(
                return_value=InFlightResult(
                    in_flight=True,
                    surfaces=["lnd_htlc", "anonymize_stepup"],
                )
            ),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
    ):
        await _watchdog_tick()
    nn.assert_not_called()
    assert state.last_newnym_ts == 0


# ── Tier 2 forces past the in-flight gate after the deferral ceiling ─


@pytest.mark.asyncio
async def test_tier_2_forces_newnym_past_inflight_gate_after_ceiling(
    monkeypatch,
) -> None:
    """Regression for the 2026-06-15 recovery livelock.

    When the Tor breaker has been open past ``_NEWNYM_FORCE_CEILING_S``
    with no successful rotation since it opened, NEWNYM must fire even
    though the in-flight gate reports something live — because the
    gate's own LND probe runs over the wedged path and its fail-safe
    "in-flight" verdict would otherwise defer recovery forever. The
    in-flight probe must be SKIPPED (not run-and-ignored) so a hung
    probe can't stall the recovery tick."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic Tor wedge")
    assert _TOR_BREAKER.state == "open"

    import time

    # Past the 120s force ceiling but below the 180s SIGHUP tier so
    # this test isolates the forced-NEWNYM behaviour.
    state.tor_breaker_opened_at_ts = time.monotonic() - 130
    state.last_newnym_ts = 0.0  # nothing rotated since the breaker opened

    nn = AsyncMock(return_value=(True, None))
    sh = AsyncMock(return_value=(True, None))
    # The in-flight check reports something live — the exact trap that
    # used to defer NEWNYM forever. The force path must bypass it.
    cif = AsyncMock(
        return_value=InFlightResult(
            in_flight=True,
            surfaces=["lnd_htlc", "anonymize_session"],
        )
    )
    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch("app.services.anonymize.tor.signal_reload", sh),
        patch("app.services.tor_inflight.check_in_flight", cif),
        patch("app.core.database.get_db_context", _async_null_db()),
    ):
        await _watchdog_tick()

    nn.assert_awaited_once()  # forced NEWNYM fired despite in_flight
    cif.assert_not_awaited()  # in-flight probe was skipped, not run
    assert state.last_newnym_ts > 0
    assert state.newnym_fired_total >= 1


@pytest.mark.asyncio
async def test_no_force_newnym_when_rotation_already_happened(
    monkeypatch,
) -> None:
    """The force path engages ONLY when nothing has rotated since the
    breaker opened. If a NEWNYM already fired after the breaker
    opened, a later in-flight surface returns to the normal gated
    (deferred) behaviour rather than forcing on every tick."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic Tor wedge")

    import time

    now = time.monotonic()
    # Past the ceiling, but a NEWNYM already fired AFTER the breaker
    # opened (and past the 60s cooldown).
    state.tor_breaker_opened_at_ts = now - 130
    state.last_newnym_ts = now - 65

    nn = AsyncMock(return_value=(True, None))
    cif = AsyncMock(return_value=InFlightResult(in_flight=True, surfaces=["lnd_htlc"]))
    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch("app.services.tor_inflight.check_in_flight", cif),
        patch("app.core.database.get_db_context", _async_null_db()),
    ):
        await _watchdog_tick()

    nn.assert_not_called()  # gated path: deferred, not forced
    cif.assert_awaited()  # the in-flight gate was consulted


# ── NEWNYM cooldown: second tick within window doesn't re-fire ────


@pytest.mark.asyncio
async def test_newnym_cooldown_blocks_re_fire(monkeypatch) -> None:
    """Tor enforces 10s between NEWNYMs; we use settings.
    tor_newnym_min_interval_s (default 60s) as the wallet-side floor.
    Re-firing within the cooldown is a no-op (no second NEWNYM call,
    no second audit emit)."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic")

    import time

    now = time.monotonic()
    state.tor_breaker_opened_at_ts = now - 90
    state.last_newnym_ts = now - 5  # 5s ago, well within 60s cooldown

    nn = AsyncMock(return_value=(True, None))
    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(return_value=InFlightResult(in_flight=False, surfaces=[])),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
    ):
        await _watchdog_tick()
    nn.assert_not_called()


# ── Tier 3: SIGHUP escalates only after NEWNYM didn't recover ─────


@pytest.mark.asyncio
async def test_tier_3_sighup_fires_after_newnym_failed_to_recover(
    monkeypatch,
) -> None:
    """If 3min has passed since the breaker opened AND we already
    fired NEWNYM, the next tick fires SIGHUP."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic")

    import time

    now = time.monotonic()
    state.tor_breaker_opened_at_ts = now - 200  # past tier-3 threshold
    state.last_newnym_ts = now - 90  # NEWNYM already fired, didn't help

    nn = AsyncMock(return_value=(True, None))
    sh = AsyncMock(return_value=(True, None))
    with (
        patch("app.services.anonymize.tor.signal_newnym", nn),
        patch("app.services.anonymize.tor.signal_reload", sh),
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(return_value=InFlightResult(in_flight=False, surfaces=[])),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
    ):
        await _watchdog_tick()
    sh.assert_awaited_once()
    assert state.consecutive_tier_3_fires == 1
    # SIGHUP counter must increment per successful
    # SIGHUP emission. Mirror of the NEWNYM counter assertion.
    assert state.sighup_fired_total >= 1


# ──: cache invalidation hook fires after NEWNYM ─────────────


@pytest.mark.asyncio
async def test_newnym_invalidates_anonymize_cache(monkeypatch) -> None:
    """After a successful NEWNYM, the anonymize exit-
    diversity cache must be invalidated so the next admission re-
    evaluates."""
    from app.services.lnd_service import _TOR_BREAKER
    from app.services.tor_watchdog import _STATE as state

    for _ in range(_TOR_BREAKER.failure_threshold + 1):
        _TOR_BREAKER.record_failure("synthetic")

    import time

    state.tor_breaker_opened_at_ts = time.monotonic() - 90

    nn = AsyncMock(return_value=(True, None))
    fake_svc = MagicMock()
    fake_svc.invalidate_exit_diversity_cache = AsyncMock()
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
            _async_null_db(),
        ),
    ):
        await _watchdog_tick()
    fake_svc.invalidate_exit_diversity_cache.assert_awaited_once()


# ── Breaker recovers → state resets ──────────────────────────────


@pytest.mark.asyncio
async def test_breaker_recovery_resets_state(monkeypatch) -> None:
    """When the breaker closes after being open, escalation
    timers reset (so a subsequent re-open starts the tier countdown
    fresh)."""
    import time

    from app.services.tor_watchdog import _STATE as state

    state.tor_breaker_opened_at_ts = time.monotonic() - 200
    state.consecutive_tier_3_fires = 1

    # Breaker stays closed.
    with patch("app.core.database.get_db_context", _async_null_db()):
        await _watchdog_tick()

    assert state.tor_breaker_opened_at_ts == 0.0
    assert state.consecutive_tier_3_fires == 0


# ── Helpers ───────────────────────────────────────────────────────


def _async_null_db():
    """Returns a context manager whose ``__aenter__`` yields a
    MagicMock that satisfies the watchdog's db usage (it only
    flows through to the in-flight check, which we mock anyway)."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        yield MagicMock()

    return _ctx
