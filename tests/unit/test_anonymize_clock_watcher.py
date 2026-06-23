# SPDX-License-Identifier: MIT
"""Mid-flight clock-drift watcher."""

from __future__ import annotations

import time

from app.core.config import settings
from app.services.anonymize.clock import (
    ClockSkewState,
    ClockWatcherInputs,
    time_since_last_probe_s,
    update_clock_skew,
    watcher_decision,
)


def _inputs(*, state: ClockSkewState, now: float, last_probe: float | None = None) -> ClockWatcherInputs:
    return ClockWatcherInputs(state=state, now_unix_s=now, last_probe_unix_s=last_probe)


def test_decision_is_stale_when_never_probed() -> None:
    out = watcher_decision(_inputs(state=ClockSkewState.empty(), now=time.time()))
    assert out == "stale_no_probe"


def test_decision_is_ok_within_runtime_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_runtime_clock_skew_ms", 5000)
    monkeypatch.setattr(settings, "anonymize_clock_recheck_interval_s", 1800)
    state = update_clock_skew(ClockSkewState(), skew_ms=200)
    out = watcher_decision(_inputs(state=state, now=time.time()))
    assert out == "ok"


def test_decision_drift_excursion_above_runtime_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_runtime_clock_skew_ms", 5000)
    monkeypatch.setattr(settings, "anonymize_clock_recheck_interval_s", 1800)
    state = update_clock_skew(ClockSkewState(), skew_ms=10_000)
    out = watcher_decision(_inputs(state=state, now=time.time()))
    assert out == "drift_excursion"


def test_decision_stale_when_state_older_than_2x_recheck(monkeypatch) -> None:
    """A measurement older than 2× re-probe interval is treated as stale."""
    monkeypatch.setattr(settings, "anonymize_max_runtime_clock_skew_ms", 5000)
    monkeypatch.setattr(settings, "anonymize_clock_recheck_interval_s", 1800)
    state = update_clock_skew(ClockSkewState(), skew_ms=200)
    # Force the timestamp far enough back that staleness predicate fires.
    state.measured_at_unix_s = time.time() - (2 * 1800 + 100)
    out = watcher_decision(_inputs(state=state, now=time.time()))
    assert out == "stale_no_probe"


def test_time_since_last_probe_handles_none() -> None:
    inputs = _inputs(state=ClockSkewState.empty(), now=1_000_000.0, last_probe=None)
    assert time_since_last_probe_s(inputs) == float("inf")


def test_time_since_last_probe_returns_nonnegative_delta() -> None:
    inputs = _inputs(
        state=ClockSkewState.empty(),
        now=1_000_100.0,
        last_probe=1_000_000.0,
    )
    assert time_since_last_probe_s(inputs) == 100.0


def test_time_since_last_probe_clock_backwards_returns_zero() -> None:
    inputs = _inputs(
        state=ClockSkewState.empty(),
        now=1_000_000.0,
        last_probe=1_000_500.0,
    )
    # Clock went backwards (or last_probe was supplied from a future
    # source); still report a non-negative number.
    assert time_since_last_probe_s(inputs) == 0.0
