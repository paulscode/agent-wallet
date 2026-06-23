# SPDX-License-Identifier: MIT
"""Clock-skew gate.

State container + threshold predicate. The probe itself ships with
the supervisor; this test pins the predicate semantics so the
session-create gate has a stable contract to call into.
"""

from __future__ import annotations

import time

from app.core.config import settings
from app.services.anonymize.clock import (
    ClockSkewState,
    is_clock_skew_within_threshold,
    update_clock_skew,
)


def test_empty_state_fails_threshold_predicate() -> None:
    """Fail-closed: no measurement = not within threshold."""
    state = ClockSkewState.empty()
    assert is_clock_skew_within_threshold(state) is False
    assert state.skew_ms is None


def test_within_threshold_returns_true(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_clock_skew_ms", 100)
    state = update_clock_skew(ClockSkewState(), skew_ms=50)
    assert is_clock_skew_within_threshold(state) is True


def test_negative_skew_uses_absolute_value(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_clock_skew_ms", 100)
    state = update_clock_skew(ClockSkewState(), skew_ms=-90)
    assert is_clock_skew_within_threshold(state) is True


def test_above_threshold_returns_false(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_clock_skew_ms", 100)
    state = update_clock_skew(ClockSkewState(), skew_ms=150)
    assert is_clock_skew_within_threshold(state) is False


def test_state_is_stale_after_max_age() -> None:
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    assert state.is_stale(max_age_s=10_000) is False
    # Force the measurement back in time by mutating; the state is
    # treated as immutable at the API surface, but the test patches
    # the timestamp to verify the staleness check works.
    state.measured_at_unix_s = time.time() - 100
    assert state.is_stale(max_age_s=10) is True


def test_update_records_sources_consulted() -> None:
    state = update_clock_skew(
        ClockSkewState(),
        skew_ms=5,
        sources_consulted=("ntp.example.onion", "ntp.other.onion"),
    )
    assert state.sources_consulted == ("ntp.example.onion", "ntp.other.onion")
