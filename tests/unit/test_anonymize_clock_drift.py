# SPDX-License-Identifier: MIT
"""Mid-flight clock-drift re-assertion.

Two predicates exposed by ``clock.py``:

* :func:`is_runtime_clock_skew_acceptable` — looser than the
  create-time gate; sessions crossing the runtime threshold route to
  ``awaiting_reconciliation``.
* :func:`is_deadline_inside_skew_window` — pre-self-broadcast guard:
  if the deadline lies inside our drift estimate, the orchestrator
  holds at ``delaying`` rather than firing the broadcast.
"""

from __future__ import annotations

import time

from app.core.config import settings
from app.services.anonymize.clock import (
    ClockSkewState,
    is_deadline_inside_skew_window,
    is_runtime_clock_skew_acceptable,
    update_clock_skew,
)


def test_runtime_skew_fails_closed_when_unmeasured() -> None:
    state = ClockSkewState.empty()
    assert is_runtime_clock_skew_acceptable(state) is False


def test_runtime_skew_acceptable_within_runtime_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_runtime_clock_skew_ms", 5000)
    state = update_clock_skew(ClockSkewState(), skew_ms=4000)
    assert is_runtime_clock_skew_acceptable(state) is True


def test_runtime_skew_rejected_above_runtime_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_runtime_clock_skew_ms", 5000)
    state = update_clock_skew(ClockSkewState(), skew_ms=10_000)
    assert is_runtime_clock_skew_acceptable(state) is False


def test_runtime_skew_uses_absolute_value(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_runtime_clock_skew_ms", 5000)
    state = update_clock_skew(ClockSkewState(), skew_ms=-4500)
    assert is_runtime_clock_skew_acceptable(state) is True


def test_deadline_inside_skew_holds_when_unmeasured() -> None:
    """Fail-closed: with no measurement, the predicate returns True so
    the orchestrator holds rather than fires the broadcast."""
    state = ClockSkewState.empty()
    assert is_deadline_inside_skew_window(time.time(), state=state) is True


def test_deadline_outside_skew_window_returns_false() -> None:
    now = 1_000_000.0
    # 100 ms skew → 0.1 s window; deadline is 5 s past.
    state = update_clock_skew(ClockSkewState(), skew_ms=100)
    assert is_deadline_inside_skew_window(now - 5.0, state=state, now_unix_s=now) is False


def test_deadline_inside_skew_window_returns_true() -> None:
    """A deadline whose miss-window is smaller than measured skew is held."""
    now = 1_000_000.0
    state = update_clock_skew(ClockSkewState(), skew_ms=2000)  # 2 s skew
    # Deadline is 1 s past now — inside the 2-second skew window.
    assert is_deadline_inside_skew_window(now - 1.0, state=state, now_unix_s=now) is True


def test_deadline_none_returns_false() -> None:
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    assert is_deadline_inside_skew_window(None, state=state) is False
