# SPDX-License-Identifier: MIT
"""Health-gate hysteresis."""

from __future__ import annotations

from app.core.config import settings
from app.services.anonymize.health_gate import (
    HealthGateState,
    operator_unavailable_response_kind,
)


def test_gate_open_on_fresh_deployment() -> None:
    """Empty window admits — starts up admitting until a probe fires."""
    s = HealthGateState(threshold=2)
    assert s.admitted() is True


def test_gate_closes_after_threshold_unhealthy_probes() -> None:
    """``threshold`` consecutive False probes close the gate."""
    s = HealthGateState(threshold=2)
    s.record(False)
    # One bad probe alone — gate stays open via hysteresis.
    assert s.admitted() is True
    s.record(False)
    # Both inside the window are bad — gate closes.
    assert s.admitted() is False


def test_gate_reopens_after_threshold_healthy_probes() -> None:
    """After a closure, ``threshold`` consecutive True probes reopen."""
    s = HealthGateState(threshold=2)
    s.record(False)
    s.record(False)
    assert s.admitted() is False
    s.record(True)
    # One good probe alone — gate stays closed.
    assert s.admitted() is False
    s.record(True)
    # Both inside window are good — gate reopens.
    assert s.admitted() is True


def test_gate_hysteresis_keeps_state_on_mixed_window() -> None:
    """A mixed window preserves the last decided gate state."""
    s = HealthGateState(threshold=3)
    # Start with all-good — gate open.
    for _ in range(3):
        s.record(True)
    assert s.admitted() is True
    # One bad probe inside a 3-wide window — still 2 good, 1 bad. Mixed.
    s.record(False)
    assert s.admitted() is True  # hysteresis preserves prior


def test_from_settings_uses_configured_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_health_flip_threshold", 5)
    s = HealthGateState.from_settings()
    assert s.threshold == 5


def test_window_evicts_oldest_entries() -> None:
    """A bounded window doesn't grow past ``threshold``."""
    s = HealthGateState(threshold=2)
    for _ in range(10):
        s.record(True)
    assert len(s.recent) == 2


def test_operator_unavailable_response_kind_is_409_requote() -> None:
    """Distinct from 503; tells SPA to re-quote."""
    assert "409" in operator_unavailable_response_kind()
    assert "requote" in operator_unavailable_response_kind()
