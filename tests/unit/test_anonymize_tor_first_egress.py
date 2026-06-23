# SPDX-License-Identifier: MIT
"""Tor bootstrap-gate + first-egress jitter."""

from __future__ import annotations

from app.core.config import settings
from app.services.anonymize.tor import (
    bootstrap_timeout_seconds,
    sample_first_egress_jitter_s,
)


def test_first_egress_jitter_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_first_egress_bootstrap_jitter_s", 60)
    for _ in range(50):
        out = sample_first_egress_jitter_s()
        assert 0.0 <= out <= 60.0


def test_first_egress_jitter_zero_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_first_egress_bootstrap_jitter_s", 0)
    assert sample_first_egress_jitter_s() == 0.0


def test_first_egress_jitter_distribution_is_random(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_first_egress_bootstrap_jitter_s", 60)
    seen: set[float] = set()
    for _ in range(20):
        seen.add(sample_first_egress_jitter_s())
    # Even modest jitter should produce >1 distinct value across 20 samples.
    assert len(seen) > 1


def test_bootstrap_timeout_returns_configured_value(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_tor_bootstrap_timeout_s", 120)
    assert bootstrap_timeout_seconds() == 120


def test_bootstrap_timeout_clamps_to_minimum_one(monkeypatch) -> None:
    """A 0 or negative timeout makes the supervisor unstartable."""
    monkeypatch.setattr(settings, "anonymize_tor_bootstrap_timeout_s", 0)
    assert bootstrap_timeout_seconds() == 1
