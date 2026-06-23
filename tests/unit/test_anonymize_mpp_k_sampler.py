# SPDX-License-Identifier: MIT
"""Per-session randomized MPP K sampler."""

from __future__ import annotations

from collections import Counter

import pytest

from app.core.config import settings
from app.services.anonymize.cooperative_claim import (
    assert_mpp_k_range_non_degenerate,
    sample_requested_mpp_k,
)


def test_sample_within_configured_range(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_min", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 4)
    seen: Counter[int] = Counter()
    for _ in range(200):
        v = sample_requested_mpp_k()
        assert 2 <= v <= 4
        seen[v] += 1
    # Distribution should cover at least 3 values.
    assert len(seen) == 3


def test_sample_handles_inverted_range(monkeypatch) -> None:
    """A misconfigured ``hi < lo`` is clamped to ``hi=lo`` rather than crashing."""
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_min", 3)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 1)
    out = sample_requested_mpp_k()
    assert out == 3


def test_sample_clamps_low_to_one(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_min", 0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 0)
    out = sample_requested_mpp_k()
    assert out >= 1


def test_degenerate_range_raises_without_opt_in(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_min", 3)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 3)
    monkeypatch.setattr(settings, "anonymize_allow_degenerate_mpp_k_range", False)
    with pytest.raises(ValueError, match="degenerate"):
        assert_mpp_k_range_non_degenerate()


def test_degenerate_range_passes_with_opt_in(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_min", 3)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 3)
    monkeypatch.setattr(settings, "anonymize_allow_degenerate_mpp_k_range", True)
    assert_mpp_k_range_non_degenerate()  # no raise


def test_range_at_one_one_passes_without_opt_in(monkeypatch) -> None:
    """Range (1, 1) is a deliberate "single chunk" deployment, not a regression."""
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_min", 1)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 1)
    monkeypatch.setattr(settings, "anonymize_allow_degenerate_mpp_k_range", False)
    assert_mpp_k_range_non_degenerate()  # no raise
