# SPDX-License-Identifier: MIT
"""Opportunistic decoy K-decrement sampler."""

from __future__ import annotations

import random
from collections import Counter

from app.core.config import settings
from app.services.anonymize.cooperative_claim import (
    sample_decoy_decrement_decision,
)


def test_zero_rate_never_decrements(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_rate", 0.0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)
    for _ in range(200):
        assert sample_decoy_decrement_decision(requested_k=4) is False


def test_full_rate_always_decrements(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_rate", 1.0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)
    for _ in range(20):
        assert sample_decoy_decrement_decision(requested_k=4) is True


def test_headroom_invariant_blocks_low_k(monkeypatch) -> None:
    """K below floor + headroom never decrements regardless of rate."""
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_rate", 1.0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)
    # K=2 + headroom=2 needs requested_k>=4. K=3 fails.
    assert sample_decoy_decrement_decision(requested_k=3) is False
    assert sample_decoy_decrement_decision(requested_k=2) is False


def test_headroom_invariant_admits_high_k(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_rate", 1.0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)
    assert sample_decoy_decrement_decision(requested_k=4) is True
    assert sample_decoy_decrement_decision(requested_k=5) is True


def test_partial_rate_distribution_deterministic_seed(monkeypatch) -> None:
    """Seeded RNG gives exact-equality on the empirical count.

    The stochastic property (empirical mean over N=100 000 with a wider
    tolerance band) lives in the nightly distribution suite under
    ``tests/integration/`` behind ``@pytest.mark.slow``. Per-PR runs
    MUST use a fixed seed and assert the exact count so the test never
    flakes.
    """
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_rate", 0.30)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)
    seeded_rng = random.Random(settings.anonymize_test_deterministic_rng_seed)
    counts: Counter[bool] = Counter()
    for _ in range(2_000):
        counts[
            sample_decoy_decrement_decision(requested_k=4, rng=seeded_rng)  # type: ignore[arg-type]
        ] += 1
    # Exact-equality: seed=1, rate=0.30, N=2000 → counts are reproducible.
    # Recompute on first run; check current value matches.
    assert counts[True] + counts[False] == 2_000
    # Sanity: a 30% sampler should produce roughly 600 trues; the actual
    # seeded count is asserted exactly so the test never flakes.
    assert counts[True] == 584
