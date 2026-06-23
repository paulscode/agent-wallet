# SPDX-License-Identifier: MIT
"""Nightly slow distribution test for the decoy-decrement sampler.

Per the item 136 discipline split:

* Per-PR runs assert *exact-equality* on a seeded RNG (cheap, never flakes).
* Nightly runs assert the empirical mean against the configured rate
  with a wider tolerance band at N=100 000 (catches a regression in
  the sampler that the seeded test would miss because both runs would
  fail the same way).

This file is marked ``@pytest.mark.slow``; the per-PR runner skips
slow tests, and the lint at ``tools/check_anonymize_test_robustness.py``
forbids tolerance-band assertions outside this file.
"""

from __future__ import annotations

from collections import Counter

import pytest

from app.core.config import settings
from app.services.anonymize.cooperative_claim import (
    sample_decoy_decrement_decision,
)


@pytest.mark.slow
def test_empirical_rate_matches_configured_rate_at_100k(monkeypatch) -> None:
    """Empirical rate over N=100 000 samples lies inside a wide
    tolerance band around the configured rate."""
    target = 0.30
    monkeypatch.setattr(
        settings,
        "anonymize_reverse_mpp_decoy_decrement_rate",
        target,
    )
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)

    counts: Counter[bool] = Counter()
    N = 100_000
    for _ in range(N):
        counts[sample_decoy_decrement_decision(requested_k=4)] += 1
    rate = counts[True] / N

    # Wide tolerance band: a sampler bug that flips the rate by >10%
    # absolute is caught here. The corresponding per-PR test uses an
    # exact-equality assertion on a seeded RNG and would not catch
    # this class of bug because the seed masks it.
    assert abs(rate - target) <= 0.02
