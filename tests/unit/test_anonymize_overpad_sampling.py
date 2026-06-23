# SPDX-License-Identifier: MIT
"""/ items 56 + 65 — over-pad consolidation sampler.

The sampler returns ``bin + max_fee + Uniform(min, max)`` and refuses
to produce a value that collides with any *other* published bin
within ``ANONYMIZE_EXACT_BIN_TOLERANCE_SAT``.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.coin_control import (
    OverPadResampleExceededError,
    collides_with_any_bin,
    sample_over_pad,
)


def test_collides_with_any_bin_true_at_tolerance() -> None:
    bins = [50_000, 100_000, 250_000]
    assert collides_with_any_bin(50_010, bins=bins, tolerance_sat=50)
    assert collides_with_any_bin(99_960, bins=bins, tolerance_sat=50)
    assert not collides_with_any_bin(75_000, bins=bins, tolerance_sat=50)


def test_sample_over_pad_returns_value_above_base(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_min_sat", 0)
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_max_sat", 25_000)
    bin_amount = 250_000
    fee = 600
    sampled = sample_over_pad(bin_amount_sat=bin_amount, max_estimated_fee_sat=fee)
    assert sampled >= bin_amount + fee
    assert sampled <= bin_amount + fee + 25_000


def test_sample_over_pad_avoids_other_bins(monkeypatch) -> None:
    """A sample that would collide with a different bin is re-rolled."""
    # Set up so that bin=250_000, max_fee=600, overpad band [0, 49500] —
    # this band could land at 299_500 which is within tolerance of
    # 300_000. The default bins include 500_000, so we pick a band
    # near another bin.
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_min_sat", 249_400)
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_max_sat", 249_400)
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    # bin=250_000 + fee=600 + overpad=249_400 = 500_000 — exact collision
    # with the 500_000 bin → MUST resample, MUST eventually fail-closed.
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_resample_limit", 4)
    with pytest.raises(OverPadResampleExceededError):
        sample_over_pad(bin_amount_sat=250_000, max_estimated_fee_sat=600)


def test_sample_over_pad_succeeds_when_band_is_safe(monkeypatch) -> None:
    """A sufficiently-spaced band always finds a safe value."""
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_min_sat", 1_000)
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_max_sat", 5_000)
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_resample_limit", 32)
    sampled = sample_over_pad(bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert 251_600 <= sampled <= 255_600


def test_sample_over_pad_target_bin_does_not_count_as_collision(monkeypatch) -> None:
    """Collision check excludes the target bin itself.

    The chosen bin is the user's anonymity-set choice; the *over-pad*
    must not coincide with another bin, but matching the target bin
    is fine (the consolidation tx output is sized to bin + fee + overpad,
    so it can't equal the target bin anyway).
    """
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_min_sat", 0)
    monkeypatch.setattr(settings, "anonymize_preconsolidation_overpad_max_sat", 0)
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    # bin + 0 + 0 = 250_000 + fee. Use fee=0 so the sampled value
    # equals the bin exactly — must succeed (target bin excluded).
    sampled = sample_over_pad(bin_amount_sat=250_000, max_estimated_fee_sat=0)
    assert sampled == 250_000
