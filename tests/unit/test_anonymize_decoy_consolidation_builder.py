# SPDX-License-Identifier: MIT
"""Decoy-output consolidation builder.

The wallet's PSBT layer translates the :class:`DecoyConsolidationOutputs`
payload into a concrete tx. The on-chain self-source in-process flow uses this
builder to assemble the (consolidation, decoy) value pair.
"""

from __future__ import annotations

import secrets

import pytest

from app.core.config import settings
from app.services.anonymize.coin_control import (
    DecoyConsolidationOutputs,
    build_decoy_consolidation_outputs,
)


def test_build_returns_documented_two_output_shape(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_preconsolidation_overpad_min_sat",
        50_000,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_preconsolidation_overpad_max_sat",
        100_000,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_consolidation_decoy_min_sat",
        200_000,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_consolidation_decoy_max_sat",
        500_000,
    )

    out = build_decoy_consolidation_outputs(
        bin_amount_sat=250_000,
        max_estimated_fee_sat=400,
        decoy_address="bcrt1p" + "a" * 56,
        decoy_derivation_index=7,
    )
    assert isinstance(out, DecoyConsolidationOutputs)
    # Consolidation value = bin + max_fee + Uniform(over_pad).
    assert 250_000 + 400 + 50_000 <= out.consolidation_value_sat <= 250_000 + 400 + 100_000
    # Decoy value in the configured band.
    assert 200_000 <= out.decoy_value_sat <= 500_000
    assert out.decoy_address == "bcrt1p" + "a" * 56
    assert out.decoy_derivation_index == 7


def test_build_uses_empirical_histogram_when_supplied(monkeypatch) -> None:
    """When a non-anonymize change-output histogram is
    supplied, the decoy sampler draws from it (empirical-distribution
    mimicry)."""
    monkeypatch.setattr(
        settings,
        "anonymize_preconsolidation_overpad_min_sat",
        0,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_preconsolidation_overpad_max_sat",
        0,
    )
    hist = [100_000, 200_000, 300_000]
    rng = secrets.SystemRandom()
    for _ in range(20):
        out = build_decoy_consolidation_outputs(
            bin_amount_sat=250_000,
            max_estimated_fee_sat=400,
            decoy_address="bcrt1p" + "b" * 56,
            decoy_derivation_index=0,
            rng=rng,
            decoy_histogram=hist,
        )
        assert out.decoy_value_sat in hist


def test_build_rejects_non_positive_bin_amount() -> None:
    with pytest.raises(ValueError, match="bin_amount_sat must be positive"):
        build_decoy_consolidation_outputs(
            bin_amount_sat=0,
            max_estimated_fee_sat=400,
            decoy_address="bcrt1p" + "c" * 56,
            decoy_derivation_index=0,
        )


def test_build_admits_none_decoy_address() -> None:
    """The address can be None when the caller wants to pre-compute
    the value-pair before knowing the BIP-86 derivation result."""
    out = build_decoy_consolidation_outputs(
        bin_amount_sat=250_000,
        max_estimated_fee_sat=400,
        decoy_address=None,
        decoy_derivation_index=0,
    )
    assert out.decoy_address is None
    assert out.consolidation_value_sat > 250_000
