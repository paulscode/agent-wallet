# SPDX-License-Identifier: MIT
"""/ items 99 + 105 + 108 — decoy + refund helpers."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.coin_control import (
    RefundUtxoLabel,
    make_refund_lockdown_label,
    refund_lockdown_enabled,
    refund_override_spends_refused,
    sample_consolidation_to_submarine_delay_s,
    sample_decoy_output_value_sat,
)

# ── items 99 + 105 — decoy output sampler ─────────────────────────


def test_decoy_value_within_default_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_consolidation_decoy_min_sat", 20_000)
    monkeypatch.setattr(settings, "anonymize_consolidation_decoy_max_sat", 80_000)
    for _ in range(50):
        v = sample_decoy_output_value_sat()
        assert 20_000 <= v <= 80_000


def test_decoy_value_uses_histogram_when_supplied() -> None:
    """Empirical-distribution mimicry: sampling draws from the histogram."""
    histogram = [12_345, 67_890, 100_000_000]
    seen: set[int] = set()
    for _ in range(50):
        seen.add(sample_decoy_output_value_sat(histogram=histogram))
    # All sampled values must come from the histogram.
    assert seen <= set(histogram)
    # And sampling produces a non-trivial spread.
    assert len(seen) >= 2


def test_decoy_delay_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_consolidation_to_submarine_delay_min_s", 300)
    monkeypatch.setattr(settings, "anonymize_consolidation_to_submarine_delay_max_s", 7200)
    for _ in range(20):
        v = sample_consolidation_to_submarine_delay_s()
        assert 300 <= v <= 7200


# ── item 108 — refund-UTXO lockdown ───────────────────────────────


def test_refund_label_is_do_not_spend() -> None:
    label = make_refund_lockdown_label(outpoint="aa" * 32 + ":0", reason="timeout")
    assert isinstance(label, RefundUtxoLabel)
    assert label.do_not_spend is True
    assert label.label == "auto:anonymize-refund"
    assert label.reason == "timeout"


def test_refund_label_rejects_unknown_reason() -> None:
    with pytest.raises(ValueError, match="documented enum"):
        make_refund_lockdown_label(outpoint="aa" * 32 + ":0", reason="bogus")


def test_refund_lockdown_enabled_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_refund_utxo_hardening_enabled", True)
    assert refund_lockdown_enabled() is True


def test_refund_lockdown_disabled_via_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_refund_utxo_hardening_enabled", False)
    assert refund_lockdown_enabled() is False


def test_refund_override_refusal_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_refuse_refund_override_spends", False)
    assert refund_override_spends_refused() is False
    monkeypatch.setattr(settings, "anonymize_refuse_refund_override_spends", True)
    assert refund_override_spends_refused() is True
