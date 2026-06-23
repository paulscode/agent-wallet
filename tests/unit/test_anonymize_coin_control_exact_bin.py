# SPDX-License-Identifier: MIT
"""Exact-bin source coin-selection helper."""

from __future__ import annotations

from app.core.config import settings
from app.services.anonymize.coin_control import (
    CoinSelection,
    WalletUtxo,
    is_existing_utxo_exact_bin_shaped,
    select_exact_bin_funding,
)


def _u(value: int, *, name: str = "u", confs: int = 6) -> WalletUtxo:
    return WalletUtxo(outpoint=f"{name}:{value}", value_sat=value, confirmations=confs)


def test_picks_exact_bin_utxo_when_present(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    utxos = [_u(100_000, name="a"), _u(250_650, name="b"), _u(500_000, name="c")]
    sel = select_exact_bin_funding(utxos, bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert isinstance(sel, CoinSelection)
    assert sel.chosen_outpoints == ("b:250650",)
    assert sel.has_change is False
    assert sel.needs_consolidation is False
    assert sel.target_funding_value_sat == 250_600


def test_no_exact_bin_utxo_returns_needs_consolidation(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    # Closest is 251_000 — outside the 50-sat tolerance of 250_600.
    utxos = [_u(80_000), _u(251_000)]
    sel = select_exact_bin_funding(utxos, bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert sel.chosen_outpoints == ()
    assert sel.needs_consolidation is True
    assert sel.has_change is False


def test_unconfirmed_utxos_are_excluded(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    utxos = [_u(250_600, name="a", confs=0)]  # unconfirmed
    sel = select_exact_bin_funding(utxos, bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert sel.needs_consolidation is True


def test_picks_closest_utxo_within_tolerance(monkeypatch) -> None:
    """When two UTXOs both fall within tolerance, pick the closer one."""
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 100)
    utxos = [_u(250_660, name="far"), _u(250_605, name="close")]
    sel = select_exact_bin_funding(utxos, bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert sel.chosen_outpoints == ("close:250605",)


def test_zero_value_utxos_filtered() -> None:
    utxos = [_u(0, confs=10)]
    sel = select_exact_bin_funding(utxos, bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert sel.needs_consolidation is True


def test_explicit_tolerance_overrides_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    utxos = [_u(250_700)]
    # Default tolerance (50) — would reject.
    default_sel = select_exact_bin_funding(utxos, bin_amount_sat=250_000, max_estimated_fee_sat=600)
    assert default_sel.needs_consolidation is True
    # Explicit larger tolerance — accept.
    accepted = select_exact_bin_funding(
        utxos,
        bin_amount_sat=250_000,
        max_estimated_fee_sat=600,
        tolerance_sat=200,
    )
    assert accepted.chosen_outpoints == ("u:250700",)


def test_existing_utxo_exact_bin_shaped(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_exact_bin_tolerance_sat", 50)
    # 100_000 is one of the published bins.
    assert is_existing_utxo_exact_bin_shaped(_u(100_010)) is True
    # 100_000 is one of the published bins; tolerance does NOT apply
    # here because we're checking against the bin set, not an offset.
    assert is_existing_utxo_exact_bin_shaped(_u(123_456)) is False
