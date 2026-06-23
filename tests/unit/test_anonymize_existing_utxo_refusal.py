# SPDX-License-Identifier: MIT
"""Pre-existing exact-bin UTXO refusal."""

from __future__ import annotations

from datetime import date, datetime, timezone

from app.services.anonymize.coin_control import (
    WalletUtxo,
    is_utxo_refused_as_anonymize_source,
)

_BINS = [50_000, 100_000, 250_000, 500_000]
_FEATURE_DAY = date(2026, 5, 10)


def _u(value: int) -> WalletUtxo:
    return WalletUtxo(outpoint=f"x:{value}", value_sat=value, confirmations=10)


def test_admits_utxo_whose_value_does_not_match_any_bin() -> None:
    refused, reason = is_utxo_refused_as_anonymize_source(
        _u(123_456),
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS,
        tolerance_sat=50,
    )
    assert refused is False
    assert reason is None


def test_refuses_exact_bin_utxo_confirmed_after_feature_day() -> None:
    refused, reason = is_utxo_refused_as_anonymize_source(
        _u(250_000),
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS,
        tolerance_sat=50,
    )
    assert refused is True
    assert "over-pad consolidation" in (reason or "")


def test_admits_exact_bin_utxo_predating_feature_day() -> None:
    """Historical exact-bin UTXO ⇒ admit (not part of the analyst's pattern)."""
    refused, reason = is_utxo_refused_as_anonymize_source(
        _u(250_000),
        confirmed_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS,
        tolerance_sat=50,
    )
    assert refused is False
    assert reason is None


def test_admits_exact_bin_utxo_when_feature_day_not_yet_set() -> None:
    """Feature has never been enabled on this wallet → no refusal yet."""
    refused, reason = is_utxo_refused_as_anonymize_source(
        _u(250_000),
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=None,
        bins_at_confirmation=_BINS,
        tolerance_sat=50,
    )
    assert refused is False
    # Still emits a hint so the caller knows to record the day.
    assert reason is not None and "feature_enabled_at_day" in reason


def test_refuses_when_value_within_tolerance() -> None:
    refused, _ = is_utxo_refused_as_anonymize_source(
        _u(250_010),  # 10 sat above bin
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS,
        tolerance_sat=50,
    )
    assert refused is True


def test_admits_when_value_outside_tolerance() -> None:
    refused, _ = is_utxo_refused_as_anonymize_source(
        _u(250_500),  # 500 sat above bin → outside 50-sat tolerance
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS,
        tolerance_sat=50,
    )
    assert refused is False


def test_uses_provided_bins_at_confirmation() -> None:
    """The historical bin set may differ from the live one — the
    historical set is what the predicate consults."""
    refused, _ = is_utxo_refused_as_anonymize_source(
        _u(750_000),
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS + [750_000],
        tolerance_sat=50,
    )
    assert refused is True
    # Same UTXO under the original (smaller) bin set ⇒ admitted.
    refused2, _ = is_utxo_refused_as_anonymize_source(
        _u(750_000),
        confirmed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        feature_enabled_at_day=_FEATURE_DAY,
        bins_at_confirmation=_BINS,  # original set, no 750_000
        tolerance_sat=50,
    )
    assert refused2 is False
