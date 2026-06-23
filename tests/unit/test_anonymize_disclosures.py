# SPDX-License-Identifier: MIT
"""Disclosure copy.

Pin the exact wording the wizard renders so a future regression that
softens the language is caught at PR time. The disclosures module
specifies the on-chain warning verbatim — these strings are part of
the security contract.
"""

from __future__ import annotations

from app.services.anonymize.disclosures import (
    AUDIT_LOG_DISCLOSURE,
    DESTINATION_ADDRESS_WARNING,
    DESTINATION_RETENTION_DISCLOSURE,
    EXT_ONCHAIN_DEPOSITOR_WARNING,
    EXTERNAL_EXPLORER_DISCLOSURE,
    ONCHAIN_INTER_LEG_DELAY_NOTICE,
    SOURCE_UTXO_DOXING_WARNING,
    disclosures_for_source_kind,
)


def test_source_utxo_warning_uses_pinned_phrasing() -> None:
    """wording must be preserved verbatim."""
    assert "permanently imported into the chain analyst's pairing problem" in (SOURCE_UTXO_DOXING_WARNING)
    assert "CANNOT be removed by this pipeline" in SOURCE_UTXO_DOXING_WARNING


def test_ext_onchain_warning_targets_depositor() -> None:
    assert "depositor" in EXT_ONCHAIN_DEPOSITOR_WARNING.lower()
    assert "permanently imported" in EXT_ONCHAIN_DEPOSITOR_WARNING


def test_destination_warning_is_raw_address_only() -> None:
    """Destination input must be raw address only."""
    assert "Raw address only" in DESTINATION_ADDRESS_WARNING
    assert "no bitcoin: URI" in DESTINATION_ADDRESS_WARNING


def test_lightning_source_disclosures_omit_onchain_warnings() -> None:
    out = disclosures_for_source_kind("ext-lightning")
    assert SOURCE_UTXO_DOXING_WARNING not in out
    assert EXT_ONCHAIN_DEPOSITOR_WARNING not in out
    assert ONCHAIN_INTER_LEG_DELAY_NOTICE not in out
    # But the destination + retention + audit + explorer disclosures
    # are always present.
    assert DESTINATION_ADDRESS_WARNING in out
    assert DESTINATION_RETENTION_DISCLOSURE in out
    assert AUDIT_LOG_DISCLOSURE in out
    assert EXTERNAL_EXPLORER_DISCLOSURE in out


def test_onchain_self_includes_source_warning_and_inter_leg_delay() -> None:
    out = disclosures_for_source_kind("onchain-self")
    assert SOURCE_UTXO_DOXING_WARNING in out
    assert ONCHAIN_INTER_LEG_DELAY_NOTICE in out
    # The source-side warning is the *first* disclosure shown.
    assert out[0] == SOURCE_UTXO_DOXING_WARNING


def test_ext_onchain_includes_depositor_warning_and_inter_leg_delay() -> None:
    out = disclosures_for_source_kind("ext-onchain")
    assert EXT_ONCHAIN_DEPOSITOR_WARNING in out
    assert ONCHAIN_INTER_LEG_DELAY_NOTICE in out
    assert out[0] == EXT_ONCHAIN_DEPOSITOR_WARNING


def test_unknown_source_kind_returns_baseline() -> None:
    """An unknown source kind still gets the baseline disclosure set."""
    out = disclosures_for_source_kind("not-a-source")
    assert DESTINATION_ADDRESS_WARNING in out
    assert SOURCE_UTXO_DOXING_WARNING not in out
