# SPDX-License-Identifier: MIT
"""Liquid network + L-BTC asset-id resolution.

Covers:

* ``resolve_liquid_network()`` maps ``BITCOIN_NETWORK`` to the
  matching :class:`LiquidNetwork` (mainnet → mainnet, testnet →
  testnet, regtest/signet → regtest).
* ``resolve_liquid_btc_asset_id()`` precedence: explicit
  ``ANONYMIZE_LIQUID_BTC_ASSET_ID`` setting overrides the network
  default; mainnet/testnet have built-in constants; regtest without
  the setting raises.
* ``assert_liquid_btc_asset_id_configured()`` startup gate: no-op
  when hop disabled, raises on regtest-without-config, passes on
  mainnet/testnet defaults.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.liquid_address import LiquidNetwork
from app.services.anonymize.liquid_ct import (
    LBTC_ASSET_ID_MAINNET,
    LBTC_ASSET_ID_TESTNET,
)
from app.services.anonymize.liquid_seed import (
    LiquidSeedError,
    assert_liquid_btc_asset_id_configured,
    resolve_liquid_btc_asset_id,
    resolve_liquid_network,
)

# ── resolve_liquid_network ─────────────────────────────────────────


@pytest.mark.parametrize(
    "bitcoin_network,expected",
    [
        ("bitcoin", LiquidNetwork.MAINNET),
        ("mainnet", LiquidNetwork.MAINNET),
        ("BITCOIN", LiquidNetwork.MAINNET),  # case-insensitive
        ("testnet", LiquidNetwork.TESTNET),
        ("regtest", LiquidNetwork.REGTEST),
        ("signet", LiquidNetwork.REGTEST),  # signet maps to regtest
        ("", LiquidNetwork.REGTEST),  # unknown → regtest (operator-config)
    ],
)
def test_resolve_network_from_bitcoin_setting(
    monkeypatch,
    bitcoin_network,
    expected,
) -> None:
    monkeypatch.setattr(settings, "bitcoin_network", bitcoin_network)
    assert resolve_liquid_network() == expected


# ── resolve_liquid_btc_asset_id ────────────────────────────────────


def test_resolve_asset_id_mainnet_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    assert resolve_liquid_btc_asset_id() == LBTC_ASSET_ID_MAINNET


def test_resolve_asset_id_testnet_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "bitcoin_network", "testnet")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    assert resolve_liquid_btc_asset_id() == LBTC_ASSET_ID_TESTNET


def test_resolve_asset_id_regtest_unset_raises(monkeypatch) -> None:
    """Regtest without operator-supplied asset id → fail loud."""
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    with pytest.raises(LiquidSeedError) as exc:
        resolve_liquid_btc_asset_id()
    assert "ANONYMIZE_LIQUID_BTC_ASSET_ID" in str(exc.value)


def test_resolve_asset_id_explicit_overrides_default(monkeypatch) -> None:
    """An operator can pin a specific asset id even on mainnet (e.g.,
    a custom regtest topology that uses the mainnet network family
    but a different bitcoin peg policy)."""
    custom = bytes.fromhex("ee" * 32)
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        custom.hex(),
    )
    assert resolve_liquid_btc_asset_id() == custom


def test_resolve_asset_id_regtest_with_setting(monkeypatch) -> None:
    """Regtest with explicit setting — the canonical operator config."""
    regtest_asset = bytes.fromhex("ad" * 32)
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        regtest_asset.hex(),
    )
    assert resolve_liquid_btc_asset_id() == regtest_asset


def test_resolve_asset_id_rejects_wrong_length(monkeypatch) -> None:
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        "ee" * 16,  # 32 chars, half
    )
    with pytest.raises(LiquidSeedError) as exc:
        resolve_liquid_btc_asset_id()
    assert "64 hex chars" in str(exc.value)


def test_resolve_asset_id_rejects_non_hex(monkeypatch) -> None:
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        "z" * 64,  # right length, bad chars
    )
    with pytest.raises(LiquidSeedError) as exc:
        resolve_liquid_btc_asset_id()
    assert "not valid hex" in str(exc.value)


def test_resolve_asset_id_lowercases_input(monkeypatch) -> None:
    """Operator may supply upper-case hex; helper normalises."""
    custom = bytes.fromhex("ab" * 32)
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        custom.hex().upper(),
    )
    assert resolve_liquid_btc_asset_id() == custom


def test_resolve_asset_id_whitespace_tolerant(monkeypatch) -> None:
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        "  " + ("ee" * 32) + "  ",
    )
    assert resolve_liquid_btc_asset_id() == bytes.fromhex("ee" * 32)


# ── assert_liquid_btc_asset_id_configured (startup gate) ───────────


def test_assert_noop_when_liquid_disabled(monkeypatch) -> None:
    """When the Liquid hop is off, the asset-id config is irrelevant."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    # Must NOT raise even though regtest has no built-in default.
    assert_liquid_btc_asset_id_configured()


def test_assert_passes_on_mainnet_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    assert_liquid_btc_asset_id_configured()  # no raise


def test_assert_passes_on_testnet_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "bitcoin_network", "testnet")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    assert_liquid_btc_asset_id_configured()  # no raise


def test_assert_passes_on_regtest_with_explicit_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        "ad" * 32,
    )
    assert_liquid_btc_asset_id_configured()  # no raise


def test_assert_raises_on_regtest_without_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "")
    with pytest.raises(LiquidSeedError):
        assert_liquid_btc_asset_id_configured()


def test_assert_raises_on_malformed_setting(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_btc_asset_id",
        "ff" * 10,  # wrong length
    )
    with pytest.raises(LiquidSeedError):
        assert_liquid_btc_asset_id_configured()
