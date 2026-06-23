# SPDX-License-Identifier: MIT
"""Tests for Bitcoin address validation in InitiateSwapRequest."""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.api.cold_storage import InitiateSwapRequest

VALID_MAINNET = [
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",  # taproot
]

VALID_TESTNET = [
    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
    "n3wVtXLZvUPJd9wHzLRdPHNq9noyLfy36p",
    "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc",
]

VALID_REGTEST = [
    "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",  # m/n also valid on regtest
]


def _make_request(address: str, amount: int = 100_000):
    return InitiateSwapRequest(
        amount_sats=amount,
        destination_address=address,
    )


class TestMainnetAddresses:
    """Address validation with bitcoin_network='bitcoin'."""

    @pytest.fixture(autouse=True)
    def set_mainnet(self):
        with patch("app.core.validation.settings") as mock_settings:
            mock_settings.bitcoin_network = "bitcoin"
            yield

    @pytest.mark.parametrize("addr", VALID_MAINNET)
    def test_valid_mainnet_address(self, addr):
        req = _make_request(addr)
        assert req.destination_address == addr

    def test_reject_testnet_on_mainnet(self):
        with pytest.raises(ValidationError, match="mainnet"):
            _make_request("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")

    def test_reject_regtest_on_mainnet(self):
        with pytest.raises(ValidationError, match="mainnet"):
            _make_request("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080")


class TestTestnetAddresses:
    """Address validation with bitcoin_network='testnet'."""

    @pytest.fixture(autouse=True)
    def set_testnet(self):
        with patch("app.core.validation.settings") as mock_settings:
            mock_settings.bitcoin_network = "testnet"
            yield

    @pytest.mark.parametrize("addr", VALID_TESTNET)
    def test_valid_testnet_address(self, addr):
        req = _make_request(addr)
        assert req.destination_address == addr

    def test_reject_mainnet_on_testnet(self):
        with pytest.raises(ValidationError, match="testnet"):
            _make_request("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")


class TestRegtestAddresses:
    """Address validation with bitcoin_network='regtest'."""

    @pytest.fixture(autouse=True)
    def set_regtest(self):
        with patch("app.core.validation.settings") as mock_settings:
            mock_settings.bitcoin_network = "regtest"
            yield

    @pytest.mark.parametrize("addr", VALID_REGTEST)
    def test_valid_regtest_address(self, addr):
        req = _make_request(addr)
        assert req.destination_address == addr

    def test_reject_mainnet_on_regtest(self):
        with pytest.raises(ValidationError, match="regtest"):
            _make_request("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")


class TestEdgeCases:
    """Edge cases for address validation."""

    @pytest.fixture(autouse=True)
    def set_mainnet(self):
        with patch("app.core.validation.settings") as mock_settings:
            mock_settings.bitcoin_network = "bitcoin"
            yield

    def test_too_short(self):
        with pytest.raises(ValidationError):
            _make_request("bc1short")

    def test_empty_string(self):
        with pytest.raises(ValidationError):
            _make_request("")

    def test_amount_below_minimum(self):
        with pytest.raises(ValidationError):
            _make_request(VALID_MAINNET[0], amount=1_000)

    def test_amount_above_maximum(self):
        with pytest.raises(ValidationError):
            _make_request(VALID_MAINNET[0], amount=100_000_000)

    def test_unknown_network_accepts_any(self):
        """Unknown network should accept any plausible address."""
        with patch("app.api.cold_storage.settings") as mock_settings:
            mock_settings.bitcoin_network = "liquidv1"
            # Should not raise — unknown network falls through
            req = _make_request(VALID_MAINNET[0])
            assert req.destination_address == VALID_MAINNET[0]
