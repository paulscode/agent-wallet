# SPDX-License-Identifier: MIT
"""Liquid address parsing tests.

Covers the bech32 (unconfidential) and blech32 (confidential) Liquid
address formats for mainnet / testnet / regtest. Anchored against
wallycore's encode/decode and tested via build-then-parse roundtrips.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.liquid_address import (
    LiquidAddressError,
    LiquidAddressInfo,
    LiquidNetwork,
    encode_confidential_segwit,
    encode_unconfidential_segwit,
    hrps_for_network,
    is_liquid_address,
    parse_liquid_address,
)

# Synthetic but well-formed scripts + pubkeys for the tests.
_P2WPKH_SCRIPT = bytes.fromhex("0014") + b"\x11" * 20  # OP_0 OP_PUSH20 hash
_P2WPKH_SCRIPT_B = bytes.fromhex("0014") + b"\x22" * 20  # different hash
_P2TR_SCRIPT = bytes.fromhex("5120") + b"\x33" * 32  # OP_1 OP_PUSH32 xonly
_BLINDING_PUBKEY = b"\x02" + b"\x42" * 32  # 33 bytes
_BLINDING_PUBKEY_B = b"\x03" + b"\x55" * 32  # different


# ── HRP map ─────────────────────────────────────────────────────────


def test_hrps_for_each_network() -> None:
    assert hrps_for_network(LiquidNetwork.MAINNET) == ("ex", "lq")
    assert hrps_for_network(LiquidNetwork.TESTNET) == ("tex", "tlq")
    assert hrps_for_network(LiquidNetwork.REGTEST) == ("ert", "el")


# ── Unconfidential encode + decode roundtrips ──────────────────────


@pytest.mark.parametrize(
    "network,hrp",
    [
        (LiquidNetwork.MAINNET, "ex"),
        (LiquidNetwork.TESTNET, "tex"),
        (LiquidNetwork.REGTEST, "ert"),
    ],
)
def test_unconfidential_p2wpkh_roundtrip(network, hrp) -> None:
    addr = encode_unconfidential_segwit(_P2WPKH_SCRIPT, network=network)
    assert addr.startswith(hrp + "1")
    info = parse_liquid_address(addr)
    assert isinstance(info, LiquidAddressInfo)
    assert info.network == network
    assert info.script_pubkey == _P2WPKH_SCRIPT
    assert info.blinding_pubkey is None
    assert info.is_confidential is False


@pytest.mark.parametrize(
    "network",
    [
        LiquidNetwork.MAINNET,
        LiquidNetwork.TESTNET,
        LiquidNetwork.REGTEST,
    ],
)
def test_unconfidential_p2tr_roundtrip(network) -> None:
    """Witness v1 (taproot) outputs use bech32m. wallycore handles
    the bech32-vs-bech32m switch internally based on the witness
    version byte; we just round-trip and confirm parsing recovers
    the same script."""
    addr = encode_unconfidential_segwit(_P2TR_SCRIPT, network=network)
    info = parse_liquid_address(addr)
    assert info.network == network
    assert info.script_pubkey == _P2TR_SCRIPT
    assert info.is_confidential is False


# ── Confidential encode + decode roundtrips ────────────────────────


@pytest.mark.parametrize(
    "network,hrp",
    [
        (LiquidNetwork.MAINNET, "lq"),
        (LiquidNetwork.TESTNET, "tlq"),
        (LiquidNetwork.REGTEST, "el"),
    ],
)
def test_confidential_p2wpkh_roundtrip(network, hrp) -> None:
    addr = encode_confidential_segwit(
        _P2WPKH_SCRIPT,
        _BLINDING_PUBKEY,
        network=network,
    )
    assert addr.startswith(hrp + "1")
    info = parse_liquid_address(addr)
    assert info.network == network
    assert info.script_pubkey == _P2WPKH_SCRIPT
    assert info.blinding_pubkey == _BLINDING_PUBKEY
    assert info.is_confidential is True


@pytest.mark.parametrize(
    "network",
    [
        LiquidNetwork.MAINNET,
        LiquidNetwork.TESTNET,
        LiquidNetwork.REGTEST,
    ],
)
def test_confidential_p2tr_roundtrip(network) -> None:
    addr = encode_confidential_segwit(
        _P2TR_SCRIPT,
        _BLINDING_PUBKEY,
        network=network,
    )
    info = parse_liquid_address(addr)
    assert info.network == network
    assert info.script_pubkey == _P2TR_SCRIPT
    assert info.blinding_pubkey == _BLINDING_PUBKEY


def test_confidential_address_changes_with_blinding_pubkey() -> None:
    """Same script, different blinding pubkey → different address.
    This is the contract: a passive observer who learns the
    address learns the blinding pubkey, but per-output blinding
    keys still defeat amount-correlation."""
    a = encode_confidential_segwit(
        _P2WPKH_SCRIPT,
        _BLINDING_PUBKEY,
        network=LiquidNetwork.MAINNET,
    )
    b = encode_confidential_segwit(
        _P2WPKH_SCRIPT,
        _BLINDING_PUBKEY_B,
        network=LiquidNetwork.MAINNET,
    )
    assert a != b


def test_confidential_address_changes_with_script() -> None:
    a = encode_confidential_segwit(
        _P2WPKH_SCRIPT,
        _BLINDING_PUBKEY,
        network=LiquidNetwork.MAINNET,
    )
    b = encode_confidential_segwit(
        _P2WPKH_SCRIPT_B,
        _BLINDING_PUBKEY,
        network=LiquidNetwork.MAINNET,
    )
    assert a != b


# ── Network auto-detection ──────────────────────────────────────────


def test_network_auto_detected_from_hrp() -> None:
    """parse_liquid_address must pick the right network from the
    address prefix without operator-supplied hints."""
    for net in (
        LiquidNetwork.MAINNET,
        LiquidNetwork.TESTNET,
        LiquidNetwork.REGTEST,
    ):
        addr = encode_unconfidential_segwit(_P2WPKH_SCRIPT, network=net)
        assert parse_liquid_address(addr).network == net


# ── Refusals ────────────────────────────────────────────────────────


def test_parse_rejects_bitcoin_mainnet_address() -> None:
    """Bitcoin's ``bc1...`` must NOT parse as Liquid — confusing the
    two networks at the address layer would send funds into the
    void on either side."""
    with pytest.raises(LiquidAddressError):
        parse_liquid_address("bc1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3aw53mz")


def test_parse_rejects_bitcoin_testnet_address() -> None:
    with pytest.raises(LiquidAddressError):
        parse_liquid_address("tb1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3aw53mz")


def test_parse_rejects_bitcoin_regtest_address() -> None:
    with pytest.raises(LiquidAddressError):
        parse_liquid_address("bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6")


def test_parse_rejects_garbage() -> None:
    with pytest.raises(LiquidAddressError):
        parse_liquid_address("not-an-address")


def test_parse_rejects_empty() -> None:
    with pytest.raises(LiquidAddressError):
        parse_liquid_address("")


def test_parse_rejects_non_string() -> None:
    with pytest.raises(LiquidAddressError):
        parse_liquid_address(None)  # type: ignore[arg-type]


def test_encode_unconfidential_rejects_empty_script() -> None:
    with pytest.raises(LiquidAddressError):
        encode_unconfidential_segwit(b"", network=LiquidNetwork.MAINNET)


def test_encode_confidential_rejects_wrong_pubkey_length() -> None:
    with pytest.raises(LiquidAddressError):
        encode_confidential_segwit(
            _P2WPKH_SCRIPT,
            b"\x02" + b"\x00" * 16,
            network=LiquidNetwork.MAINNET,
        )


def test_encode_confidential_rejects_empty_pubkey() -> None:
    with pytest.raises(LiquidAddressError):
        encode_confidential_segwit(
            _P2WPKH_SCRIPT,
            b"",
            network=LiquidNetwork.MAINNET,
        )


# ── is_liquid_address predicate ─────────────────────────────────────


def test_is_liquid_address_true_for_valid() -> None:
    addr = encode_unconfidential_segwit(_P2WPKH_SCRIPT, network=LiquidNetwork.MAINNET)
    assert is_liquid_address(addr) is True


def test_is_liquid_address_false_for_bitcoin() -> None:
    assert is_liquid_address("bc1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3aw53mz") is False


def test_is_liquid_address_false_for_garbage() -> None:
    assert is_liquid_address("not-an-address") is False


# ── Network-correctness: testnet address parsed under mainnet network ─


def test_mainnet_address_does_not_parse_as_testnet() -> None:
    """Each network's HRP is distinct, so we can't accidentally route
    a mainnet address through a testnet code path or vice versa."""
    addr_mainnet = encode_unconfidential_segwit(
        _P2WPKH_SCRIPT,
        network=LiquidNetwork.MAINNET,
    )
    info = parse_liquid_address(addr_mainnet)
    assert info.network == LiquidNetwork.MAINNET
    assert info.network != LiquidNetwork.TESTNET


def test_case_insensitivity() -> None:
    """bech32 addresses are case-insensitive; the parser should accept
    upper-case or mixed-case input (we lowercase internally)."""
    addr = encode_unconfidential_segwit(_P2WPKH_SCRIPT, network=LiquidNetwork.MAINNET)
    info = parse_liquid_address(addr.upper())
    assert info.script_pubkey == _P2WPKH_SCRIPT
