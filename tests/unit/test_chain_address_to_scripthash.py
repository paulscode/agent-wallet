# SPDX-License-Identifier: MIT
"""Vectors for ``address_to_script_pubkey`` / ``address_to_scripthash``.

The reference scripthashes were precomputed with the same primitive
chain (decode address → derive scriptPubKey → sha256 → reverse →
hex). They cover P2PKH, P2SH, P2WPKH, P2WSH and P2TR on mainnet plus
testnet/regtest variants and a few error paths.
"""

from __future__ import annotations

import hashlib

import pytest

from app.services.chain.electrum_protocol import (
    address_to_script_pubkey,
    address_to_scripthash,
)


def _expected_scripthash(spk_hex: str) -> str:
    spk = bytes.fromhex(spk_hex)
    return hashlib.sha256(spk).digest()[::-1].hex()


# ─── scriptPubKey shape ───────────────────────────────────────────


@pytest.mark.parametrize(
    "address, network, expected_spk_hex",
    [
        # P2PKH mainnet — Genesis block coinbase.
        (
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "bitcoin",
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
        ),
        # P2SH mainnet (3-prefix).
        (
            "3P14159f73E4gFr7JterCCQh9QjiTjiZrG",
            "bitcoin",
            "a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87",
        ),
        # P2WPKH mainnet (BIP-141 test vector).
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bitcoin",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        # P2WSH mainnet (BIP-141 test vector).
        (
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            "bitcoin",
            "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        ),
        # P2TR mainnet (BIP-350 test vector).
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "bitcoin",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        # P2WPKH testnet.
        (
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "testnet",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        # P2WPKH regtest.
        (
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            "regtest",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
    ],
)
def test_address_to_script_pubkey_known_vectors(address: str, network: str, expected_spk_hex: str) -> None:
    assert address_to_script_pubkey(address, network).hex() == expected_spk_hex


@pytest.mark.parametrize(
    "address, network, expected_spk_hex",
    [
        (
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "bitcoin",
            "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
        ),
        (
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bitcoin",
            "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "bitcoin",
            "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
    ],
)
def test_address_to_scripthash_matches_sha256_reversed(address: str, network: str, expected_spk_hex: str) -> None:
    assert address_to_scripthash(address, network) == _expected_scripthash(expected_spk_hex)


def test_address_to_scripthash_returns_64_hex_chars() -> None:
    sh = address_to_scripthash("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bitcoin")
    assert len(sh) == 64
    int(sh, 16)  # must parse


# ─── Error / mismatch paths ───────────────────────────────────────


def test_rejects_empty_address() -> None:
    with pytest.raises(ValueError):
        address_to_script_pubkey("", "bitcoin")


def test_rejects_unknown_network() -> None:
    with pytest.raises(ValueError):
        address_to_script_pubkey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mars")


def test_rejects_hrp_network_mismatch() -> None:
    # mainnet bech32 against testnet network must error.
    with pytest.raises(ValueError, match="HRP"):
        address_to_script_pubkey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "testnet")


def test_rejects_mainnet_p2pkh_against_testnet() -> None:
    with pytest.raises(ValueError, match="version"):
        address_to_script_pubkey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "testnet")


def test_rejects_garbage_address() -> None:
    with pytest.raises(ValueError, match="unrecognised"):
        address_to_script_pubkey("not-an-address-at-all", "bitcoin")


def test_rejects_mixed_case_segwit() -> None:
    # BIP-173: mixed case is invalid.
    with pytest.raises(ValueError):
        address_to_script_pubkey("BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bitcoin")


def test_rejects_bad_checksum_p2pkh() -> None:
    # Flip a character in a known-good address → checksum failure.
    with pytest.raises(ValueError):
        address_to_script_pubkey("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "bitcoin")
