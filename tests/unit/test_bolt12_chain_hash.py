# SPDX-License-Identifier: MIT
"""Tests for :mod:`app.services.bolt12.chain_hash`."""

from __future__ import annotations

import pytest

from app.services.bolt12.chain_hash import (
    MAINNET_CHAIN_HASH,
    REGTEST_CHAIN_HASH,
    SIGNET_CHAIN_HASH,
    TESTNET_CHAIN_HASH,
    accepts_chain,
    chain_hash_for,
)


def test_chain_hash_for_known_networks() -> None:
    assert chain_hash_for("bitcoin") == MAINNET_CHAIN_HASH
    assert chain_hash_for("mainnet") == MAINNET_CHAIN_HASH
    assert chain_hash_for("testnet") == TESTNET_CHAIN_HASH
    assert chain_hash_for("signet") == SIGNET_CHAIN_HASH
    assert chain_hash_for("regtest") == REGTEST_CHAIN_HASH


def test_chain_hash_for_unknown_raises() -> None:
    with pytest.raises(ValueError, match="unsupported bitcoin_network"):
        chain_hash_for("liquid")


# ── inbound policy ──


def test_mainnet_accepts_no_invreq_chain() -> None:
    # "Implicit mainnet" — invreq_chain absent and no offer_chains
    # set is the BOLT 12 default and must be accepted on mainnet.
    assert accepts_chain(our_network="bitcoin", invreq_chain=None, offer_chains=())


def test_mainnet_accepts_explicit_mainnet_invreq_chain() -> None:
    assert accepts_chain(
        our_network="bitcoin",
        invreq_chain=MAINNET_CHAIN_HASH,
        offer_chains=(MAINNET_CHAIN_HASH,),
    )


def test_mainnet_rejects_testnet_invreq_chain() -> None:
    assert not accepts_chain(
        our_network="bitcoin",
        invreq_chain=TESTNET_CHAIN_HASH,
        offer_chains=(),
    )


def test_regtest_rejects_implicit_mainnet_invreq() -> None:
    # invreq_chain absent means mainnet — must be rejected when our
    # wallet is on regtest.
    assert not accepts_chain(our_network="regtest", invreq_chain=None, offer_chains=())


def test_regtest_accepts_matching_invreq_chain() -> None:
    assert accepts_chain(
        our_network="regtest",
        invreq_chain=REGTEST_CHAIN_HASH,
        offer_chains=(REGTEST_CHAIN_HASH,),
    )


def test_regtest_rejects_mainnet_only_offer_chains() -> None:
    # Offer says "mainnet only" (empty chains) but we're on regtest.
    assert not accepts_chain(
        our_network="regtest",
        invreq_chain=REGTEST_CHAIN_HASH,
        offer_chains=(),
    )


def test_offer_chains_must_include_our_chain() -> None:
    # Offer enumerates testnet+signet, we're on mainnet → reject.
    assert not accepts_chain(
        our_network="bitcoin",
        invreq_chain=MAINNET_CHAIN_HASH,
        offer_chains=(TESTNET_CHAIN_HASH, SIGNET_CHAIN_HASH),
    )
