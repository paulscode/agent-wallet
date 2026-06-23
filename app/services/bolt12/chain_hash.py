# SPDX-License-Identifier: MIT
"""Bitcoin chain-hash constants and helpers for BOLT 12.

BOLT 12 identifies the chain a payment is denominated in by the
genesis block hash (in *natural* byte order — i.e. how it appears
in block headers, which is the SHA-256d output, **not** the human-
readable big-endian "block id"). When omitted, the spec treats the
chain as Bitcoin mainnet.

This module exposes:

* ``CHAIN_HASHES`` — mapping from the wallet's
  ``settings.bitcoin_network`` literal to its 32-byte chain hash.
* ``MAINNET_CHAIN_HASH`` — convenience constant used by the
  responder to know when an absent ``invreq_chain`` is OK.
* :func:`chain_hash_for` — lookup helper that raises on unknown
  network names.
* :func:`accepts_chain` — policy check used by the inbound
  responder and the outbound builder.

Hex values are sourced from each network's genesis block; see
``tests/unit/bolt12/test_chain_hash.py`` for verification against
known-good vectors.
"""

from __future__ import annotations

from typing import Final, Mapping

# Genesis-block SHA256d, in natural byte order (little-endian of the
# block's "block id"). These match LDK's ``ChainHash`` constants and
# lightning's ``BOLT 12`` test vectors.
MAINNET_CHAIN_HASH: Final[bytes] = bytes.fromhex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")
TESTNET_CHAIN_HASH: Final[bytes] = bytes.fromhex("43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000")
SIGNET_CHAIN_HASH: Final[bytes] = bytes.fromhex("f61eee3b63a380a477a063af32b2bbc97e9e0a825b5ddf80b40d6b4f2dc4e6e4")
REGTEST_CHAIN_HASH: Final[bytes] = bytes.fromhex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f")

CHAIN_HASHES: Final[Mapping[str, bytes]] = {
    "bitcoin": MAINNET_CHAIN_HASH,
    "mainnet": MAINNET_CHAIN_HASH,
    "testnet": TESTNET_CHAIN_HASH,
    "testnet3": TESTNET_CHAIN_HASH,
    "signet": SIGNET_CHAIN_HASH,
    "regtest": REGTEST_CHAIN_HASH,
}


def chain_hash_for(network: str) -> bytes:
    """Return the 32-byte chain hash for ``network``.

    ``network`` matches the values accepted by
    :attr:`app.core.config.Settings.bitcoin_network`. Unknown names
    raise :class:`ValueError`.
    """
    try:
        return CHAIN_HASHES[network.lower()]
    except KeyError as exc:
        raise ValueError(
            f"unsupported bitcoin_network={network!r}; expected one of {sorted(set(CHAIN_HASHES))}"
        ) from exc


def accepts_chain(*, our_network: str, invreq_chain: bytes | None, offer_chains: tuple[bytes, ...]) -> bool:
    """Policy check for inbound invreqs.

    Returns ``True`` iff:

    * ``invreq_chain`` (when present) matches our configured chain
      hash, **and**
    * ``offer_chains`` (when non-empty) includes our chain hash —
      an empty ``offer_chains`` tuple is shorthand for "mainnet
      only" per BOLT 12.

    Mainnet is treated as the default when ``invreq_chain`` is
    ``None`` (BOLT 12 §"Requirements"): "if the chain for the invoice
    is not solely bitcoin: MUST specify invreq_chain […] otherwise
    MUST NOT specify invreq_chain".
    """
    our_hash = chain_hash_for(our_network)
    if invreq_chain is None:
        # Implicit mainnet — only valid if we're on mainnet.
        if our_hash != MAINNET_CHAIN_HASH:
            return False
    else:
        if invreq_chain != our_hash:
            return False
    # Offer's chains constraint.
    if offer_chains:
        if our_hash not in offer_chains:
            return False
    elif our_hash != MAINNET_CHAIN_HASH:
        # Empty offer_chains == mainnet-only; reject if we aren't on
        # mainnet.
        return False
    return True


__all__ = [
    "CHAIN_HASHES",
    "MAINNET_CHAIN_HASH",
    "TESTNET_CHAIN_HASH",
    "SIGNET_CHAIN_HASH",
    "REGTEST_CHAIN_HASH",
    "accepts_chain",
    "chain_hash_for",
]
