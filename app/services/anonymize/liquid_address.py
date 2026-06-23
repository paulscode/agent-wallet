# SPDX-License-Identifier: MIT
"""Liquid address parsing — bech32 (unconfidential) + blech32 (confidential).

Liquid segwit addresses come in two flavours:

* **Unconfidential bech32 / bech32m** — `ex1...` mainnet, `tex1...`
  testnet, `ert1...` regtest. Encodes the scriptPubKey directly,
  exactly like Bitcoin's `bc1...` but with Liquid HRPs. Witness v0
  uses bech32; v1 (taproot) uses bech32m.
* **Confidential blech32** — `lq1...` mainnet, `tlq1...` testnet,
  `el1...` regtest. Encodes both the scriptPubKey AND a 33-byte
  blinding pubkey the sender uses to construct the CT commitment
  for that output.

Boltz chain swaps use confidential addresses for the Liquid-side
credit so amounts are CT-blinded from issuance. This module is the
wallet's entry point for parsing those addresses and building new
ones from a derived blinding key.

The underlying encode/decode is delegated to wallycore; this layer
adds network auto-detection, type-hinted return shapes, and input
validation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import cast

import wallycore as _wally


class LiquidNetwork(str, enum.Enum):
    """Liquid networks the wallet understands."""

    MAINNET = "mainnet"  # liquidv1
    TESTNET = "testnet"  # liquidv1t
    REGTEST = "regtest"  # elementsregtest


@dataclass(frozen=True)
class _HrpPair:
    """Per-network (segwit_hrp, confidential_hrp) tuple."""

    segwit: str
    confidential: str


# Liquid HRPs by network — well-known constants.
_HRPS: dict[LiquidNetwork, _HrpPair] = {
    LiquidNetwork.MAINNET: _HrpPair(segwit="ex", confidential="lq"),
    LiquidNetwork.TESTNET: _HrpPair(segwit="tex", confidential="tlq"),
    LiquidNetwork.REGTEST: _HrpPair(segwit="ert", confidential="el"),
}


BLINDING_PUBKEY_LEN: int = 33


class LiquidAddressError(ValueError):
    """Raised when a Liquid address fails to parse or build."""


@dataclass(frozen=True)
class LiquidAddressInfo:
    """Parsed Liquid address.

    ``script_pubkey`` is the *unconfidential* scriptPubKey (the bytes
    that go into a Liquid TxOut's script field). ``blinding_pubkey``
    is the 33-byte compressed EC pubkey from a confidential address,
    or ``None`` when the address is unconfidential.
    """

    network: LiquidNetwork
    script_pubkey: bytes
    blinding_pubkey: bytes | None

    @property
    def is_confidential(self) -> bool:
        return self.blinding_pubkey is not None


# ── Decode ──────────────────────────────────────────────────────────


def _try_decode_segwit(addr: str, hrp: str) -> bytes | None:
    """Attempt to decode an unconfidential segwit address under ``hrp``.

    Returns the script bytes on success, ``None`` if the HRP doesn't
    match. Other failures propagate as :class:`LiquidAddressError`.
    """
    if not addr.startswith(hrp + "1"):
        return None
    try:
        return bytes(_wally.addr_segwit_to_bytes(addr, hrp, 0))
    except Exception as exc:  # noqa: BLE001 — wallycore raises a variety
        raise LiquidAddressError(f"address looks like {hrp!r} segwit but fails decode: {exc}") from exc


def _try_decode_confidential(
    addr: str,
    confidential_hrp: str,
    segwit_hrp: str,
) -> tuple[bytes, bytes] | None:
    """Attempt to decode a confidential segwit address.

    Returns ``(script_pubkey, blinding_pubkey)`` on success or
    ``None`` if the HRP doesn't match. Other failures raise.
    """
    if not addr.startswith(confidential_hrp + "1"):
        return None
    try:
        unconf = _wally.confidential_addr_to_addr_segwit(
            addr,
            confidential_hrp,
            segwit_hrp,
        )
        script = bytes(_wally.addr_segwit_to_bytes(unconf, segwit_hrp, 0))
        pubkey = bytes(
            _wally.confidential_addr_segwit_to_ec_public_key(
                addr,
                confidential_hrp,
            )
        )
    except Exception as exc:  # noqa: BLE001
        raise LiquidAddressError(
            f"address looks like {confidential_hrp!r} confidential but fails decode: {exc}"
        ) from exc
    if len(pubkey) != BLINDING_PUBKEY_LEN:
        raise LiquidAddressError(f"decoded blinding pubkey is {len(pubkey)} bytes; expected {BLINDING_PUBKEY_LEN}")
    return script, pubkey


def parse_liquid_address(addr: str) -> LiquidAddressInfo:
    """Parse a Liquid address (any network, confidential or not).

    Auto-detects the network from the HRP. Raises
    :class:`LiquidAddressError` for non-Liquid addresses (e.g.,
    Bitcoin ``bc1...``) or malformed Liquid addresses.
    """
    if not isinstance(addr, str) or not addr:
        raise LiquidAddressError("address must be a non-empty string")
    a = addr.strip().lower()

    # Try confidential first — its HRP is more specific.
    for network, hrps in _HRPS.items():
        out = _try_decode_confidential(a, hrps.confidential, hrps.segwit)
        if out is not None:
            script, pubkey = out
            return LiquidAddressInfo(
                network=network,
                script_pubkey=script,
                blinding_pubkey=pubkey,
            )

    # Then unconfidential segwit.
    for network, hrps in _HRPS.items():
        seg_script = _try_decode_segwit(a, hrps.segwit)
        if seg_script is not None:
            return LiquidAddressInfo(
                network=network,
                script_pubkey=seg_script,
                blinding_pubkey=None,
            )

    raise LiquidAddressError(f"address {addr!r} doesn't match any known Liquid HRP")


# ── Encode ──────────────────────────────────────────────────────────


def encode_unconfidential_segwit(
    script_pubkey: bytes,
    *,
    network: LiquidNetwork,
) -> str:
    """Encode a scriptPubKey as a Liquid unconfidential bech32 address.

    Witness v0 → bech32; v1 (taproot) → bech32m. Handled internally
    by wallycore based on the script's witness-version byte.
    """
    if not isinstance(script_pubkey, (bytes, bytearray)) or not script_pubkey:
        raise LiquidAddressError("script_pubkey must be non-empty bytes")
    hrps = _HRPS[network]
    try:
        # wallycore is untyped → returns Any; the wally API returns str.
        return cast(str, _wally.addr_segwit_from_bytes(bytes(script_pubkey), hrps.segwit, 0))
    except Exception as exc:  # noqa: BLE001
        raise LiquidAddressError(f"failed to encode segwit address on {network.value}: {exc}") from exc


def encode_confidential_segwit(
    script_pubkey: bytes,
    blinding_pubkey: bytes,
    *,
    network: LiquidNetwork,
) -> str:
    """Encode a scriptPubKey + blinding pubkey as a Liquid confidential
    address.

    ``blinding_pubkey`` must be a 33-byte compressed EC pubkey
    (typically produced by
    :func:`liquid_ct.derive_script_blinding_pubkey`).
    """
    if len(blinding_pubkey) != BLINDING_PUBKEY_LEN:
        raise LiquidAddressError(f"blinding_pubkey must be {BLINDING_PUBKEY_LEN} bytes; got {len(blinding_pubkey)}")
    unconf = encode_unconfidential_segwit(script_pubkey, network=network)
    hrps = _HRPS[network]
    try:
        # wallycore is untyped → returns Any; the wally API returns str.
        return cast(
            str,
            _wally.confidential_addr_from_addr_segwit(
                unconf,
                hrps.segwit,
                hrps.confidential,
                bytes(blinding_pubkey),
            ),
        )
    except Exception as exc:  # noqa: BLE001
        raise LiquidAddressError(f"failed to encode confidential address on {network.value}: {exc}") from exc


# ── Helpers ─────────────────────────────────────────────────────────


def is_liquid_address(addr: str) -> bool:
    """Cheap predicate — True iff ``addr`` parses as any Liquid form."""
    try:
        parse_liquid_address(addr)
        return True
    except LiquidAddressError:
        return False


def hrps_for_network(network: LiquidNetwork) -> tuple[str, str]:
    """Return ``(segwit_hrp, confidential_hrp)`` for ``network``."""
    hrps = _HRPS[network]
    return hrps.segwit, hrps.confidential


__all__ = [
    "BLINDING_PUBKEY_LEN",
    "LiquidAddressError",
    "LiquidAddressInfo",
    "LiquidNetwork",
    "encode_confidential_segwit",
    "encode_unconfidential_segwit",
    "hrps_for_network",
    "is_liquid_address",
    "parse_liquid_address",
]
