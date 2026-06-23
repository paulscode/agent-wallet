# SPDX-License-Identifier: MIT
"""Liquid Confidential Transactions wrapper.

Wraps the ``wallycore`` (Blockstream libwally) CT primitives the
Liquid hop needs. Keeping the wrapper here means the rest of
the code never imports ``wallycore`` directly — type hints, input
validation, and any future migration to a different CT library all
live behind this surface.

What's exposed:

* SLIP-77 master blinding key derivation from a seed.
* Per-script blinding keypair derivation (the privkey signs CT
  proofs; the pubkey goes into the blinded output).
* Pedersen value commitments + asset generators (the on-wire CT
  commitment values).
* L-BTC asset-ID constants for mainnet + testnet (regtest is
  network-config-dependent and operator-supplied).

What's NOT yet exposed (lands as the higher-level layers grow):
rangeproof creation, surjection proof creation, output unblinding,
full tx serialisation. The library has all of these (verified via
the CT verification round); they're wrapped as their callers
land.
"""

from __future__ import annotations

import wallycore as _wally

# ── Sizes ───────────────────────────────────────────────────────────

MASTER_BLINDING_KEY_LEN: int = 64
"""SLIP-77 master blinding key — 64 bytes (32-byte key + 32-byte chain code)."""

SCRIPT_BLINDING_PRIVKEY_LEN: int = 32
SCRIPT_BLINDING_PUBKEY_LEN: int = 33
ASSET_ID_LEN: int = 32
BLINDING_FACTOR_LEN: int = 32  # ABF (asset) and VBF (value) blinding factors
ASSET_GENERATOR_LEN: int = 33
VALUE_COMMITMENT_LEN: int = 33


# ── Canonical L-BTC asset IDs (well-known network constants) ────────

LBTC_ASSET_ID_MAINNET: bytes = bytes.fromhex("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eef38364902")
LBTC_ASSET_ID_TESTNET: bytes = bytes.fromhex("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49")


class LiquidCTError(ValueError):
    """Raised on a recoverable CT-layer error (bad input length, etc.)."""


# ── SLIP-77 blinding keys ───────────────────────────────────────────


def derive_slip77_master_blinding_key(seed: bytes) -> bytes:
    """Derive the SLIP-77 master blinding key from ``seed``.

    ``seed`` is typically the 64-byte BIP-39 seed from the operator's
    dedicated ``ANONYMIZE_LIQUID_SEED_FERNET`` material. The returned
    64-byte master is passed to :func:`derive_script_blinding_privkey`
    + :func:`derive_script_blinding_pubkey` per output to obtain the
    actual blinding keypair.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise LiquidCTError("seed must be bytes")
    if len(seed) == 0:
        raise LiquidCTError("seed must be non-empty")
    out = bytes(_wally.asset_blinding_key_from_seed(bytes(seed)))
    if len(out) != MASTER_BLINDING_KEY_LEN:
        raise LiquidCTError(f"unexpected SLIP-77 master key length: {len(out)}")
    return out


def derive_script_blinding_privkey(
    master: bytes,
    script_pubkey: bytes,
) -> bytes:
    """Derive the 32-byte blinding privkey for ``script_pubkey``.

    SLIP-77 ties each blinding key to the recipient's scriptPubKey,
    so a single master blinding key produces a distinct key per
    output without revealing any cross-output linkage.
    """
    if len(master) != MASTER_BLINDING_KEY_LEN:
        raise LiquidCTError(f"master must be {MASTER_BLINDING_KEY_LEN} bytes; got {len(master)}")
    if not isinstance(script_pubkey, (bytes, bytearray)) or not script_pubkey:
        raise LiquidCTError("script_pubkey must be non-empty bytes")
    out = bytes(
        _wally.asset_blinding_key_to_ec_private_key(
            bytes(master),
            bytes(script_pubkey),
        )
    )
    if len(out) != SCRIPT_BLINDING_PRIVKEY_LEN:
        raise LiquidCTError(f"unexpected blinding privkey length: {len(out)}")
    return out


def derive_script_blinding_pubkey(
    master: bytes,
    script_pubkey: bytes,
) -> bytes:
    """Derive the 33-byte compressed blinding pubkey for ``script_pubkey``.

    Cross-derived from the privkey via libsecp256k1; result is the
    EC compressed-pubkey encoding (``0x02``/``0x03`` prefix + 32-byte
    x coordinate).
    """
    priv = derive_script_blinding_privkey(master, script_pubkey)
    out = bytes(_wally.ec_public_key_from_private_key(priv))
    if len(out) != SCRIPT_BLINDING_PUBKEY_LEN:
        raise LiquidCTError(f"unexpected blinding pubkey length: {len(out)}")
    return out


# ── Asset + value commitments ───────────────────────────────────────


def make_asset_generator(asset_id: bytes, abf: bytes) -> bytes:
    """Compute the asset generator (committed asset) for ``asset_id``.

    The 33-byte output is the Pedersen-commitment-style asset generator
    used to compute the value commitment. ``abf`` is the asset blinding
    factor (32 bytes of high-entropy randomness).
    """
    if len(asset_id) != ASSET_ID_LEN:
        raise LiquidCTError(f"asset_id must be {ASSET_ID_LEN} bytes; got {len(asset_id)}")
    if len(abf) != BLINDING_FACTOR_LEN:
        raise LiquidCTError(f"abf must be {BLINDING_FACTOR_LEN} bytes; got {len(abf)}")
    out = bytes(_wally.asset_generator_from_bytes(bytes(asset_id), bytes(abf)))
    if len(out) != ASSET_GENERATOR_LEN:
        raise LiquidCTError(f"unexpected asset generator length: {len(out)}")
    return out


def make_value_commitment(
    value_sat: int,
    vbf: bytes,
    generator: bytes,
) -> bytes:
    """Compute the Pedersen value commitment for ``value_sat``.

    The 33-byte output is what goes into the Elements/Liquid TxOut
    ``value`` field for a blinded output. ``vbf`` is the value
    blinding factor (32 bytes of high-entropy randomness);
    ``generator`` is the output of :func:`make_asset_generator`.
    """
    if not isinstance(value_sat, int) or value_sat < 0:
        raise LiquidCTError("value_sat must be a non-negative int")
    if len(vbf) != BLINDING_FACTOR_LEN:
        raise LiquidCTError(f"vbf must be {BLINDING_FACTOR_LEN} bytes; got {len(vbf)}")
    if len(generator) != ASSET_GENERATOR_LEN:
        raise LiquidCTError(f"generator must be {ASSET_GENERATOR_LEN} bytes; got {len(generator)}")
    out = bytes(
        _wally.asset_value_commitment(
            int(value_sat),
            bytes(vbf),
            bytes(generator),
        )
    )
    if len(out) != VALUE_COMMITMENT_LEN:
        raise LiquidCTError(f"unexpected value commitment length: {len(out)}")
    return out


# ── Asset-id lookup ─────────────────────────────────────────────────


def lbtc_asset_id_for_network(network: str) -> bytes:
    """Return the L-BTC asset ID for ``network``.

    ``network`` matches the wallet's ``BITCOIN_NETWORK`` settings:
    ``"bitcoin"``/``"mainnet"`` → mainnet, ``"testnet"`` → testnet.
    Regtest is operator-config-dependent — operators set
    ``ANONYMIZE_LIQUID_BTC_ASSET_ID`` explicitly in regtest
    deployments and this helper raises so the missing config is
    visible immediately.
    """
    n = (network or "").strip().lower()
    if n in ("bitcoin", "mainnet", "liquidv1"):
        return LBTC_ASSET_ID_MAINNET
    if n in ("testnet", "liquidv1t"):
        return LBTC_ASSET_ID_TESTNET
    raise LiquidCTError(
        f"L-BTC asset id for network {network!r} is not built-in — set ANONYMIZE_LIQUID_BTC_ASSET_ID explicitly"
    )


__all__ = [
    "ASSET_GENERATOR_LEN",
    "ASSET_ID_LEN",
    "BLINDING_FACTOR_LEN",
    "LBTC_ASSET_ID_MAINNET",
    "LBTC_ASSET_ID_TESTNET",
    "LiquidCTError",
    "MASTER_BLINDING_KEY_LEN",
    "SCRIPT_BLINDING_PRIVKEY_LEN",
    "SCRIPT_BLINDING_PUBKEY_LEN",
    "VALUE_COMMITMENT_LEN",
    "derive_script_blinding_privkey",
    "derive_script_blinding_pubkey",
    "derive_slip77_master_blinding_key",
    "lbtc_asset_id_for_network",
    "make_asset_generator",
    "make_value_commitment",
]
