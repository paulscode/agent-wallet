# SPDX-License-Identifier: MIT
"""BIP-32 + BIP-86 + BIP-340 decoy-output signer.

The on-chain self-source path treats decoy outputs as *receive-only*;
the runbook documents spending them via an external single-sig
signer. The strongest tier closes the in-process-spending path: this
module owns the key derivation + Schnorr signing primitives so the
dashboard's
spend-override flow can sign a PSBT-style sighash without leaving
the wallet process.

Layering:

* BIP-32 — pure-Python HMAC-SHA512 chain-code walk, with the EC
  scalar add and pubkey serialisation delegated to ``coincurve``
  (libsecp256k1 binding). Both hardened (index ≥ 2³¹) and non-
  hardened paths are supported.
* BIP-86 — single-key taproot tweak with empty merkle root: the
  tweak is the tagged hash ``SHA256_TapTweak(internal_pubkey_x)``,
  applied to the internal private key with the standard y-parity
  sign correction (BIP-340 even-y convention).
* BIP-340 — Schnorr signing of a 32-byte sighash; delegated to
  ``coincurve``'s ``sign_schnorr``.

The BIP-32 walking layer is straightforward but security-sensitive,
so the test suite anchors derivation against the well-known BIP-86
vector (m/86'/0'/0'/0/0 from the all-``abandon`` mnemonic seed) to
pin the implementation against the published reference.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Sequence

from coincurve import PrivateKey

# secp256k1 group order (BIP-32 / BIP-340).
_SECP256K1_ORDER: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# BIP-32 hardened-derivation offset.
HARDENED_OFFSET: int = 0x80000000


class DecoySignerError(RuntimeError):
    """Raised on a recoverable signer-layer error (e.g. bad seed)."""


def _ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")


def _ser256(i: int) -> bytes:
    return i.to_bytes(32, "big")


def _parse256(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _compressed_pubkey(priv32: bytes) -> bytes:
    return PrivateKey(priv32).public_key.format(compressed=True)


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged-hash construction.

    H_tag(x) = SHA256(SHA256(tag) || SHA256(tag) || x).
    """
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


# ── BIP-32 ──────────────────────────────────────────────────────────


def bip32_master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Derive the BIP-32 master (priv, chaincode) from a seed.

    ``seed`` is typically 32–64 bytes; BIP-39-derived seeds are 64
    bytes. The HMAC tag is the BIP-32-defined constant ``b"Bitcoin
    seed"``.
    """
    if not seed:
        raise DecoySignerError("BIP-32 seed must be non-empty")
    # I / IL / IR are the canonical BIP-32 spec names (HMAC-SHA512 output
    # split into left/right halves); kept verbatim for spec correspondence.
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()  # noqa: N806, E741
    IL, IR = I[:32], I[32:]  # noqa: N806
    if _parse256(IL) == 0 or _parse256(IL) >= _SECP256K1_ORDER:
        raise DecoySignerError("invalid master key derived from seed (negligible probability)")
    return IL, IR


def bip32_ckd_priv(
    parent_priv: bytes,
    parent_cc: bytes,
    index: int,
) -> tuple[bytes, bytes]:
    """One step of CKD-priv (BIP-32)."""
    if index < 0 or index >= 2**32:
        raise DecoySignerError(f"derivation index out of range: {index}")
    if index >= HARDENED_OFFSET:
        data = b"\x00" + parent_priv + _ser32(index)
    else:
        data = _compressed_pubkey(parent_priv) + _ser32(index)
    # BIP-32 spec names (see bip32_master_from_seed); kept verbatim.
    I = hmac.new(parent_cc, data, hashlib.sha512).digest()  # noqa: N806, E741
    IL, IR = I[:32], I[32:]  # noqa: N806
    IL_int = _parse256(IL)  # noqa: N806
    parent_int = _parse256(parent_priv)
    child_int = (IL_int + parent_int) % _SECP256K1_ORDER
    if IL_int >= _SECP256K1_ORDER or child_int == 0:
        # Per BIP-32: vanishingly unlikely; advance to the next index.
        return bip32_ckd_priv(parent_priv, parent_cc, index + 1)
    return _ser256(child_int), IR


def bip32_derive_path(
    seed: bytes,
    path: Sequence[int],
) -> tuple[bytes, bytes]:
    """Walk a path-component list from the seed; return (priv, cc)."""
    priv, cc = bip32_master_from_seed(seed)
    for index in path:
        priv, cc = bip32_ckd_priv(priv, cc, index)
    return priv, cc


def parse_bip32_path(path_str: str) -> list[int]:
    """Parse a BIP-32 path string like ``m/86'/0'/0'/0/0`` into the
    component-int list ``[86+2^31, 0+2^31, 0+2^31, 0, 0]``.

    Accepts both ``'`` and ``h`` as the hardened suffix. The leading
    ``m/`` (or bare ``m``) is optional.
    """
    s = path_str.strip()
    if s == "m" or s == "m/" or s == "":
        return []
    if s.startswith("m/"):
        s = s[2:]
    out: list[int] = []
    for comp in s.split("/"):
        comp = comp.strip()
        if not comp:
            continue
        if comp.endswith("'") or comp.endswith("h") or comp.endswith("H"):
            n = int(comp[:-1])
            if n < 0 or n >= HARDENED_OFFSET:
                raise DecoySignerError(f"hardened path component out of range: {comp}")
            out.append(n + HARDENED_OFFSET)
        else:
            n = int(comp)
            if n < 0 or n >= HARDENED_OFFSET:
                raise DecoySignerError(f"non-hardened path component out of range: {comp}")
            out.append(n)
    return out


# ── BIP-86 ──────────────────────────────────────────────────────────


def bip86_internal_pubkey_xonly(internal_priv32: bytes) -> bytes:
    """Return the 32-byte x-only internal pubkey for ``internal_priv32``."""
    pub = PrivateKey(internal_priv32).public_key.format(compressed=True)
    return pub[1:]


def bip86_tweaked_priv(internal_priv32: bytes) -> bytes:
    """BIP-86 single-key taproot tweak.

    Empty-merkle-root tweak: ``t = SHA256_TapTweak(P_x)`` where
    ``P_x`` is the x-only internal pubkey. The output private key is
    ``(d + t) mod n`` after applying the BIP-340 even-y sign
    correction to the internal key.
    """
    sk = PrivateKey(internal_priv32)
    pub = sk.public_key.format(compressed=True)
    is_odd_y = pub[0] == 0x03
    x_only = pub[1:]  # 32 bytes
    d = _parse256(internal_priv32)
    if is_odd_y:
        d = _SECP256K1_ORDER - d
    t = _parse256(_tagged_hash("TapTweak", x_only))
    if t >= _SECP256K1_ORDER:
        raise DecoySignerError("TapTweak exceeds curve order (negligible probability)")
    tweaked = (d + t) % _SECP256K1_ORDER
    if tweaked == 0:
        raise DecoySignerError("tweaked privkey is zero (negligible probability)")
    return _ser256(tweaked)


def bip86_output_pubkey_xonly(internal_priv32: bytes) -> bytes:
    """Return the 32-byte x-only output (tweaked) pubkey for BIP-86."""
    tweaked = bip86_tweaked_priv(internal_priv32)
    pub = PrivateKey(tweaked).public_key.format(compressed=True)
    return pub[1:]


# ── BIP-340 signing ─────────────────────────────────────────────────


def sign_taproot_keypath_sighash(
    *,
    tweaked_priv32: bytes,
    sighash32: bytes,
) -> bytes:
    """BIP-340 Schnorr-sign ``sighash32`` under the tweaked private key.

    The caller is responsible for computing the BIP-341 sighash; this
    helper only signs the 32-byte digest. Returns the 64-byte
    BIP-340 signature.
    """
    if len(sighash32) != 32:
        raise DecoySignerError("sighash must be 32 bytes")
    if len(tweaked_priv32) != 32:
        raise DecoySignerError("tweaked_priv must be 32 bytes")
    return PrivateKey(tweaked_priv32).sign_schnorr(sighash32)


def verify_taproot_keypath_sig(
    *,
    output_pub_xonly: bytes,
    sighash32: bytes,
    sig64: bytes,
) -> bool:
    """BIP-340 Schnorr verify (helper for the test layer / read-back).

    Returns False — never raises — on any verification failure.
    """
    if len(output_pub_xonly) != 32 or len(sig64) != 64 or len(sighash32) != 32:
        return False
    try:
        from coincurve.keys import PublicKeyXOnly

        pub = PublicKeyXOnly(output_pub_xonly)
        return bool(pub.verify(sig64, sighash32))
    except Exception:  # noqa: BLE001
        return False


# ── High-level: derive + tweak + sign in one call ───────────────────


def derive_decoy_signing_key(
    *,
    seed: bytes,
    path_components: Sequence[int],
) -> bytes:
    """Walk the path from the seed; apply the BIP-86 tweak; return the
    32-byte signing private key for a key-path P2TR spend."""
    internal_priv, _ = bip32_derive_path(seed, path_components)
    return bip86_tweaked_priv(internal_priv)


def derive_decoy_output_pubkey_xonly(
    *,
    seed: bytes,
    path_components: Sequence[int],
) -> bytes:
    """The 32-byte x-only output (tweaked) pubkey for a derivation path.

    This is what ends up in the P2TR scriptPubKey: ``OP_1 <32-byte-pubkey>``.
    """
    internal_priv, _ = bip32_derive_path(seed, path_components)
    return bip86_output_pubkey_xonly(internal_priv)


def sign_decoy_taproot_input(
    *,
    seed: bytes,
    path_components: Sequence[int],
    sighash32: bytes,
) -> bytes:
    """Top-level: derive the BIP-86 signing key + Schnorr-sign ``sighash32``.

    Used by the dashboard's decoy-spend flow once the override step-up
    nonce has verified and the audit event has been emitted. The
    caller is responsible for computing the BIP-341 sighash for the
    PSBT input being signed.
    """
    tweaked = derive_decoy_signing_key(
        seed=seed,
        path_components=path_components,
    )
    return sign_taproot_keypath_sighash(
        tweaked_priv32=tweaked,
        sighash32=sighash32,
    )


# ── BIP-341 sighash (SIGHASH_DEFAULT key-path spend) ────────────────


def _compact_size(n: int) -> bytes:
    """Bitcoin compact-size (varint) serialisation."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _parse_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """Read one compact-size; return ``(value, new_offset)``."""
    n = data[offset]
    if n < 0xFD:
        return n, offset + 1
    if n == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), offset + 3
    if n == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), offset + 5
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), offset + 9


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


@dataclass(frozen=True)
class SpentInput:
    """One spent input for BIP-341 sighash computation.

    ``prevout_txid`` is little-endian internal byte order (as it
    appears in the wire transaction — display order is reversed).
    """

    prevout_txid: bytes  # 32 bytes
    prevout_vout: int
    sequence: int
    amount_sat: int
    script_pubkey: bytes


@dataclass(frozen=True)
class TxOutput:
    """One transaction output for BIP-341 sighash computation."""

    amount_sat: int
    script_pubkey: bytes


def bip341_sighash_keypath(
    *,
    n_version: int,
    n_locktime: int,
    spent_inputs: Sequence[SpentInput],
    outputs: Sequence[TxOutput],
    input_index: int,
) -> bytes:
    """BIP-341 ``SIGHASH_DEFAULT`` key-path-spend sighash.

    Computes the 32-byte ``TapSighash`` for ``input_index`` of a
    taproot key-path spend with no annex, no tapscript, and the
    default sighash type. The output value is what
    :func:`sign_taproot_keypath_sighash` expects as input.

    See BIP-341 "Common signature message" for the exact byte layout.
    """
    if input_index < 0 or input_index >= len(spent_inputs):
        raise DecoySignerError(f"input_index {input_index} out of range for {len(spent_inputs)} inputs")
    if not spent_inputs:
        raise DecoySignerError("spent_inputs must be non-empty")

    # Precomputed input/output digests.
    sha_prevouts = _sha256(b"".join(i.prevout_txid + i.prevout_vout.to_bytes(4, "little") for i in spent_inputs))
    sha_amounts = _sha256(b"".join(i.amount_sat.to_bytes(8, "little") for i in spent_inputs))
    sha_scriptpubkeys = _sha256(b"".join(_compact_size(len(i.script_pubkey)) + i.script_pubkey for i in spent_inputs))
    sha_sequences = _sha256(b"".join(i.sequence.to_bytes(4, "little") for i in spent_inputs))
    sha_outputs = _sha256(
        b"".join(
            o.amount_sat.to_bytes(8, "little") + _compact_size(len(o.script_pubkey)) + o.script_pubkey for o in outputs
        )
    )

    # SIGHASH_DEFAULT key-path-spend, no annex, no tapscript.
    epoch = 0x00
    hash_type = 0x00  # SIGHASH_DEFAULT
    spend_type = 0x00  # ext_flag=0, no annex

    sig_msg = (
        bytes([epoch])
        + bytes([hash_type])
        + n_version.to_bytes(4, "little")
        + n_locktime.to_bytes(4, "little")
        + sha_prevouts
        + sha_amounts
        + sha_scriptpubkeys
        + sha_sequences
        + sha_outputs
        + bytes([spend_type])
        + input_index.to_bytes(4, "little")
    )
    return _tagged_hash("TapSighash", sig_msg)


def parse_unsigned_tx(
    raw_hex: str,
) -> tuple[int, list[tuple[bytes, int, int]], list[TxOutput], int]:
    """Minimal unsigned-tx parser for the BIP-341 sighash test surface.

    Returns ``(n_version, inputs, outputs, n_locktime)`` where each
    input is ``(prevout_txid, prevout_vout, sequence)``. Witness data
    is not parsed (unsigned txs have no witness section). The caller
    pairs each input with its spent ``utxo`` (amount + scriptPubKey)
    to build :class:`SpentInput` instances.
    """
    data = bytes.fromhex(raw_hex)
    o = 0
    n_version = int.from_bytes(data[o : o + 4], "little")
    o += 4
    n_inputs, o = _parse_compact_size(data, o)
    inputs: list[tuple[bytes, int, int]] = []
    for _ in range(n_inputs):
        prevout_txid = data[o : o + 32]
        o += 32
        prevout_vout = int.from_bytes(data[o : o + 4], "little")
        o += 4
        script_len, o = _parse_compact_size(data, o)
        o += script_len  # scriptSig is empty on a taproot unsigned tx
        sequence = int.from_bytes(data[o : o + 4], "little")
        o += 4
        inputs.append((prevout_txid, prevout_vout, sequence))
    n_outputs, o = _parse_compact_size(data, o)
    outputs: list[TxOutput] = []
    for _ in range(n_outputs):
        amount = int.from_bytes(data[o : o + 8], "little")
        o += 8
        script_len, o = _parse_compact_size(data, o)
        script = data[o : o + script_len]
        o += script_len
        outputs.append(TxOutput(amount_sat=amount, script_pubkey=script))
    n_locktime = int.from_bytes(data[o : o + 4], "little")
    o += 4
    return n_version, inputs, outputs, n_locktime


__all__ = [
    "HARDENED_OFFSET",
    "DecoySignerError",
    "SpentInput",
    "TxOutput",
    "bip341_sighash_keypath",
    "parse_unsigned_tx",
    "bip32_ckd_priv",
    "bip32_derive_path",
    "bip32_master_from_seed",
    "bip86_internal_pubkey_xonly",
    "bip86_output_pubkey_xonly",
    "bip86_tweaked_priv",
    "derive_decoy_output_pubkey_xonly",
    "derive_decoy_signing_key",
    "parse_bip32_path",
    "sign_decoy_taproot_input",
    "sign_taproot_keypath_sighash",
    "verify_taproot_keypath_sig",
]
