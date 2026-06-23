# SPDX-License-Identifier: MIT
"""Taproot key-path spend transaction builder.

The dashboard's in-process decoy-spend flow composes against three
layers:

1. The cryptographic primitives in :mod:`decoy_signer` — BIP-32
   derivation, BIP-86 taproot tweak, BIP-340 Schnorr signing,
   BIP-341 SIGHASH_DEFAULT key-path sighash.
2. This module — assembles N taproot inputs + N outputs into an
   unsigned tx, computes the per-input BIP-341 sighash, signs each
   with the corresponding derived key, and serialises the final
   witness-bearing transaction.
3. The dashboard endpoint (separate concern) — wires the coin
   selector + the step-up verify flow + the audit event emitter
   to this layer.

The serialiser produces a standard witness transaction wire format
(BIP-141) suitable for direct broadcast via the chain backend; the
witness stack for a SIGHASH_DEFAULT key-path spend is exactly one
item, the 64-byte BIP-340 signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .decoy_signer import (
    DecoySignerError,
    SpentInput,
    TxOutput,
    bip341_sighash_keypath,
    derive_decoy_signing_key,
    sign_taproot_keypath_sighash,
)


@dataclass(frozen=True)
class TaprootSpendInput:
    """A taproot key-path input to spend.

    Carries the spent-UTXO data (prevout, amount, scriptPubKey,
    sequence) plus the BIP-32 derivation path that produces the
    signing key. ``sequence`` defaults to the standard 0xFFFFFFFF
    (no RBF, no relative timelock).
    """

    prevout_txid: bytes  # 32 bytes
    prevout_vout: int
    amount_sat: int
    script_pubkey: bytes
    derivation_path: tuple[int, ...]
    sequence: int = 0xFFFFFFFF

    def to_spent_input(self) -> SpentInput:
        return SpentInput(
            prevout_txid=self.prevout_txid,
            prevout_vout=self.prevout_vout,
            sequence=self.sequence,
            amount_sat=self.amount_sat,
            script_pubkey=self.script_pubkey,
        )


@dataclass(frozen=True)
class TaprootSpendPlan:
    """A complete N-input N-output P2TR key-path spend specification."""

    inputs: Sequence[TaprootSpendInput]
    outputs: Sequence[TxOutput]
    n_version: int = 2
    n_locktime: int = 0


# ── Serialisation helpers ───────────────────────────────────────────


def _compact_size(n: int) -> bytes:
    """Bitcoin compact-size (varint) serialisation."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _serialize_input_legacy(inp: TaprootSpendInput) -> bytes:
    """Serialise a single input in non-witness form (script_sig is
    always empty for key-path P2TR)."""
    return (
        inp.prevout_txid
        + inp.prevout_vout.to_bytes(4, "little")
        + b"\x00"  # empty scriptSig
        + inp.sequence.to_bytes(4, "little")
    )


def _serialize_output(out: TxOutput) -> bytes:
    return out.amount_sat.to_bytes(8, "little") + _compact_size(len(out.script_pubkey)) + out.script_pubkey


def serialize_unsigned_tx(plan: TaprootSpendPlan) -> bytes:
    """Serialise the spend plan as an unsigned (non-witness) transaction.

    Suitable for hashing into a txid or for the BIP-341 sighash
    helper's tx-parse cross-check.
    """
    if not plan.inputs:
        raise DecoySignerError("plan must have at least one input")
    parts = [
        plan.n_version.to_bytes(4, "little"),
        _compact_size(len(plan.inputs)),
    ]
    for inp in plan.inputs:
        parts.append(_serialize_input_legacy(inp))
    parts.append(_compact_size(len(plan.outputs)))
    for out in plan.outputs:
        parts.append(_serialize_output(out))
    parts.append(plan.n_locktime.to_bytes(4, "little"))
    return b"".join(parts)


def serialize_witness_tx(
    plan: TaprootSpendPlan,
    signatures: Sequence[bytes],
) -> bytes:
    """Serialise the final signed witness transaction (BIP-141).

    ``signatures`` must have one 64-byte BIP-340 signature per input,
    in input order. The witness stack for each input is a single
    item (the signature) — that's the SIGHASH_DEFAULT key-path
    encoding.
    """
    if len(signatures) != len(plan.inputs):
        raise DecoySignerError(f"signatures length {len(signatures)} != inputs length {len(plan.inputs)}")
    for i, sig in enumerate(signatures):
        if len(sig) != 64:
            raise DecoySignerError(f"signature #{i} is {len(sig)} bytes; expected 64")

    parts = [
        plan.n_version.to_bytes(4, "little"),
        b"\x00\x01",  # marker + flag (BIP-141)
        _compact_size(len(plan.inputs)),
    ]
    for inp in plan.inputs:
        parts.append(_serialize_input_legacy(inp))
    parts.append(_compact_size(len(plan.outputs)))
    for out in plan.outputs:
        parts.append(_serialize_output(out))
    # Witness section — one stack per input.
    for sig in signatures:
        parts.append(_compact_size(1))  # 1 stack item
        parts.append(_compact_size(64))  # item length 64
        parts.append(sig)
    parts.append(plan.n_locktime.to_bytes(4, "little"))
    return b"".join(parts)


# ── Signing ─────────────────────────────────────────────────────────


def sign_taproot_spend_plan(
    plan: TaprootSpendPlan,
    *,
    seed: bytes,
) -> list[bytes]:
    """Compute the BIP-341 sighash for each input + sign under the
    BIP-32 / BIP-86 derived key for that input.

    Returns the list of 64-byte BIP-340 signatures, in input order.
    """
    if not plan.inputs:
        raise DecoySignerError("plan must have at least one input")
    spent = [inp.to_spent_input() for inp in plan.inputs]
    signatures: list[bytes] = []
    for i, inp in enumerate(plan.inputs):
        sighash = bip341_sighash_keypath(
            n_version=plan.n_version,
            n_locktime=plan.n_locktime,
            spent_inputs=spent,
            outputs=plan.outputs,
            input_index=i,
        )
        signing_key = derive_decoy_signing_key(
            seed=seed,
            path_components=list(inp.derivation_path),
        )
        sig = sign_taproot_keypath_sighash(
            tweaked_priv32=signing_key,
            sighash32=sighash,
        )
        signatures.append(sig)
    return signatures


def build_signed_taproot_keypath_tx(
    plan: TaprootSpendPlan,
    *,
    seed: bytes,
) -> bytes:
    """Top-level: sign every input + serialise the witness tx.

    Returns the BIP-141 wire-format bytes ready for chain-backend
    broadcast.
    """
    signatures = sign_taproot_spend_plan(plan, seed=seed)
    return serialize_witness_tx(plan, signatures)


# ── Fee + sizing helpers ────────────────────────────────────────────


# BIP-141 wtxid weight units. A single 64-byte witness stack item
# (length prefix + bytes) costs: 1 byte stack count + 1 byte length
# + 64 bytes data = 66 bytes of *witness* (weight 66, not 66*4).
_WITNESS_BYTES_PER_INPUT = 1 + 1 + 64


def estimate_vbytes(plan: TaprootSpendPlan) -> int:
    """Rough vbyte estimate for fee-rate × size budgeting.

    Computes ``ceil((base_size * 4 + witness_size) / 4)`` per BIP-141.
    ``base_size`` excludes the witness; ``witness_size`` is the
    marker + flag + per-input witness stacks. Suitable for
    operator-side fee planning; the exact size emerges after
    serialisation.
    """
    if not plan.inputs:
        raise DecoySignerError("plan must have at least one input")
    base = (
        4  # nVersion
        + len(_compact_size(len(plan.inputs)))
        + sum(len(_serialize_input_legacy(i)) for i in plan.inputs)
        + len(_compact_size(len(plan.outputs)))
        + sum(len(_serialize_output(o)) for o in plan.outputs)
        + 4  # nLocktime
    )
    witness = (
        2  # marker + flag
        + _WITNESS_BYTES_PER_INPUT * len(plan.inputs)
    )
    weight = base * 4 + witness
    return (weight + 3) // 4


__all__ = [
    "TaprootSpendInput",
    "TaprootSpendPlan",
    "build_signed_taproot_keypath_tx",
    "estimate_vbytes",
    "serialize_unsigned_tx",
    "serialize_witness_tx",
    "sign_taproot_spend_plan",
]
