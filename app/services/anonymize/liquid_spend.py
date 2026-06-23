# SPDX-License-Identifier: MIT
"""Liquid CT spend-output construction.

Given the (unblinded) Liquid inputs we control + a list of output
specs (cleartext value + asset + destination blinding pubkey +
scriptPubKey), this module produces the on-wire blinded outputs:

* Per-output asset blinding factor (ABF) + value blinding factor
  (VBF).
* Pedersen asset generator (committed asset).
* Pedersen value commitment.
* ECDH nonce commitment (sender's ephemeral compressed pubkey).
* Rangeproof + surjection proof.

The **balance invariant** is enforced: the sum of input blinding
factors equals the sum of output blinding factors (mod the curve
order). The last output's VBF is computed via
:func:`wallycore.asset_final_vbf` to satisfy this; the rest are
random. Without this, the produced tx would fail Liquid consensus
validation (the federation's CT-balance check).

This module produces the per-output **CT material**. Transaction
assembly — picking the Liquid tx wire format, the sighash, the
signing scheme (MuSig2 cooperative for Boltz chain swaps, single-sig
for direct spends) — is the next layer up and lands alongside the
hop body that composes against this primitive.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Optional, Sequence

import wallycore as _wally

from .liquid_ct import (
    ASSET_GENERATOR_LEN,
    ASSET_ID_LEN,
    BLINDING_FACTOR_LEN,
    SCRIPT_BLINDING_PUBKEY_LEN,
)


class LiquidSpendError(RuntimeError):
    """Raised on a recoverable spend-construction failure."""


# ── Value objects ──────────────────────────────────────────────────


@dataclass(frozen=True)
class InputBlindingFactors:
    """One unblinded input we're spending from.

    These are the cleartext fields recovered by the receive path
    (:class:`liquid_receive.UnblindedUtxo`), repackaged in the shape
    the balancing computation needs.
    """

    value_sat: int
    asset_id: bytes  # 32 bytes
    abf: bytes  # 32 bytes
    vbf: bytes  # 32 bytes
    asset_generator: bytes  # 33 bytes (built from asset + abf)


@dataclass(frozen=True)
class OutputBlindingSpec:
    """One output we want to produce.

    ``destination_blinding_pubkey`` is the recipient's 33-byte
    blinding pubkey (extracted from a confidential address or
    derived from a known recipient's master blinding key + the
    output's scriptPubKey).
    """

    value_sat: int
    asset_id: bytes  # 32 bytes
    destination_blinding_pubkey: bytes  # 33 bytes
    script_pubkey: bytes  # the output's scriptPubKey


@dataclass(frozen=True)
class LiquidOutputBlindingMaterial:
    """The on-wire CT material for one blinded output.

    These five bytes-fields are exactly what an Elements/Liquid
    transaction serializer drops into the output struct (the
    surjection proof goes into the per-output proof section
    alongside the rangeproof).
    """

    script_pubkey: bytes
    asset_generator: bytes  # 33 bytes
    value_commitment: bytes  # 33 bytes
    nonce_commitment: bytes  # 33 bytes (sender ephemeral pubkey)
    rangeproof: bytes
    surjection_proof: bytes
    # Useful for downstream verification + change tracking.
    cleartext_value_sat: int
    cleartext_asset_id: bytes
    asset_blinding_factor: bytes  # 32 bytes
    value_blinding_factor: bytes  # 32 bytes


# ── Balance helper ─────────────────────────────────────────────────


def compute_balancing_vbf(
    *,
    input_values: Sequence[int],
    output_values: Sequence[int],
    abfs_concat: bytes,
    prior_vbfs_concat: bytes,
) -> bytes:
    """Compute the final output VBF that balances the CT commitments.

    Wraps :func:`wallycore.asset_final_vbf`:

    * ``abfs_concat`` is the per-entry concatenation of ABFs in
      order: every input ABF + every output ABF, 32 bytes each.
    * ``prior_vbfs_concat`` is the per-entry concatenation of every
      VBF the function does NOT compute — every input VBF + every
      output VBF except the last one. The function computes the
      LAST output VBF.

    The returned 32-byte VBF goes into the value commitment for the
    last output so the per-asset sum of inputs equals the per-asset
    sum of outputs (modulo the curve order).
    """
    n_in = len(input_values)
    n_out = len(output_values)
    if n_in <= 0:
        raise LiquidSpendError("must have at least one input")
    if n_out <= 0:
        raise LiquidSpendError("must have at least one output")
    expected_abfs_len = (n_in + n_out) * BLINDING_FACTOR_LEN
    if len(abfs_concat) != expected_abfs_len:
        raise LiquidSpendError(f"abfs_concat must be {expected_abfs_len} bytes; got {len(abfs_concat)}")
    expected_prior_len = (n_in + n_out - 1) * BLINDING_FACTOR_LEN
    if len(prior_vbfs_concat) != expected_prior_len:
        raise LiquidSpendError(f"prior_vbfs_concat must be {expected_prior_len} bytes; got {len(prior_vbfs_concat)}")
    all_values = list(input_values) + list(output_values)
    try:
        out = _wally.asset_final_vbf(
            all_values,
            n_in,
            bytes(abfs_concat),
            bytes(prior_vbfs_concat),
        )
    except (ValueError, Exception) as exc:  # noqa: BLE001
        raise LiquidSpendError(f"asset_final_vbf failed: {exc}") from exc
    out_b = bytes(out)
    if len(out_b) != BLINDING_FACTOR_LEN:
        raise LiquidSpendError(f"final VBF is {len(out_b)} bytes; expected {BLINDING_FACTOR_LEN}")
    return out_b


# ── Surjection proof ───────────────────────────────────────────────


def make_asset_surjection_proof(
    *,
    output_asset_id: bytes,
    output_abf: bytes,
    output_generator: bytes,
    input_assets_concat: bytes,
    input_abfs_concat: bytes,
    input_generators_concat: bytes,
    entropy: Optional[bytes] = None,
) -> bytes:
    """Build the asset surjection proof for one output.

    Proves the output's asset commitment is the same as one of the
    inputs' asset commitments — without revealing which input. Each
    input contributes (asset_id, abf, generator); the proof binds
    the output_abf to the input set.

    ``entropy`` is 32 bytes of randomness; auto-generated if omitted.
    """
    if len(output_asset_id) != ASSET_ID_LEN:
        raise LiquidSpendError(f"output_asset_id must be {ASSET_ID_LEN} bytes")
    if len(output_abf) != BLINDING_FACTOR_LEN:
        raise LiquidSpendError(f"output_abf must be {BLINDING_FACTOR_LEN} bytes")
    if len(output_generator) != ASSET_GENERATOR_LEN:
        raise LiquidSpendError(f"output_generator must be {ASSET_GENERATOR_LEN} bytes")
    n_inputs = len(input_assets_concat) // ASSET_ID_LEN
    if n_inputs == 0 or len(input_assets_concat) != n_inputs * ASSET_ID_LEN:
        raise LiquidSpendError(f"input_assets_concat must be a positive multiple of {ASSET_ID_LEN}")
    if len(input_abfs_concat) != n_inputs * BLINDING_FACTOR_LEN:
        raise LiquidSpendError(f"input_abfs_concat must be {n_inputs * BLINDING_FACTOR_LEN} bytes")
    if len(input_generators_concat) != n_inputs * ASSET_GENERATOR_LEN:
        raise LiquidSpendError(f"input_generators_concat must be {n_inputs * ASSET_GENERATOR_LEN} bytes")
    ent = entropy if entropy is not None else secrets.token_bytes(32)
    if len(ent) != 32:
        raise LiquidSpendError("entropy must be 32 bytes")
    try:
        out = _wally.asset_surjectionproof(
            bytes(output_asset_id),
            bytes(output_abf),
            bytes(output_generator),
            bytes(ent),
            bytes(input_assets_concat),
            bytes(input_abfs_concat),
            bytes(input_generators_concat),
        )
    except (ValueError, Exception) as exc:  # noqa: BLE001
        raise LiquidSpendError(f"asset_surjectionproof failed: {exc}") from exc
    return bytes(out)


# ── Orchestrator ───────────────────────────────────────────────────


def blind_spend_outputs(
    *,
    inputs: Sequence[InputBlindingFactors],
    outputs: Sequence[OutputBlindingSpec],
    rng: Optional[secrets.SystemRandom] = None,
) -> list[LiquidOutputBlindingMaterial]:
    """Produce blinded CT material for every output of a Liquid spend.

    For each output:

    * Picks a fresh ABF.
    * For every output except the last: picks a fresh VBF.
    * For the last output: computes the balancing VBF via
      :func:`compute_balancing_vbf`.
    * Builds the Pedersen asset generator + value commitment.
    * Picks a fresh sender ephemeral keypair and computes the
      rangeproof.
    * Builds the surjection proof.

    Returns the list of :class:`LiquidOutputBlindingMaterial`, one
    per output, in input order. Each carries the cleartext
    (value, asset_id, abf, vbf) alongside the on-wire commitments so
    downstream verification + change tracking has the full state.

    The function does NOT verify that the sums balance — the
    balancing VBF formula is correct by construction. Higher layers
    that want defense in depth can roundtrip via the receive path.
    """
    if not inputs:
        raise LiquidSpendError("must have at least one input")
    if not outputs:
        raise LiquidSpendError("must have at least one output")
    rng = rng or secrets.SystemRandom()

    # Per-input length validation (defense in depth).
    for i, inp in enumerate(inputs):
        if len(inp.asset_id) != ASSET_ID_LEN:
            raise LiquidSpendError(f"input #{i}: asset_id must be 32 bytes")
        if len(inp.abf) != BLINDING_FACTOR_LEN:
            raise LiquidSpendError(f"input #{i}: abf must be 32 bytes")
        if len(inp.vbf) != BLINDING_FACTOR_LEN:
            raise LiquidSpendError(f"input #{i}: vbf must be 32 bytes")
        if len(inp.asset_generator) != ASSET_GENERATOR_LEN:
            raise LiquidSpendError(f"input #{i}: asset_generator must be 33 bytes")

    for i, out in enumerate(outputs):
        if out.value_sat < 0:
            raise LiquidSpendError(f"output #{i}: value_sat must be non-negative")
        if len(out.asset_id) != ASSET_ID_LEN:
            raise LiquidSpendError(f"output #{i}: asset_id must be 32 bytes")
        if len(out.destination_blinding_pubkey) != SCRIPT_BLINDING_PUBKEY_LEN:
            raise LiquidSpendError(f"output #{i}: destination_blinding_pubkey must be 33 bytes")
        if not out.script_pubkey:
            raise LiquidSpendError(f"output #{i}: script_pubkey must be non-empty")

    # Pick output ABFs and pre-build output asset generators (the
    # surjection proof needs the generator, and ``asset_final_vbf``
    # needs every ABF in order to compute the balance).
    output_abfs: list[bytes] = []
    output_generators: list[bytes] = []
    for out in outputs:
        abf = rng.randbytes(BLINDING_FACTOR_LEN)
        gen = bytes(
            _wally.asset_generator_from_bytes(
                bytes(out.asset_id),
                abf,
            )
        )
        output_abfs.append(abf)
        output_generators.append(gen)

    # Pick VBFs for every output except the last; the last is
    # computed for balance.
    output_vbfs: list[bytes] = [rng.randbytes(BLINDING_FACTOR_LEN) for _ in range(len(outputs) - 1)]
    final_vbf = compute_balancing_vbf(
        input_values=[i.value_sat for i in inputs],
        output_values=[o.value_sat for o in outputs],
        abfs_concat=b"".join(i.abf for i in inputs) + b"".join(output_abfs),
        prior_vbfs_concat=(b"".join(i.vbf for i in inputs) + b"".join(output_vbfs)),
    )
    output_vbfs.append(final_vbf)

    # Pre-build the concat blobs the surjection proof needs.
    inp_assets = b"".join(i.asset_id for i in inputs)
    inp_abfs = b"".join(i.abf for i in inputs)
    inp_gens = b"".join(i.asset_generator for i in inputs)

    materials: list[LiquidOutputBlindingMaterial] = []
    for i, out in enumerate(outputs):
        abf = output_abfs[i]
        vbf = output_vbfs[i]
        gen = output_generators[i]
        value_comm = bytes(
            _wally.asset_value_commitment(
                int(out.value_sat),
                vbf,
                gen,
            )
        )
        sender_ephem_priv = rng.randbytes(32)
        sender_ephem_pub = bytes(
            _wally.ec_public_key_from_private_key(
                sender_ephem_priv,
            )
        )
        try:
            rangeproof = bytes(
                _wally.asset_rangeproof(
                    int(out.value_sat),
                    bytes(out.destination_blinding_pubkey),
                    sender_ephem_priv,
                    bytes(out.asset_id),
                    abf,
                    vbf,
                    value_comm,
                    bytes(out.script_pubkey),
                    gen,
                    1,
                    0,
                    36,
                )
            )
        except (ValueError, Exception) as exc:  # noqa: BLE001
            raise LiquidSpendError(f"output #{i}: rangeproof construction failed: {exc}") from exc
        surj = make_asset_surjection_proof(
            output_asset_id=out.asset_id,
            output_abf=abf,
            output_generator=gen,
            input_assets_concat=inp_assets,
            input_abfs_concat=inp_abfs,
            input_generators_concat=inp_gens,
        )
        materials.append(
            LiquidOutputBlindingMaterial(
                script_pubkey=out.script_pubkey,
                asset_generator=gen,
                value_commitment=value_comm,
                nonce_commitment=sender_ephem_pub,
                rangeproof=rangeproof,
                surjection_proof=surj,
                cleartext_value_sat=int(out.value_sat),
                cleartext_asset_id=bytes(out.asset_id),
                asset_blinding_factor=abf,
                value_blinding_factor=vbf,
            )
        )
    return materials


__all__ = [
    "InputBlindingFactors",
    "LiquidOutputBlindingMaterial",
    "LiquidSpendError",
    "OutputBlindingSpec",
    "blind_spend_outputs",
    "compute_balancing_vbf",
    "make_asset_surjection_proof",
]
