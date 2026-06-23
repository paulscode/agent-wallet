# SPDX-License-Identifier: MIT
"""Liquid CT receive path.

When the Boltz LN→L-BTC chain swap publishes its lockup transaction
on Liquid, we observe the blinded output via the
:class:`LiquidBackend`. The on-wire output carries Pedersen
commitments + a rangeproof but **not** the cleartext amount or
asset id — those are blinded.

This module owns the locally-executed unblinding:

1. Derive the SLIP-77 per-script blinding privkey for the output's
   scriptPubKey (caller-supplied; derives via :mod:`liquid_ct`).
2. Run :func:`wallycore.asset_unblind` to recover ``(value, asset,
   abf, vbf)``.
3. Validate the recovered ``(asset_id, value)`` against the expected
   L-BTC asset id + the expected amount range.

The wallet **never** trusts backend-supplied cleartext values
(``LiquidUtxo.advisory_value_sat`` / ``advisory_asset_id``) for
authorisation; those are only useful for backend-side display +
optimisation. Authority sits with the local unblinding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import wallycore as _wally

from .liquid_backend import LiquidUtxo
from .liquid_ct import (
    ASSET_GENERATOR_LEN,
    ASSET_ID_LEN,
    BLINDING_FACTOR_LEN,
    SCRIPT_BLINDING_PRIVKEY_LEN,
    SCRIPT_BLINDING_PUBKEY_LEN,
    VALUE_COMMITMENT_LEN,
)


class LiquidReceiveError(RuntimeError):
    """Raised when a blinded output cannot be processed safely."""


@dataclass(frozen=True)
class UnblindedUtxo:
    """A Liquid UTXO with its cleartext fields recovered.

    The full :class:`LiquidUtxo` is retained alongside for downstream
    use (the wallet may need the rangeproof + commitments later, for
    the spend-side blinding-factor balance).
    """

    utxo: LiquidUtxo
    value_sat: int
    asset_id: bytes
    asset_blinding_factor: bytes  # 32 bytes
    value_blinding_factor: bytes  # 32 bytes


def unblind_liquid_utxo(
    *,
    utxo: LiquidUtxo,
    blinding_privkey: bytes,
) -> UnblindedUtxo:
    """Unblind ``utxo`` using ``blinding_privkey``.

    ``blinding_privkey`` is the 32-byte SLIP-77 per-script blinding
    privkey for ``utxo.script_pubkey`` (obtain via
    :func:`liquid_ct.derive_script_blinding_privkey`).

    Raises :class:`LiquidReceiveError` on any failure — the
    wallycore call surfaces a :class:`ValueError` if the proof
    doesn't verify under the supplied blinding key (e.g. the output
    isn't actually for us, or the rangeproof was tampered with).
    """
    if len(blinding_privkey) != SCRIPT_BLINDING_PRIVKEY_LEN:
        raise LiquidReceiveError(
            f"blinding_privkey must be {SCRIPT_BLINDING_PRIVKEY_LEN} bytes; got {len(blinding_privkey)}"
        )
    if len(utxo.value_commitment) != VALUE_COMMITMENT_LEN:
        raise LiquidReceiveError(f"value_commitment must be {VALUE_COMMITMENT_LEN} bytes")
    if len(utxo.asset_commitment) != ASSET_GENERATOR_LEN:
        raise LiquidReceiveError(f"asset_commitment must be {ASSET_GENERATOR_LEN} bytes")
    if len(utxo.nonce_commitment) != SCRIPT_BLINDING_PUBKEY_LEN:
        raise LiquidReceiveError(f"nonce_commitment must be {SCRIPT_BLINDING_PUBKEY_LEN} bytes")
    if not utxo.rangeproof:
        raise LiquidReceiveError("rangeproof must be non-empty")
    if not utxo.script_pubkey:
        raise LiquidReceiveError("script_pubkey must be non-empty")

    try:
        value, asset, abf, vbf = _wally.asset_unblind(
            bytes(utxo.nonce_commitment),
            bytes(blinding_privkey),
            bytes(utxo.rangeproof),
            bytes(utxo.value_commitment),
            bytes(utxo.script_pubkey),
            bytes(utxo.asset_commitment),
        )
    except (ValueError, Exception) as exc:  # noqa: BLE001
        raise LiquidReceiveError(f"asset_unblind failed: {exc}") from exc

    # ``wally_asset_unblind`` returns the asset id in **little-endian**
    # bytes (matching the on-wire commitment minus the prefix byte).
    # The wallet's well-known constants
    # (:data:`liquid_ct.LBTC_ASSET_ID_MAINNET` /
    # :data:`liquid_ct.LBTC_ASSET_ID_TESTNET`) — and the harness's
    # ``getsidechaininfo.pegged_asset`` — use the canonical
    # **big-endian / display** form. Reverse once here so
    # downstream consumers (validation, swap-state stashing, the
    # claim + lock subprocesses' ``utxoAssetIdHex`` kwarg) operate
    # consistently on the BE form.
    asset_bytes = bytes(asset)[::-1]
    abf_bytes = bytes(abf)
    vbf_bytes = bytes(vbf)
    if len(asset_bytes) != ASSET_ID_LEN:
        raise LiquidReceiveError(f"unblinded asset is {len(asset_bytes)} bytes; expected {ASSET_ID_LEN}")
    if len(abf_bytes) != BLINDING_FACTOR_LEN:
        raise LiquidReceiveError(f"unblinded abf is {len(abf_bytes)} bytes; expected {BLINDING_FACTOR_LEN}")
    if len(vbf_bytes) != BLINDING_FACTOR_LEN:
        raise LiquidReceiveError(f"unblinded vbf is {len(vbf_bytes)} bytes; expected {BLINDING_FACTOR_LEN}")
    return UnblindedUtxo(
        utxo=utxo,
        value_sat=int(value),
        asset_id=asset_bytes,
        asset_blinding_factor=abf_bytes,
        value_blinding_factor=vbf_bytes,
    )


def validate_lbtc_credit(
    unblinded: UnblindedUtxo,
    *,
    expected_asset_id: bytes,
    expected_min_amount_sat: int,
    expected_max_amount_sat: Optional[int] = None,
) -> Optional[str]:
    """Validate the unblinded credit against the expected swap envelope.

    Returns ``None`` on success or a short error string on
    rejection. The caller maps the error into the hop's error
    outcome.

    Checks:
    * ``asset_id`` matches the expected L-BTC asset id (defends
      against an operator credit denominated in a different Liquid
      asset).
    * ``value_sat`` is ≥ ``expected_min_amount_sat`` (defends
      against under-payment).
    * ``value_sat`` is ≤ ``expected_max_amount_sat`` when supplied
      (defends against over-payment / dust attacks).
    """
    if len(expected_asset_id) != ASSET_ID_LEN:
        return f"expected_asset_id must be {ASSET_ID_LEN} bytes; got {len(expected_asset_id)}"
    if expected_min_amount_sat < 0:
        return "expected_min_amount_sat must be non-negative"
    if unblinded.asset_id != expected_asset_id:
        return f"unexpected asset_id: got {unblinded.asset_id.hex()}, expected {expected_asset_id.hex()}"
    if unblinded.value_sat < expected_min_amount_sat:
        return f"credit value {unblinded.value_sat} below minimum {expected_min_amount_sat}"
    if expected_max_amount_sat is not None and unblinded.value_sat > expected_max_amount_sat:
        return f"credit value {unblinded.value_sat} above maximum {expected_max_amount_sat}"
    return None


__all__ = [
    "LiquidReceiveError",
    "UnblindedUtxo",
    "unblind_liquid_utxo",
    "validate_lbtc_credit",
]
