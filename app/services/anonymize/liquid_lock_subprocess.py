# SPDX-License-Identifier: MIT
"""Subprocess wrapper for ``scripts/boltz_lock_liquid.js``.

The L-BTC → LN submarine leg's funding transaction is built in
JavaScript using ``liquidjs-lib``'s PSET-V2 codec + ``confidential``
helpers. The wallet supplies:

* The cleartext UTXO it claimed from the leg-1 cooperative claim
  (txid, vout, value, asset id, asset blinding factor, value blinding
  factor, full prevout hex).
* The single-sig p2wpkh spending privkey for that UTXO.
* The destination address Boltz returned for the submarine swap.
* The target Liquid network + (regtest-customizable) asset id.

The script assembles + signs + broadcasts a Liquid spend that:

* Pays the full destination amount to Boltz's lockup (CT-blinded
  output).
* Pays a single explicit fee output (Liquid's tx-fee convention).
* Optionally pays a CT-blinded change output back to the wallet when
  the wallet's UTXO exceeds the destination amount + fee.

The fee-rate and target amount are wallet-side decisions; the script
reads them as inputs (no policy-side logic in JS).

Inputs come in as a structured dataclass so the test path can assert
the payload shape we hand to the script. The output is the broadcast
txid plus the raw signed tx hex (fd 3, redactor-safe).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from app.core.config import settings

from .metadata import ANONYMIZE_LOGGER_NAME
from .subprocess import (
    SubprocessOutputTooLargeError,
    SubprocessResult,
    SubprocessTimeoutError,
    run_boltz_claim_js,
)

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


_SCRIPT_NAME = "scripts/boltz_lock_liquid.js"


class LiquidLockSubprocessError(RuntimeError):
    """Raised when the subprocess refuses or fails to broadcast a lock TX."""


class LiquidLockIntegrationNotVerifiedError(LiquidLockSubprocessError):
    """Raised when the runtime gate is off.

    Separate exception class so the hop body can distinguish a gate
    refusal (deployment-side decision; route to reconciliation) from
    a generic subprocess failure (transient; the bounded retry can
    re-attempt).
    """


@dataclass(frozen=True)
class LiquidLockRequest:
    """All inputs the JS subprocess needs to assemble a lock TX.

    Every field corresponds 1:1 to a JSON key on the subprocess's
    stdin payload. The wallet's L-BTC UTXO is fully described by its
    on-chain fields plus the cleartext recovered locally during the
    leg-1 receive-path unblinding.
    """

    # Wallet's UTXO (the leg-1 claim output) — fully unblinded.
    utxo_txid: str
    utxo_vout: int
    utxo_value_sat: int
    utxo_asset_id_hex: str
    utxo_asset_blinding_factor_hex: str
    utxo_value_blinding_factor_hex: str
    utxo_prevout_tx_hex: str
    utxo_script_pubkey_hex: str

    # Single-sig spending keypair for the UTXO.
    spending_private_key_hex: str

    # Destination (Boltz submarine lockup) + economics.
    destination_address: str
    destination_amount_sat: int
    fee_sat_per_vbyte: float

    # Change comes back to the wallet's own per-session CT address.
    # Set to None when ``destination_amount_sat`` consumes the input
    # in full (rounded to fee).
    change_address: Optional[str]

    # Network + (regtest-customizable) L-BTC asset id.
    network: str  # "mainnet" | "testnet" | "regtest"
    asset_id_hex: str

    # Boltz operator base URL — used only to broadcast the signed tx.
    boltz_url: str
    socks_proxy: Optional[str] = None


@dataclass(frozen=True)
class LiquidLockResult:
    """Output of one successful Liquid-lock subprocess run."""

    lock_tx_hex: str
    txid: str
    raw_stdout_redacted: bytes
    raw_stderr_redacted: bytes


def _payload_for(request: LiquidLockRequest) -> dict[str, Any]:
    """Translate the dataclass into the JS subprocess wire shape.

    Centralised so the test path can assert the exact key set + names.
    """
    payload: dict[str, Any] = {
        "utxoTxid": request.utxo_txid,
        "utxoVout": int(request.utxo_vout),
        "utxoValueSat": int(request.utxo_value_sat),
        "utxoAssetIdHex": request.utxo_asset_id_hex,
        "utxoAssetBlindingFactorHex": request.utxo_asset_blinding_factor_hex,
        "utxoValueBlindingFactorHex": request.utxo_value_blinding_factor_hex,
        "utxoPrevoutTxHex": request.utxo_prevout_tx_hex,
        "utxoScriptPubKeyHex": request.utxo_script_pubkey_hex,
        "spendingPrivateKey": request.spending_private_key_hex,
        "destinationAddress": request.destination_address,
        "destinationAmountSat": int(request.destination_amount_sat),
        "feeSatPerVbyte": float(request.fee_sat_per_vbyte),
        "network": request.network,
        "assetId": request.asset_id_hex,
        "boltzUrl": request.boltz_url,
    }
    if request.change_address:
        payload["changeAddress"] = request.change_address
    if request.socks_proxy:
        payload["socksProxy"] = request.socks_proxy
    return payload


def _integration_verified() -> bool:
    return bool(getattr(settings, "anonymize_liquid_integration_verified", False))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _parse_stdout_txid(stdout_redacted: bytes) -> Optional[str]:
    """Pull the broadcast txid out of the structured stdout event.

    The JS script emits exactly one JSON line on stdout:
    ``{"event":"liquid_lock_broadcast_complete","txid":"<hex>"}``.
    """
    if not stdout_redacted:
        return None
    line = stdout_redacted.strip().splitlines()[-1] if stdout_redacted.strip() else b""
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("event") != "liquid_lock_broadcast_complete":
        return None
    txid = obj.get("txid")
    return txid if isinstance(txid, str) and txid else None


async def run_liquid_lock_subprocess(
    request: LiquidLockRequest,
    *,
    timeout_s: Optional[float] = None,
) -> LiquidLockResult:
    """Spawn ``boltz_lock_liquid.js`` and return the parsed result.

    Raises :class:`LiquidLockIntegrationNotVerifiedError` immediately when
    ``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false``. Otherwise raises
    :class:`LiquidLockSubprocessError` on any failure mode.
    """
    if not _integration_verified():
        raise LiquidLockIntegrationNotVerifiedError(
            "ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing to "
            "invoke boltz_lock_liquid.js until the operator confirms "
            "end-to-end integration in their environment"
        )

    payload = _payload_for(request)
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    try:
        result: SubprocessResult = await run_boltz_claim_js(
            args=(_SCRIPT_NAME,),
            cwd=_repo_root(),
            timeout_s=timeout_s,
            stdin_payload=payload_bytes,
            use_tx_out_file=True,
        )
    except SubprocessTimeoutError as exc:
        raise LiquidLockSubprocessError(f"liquid lock subprocess timeout: {exc}") from exc
    except SubprocessOutputTooLargeError as exc:
        raise LiquidLockSubprocessError(f"liquid lock subprocess produced too much output: {exc}") from exc
    except RuntimeError as exc:
        raise LiquidLockSubprocessError(f"liquid lock subprocess failed to spawn: {exc}") from exc

    if result.returncode != 0:
        raise LiquidLockSubprocessError(
            f"liquid lock subprocess exit={result.returncode}; stderr={result.stderr_redacted!r}"
        )

    lock_tx_hex = result.claim_tx_hex.value if result.claim_tx_hex is not None else None
    if not lock_tx_hex:
        raise LiquidLockSubprocessError("liquid lock subprocess produced no fd-3 hex")

    txid = _parse_stdout_txid(result.stdout_redacted)
    if not txid:
        raise LiquidLockSubprocessError("liquid lock subprocess stdout missing broadcast txid event")

    return LiquidLockResult(
        lock_tx_hex=lock_tx_hex,
        txid=txid,
        raw_stdout_redacted=result.stdout_redacted,
        raw_stderr_redacted=result.stderr_redacted,
    )


__all__ = [
    "LiquidLockRequest",
    "LiquidLockResult",
    "LiquidLockSubprocessError",
    "LiquidLockIntegrationNotVerifiedError",
    "run_liquid_lock_subprocess",
]
