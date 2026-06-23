# SPDX-License-Identifier: MIT
"""Subprocess wrapper for ``scripts/submarine_refund_liquid.js``.

The L-BTC submarine refund ceremony (cooperative MuSig2 or unilateral
script-path) is implemented in JavaScript because the reference
``boltz-core`` Liquid Confidential-Transaction codec ships only as a
Node library. This module wraps that script with a typed Python
surface — parallel to :mod:`liquid_claim_subprocess` but driving the
L-BTC submarine refund flow used to unwind a stuck L-BTC→LN leg of
the Anonymize Liquid round-trip hop.

The runtime gate ``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED`` guards
this entrypoint, matching the claim wrapper: operators must complete
the regtest harness before the wallet is allowed to broadcast L-BTC
TXs against a live operator.
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


_SCRIPT_NAME = "scripts/submarine_refund_liquid.js"


class LiquidRefundSubprocessError(RuntimeError):
    """Raised when the subprocess refuses or fails to produce a refund."""


class LiquidIntegrationNotVerifiedError(LiquidRefundSubprocessError):
    """Raised when the runtime gate is off.

    Same semantics as :class:`liquid_claim_subprocess.LiquidIntegrationNotVerifiedError`
    — the failure is a deployment-side decision, not transient.
    """


@dataclass(frozen=True)
class LiquidRefundRequest:
    """All inputs the JS subprocess needs to assemble a refund TX.

    Each field corresponds 1:1 to a JSON key on the subprocess's
    stdin payload (camelCase on the wire, snake_case on the dataclass).
    Frozen so tests can pin payload shape without round-tripping JSON.

    The Liquid refund flow has TWO modes:

    * ``cooperative`` (default) — Musig2 partial-sig handshake with
      Boltz. Requires ``claim_public_key_hex``. Works immediately;
      no timeout wait.
    * ``unilateral`` — refund-leaf script-path spend. Requires the
      Liquid chain tip to have reached ``timeout_block_height``.
      Used when Boltz refuses or is unreachable.
    """

    boltz_url: str
    swap_id: str
    refund_private_key_hex: str
    swap_tree: dict[str, Any]
    lockup_tx_hex: str
    refund_address: str
    blinding_key_hex: str
    timeout_block_height: int
    network: str  # "mainnet" | "testnet" | "regtest"
    claim_public_key_hex: Optional[str] = None
    asset_id_hex: Optional[str] = None
    current_block_height: Optional[int] = None
    fee_rate_sat_per_vb: Optional[int] = None
    socks_proxy: Optional[str] = None
    mode: str = "cooperative"


@dataclass(frozen=True)
class LiquidRefundResult:
    """Output of one successful Liquid-refund subprocess run."""

    refund_tx_hex: str
    txid: str
    mode: str
    raw_stdout_redacted: bytes
    raw_stderr_redacted: bytes


def _payload_for(request: LiquidRefundRequest) -> dict[str, Any]:
    """Translate the dataclass into the JS subprocess wire shape.

    Optional fields are omitted when unset so the payload size stays
    minimal and the JS-side destructure picks up its defaults.
    """
    payload: dict[str, Any] = {
        "boltzUrl": request.boltz_url,
        "swapId": request.swap_id,
        "refundPrivateKey": request.refund_private_key_hex,
        "swapTree": request.swap_tree,
        "lockupTxHex": request.lockup_tx_hex,
        "refundAddress": request.refund_address,
        "blindingKey": request.blinding_key_hex,
        "timeoutBlockHeight": int(request.timeout_block_height),
        "network": request.network,
    }
    if request.claim_public_key_hex:
        payload["claimPublicKey"] = request.claim_public_key_hex
    if request.asset_id_hex:
        payload["assetId"] = request.asset_id_hex
    if request.current_block_height is not None:
        payload["currentBlockHeight"] = int(request.current_block_height)
    if request.fee_rate_sat_per_vb is not None:
        payload["feeRate"] = int(request.fee_rate_sat_per_vb)
    if request.socks_proxy:
        payload["socksProxy"] = request.socks_proxy
    # Emit ``mode`` only when non-default so a cooperative-mode
    # request produces a minimal payload (matters for future
    # wire-shape regression tests).
    if request.mode != "cooperative":
        payload["mode"] = request.mode
    return payload


def _integration_verified() -> bool:
    return bool(getattr(settings, "anonymize_liquid_integration_verified", False))


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _parse_stdout_event(stdout_redacted: bytes) -> Optional[dict[str, Any]]:
    """Pull the structured broadcast event off stdout.

    The JS script emits exactly one line:
    ``{"event":"liquid_submarine_refund_broadcast","mode":"…","txid":"…"}``.
    """
    if not stdout_redacted:
        return None
    stripped = stdout_redacted.strip()
    if not stripped:
        return None
    line = stripped.splitlines()[-1]
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("event") != "liquid_submarine_refund_broadcast":
        return None
    return obj


async def run_liquid_refund_subprocess(
    request: LiquidRefundRequest,
    *,
    timeout_s: Optional[float] = None,
) -> LiquidRefundResult:
    """Spawn ``submarine_refund_liquid.js`` and return the parsed result.

    Raises :class:`LiquidIntegrationNotVerifiedError` when the runtime
    gate is off.

    Raises :class:`LiquidRefundSubprocessError` on any failure mode
    (timeout, non-zero exit, missing fd-3 hex, missing/malformed
    stdout event).
    """
    if not _integration_verified():
        raise LiquidIntegrationNotVerifiedError(
            "ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing to "
            "invoke submarine_refund_liquid.js until the operator "
            "confirms end-to-end integration in their environment"
        )

    if request.mode not in {"cooperative", "unilateral"}:
        raise LiquidRefundSubprocessError(f"unsupported refund mode: {request.mode!r}")

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
        raise LiquidRefundSubprocessError(f"liquid refund subprocess timeout: {exc}") from exc
    except SubprocessOutputTooLargeError as exc:
        raise LiquidRefundSubprocessError(f"liquid refund subprocess produced too much output: {exc}") from exc
    except RuntimeError as exc:
        raise LiquidRefundSubprocessError(f"liquid refund subprocess failed to spawn: {exc}") from exc

    if result.returncode != 0:
        raise LiquidRefundSubprocessError(
            f"liquid refund subprocess exit={result.returncode}; stderr={result.stderr_redacted!r}"
        )

    refund_tx_hex = result.claim_tx_hex.value if result.claim_tx_hex is not None else None
    if not refund_tx_hex:
        raise LiquidRefundSubprocessError("liquid refund subprocess produced no fd-3 hex")

    event = _parse_stdout_event(result.stdout_redacted)
    if event is None:
        raise LiquidRefundSubprocessError("liquid refund subprocess stdout missing broadcast event")
    txid = event.get("txid")
    mode = event.get("mode")
    if not isinstance(txid, str) or not txid:
        raise LiquidRefundSubprocessError("liquid refund subprocess broadcast event missing txid")
    if not isinstance(mode, str) or not mode:
        raise LiquidRefundSubprocessError("liquid refund subprocess broadcast event missing mode")

    return LiquidRefundResult(
        refund_tx_hex=refund_tx_hex,
        txid=txid,
        mode=mode,
        raw_stdout_redacted=result.stdout_redacted,
        raw_stderr_redacted=result.stderr_redacted,
    )
