# SPDX-License-Identifier: MIT
"""Subprocess wrapper for ``scripts/boltz_claim_liquid.js``.

The cooperative MuSig2 claim of a Boltz Liquid reverse-swap lockup
is implemented in JavaScript because the reference ``boltz-core``
crypto primitives (plus liquidjs-lib's confidential-transaction
codec) only ship as a Node library. This module wraps that script
behind the sandboxed subprocess runner so the wallet keeps a
single Python-side surface for "run the Liquid claim ceremony".

The runtime gate ``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false``
guards this entrypoint: operators must complete the regtest
integration test before flipping the gate, otherwise a misconfigured
deployment can broadcast malformed claim transactions against the
live operator and strand its funds.

Inputs come in as a structured dataclass so the test path can assert
the payload shape we hand to the script (rather than re-parsing the
JSON the subprocess receives). The output is the claim-tx hex from
fd 3 plus the broadcast txid the script logs on stdout.
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


_SCRIPT_NAME = "scripts/boltz_claim_liquid.js"


class LiquidClaimSubprocessError(RuntimeError):
    """Raised when the subprocess refuses or fails to produce a claim."""


class LiquidIntegrationNotVerifiedError(LiquidClaimSubprocessError):
    """Raised when the runtime gate is off.

    Kept distinct from generic failures so the caller can route the
    session to reconciliation rather than retry: the failure is a
    deployment-side decision, not a transient backend issue.
    """


@dataclass(frozen=True)
class LiquidClaimRequest:
    """All inputs the JS subprocess needs to assemble a claim TX.

    Each field corresponds 1:1 to a JSON key on the subprocess's
    stdin payload. Kept as a frozen dataclass so the caller can
    assert payload shape in tests without round-tripping JSON.
    """

    boltz_url: str
    swap_id: str
    preimage_hex: str
    claim_private_key_hex: str
    refund_public_key_hex: str
    swap_tree: dict[str, Any]
    lockup_tx_hex: str
    destination_address: str
    blinding_key_hex: str
    network: str  # "mainnet" | "testnet" | "regtest"
    asset_id_hex: Optional[str] = None
    socks_proxy: Optional[str] = None
    # Claim ceremony to drive in the JS subprocess. ``cooperative``
    # (the default) negotiates a MuSig2 partial signature with
    # Boltz on the LN→L-BTC reverse-leg lockup; ``unilateral``
    # builds a script-path spend via the swap's claim leaf using
    # preimage + claim key, contacting Boltz only to broadcast.
    # Unilateral is the post-preimage-reveal escape hatch for the
    # Liquid reverse leg when the operator refuses to co-sign.
    mode: str = "cooperative"


@dataclass(frozen=True)
class LiquidClaimResult:
    """Output of one successful Liquid-claim subprocess run."""

    claim_tx_hex: str
    txid: str
    raw_stdout_redacted: bytes
    raw_stderr_redacted: bytes


def _payload_for(request: LiquidClaimRequest) -> dict[str, Any]:
    """Translate the dataclass into the JS subprocess wire shape.

    Centralised so the test path can assert the exact key set + names.
    """
    payload: dict[str, Any] = {
        "boltzUrl": request.boltz_url,
        "swapId": request.swap_id,
        "preimage": request.preimage_hex,
        "claimPrivateKey": request.claim_private_key_hex,
        "refundPublicKey": request.refund_public_key_hex,
        "swapTree": request.swap_tree,
        "lockupTxHex": request.lockup_tx_hex,
        "destinationAddress": request.destination_address,
        "blindingKey": request.blinding_key_hex,
        "network": request.network,
    }
    if request.asset_id_hex:
        payload["assetId"] = request.asset_id_hex
    if request.socks_proxy:
        payload["socksProxy"] = request.socks_proxy
    # Only emit ``mode`` when non-default so existing cooperative
    # call sites keep producing byte-identical payloads (matters for
    # the wire-shape regression test).
    if request.mode != "cooperative":
        payload["mode"] = request.mode
    return payload


def _integration_verified() -> bool:
    return bool(getattr(settings, "anonymize_liquid_integration_verified", False))


def _repo_root() -> Path:
    # The subprocess runner CWDs to the repo root and resolves the
    # script via its relative path, matching the BTC claim contract
    # (see ``hop_dispatcher.py`` ``_run_refund_subprocess``).
    return Path(__file__).resolve().parents[3]


def _parse_stdout_txid(stdout_redacted: bytes) -> Optional[str]:
    """Pull the broadcast txid out of the structured stdout event.

    The JS script emits exactly one JSON line on stdout:
    ``{"event":"liquid_claim_broadcast_complete","txid":"<hex>"}``.
    The redactor doesn't touch JSON keys / non-hex-run values so
    decoding here is safe; we still defend against malformed output.
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
    if obj.get("event") != "liquid_claim_broadcast_complete":
        return None
    txid = obj.get("txid")
    return txid if isinstance(txid, str) and txid else None


async def run_liquid_claim_subprocess(
    request: LiquidClaimRequest,
    *,
    timeout_s: Optional[float] = None,
) -> LiquidClaimResult:
    """Spawn ``boltz_claim_liquid.js`` and return the parsed result.

    Raises :class:`LiquidIntegrationNotVerifiedError` immediately when
    ``ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false`` — the gate must
    cover this entrypoint too, not just the swap-create adapters.

    Raises :class:`LiquidClaimSubprocessError` on any failure mode
    (timeout, non-zero exit, missing fd-3 hex, unparseable stdout).
    """
    if not _integration_verified():
        raise LiquidIntegrationNotVerifiedError(
            "ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=false; refusing to "
            "invoke boltz_claim_liquid.js until the operator confirms "
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
        raise LiquidClaimSubprocessError(f"liquid claim subprocess timeout: {exc}") from exc
    except SubprocessOutputTooLargeError as exc:
        raise LiquidClaimSubprocessError(f"liquid claim subprocess produced too much output: {exc}") from exc
    except RuntimeError as exc:
        raise LiquidClaimSubprocessError(f"liquid claim subprocess failed to spawn: {exc}") from exc

    if result.returncode != 0:
        raise LiquidClaimSubprocessError(
            f"liquid claim subprocess exit={result.returncode}; stderr={result.stderr_redacted!r}"
        )

    claim_tx_hex = result.claim_tx_hex.value if result.claim_tx_hex is not None else None
    if not claim_tx_hex:
        raise LiquidClaimSubprocessError("liquid claim subprocess produced no fd-3 hex")

    txid = _parse_stdout_txid(result.stdout_redacted)
    if not txid:
        raise LiquidClaimSubprocessError("liquid claim subprocess stdout missing broadcast txid event")

    return LiquidClaimResult(
        claim_tx_hex=claim_tx_hex,
        txid=txid,
        raw_stdout_redacted=result.stdout_redacted,
        raw_stderr_redacted=result.stderr_redacted,
    )


__all__ = [
    "LiquidClaimRequest",
    "LiquidClaimResult",
    "LiquidClaimSubprocessError",
    "LiquidIntegrationNotVerifiedError",
    "run_liquid_claim_subprocess",
]
