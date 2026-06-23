"""Shared Boltz submarine lockup-address verifier.

This lives outside the anonymize package so BOTH the anonymize submarine
path (``app.services.anonymize.boltz_egress``) and the mainline /
Braiins-deposit submarine path (``app.services.boltz_service``) can call
a single implementation.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

__all__ = [
    "verify_submarine_lockup_address",
    "verify_reverse_lockup_address",
    "verify_liquid_lockup_address",
    "scripts_dir",
]


def _serialize_swap_tree(swap_tree: Any) -> Any:
    """Coerce a swap tree into the ``{claimLeaf, refundLeaf}`` shape the
    ``boltz-core`` deserializer expects.

    Accepts either the raw dict Boltz returned (passed straight through)
    or the :class:`app.services.anonymize.liquid_swap.SwapTree` dataclass
    (serialized field-by-field).
    """
    if isinstance(swap_tree, dict):
        return swap_tree
    claim = getattr(swap_tree, "claim_leaf", None)
    refund = getattr(swap_tree, "refund_leaf", None)
    if claim is None or refund is None:
        return swap_tree
    return {
        "claimLeaf": {"version": claim.version, "output": claim.output},
        "refundLeaf": {"version": refund.version, "output": refund.output},
    }


def verify_liquid_lockup_address(
    *,
    swap_tree: Any,
    lockup_address: str,
    network: str,
    swap_type: str,
    verify_leaf: str,
    refund_public_key_hex: str | None = None,
    claim_public_key_hex: str | None = None,
    asset_id_hex: str | None = None,
) -> tuple[bool, str]:
    """Verify a **Liquid** lockup address commits to the swap tree + our key.

    The Liquid counterpart of :func:`verify_submarine_lockup_address`.
    Reconstructs the taproot witness program from the operator-supplied
    swap tree and the two public keys (via ``boltz-core``'s Liquid
    primitives) and confirms (1) the chosen leaf commits to our key —
    the refund leaf on the L-BTC→LN funding leg (``verify_leaf="refund"``)
    or the claim leaf on the LN→L-BTC reverse leg
    (``verify_leaf="claim"``) — and (2) the derived witness program
    equals the unconfidential scriptPubKey of ``lockup_address``. A
    malicious operator that returns an address it solely controls is
    rejected, preventing direct theft of the locked L-BTC.

    Returns ``(ok, reason)``. Fails closed on any subprocess / parse
    error so the caller refuses to fund or pay.
    """
    script = Path(scripts_dir()) / "boltz_verify_lockup_address_liquid.js"
    if not script.is_file():
        return False, "verifier_script_missing"
    payload: dict[str, Any] = {
        "swapTree": _serialize_swap_tree(swap_tree),
        "lockupAddress": lockup_address,
        "network": network,
        "swapType": "reverse" if swap_type == "reverse" else "submarine",
        "verifyLeaf": "claim" if verify_leaf == "claim" else "refund",
    }
    if refund_public_key_hex:
        payload["refundPublicKey"] = refund_public_key_hex
    if claim_public_key_hex:
        payload["claimPublicKey"] = claim_public_key_hex
    if asset_id_hex:
        payload["assetId"] = asset_id_hex
    try:
        result = subprocess.run(
            ["node", str(script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            cwd=scripts_dir(),
        )
    except subprocess.TimeoutExpired:
        return False, "verifier_timeout"
    except Exception as exc:  # noqa: BLE001
        return False, f"verifier_error:{type(exc).__name__}"
    if result.returncode != 0:
        return False, "verifier_nonzero_exit"
    try:
        parsed = json.loads(result.stdout.strip())
    except (ValueError, TypeError):
        return False, "verifier_bad_output"
    return bool(parsed.get("ok")), str(parsed.get("reason") or ("ok" if parsed.get("ok") else "unknown"))


def verify_reverse_lockup_address(
    *,
    swap_tree_json: Any,
    claim_public_key_hex: str,
    refund_public_key_hex: str | None,
    lockup_address: str,
    network: str,
) -> tuple[bool, str]:
    """Verify a reverse-swap lockup address commits to the swap tree + our
    claim key BEFORE the wallet pays the swap's hold invoice.

    The reverse counterpart of :func:`verify_submarine_lockup_address`: on
    a reverse swap we hold the *claim* key, so this confirms (1) the swap
    tree's claim leaf commits to our claim key — the path we spend with our
    preimage — and (2) the address derived from ``musig(claimKey,
    refundKey)`` tweaked by the swap tree equals ``lockup_address``. An
    operator that returns a lockup whose claim path it controls is rejected
    early, before any LN funds move.

    Returns ``(ok, reason)``. Fails closed on any subprocess / parse error.
    """
    script = Path(scripts_dir()) / "boltz_verify_lockup_address.js"
    if not script.is_file():
        return False, "verifier_script_missing"
    payload = {
        "swapTree": swap_tree_json,
        "claimPublicKey": claim_public_key_hex,
        "refundPublicKey": refund_public_key_hex,
        "lockupAddress": lockup_address,
        "network": network,
        "verifyLeaf": "claim",
    }
    try:
        result = subprocess.run(
            ["node", str(script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            cwd=scripts_dir(),
        )
    except subprocess.TimeoutExpired:
        return False, "verifier_timeout"
    except Exception as exc:  # noqa: BLE001
        return False, f"verifier_error:{type(exc).__name__}"
    if result.returncode != 0:
        return False, "verifier_nonzero_exit"
    try:
        parsed = json.loads(result.stdout.strip())
    except (ValueError, TypeError):
        return False, "verifier_bad_output"
    return bool(parsed.get("ok")), str(parsed.get("reason") or ("ok" if parsed.get("ok") else "unknown"))


def scripts_dir() -> str:
    """Return the absolute path to the repo's ``scripts/`` directory.

    Node's ``require()`` resolves modules relative to the script's cwd,
    so the ``node`` subprocess must run from here — that's where
    ``scripts/package.json`` + ``scripts/node_modules`` (``ecpair``,
    ``tiny-secp256k1``, ...) live.

    This module sits at ``app/services/boltz_lockup_verify.py``, so the
    repo root is ``parents[2]``.
    """
    return str(Path(__file__).resolve().parents[2] / "scripts")


def verify_submarine_lockup_address(
    *,
    swap_tree_json: Any,
    refund_public_key_hex: str,
    lockup_address: str,
    network: str,
) -> tuple[bool, str]:
    """Verify a submarine lockup address commits to the swap tree + our
    refund key BEFORE the wallet funds it.

    Reconstructs the expected P2TR address from the operator-supplied
    swap tree and the two public keys (via ``boltz-core``) and confirms
    (1) the refund leaf commits to our refund key and (2) the derived
    address equals ``lockup_address``. A malicious operator that returns
    an address it controls (rather than a real swap output) is rejected,
    preventing direct theft of the funding amount.

    Returns ``(ok, reason)``. Fails closed: any subprocess / parse error
    yields ``(False, reason)`` so the caller refuses to fund.
    """
    script = Path(scripts_dir()) / "boltz_verify_lockup_address.js"
    if not script.is_file():
        return False, "verifier_script_missing"
    payload = {
        "swapTree": swap_tree_json,
        "refundPublicKey": refund_public_key_hex,
        "lockupAddress": lockup_address,
        "network": network,
    }
    try:
        result = subprocess.run(
            ["node", str(script)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            cwd=scripts_dir(),
        )
    except subprocess.TimeoutExpired:
        return False, "verifier_timeout"
    except Exception as exc:  # noqa: BLE001
        return False, f"verifier_error:{type(exc).__name__}"
    if result.returncode != 0:
        return False, "verifier_nonzero_exit"
    try:
        parsed = json.loads(result.stdout.strip())
    except (ValueError, TypeError):
        return False, "verifier_bad_output"
    return bool(parsed.get("ok")), str(parsed.get("reason") or ("ok" if parsed.get("ok") else "unknown"))
