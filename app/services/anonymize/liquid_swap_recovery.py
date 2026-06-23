# SPDX-License-Identifier: MIT
"""Operator-driven recovery actions for in-flight Liquid swaps.

The Liquid hop dispatcher runs the cooperative happy-path inside
``hops/liquid.py``. When a session is stuck (Boltz operator outage
past the cooperative window; subprocess persistently failing;
timeout passed without forward progress) the operator needs an
out-of-band lever to drive the recovery transaction without
manually shelling out to the JS subprocess.

This module exposes three such levers, all keyed on
``(session_id, leg)`` rather than ``swap_id``:

* :func:`cooperative_refund_submarine_leg` — Musig2 cooperative
  refund of the wallet's L-BTC submarine lockup (leg-2 of the
  Liquid round-trip).
* :func:`unilateral_refund_submarine_leg` — post-timeout script-path
  refund of the same lockup when Boltz refuses to cooperate.
* :func:`unilateral_claim_reverse_leg` — post-timeout script-path
  spend of Boltz's reverse-swap lockup (leg-1) into the wallet.

Each function:

1. Looks up the per-leg Boltz swap id from
   ``session.pipeline_json["liquid_{ln_to_lbtc,lbtc_to_ln}_swap_id"]``.
2. Hydrates the process-wide ``swap_state`` cache from
   ``session.pipeline_json["liquid_swap_state_enc"]`` via
   :func:`restore_session_swap_state`.
3. Resolves the operator URL from the per-leg operator-id column
   on ``anonymize_session`` via the signed registry.
4. Constructs the typed :class:`LiquidClaimRequest` /
   :class:`LiquidRefundRequest` from the hydrated state.
5. Spawns the subprocess and returns a structured result.

The dashboard endpoint that wraps each function is responsible
for admin-auth + CSRF + audit-log emission. This module deals
purely in the swap-state plumbing.

Refusing safely
---------------

Every entry point returns a structured ``*Result`` on success or
raises a typed exception on a deterministic failure (missing
state, wrong leg, no operator id). Subprocess failures bubble as
``LiquidClaimSubprocessError`` / ``LiquidRefundSubprocessError``
so callers can distinguish "we refused to try" from "we tried
and the JS side rejected".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from .liquid_claim_subprocess import (
    LiquidClaimRequest,
    run_liquid_claim_subprocess,
)
from .liquid_refund_subprocess import (
    LiquidRefundRequest,
    run_liquid_refund_subprocess,
)
from .liquid_seed import resolve_liquid_btc_asset_id, resolve_liquid_network
from .liquid_swap_state_persistence import restore_session_swap_state
from .metadata import ANONYMIZE_LOGGER_NAME
from .operators import resolve_operator_url_from_registry

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# Pipeline-json keys (mirrors hops/liquid.py).
_PJ_REVERSE_SWAP_ID = "liquid_ln_to_lbtc_swap_id"
_PJ_SUBMARINE_SWAP_ID = "liquid_lbtc_to_ln_swap_id"

# Valid leg identifiers.
LEG_REVERSE = "reverse"
LEG_SUBMARINE = "submarine"
_VALID_LEGS = {LEG_REVERSE, LEG_SUBMARINE}


# ── Errors ────────────────────────────────────────────────────────────


class LiquidRecoveryError(RuntimeError):
    """Base class for refusals from this module."""


class LiquidRecoveryStateMissingError(LiquidRecoveryError):
    """No persisted per-leg swap-state for the requested session+leg.

    Most likely cause: the session never reached the leg in
    question, or its pipeline_json blob was retention-purged.
    """


class LiquidRecoveryOperatorMissingError(LiquidRecoveryError):
    """The session has no operator id stamped for the requested leg.

    Pre-P2.1 sessions did not record the operator id; recovery for
    those sessions falls back to the registry's current selection
    (caller decides whether to trust that).
    """


class LiquidRecoveryUnknownLegError(LiquidRecoveryError):
    """Caller passed an unrecognised leg identifier."""


# ── Result types ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class LiquidRecoveryClaimResult:
    """Surfaced by :func:`unilateral_claim_reverse_leg`."""

    session_id: str
    leg: str
    boltz_swap_id: str
    mode: str
    txid: str
    operator_id: Optional[str]


@dataclass(frozen=True)
class LiquidRecoveryRefundResult:
    """Surfaced by both refund entry points (cooperative + unilateral)."""

    session_id: str
    leg: str
    boltz_swap_id: str
    mode: str
    txid: str
    operator_id: Optional[str]


# ── Helpers ───────────────────────────────────────────────────────────


def _network_to_subprocess_name(network: Any) -> str:
    """Map :class:`LiquidNetwork` enum to the JS subprocess wire name."""
    from .liquid_address import LiquidNetwork

    return {
        LiquidNetwork.MAINNET: "mainnet",
        LiquidNetwork.TESTNET: "testnet",
        LiquidNetwork.REGTEST: "regtest",
    }[network]


def _pipeline_swap_id(session: Any, leg: str) -> Optional[str]:
    """Pull the per-leg Boltz swap id out of ``pipeline_json``.

    Returns the swap id string or ``None`` when the leg has not
    advanced to a create-swap call yet.
    """
    pj = session.pipeline_json or {}
    if leg == LEG_REVERSE:
        sid = pj.get(_PJ_REVERSE_SWAP_ID)
    elif leg == LEG_SUBMARINE:
        sid = pj.get(_PJ_SUBMARINE_SWAP_ID)
    else:
        raise LiquidRecoveryUnknownLegError(f"unknown leg: {leg!r}")
    if not sid:
        return None
    return str(sid)


def _operator_id_for_leg(session: Any, leg: str) -> Optional[str]:
    """Return the operator id stamped on the session for ``leg``."""
    if leg == LEG_REVERSE:
        return getattr(session, "liquid_reverse_operator_id", None)
    if leg == LEG_SUBMARINE:
        return getattr(session, "liquid_submarine_operator_id", None)
    raise LiquidRecoveryUnknownLegError(f"unknown leg: {leg!r}")


def _resolve_operator_url(operator_id: Optional[str]) -> Optional[str]:
    """Look up ``operator_id`` in the signed registry; ``None`` if absent."""
    if not operator_id:
        return None
    return resolve_operator_url_from_registry(operator_id)


def _hydrate_leg_state(
    session: Any,
    leg: str,
) -> tuple[str, dict[str, Any]]:
    """Resolve ``(boltz_swap_id, swap_state_entry)`` for the leg.

    Raises :class:`LiquidRecoveryStateMissingError` when either the swap
    id is absent from pipeline_json OR the per-swap state entry is
    not in the persisted blob.
    """
    if leg not in _VALID_LEGS:
        raise LiquidRecoveryUnknownLegError(f"unknown leg: {leg!r}")

    boltz_swap_id = _pipeline_swap_id(session, leg)
    if not boltz_swap_id:
        raise LiquidRecoveryStateMissingError(
            f"session has no pipeline_json swap_id for leg={leg!r}; this leg never created a Boltz swap"
        )

    # Hydrate the swap_state map from the Fernet-encrypted blob.
    # The map is per-process; we build a fresh local one rather than
    # mutating the dispatcher's global cache to avoid leaking
    # recovery-only entries into the live hop loop.
    swap_state: dict[str, dict[str, Any]] = {}
    restore_session_swap_state(session, swap_state)
    entry = swap_state.get(boltz_swap_id)
    if entry is None:
        raise LiquidRecoveryStateMissingError(
            f"no persisted swap_state entry for boltz_swap_id="
            f"{boltz_swap_id!r} on session {session.id}; the leg's "
            "wallet-generated secrets are not recoverable from this row"
        )
    return boltz_swap_id, entry


def _build_swap_tree_dict(state: dict[str, Any]) -> dict[str, Any]:
    """Re-pack the swap-tree leaves into the JS subprocess wire shape."""
    return {
        "claimLeaf": {
            "version": 196,
            "output": str(state["swap_tree_claim_leaf"]),
        },
        "refundLeaf": {
            "version": 196,
            "output": str(state["swap_tree_refund_leaf"]),
        },
    }


def _resolve_refund_address(session: Any, state: dict[str, Any]) -> Optional[str]:
    """Pick a Liquid refund destination for the submarine leg.

    The session's leg-1 claim cached the wallet's per-session CT
    address (``session_ct_address``) when it claimed Boltz's reverse
    lockup; we reuse it for the leg-2 refund destination so the
    refunded L-BTC lands at a wallet-controlled, blinded output.
    """
    leg1 = state.get("__leg1_session_ct_address__")
    if leg1:
        return str(leg1)
    # Fallback path: walk the hydrated swap_state for the session's
    # leg-1 entry (tagged ``leg=ln_to_lbtc``) and re-use its
    # ``session_ct_address``. Caller passes the full cache via the
    # helper below; we keep the lookup here so the public entry
    # points have a single shape.
    return None


# ── Public entry points ───────────────────────────────────────────────


async def cooperative_refund_submarine_leg(
    *,
    session: Any,
    refund_address: Optional[str] = None,
    fee_rate_sat_per_vb: Optional[int] = None,
    current_block_height: Optional[int] = None,
) -> LiquidRecoveryRefundResult:
    """Drive a Musig2 cooperative refund of the L-BTC submarine lockup.

    Only valid on the submarine leg of a Liquid round-trip. The
    cooperative branch does NOT require ``timeoutBlockHeight`` to
    have passed; it just needs Boltz to co-sign.

    ``refund_address`` defaults to the session's leg-1 cached CT
    address (the wallet's per-session blinded destination). Pass
    an explicit value to redirect the refund somewhere else.
    """
    leg = LEG_SUBMARINE
    boltz_swap_id, state = _hydrate_leg_state(session, leg)
    operator_id = _operator_id_for_leg(session, leg)
    operator_url = _resolve_operator_url(operator_id)
    if not operator_url:
        raise LiquidRecoveryOperatorMissingError(
            f"no operator URL resolvable for session {session.id} leg={leg!r} (operator_id={operator_id!r})"
        )

    network = resolve_liquid_network()
    asset_id = resolve_liquid_btc_asset_id()

    # The submarine-leg state stashes ``claim_public_key_hex``
    # (Boltz's claim pubkey, needed for cooperative Musig2).
    claim_pub = state.get("claim_public_key_hex")
    if not claim_pub:
        raise LiquidRecoveryStateMissingError("leg-2 swap_state missing claim_public_key_hex")

    # The lockup tx is the wallet's own broadcast; the lock
    # subprocess stashed ``lock_tx_hex`` on leg-2 state.
    lockup_tx_hex = state.get("lock_tx_hex")
    if not lockup_tx_hex:
        raise LiquidRecoveryStateMissingError(
            "leg-2 swap_state missing lock_tx_hex; the lock subprocess must run before a refund can be constructed"
        )

    # Pick a refund destination. Caller may override; otherwise
    # fall back to the session's leg-1 CT address (re-hydrated from
    # the persisted swap_state map).
    destination = refund_address
    if not destination:
        # Walk the hydrated swap_state for the session's leg-1 entry.
        local_state: dict[str, dict[str, Any]] = {}
        restore_session_swap_state(session, local_state)
        sid = str(session.id)
        for entry in local_state.values():
            if str(entry.get("session_id") or "") == sid and entry.get("leg") == "ln_to_lbtc":
                destination = entry.get("session_ct_address")
                break
    if not destination:
        raise LiquidRecoveryStateMissingError(
            "no refund_address provided and no leg-1 session_ct_address "
            "cached on the session — pass refund_address explicitly"
        )

    blinding_priv = state.get("blinding_privkey_hex")
    if not blinding_priv:
        raise LiquidRecoveryStateMissingError("leg-2 swap_state missing blinding_privkey_hex")
    refund_priv = state.get("refund_private_key_hex")
    if not refund_priv:
        raise LiquidRecoveryStateMissingError("leg-2 swap_state missing refund_private_key_hex")

    request = LiquidRefundRequest(
        boltz_url=str(operator_url),
        swap_id=boltz_swap_id,
        refund_private_key_hex=str(refund_priv),
        swap_tree=_build_swap_tree_dict(state),
        lockup_tx_hex=str(lockup_tx_hex),
        refund_address=str(destination),
        blinding_key_hex=str(blinding_priv),
        timeout_block_height=int(state.get("timeout_block_height") or 0),
        network=_network_to_subprocess_name(network),
        claim_public_key_hex=str(claim_pub),
        asset_id_hex=asset_id.hex(),
        current_block_height=current_block_height,
        fee_rate_sat_per_vb=fee_rate_sat_per_vb,
        mode="cooperative",
    )
    result = await run_liquid_refund_subprocess(request)
    return LiquidRecoveryRefundResult(
        session_id=str(session.id),
        leg=leg,
        boltz_swap_id=boltz_swap_id,
        mode=result.mode,
        txid=result.txid,
        operator_id=operator_id,
    )


async def unilateral_refund_submarine_leg(
    *,
    session: Any,
    refund_address: Optional[str] = None,
    fee_rate_sat_per_vb: Optional[int] = None,
    current_block_height: Optional[int] = None,
) -> LiquidRecoveryRefundResult:
    """Post-timeout script-path refund of the L-BTC submarine lockup.

    Same swap-state shape as the cooperative variant; the JS
    subprocess routes to the unilateral branch via ``mode``. The
    JS side enforces that ``currentBlockHeight >= timeoutBlockHeight``
    when the caller provides ``current_block_height``; this Python
    layer does not duplicate that check (the subprocess is the
    authority on chain-tip vs. timeout).
    """
    # The cooperative builder + the unilateral builder differ only
    # in ``mode``; everything else is identical. Re-use the
    # cooperative path's body via a flag.
    leg = LEG_SUBMARINE
    boltz_swap_id, state = _hydrate_leg_state(session, leg)
    operator_id = _operator_id_for_leg(session, leg)
    # Unilateral mode does not need a reachable operator (the JS
    # script broadcasts via the wallet's own electrs-liquid when
    # Boltz is down), but the request shape still needs a URL —
    # use the registry one when present, fall back to an empty
    # string so the subprocess can detect "no upstream" cleanly.
    operator_url = _resolve_operator_url(operator_id) or ""

    network = resolve_liquid_network()
    asset_id = resolve_liquid_btc_asset_id()

    lockup_tx_hex = state.get("lock_tx_hex")
    if not lockup_tx_hex:
        raise LiquidRecoveryStateMissingError(
            "leg-2 swap_state missing lock_tx_hex; the lock subprocess must run before a refund can be constructed"
        )

    destination = refund_address
    if not destination:
        local_state: dict[str, dict[str, Any]] = {}
        restore_session_swap_state(session, local_state)
        sid = str(session.id)
        for entry in local_state.values():
            if str(entry.get("session_id") or "") == sid and entry.get("leg") == "ln_to_lbtc":
                destination = entry.get("session_ct_address")
                break
    if not destination:
        raise LiquidRecoveryStateMissingError(
            "no refund_address provided and no leg-1 session_ct_address "
            "cached on the session — pass refund_address explicitly"
        )

    blinding_priv = state.get("blinding_privkey_hex")
    refund_priv = state.get("refund_private_key_hex")
    if not blinding_priv or not refund_priv:
        raise LiquidRecoveryStateMissingError("leg-2 swap_state missing refund key material")

    request = LiquidRefundRequest(
        boltz_url=str(operator_url),
        swap_id=boltz_swap_id,
        refund_private_key_hex=str(refund_priv),
        swap_tree=_build_swap_tree_dict(state),
        lockup_tx_hex=str(lockup_tx_hex),
        refund_address=str(destination),
        blinding_key_hex=str(blinding_priv),
        timeout_block_height=int(state.get("timeout_block_height") or 0),
        network=_network_to_subprocess_name(network),
        # Unilateral path does not require Boltz's claim pubkey
        # (no Musig2); omit so the JS subprocess picks the
        # script-path branch unambiguously.
        claim_public_key_hex=None,
        asset_id_hex=asset_id.hex(),
        current_block_height=current_block_height,
        fee_rate_sat_per_vb=fee_rate_sat_per_vb,
        mode="unilateral",
    )
    result = await run_liquid_refund_subprocess(request)
    return LiquidRecoveryRefundResult(
        session_id=str(session.id),
        leg=leg,
        boltz_swap_id=boltz_swap_id,
        mode=result.mode,
        txid=result.txid,
        operator_id=operator_id,
    )


async def unilateral_claim_reverse_leg(
    *,
    session: Any,
    destination_address: Optional[str] = None,
) -> LiquidRecoveryClaimResult:
    """Post-timeout script-path claim of Boltz's reverse lockup.

    Only valid on the reverse leg (LN→L-BTC). The wallet has the
    preimage + claim privkey + the Boltz-side blinding key; the JS
    subprocess script-path-spends the lockup to a wallet-controlled
    CT address.

    ``destination_address`` defaults to the leg's cached
    ``session_ct_address`` (the same destination the cooperative
    claim would have used).
    """
    leg = LEG_REVERSE
    boltz_swap_id, state = _hydrate_leg_state(session, leg)
    operator_id = _operator_id_for_leg(session, leg)
    operator_url = _resolve_operator_url(operator_id) or ""

    network = resolve_liquid_network()
    asset_id = resolve_liquid_btc_asset_id()

    lockup_tx_hex = state.get("lockup_tx_hex")
    if not lockup_tx_hex:
        raise LiquidRecoveryStateMissingError(
            "leg-1 swap_state missing lockup_tx_hex; the observer must "
            "stash the lockup tx before a claim can be constructed"
        )

    destination = destination_address or state.get("session_ct_address")
    if not destination:
        raise LiquidRecoveryStateMissingError(
            "no destination_address provided and no session_ct_address "
            "cached on the leg-1 state — pass destination_address explicitly"
        )

    preimage = state.get("preimage_hex")
    claim_priv = state.get("claim_private_key_hex")
    refund_pub = state.get("refund_public_key_hex")
    blinding_priv = state.get("blinding_privkey_hex")
    if not (preimage and claim_priv and refund_pub and blinding_priv):
        raise LiquidRecoveryStateMissingError(
            "leg-1 swap_state missing one or more of: preimage_hex, "
            "claim_private_key_hex, refund_public_key_hex, "
            "blinding_privkey_hex"
        )

    request = LiquidClaimRequest(
        boltz_url=str(operator_url),
        swap_id=boltz_swap_id,
        preimage_hex=str(preimage),
        claim_private_key_hex=str(claim_priv),
        refund_public_key_hex=str(refund_pub),
        swap_tree=_build_swap_tree_dict(state),
        lockup_tx_hex=str(lockup_tx_hex),
        destination_address=str(destination),
        blinding_key_hex=str(blinding_priv),
        network=_network_to_subprocess_name(network),
        asset_id_hex=asset_id.hex(),
        mode="unilateral",
    )
    result = await run_liquid_claim_subprocess(request)
    return LiquidRecoveryClaimResult(
        session_id=str(session.id),
        leg=leg,
        boltz_swap_id=boltz_swap_id,
        mode=getattr(result, "mode", "unilateral"),
        txid=result.txid,
        operator_id=operator_id,
    )


__all__ = [
    "LEG_REVERSE",
    "LEG_SUBMARINE",
    "LiquidRecoveryClaimResult",
    "LiquidRecoveryError",
    "LiquidRecoveryOperatorMissingError",
    "LiquidRecoveryRefundResult",
    "LiquidRecoveryStateMissingError",
    "LiquidRecoveryUnknownLegError",
    "cooperative_refund_submarine_leg",
    "unilateral_claim_reverse_leg",
    "unilateral_refund_submarine_leg",
]
