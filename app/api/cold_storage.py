# SPDX-License-Identifier: MIT
"""
Cold Storage API endpoints — Lightning-to-On-Chain via Boltz reverse swaps.

All write operations require admin auth.
Includes comprehensive Bitcoin address validation for mainnet/testnet/signet.
"""

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.idempotency import (
    get_idempotency_key,
    lookup_or_reserve,
    release_inflight,
    store_result,
)
from app.core.rate_limit import check_payment_limits, rollback_payment_limits
from app.core.security import get_api_key, get_spend_key
from app.core.utils import sanitize_upstream_error
from app.core.validation import ONCHAIN_TX_VBYTE_ESTIMATE, validate_bitcoin_address
from app.models.api_key import APIKey
from app.services.audit_service import log_action
from app.services.boltz_recovery import classify_recovery_state
from app.services.boltz_service import BOLTZ_MAX_AMOUNT_SATS, BOLTZ_MIN_AMOUNT_SATS, boltz_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{API_V1_PREFIX}/cold-storage", tags=["cold-storage"])


# ─── Request/Response Models ─────────────────────────────────────────


class InitiateSwapRequest(BaseModel):
    """Request to initiate a Lightning-to-cold-storage swap."""

    amount_sats: int = Field(
        ...,
        ge=BOLTZ_MIN_AMOUNT_SATS,
        le=BOLTZ_MAX_AMOUNT_SATS,
        description=f"Amount in sats ({BOLTZ_MIN_AMOUNT_SATS:,} – {BOLTZ_MAX_AMOUNT_SATS:,})",
    )
    destination_address: str = Field(
        ...,
        min_length=26,
        max_length=256,
        description="Bitcoin cold storage address",
    )
    routing_fee_limit_percent: float = Field(
        default=3.0,
        ge=0.1,
        le=10.0,
        description="Maximum Lightning routing fee as % of amount",
    )

    @field_validator("destination_address")
    @classmethod
    def validate_destination(cls, v: str) -> str:
        """Validate Bitcoin address format based on configured network."""
        return validate_bitcoin_address(v)


def _swap_to_response(swap: Any) -> dict:
    """Convert a BoltzSwap model to API response dict."""
    return {
        "id": str(swap.id),
        "boltz_swap_id": swap.boltz_swap_id,
        "status": swap.status.value,
        "boltz_status": swap.boltz_status,
        "invoice_amount_sats": swap.invoice_amount_sats,
        "onchain_amount_sats": swap.onchain_amount_sats,
        "destination_address": swap.destination_address,
        "fee_percentage": swap.fee_percentage,
        "miner_fee_sats": swap.miner_fee_sats,
        "boltz_invoice": swap.boltz_invoice,
        "claim_txid": swap.claim_txid,
        "timeout_block_height": swap.timeout_block_height,
        "error_message": swap.error_message,
        "status_history": swap.status_history,
        "created_at": swap.created_at.isoformat() if swap.created_at else None,
        "updated_at": swap.updated_at.isoformat() if swap.updated_at else None,
        "completed_at": swap.completed_at.isoformat() if swap.completed_at else None,
    }


async def _augment_with_chain_data(resp: dict, swap: Any) -> dict:
    """Optionally enrich a swap response with chain-derived fields.

    Adds (when available, ``None``-elided when not):

    * ``claim_confirmations`` / ``claim_block_height`` — confirmation
      count for the claim TX, sourced from the active chain backend
      (Electrum preferred via the ``mempool_fee_service`` facade).
    * ``blocks_until_timeout`` / ``current_block_height`` — tip-aware
      Boltz timeout urgency. Uses the pushed ``headers.subscribe``
      tip cache when Electrum is active (zero RPC); otherwise omitted.
    * ``recovery`` — structured recovery hint (state, severity,
      headline, detail, available actions, metadata) produced by
      :py:func:`app.services.boltz_recovery.classify_recovery_state`.
      Drives the dashboard recovery banner and exposes which
      operator endpoints are safe to invoke.

    All fields are best-effort. Failures silently degrade — the base
    response is always returned.
    """
    from app.services.mempool_fee_service import mempool_fee_service

    # Claim confirmations.
    claim_confirmations: int | None = None
    if swap.claim_txid:
        confs = await mempool_fee_service.optional_confirmations(swap.claim_txid)
        if confs is not None:
            claim_confirmations = confs.get("confirmations")
            resp["claim_confirmations"] = claim_confirmations
            resp["claim_block_height"] = confs.get("block_height")

    # Tip-aware Boltz timeout urgency.
    tip = mempool_fee_service.cached_tip_height
    if tip is not None:
        resp["current_block_height"] = tip
        if swap.timeout_block_height is not None:
            resp["blocks_until_timeout"] = swap.timeout_block_height - tip

    # Recovery hint. Pure function — cannot raise even if chain
    # data is missing; degrades to status-based copy.
    try:
        # Stamp mempool_age_seconds when the swap has a broadcast
        # claim that hasn't confirmed yet — drives the classifier's
        # fee-bump recommendation.
        mempool_age_seconds: int | None = None
        if swap.claim_broadcast_at is not None and (claim_confirmations or 0) == 0:
            from datetime import datetime, timezone

            broadcast_at = swap.claim_broadcast_at
            if broadcast_at.tzinfo is None:
                broadcast_at = broadcast_at.replace(tzinfo=timezone.utc)
            mempool_age_seconds = int((datetime.now(timezone.utc) - broadcast_at).total_seconds())
            resp["mempool_age_seconds"] = mempool_age_seconds
        # Parallel computation for the wallet-broadcast lockup
        # (submarine direction). The classifier surfaces an RBF
        # recommendation when this age crosses the stall threshold.
        lockup_mempool_age_seconds: int | None = None
        if getattr(swap, "lockup_txid", None) and getattr(swap, "lockup_broadcast_at", None) is not None:
            from datetime import datetime, timezone

            lockup_at = swap.lockup_broadcast_at
            if lockup_at.tzinfo is None:
                lockup_at = lockup_at.replace(tzinfo=timezone.utc)
            lockup_mempool_age_seconds = int((datetime.now(timezone.utc) - lockup_at).total_seconds())
            resp["lockup_mempool_age_seconds"] = lockup_mempool_age_seconds
        hint = classify_recovery_state(
            swap,
            btc_tip_height=tip,
            claim_confirmations=claim_confirmations,
            mempool_age_seconds=mempool_age_seconds,
            lockup_mempool_age_seconds=lockup_mempool_age_seconds,
        )
        resp["recovery"] = hint.to_dict()
    except Exception:  # noqa: BLE001
        logger.exception("Recovery classifier failed for swap %s", swap.id)
    return resp


# ─── Endpoints ────────────────────────────────────────────────────────


@router.get("/fees")
async def get_swap_fees(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get current Boltz reverse swap fees and limits."""
    pair_info, error = await boltz_service.get_reverse_pair_info()
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "Boltz"))
    assert pair_info is not None
    return {
        "min_amount_sats": pair_info["min"],
        "max_amount_sats": pair_info["max"],
        "fee_percentage": pair_info["fees_percentage"],
        "miner_fee_lockup_sats": pair_info["fees_miner_lockup"],
        "miner_fee_claim_sats": pair_info["fees_miner_claim"],
        "total_miner_fee_sats": pair_info["fees_miner_lockup"] + pair_info["fees_miner_claim"],
        "tor_enabled": settings.boltz_use_tor and bool(settings.lnd_tor_proxy),
    }


@router.post("/initiate")
async def initiate_swap(
    req: InitiateSwapRequest,
    request: Request,
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Start a Boltz reverse swap to send Lightning funds to cold storage.

    1. Creates a reverse swap with Boltz (via Tor if configured)
    2. Background task pays invoice, monitors, and claims
    3. Returns swap details for status tracking

    Clients may pass ``Idempotency-Key: <uuid>`` so a retried request returns
    the original swap instead of creating a second reverse swap.
    """
    import math

    from app.services.lnd_service import lnd_service

    idem_key = get_idempotency_key(request)
    req_body = req.model_dump()
    if idem_key is not None:
        cached = lookup_or_reserve(
            api_key_id=str(api_key.id),
            idem_key=idem_key,
            request_body=req_body,
        )
        if cached is not None:
            return cached

    try:
        return await _initiate_swap_inner(
            req=req,
            request=request,
            api_key=api_key,
            db=db,
            lnd_service=lnd_service,
            math=math,
        )
    except BaseException:
        # Swap creation does not move funds synchronously (the Lightning
        # outflow happens in the background task against the persisted swap),
        # so every failure here leaves nothing committed and the key may be
        # retried. A successful 2xx already replaced the marker.
        if idem_key is not None:
            release_inflight(api_key_id=str(api_key.id), idem_key=idem_key)
        raise


async def _initiate_swap_inner(
    *,
    req: "InitiateSwapRequest",
    request: Request,
    api_key: APIKey,
    db: AsyncSession,
    lnd_service: Any,
    math: Any,
) -> Any:
    idem_key = get_idempotency_key(request)
    req_body = req.model_dump()
    # The reverse swap pays a Lightning hold invoice whose routing budget
    # is ``amount_sats × routing_fee_limit_percent`` (see the background
    # task). That fee is real outflow, so it is folded into both the
    # per-payment ceiling and the cumulative spend window — mirroring the
    # ``/pay`` endpoint — so an outsized routing-fee percent cannot move
    # value past LND_MAX_PAYMENT_SATS or the rolling ledger.
    routing_fee_budget = math.ceil(req.amount_sats * req.routing_fee_limit_percent / 100.0)
    total_sats = req.amount_sats + routing_fee_budget

    # Enforce per-payment safety limit
    max_sats = settings.lnd_max_payment_sats
    if max_sats != -1 and total_sats > max_sats:
        raise HTTPException(
            status_code=400,
            detail=f"Swap of {req.amount_sats:,} sats plus up to "
            f"{routing_fee_budget:,} sats routing fee exceeds safety limit "
            f"of {max_sats:,} sats. "
            f"Contact admin to adjust LND_MAX_PAYMENT_SATS.",
        )

    # Enforce cumulative spend + velocity limits
    allowed, limit_error, reservation = await check_payment_limits(total_sats, str(api_key.id))
    if not allowed:
        await log_action(
            db,
            api_key,
            "initiate_swap",
            "cold_storage",
            amount_sats=req.amount_sats,
            success=False,
            error_message=limit_error,
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=429, detail=limit_error)

    # Check Lightning balance
    channel_balance, _bal_err = await lnd_service.get_channel_balance()
    if channel_balance:
        local_balance = int(channel_balance.get("local_balance_sat", 0))
        if local_balance < req.amount_sats:
            await rollback_payment_limits(reservation)
            raise HTTPException(
                status_code=400,
                detail=f"Insufficient Lightning balance: {local_balance:,} sats available, "
                f"{req.amount_sats:,} sats requested.",
            )

    swap, error = await boltz_service.create_reverse_swap(
        db=db,
        api_key_id=api_key.id,
        invoice_amount_sats=req.amount_sats,
        destination_address=req.destination_address,
    )
    if error:
        await rollback_payment_limits(reservation)
        await log_action(
            db,
            api_key,
            "initiate_swap",
            "cold_storage",
            amount_sats=req.amount_sats,
            success=False,
            error_message=error,
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "Boltz"))
    assert swap is not None

    # Schedule the Celery background task
    from app.tasks.boltz_tasks import process_boltz_swap

    process_boltz_swap.delay(str(swap.id), routing_fee_limit_percent=req.routing_fee_limit_percent)

    await log_action(
        db,
        api_key,
        "initiate_swap",
        "cold_storage",
        amount_sats=req.amount_sats,
        details={
            "boltz_swap_id": swap.boltz_swap_id,
            "destination": req.destination_address,
        },
        ip_address=request.client.host if request.client else None,
    )

    response = _swap_to_response(swap)
    if idem_key is not None:
        store_result(
            api_key_id=str(api_key.id),
            idem_key=idem_key,
            request_body=req_body,
            response=response,
        )
    return response


@router.get("/swaps")
async def list_swaps(
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=50),
) -> Any:
    """List recent cold storage swaps."""
    swaps = await boltz_service.get_swaps_for_key(db, api_key.id, limit)
    return {"swaps": [_swap_to_response(s) for s in swaps]}


@router.get("/swaps/{swap_id}")
async def get_swap_status(
    swap_id: str,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Get current status of a cold storage swap."""
    try:
        swap_uuid = UUID(swap_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid swap ID format")

    swap = await boltz_service.get_swap_by_id(db, swap_uuid)
    if not swap:
        raise HTTPException(status_code=404, detail="Swap not found")
    if swap.api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="Swap not found")

    return await _augment_with_chain_data(_swap_to_response(swap), swap)


@router.post("/swaps/{swap_id}/cooperative-claim")
async def retry_cooperative_claim_endpoint(
    swap_id: str,
    request: Request,
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator-driven retry of the cooperative Taproot claim.

    Re-fetches the lockup transaction from Boltz and re-runs the
    Musig2 cooperative claim subprocess. Safe to call multiple
    times; on success the swap transitions to ``CLAIMED``. On
    failure the swap's ``recovery_count`` is incremented and the
    error is recorded on ``error_message``.

    Only valid while the swap is in ``CLAIMING`` status without a
    persisted ``claim_txid``.
    """
    try:
        swap_uuid = UUID(swap_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid swap ID format")

    swap = await boltz_service.get_swap_by_id(db, swap_uuid)
    if not swap:
        raise HTTPException(status_code=404, detail="Swap not found")
    if swap.api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="Swap not found")

    txid, error = await boltz_service.retry_cooperative_claim(db, swap)

    await log_action(
        db,
        api_key,
        "cold_storage_cooperative_claim_attempted",
        "cold_storage",
        details={
            "boltz_swap_id": swap.boltz_swap_id,
            "claim_txid": txid,
            "recovery_count": swap.recovery_count or 0,
        },
        success=txid is not None,
        error_message=error,
        ip_address=request.client.host if request.client else None,
    )

    if error:
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "Boltz"))

    return await _augment_with_chain_data(_swap_to_response(swap), swap)


@router.post("/swaps/{swap_id}/unilateral-claim")
async def unilateral_claim_endpoint(
    swap_id: str,
    request: Request,
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator-driven unilateral (script-path) claim.

    Spends the Boltz lockup via the swap's claim leaf without
    requiring Boltz cooperation. Refuses to run unless the lockup
    timeout has already passed (verified against the cached chain
    tip). On success the swap transitions to ``CLAIMED``; on
    failure ``recovery_count`` is incremented.

    Intended as the post-timeout escape hatch when Boltz refuses
    to co-sign the cooperative claim.
    """
    from app.services.mempool_fee_service import mempool_fee_service

    try:
        swap_uuid = UUID(swap_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid swap ID format")

    swap = await boltz_service.get_swap_by_id(db, swap_uuid)
    if not swap:
        raise HTTPException(status_code=404, detail="Swap not found")
    if swap.api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="Swap not found")

    tip = mempool_fee_service.cached_tip_height
    txid, error = await boltz_service.retry_unilateral_claim(
        db,
        swap,
        btc_tip_height=tip,
    )

    await log_action(
        db,
        api_key,
        "cold_storage_unilateral_claim_attempted",
        "cold_storage",
        details={
            "boltz_swap_id": swap.boltz_swap_id,
            "claim_txid": txid,
            "recovery_count": swap.recovery_count or 0,
            "current_block_height": tip,
            "timeout_block_height": swap.timeout_block_height,
        },
        success=txid is not None,
        error_message=error,
        ip_address=request.client.host if request.client else None,
    )

    if error:
        # 4xx for safety-check failures (timeout not yet passed,
        # wrong status) so the dashboard can render them inline
        # rather than as a generic upstream failure.
        status_code = (
            400
            if ("timeout has not passed" in error or "only valid" in error or "no recorded timeout" in error)
            else 502
        )
        raise HTTPException(status_code=status_code, detail=sanitize_upstream_error(error, "Boltz"))

    return await _augment_with_chain_data(_swap_to_response(swap), swap)


@router.post("/swaps/{swap_id}/bump-fee")
async def bump_fee_endpoint(
    swap_id: str,
    request: Request,
    sat_per_vbyte: int = Query(
        ...,
        ge=1,
        le=1000,
        description="Replacement fee rate in sat/vB (1..1000).",
    ),
    target: str = Query(
        "claim",
        pattern="^(claim|lockup)$",
        description=(
            "Which wallet-broadcast tx to bump: 'claim' (CPFP on the "
            "reverse-swap claim) or 'lockup' (RBF on the submarine "
            "lockup). Defaults to 'claim'."
        ),
    ),
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator-driven fee bump for a stuck wallet-broadcast swap tx.

    Two modes:

    * ``target=claim`` \u2014 CPFP against the reverse-swap claim output
      at vout 0 (single-output sweep). Used when the wallet's claim
      has been parked in the mempool past the classifier's stall
      threshold without confirming.
    * ``target=lockup`` \u2014 RBF against the submarine-swap lockup tx
      stored on ``swap.lockup_txid``. LND's WalletKit picks the
      replacement mechanism based on whether the outpoint is the
      wallet's own input.

    Refuses unless the corresponding txid is set on the swap (no
    broadcast \u2192 nothing to bump). The endpoint does NOT enforce
    the stall threshold itself \u2014 the classifier's
    ``fee_bump_recommended`` metadata is advisory; the operator can
    choose to bump earlier (e.g. fee market surge) at their
    discretion.
    """
    from app.services.lnd_service import lnd_service

    # Normalise the Query default when called directly (tests bypass
    # FastAPI routing and receive the Query() sentinel object).
    if not isinstance(target, str):
        target = "claim"
    if target not in ("claim", "lockup"):
        raise HTTPException(
            status_code=400,
            detail="target must be one of: 'claim', 'lockup'",
        )

    try:
        swap_uuid = UUID(swap_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid swap ID format")

    swap = await boltz_service.get_swap_by_id(db, swap_uuid)
    if not swap:
        raise HTTPException(status_code=404, detail="Swap not found")
    if swap.api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="Swap not found")

    if target == "claim":
        if not swap.claim_txid:
            raise HTTPException(
                status_code=400,
                detail="Swap has no claim_txid; nothing to bump.",
            )
        bump_txid = swap.claim_txid
        # The wallet-broadcast claim spends Boltz's lockup to the
        # destination address at output index 0 (single-output sweep).
        # CPFP works by pinning the claim outpoint and paying a higher
        # effective fee rate across the package.
        bump_output_index = 0
    else:  # target == "lockup"
        if not swap.lockup_txid:
            raise HTTPException(
                status_code=400,
                detail="Swap has no lockup_txid; nothing to bump.",
            )
        bump_txid = swap.lockup_txid
        # LND's BumpFee accepts any outpoint of the wallet-broadcast
        # transaction. We pass the lockup's wallet-paying output at
        # vout 0 \u2014 LND identifies the tx as wallet-broadcast and
        # routes through RBF rather than CPFP.
        bump_output_index = 0

    # A fee bump spends wallet funds as miner fee (a CPFP child or an RBF
    # replacement), so the bounded fee budget is charged against the
    # cumulative spend window and the velocity limiter. Repeated bumps
    # therefore accumulate toward the rolling cap and an automated key
    # cannot loop the endpoint to burn balance unmetered. The estimate
    # uses the same rate × vbyte model as the on-chain send path.
    fee_budget = int(sat_per_vbyte) * ONCHAIN_TX_VBYTE_ESTIMATE
    allowed, limit_error, reservation = await check_payment_limits(fee_budget, str(api_key.id))
    if not allowed:
        await log_action(
            db,
            api_key,
            "cold_storage_bump_fee_attempted",
            "cold_storage",
            details={
                "boltz_swap_id": swap.boltz_swap_id,
                "target": target,
                "txid": bump_txid,
                "sat_per_vbyte": int(sat_per_vbyte),
            },
            success=False,
            error_message=limit_error,
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=429, detail=limit_error)

    result, error = await lnd_service.bump_fee(
        txid_str=bump_txid,
        output_index=bump_output_index,
        sat_per_vbyte=int(sat_per_vbyte),
    )

    if error:
        await rollback_payment_limits(reservation)

    await log_action(
        db,
        api_key,
        "cold_storage_bump_fee_attempted",
        "cold_storage",
        details={
            "boltz_swap_id": swap.boltz_swap_id,
            "target": target,
            "txid": bump_txid,
            "sat_per_vbyte": int(sat_per_vbyte),
        },
        success=error is None,
        error_message=error,
        ip_address=request.client.host if request.client else None,
    )

    if error:
        raise HTTPException(
            status_code=502,
            detail=sanitize_upstream_error(error, "LND"),
        )

    return {
        "boltz_swap_id": swap.boltz_swap_id,
        "target": target,
        "txid": bump_txid,
        "sat_per_vbyte": int(sat_per_vbyte),
        "result": result or {},
    }


@router.post("/swaps/{swap_id}/cancel")
async def cancel_swap(
    swap_id: str,
    request: Request,
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Cancel a swap if still in early stages (before invoice payment)."""
    try:
        swap_uuid = UUID(swap_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid swap ID format")

    swap = await boltz_service.get_swap_by_id(db, swap_uuid)
    if not swap:
        raise HTTPException(status_code=404, detail="Swap not found")
    if swap.api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="Swap not found")

    success, error = await boltz_service.cancel_swap(db, swap)
    if not success:
        raise HTTPException(status_code=400, detail=error)

    await log_action(
        db,
        api_key,
        "cancel_swap",
        "cold_storage",
        details={"boltz_swap_id": swap.boltz_swap_id},
        ip_address=request.client.host if request.client else None,
    )

    return _swap_to_response(swap)
