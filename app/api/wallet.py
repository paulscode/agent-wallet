# SPDX-License-Identifier: MIT
"""
Wallet API endpoints — balances, node info, transactions.

Read-only operations only require a valid API key.
"""

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.config import API_V1_PREFIX, settings
from app.core.security import get_api_key
from app.core.utils import sanitize_upstream_error
from app.models.api_key import APIKey
from app.services.lnd_service import lnd_service
from app.services.mempool_fee_service import mempool_fee_service

router = APIRouter(prefix=f"{API_V1_PREFIX}/wallet", tags=["wallet"])


@router.get("/config")
async def get_wallet_config(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get wallet configuration status."""
    return {
        "lnd_configured": bool(settings.lnd_macaroon_hex),
        "mempool_url": settings.lnd_mempool_url.rstrip("/"),
        "max_payment_sats": settings.lnd_max_payment_sats,
        "network": settings.bitcoin_network,
    }


@router.get("/summary")
async def get_wallet_summary(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get combined wallet summary (on-chain + lightning balances, node info)."""
    summary, error = await lnd_service.get_wallet_summary()
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return summary


@router.get("/info")
async def get_node_info(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get LND node info (alias, pubkey, sync status)."""
    info, error = await lnd_service.get_info()
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return info


@router.get("/balance")
async def get_balance(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get combined on-chain and lightning balance."""
    (wallet, wallet_err), (channel, chan_err) = await asyncio.gather(
        lnd_service.get_wallet_balance(),
        lnd_service.get_channel_balance(),
    )
    if wallet is None and channel is None:
        raise HTTPException(
            status_code=503,
            detail=sanitize_upstream_error(wallet_err or chan_err or "Unable to connect to LND node.", "LND"),
        )
    return {"onchain": wallet, "lightning": channel}


@router.get("/fees")
async def get_recommended_fees(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get recommended fee rates from the configured Mempool Explorer."""
    fees, error = await mempool_fee_service.get_recommended_fees()
    if error:
        return {
            "priorities": None,
            "mempool_url": settings.lnd_mempool_url.rstrip("/"),
            "unavailable": True,
            "message": "Unable to fetch fee estimates from Mempool Explorer.",
        }
    assert fees is not None
    return {
        "priorities": {
            "low": {"label": "Low (~1 hour)", "sat_per_vbyte": fees.get("hourFee")},
            "medium": {"label": "Medium (~30 min)", "sat_per_vbyte": fees.get("halfHourFee")},
            "high": {"label": "High (next block)", "sat_per_vbyte": fees.get("fastestFee")},
        },
        "economy": fees.get("economyFee"),
        "minimum": fees.get("minimumFee"),
        "raw": fees,
        "mempool_url": settings.lnd_mempool_url.rstrip("/"),
    }


@router.get("/channels")
async def get_channels(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get list of open lightning channels."""
    channels, error = await lnd_service.get_channels()
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return {"channels": channels}


@router.get("/channels/pending")
async def get_pending_channels(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get pending channels (opening, closing, force-closing)."""
    pending, error = await lnd_service.get_pending_channels()
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return pending


@router.get("/payments")
async def get_payments(
    api_key: APIKey = Depends(get_api_key),
    limit: int = Query(default=20, ge=1, le=100),
) -> Any:
    """Get recent outgoing lightning payments."""
    payments, error = await lnd_service.get_recent_payments(max_payments=limit)
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return {"payments": payments}


@router.get("/invoices")
async def get_invoices(
    api_key: APIKey = Depends(get_api_key),
    limit: int = Query(default=20, ge=1, le=100),
) -> Any:
    """Get recent incoming lightning invoices."""
    invoices, error = await lnd_service.get_recent_invoices(num_max_invoices=limit)
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return {"invoices": invoices}


@router.get("/transactions")
async def get_transactions(
    api_key: APIKey = Depends(get_api_key),
    limit: int = Query(default=20, ge=1, le=100),
) -> Any:
    """Get recent on-chain transactions."""
    txns, error = await lnd_service.get_onchain_transactions(max_txns=limit)
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return {"transactions": txns}
