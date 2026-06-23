# SPDX-License-Identifier: MIT
"""
Mempool Explorer API endpoints — transaction tracking, address lookups,
mempool statistics, and block height queries.

All endpoints are read-only and require a valid API key.
Data is fetched from the configured Mempool Explorer instance
(configurable via LND_MEMPOOL_URL, default: https://mempool.space).
"""

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.core.config import API_V1_PREFIX
from app.core.security import get_api_key
from app.models.api_key import APIKey
from app.services.mempool_fee_service import mempool_fee_service

router = APIRouter(prefix=f"{API_V1_PREFIX}/mempool", tags=["mempool"])

# Basic validation patterns
_TXID_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
_ADDRESS_PATTERN = re.compile(r"^[a-zA-Z0-9]{26,90}$")


def _validate_txid(txid: str) -> str:
    """Validate a transaction ID is a 64-char hex string."""
    if not _TXID_PATTERN.match(txid):
        raise HTTPException(status_code=400, detail="Invalid transaction ID (must be 64 hex characters)")
    return txid


def _validate_address(address: str) -> str:
    """Basic address format check."""
    if not _ADDRESS_PATTERN.match(address):
        raise HTTPException(status_code=400, detail="Invalid Bitcoin address format")
    return address


# ─── Transaction Endpoints ────────────────────────────────────────────


@router.get("/tx/{txid}")
async def get_transaction(txid: str, api_key: APIKey = Depends(get_api_key)) -> Any:
    """Look up a transaction by txid.

    Returns confirmation status, fee, size, and output details.
    Useful for tracking on-chain payments, channel opens, and Boltz claim transactions.
    """
    _validate_txid(txid)
    tx, error = await mempool_fee_service.get_transaction(txid)
    if error:
        raise HTTPException(status_code=404, detail="Transaction not found or Mempool Explorer unavailable")
    return tx


@router.get("/tx/{txid}/confirmations")
async def get_transaction_confirmations(txid: str, api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get the confirmation count for a transaction.

    Combines the transaction's block height with current chain tip
    to calculate how many blocks have been mined since confirmation.

    Returns `confirmations: 0` and `confirmed: false` for unconfirmed transactions.
    """
    _validate_txid(txid)
    result, error = await mempool_fee_service.get_transaction_confirmations(txid)
    if error:
        raise HTTPException(status_code=404, detail="Transaction not found or Mempool Explorer unavailable")
    return result


# ─── Address Endpoints ────────────────────────────────────────────────


@router.get("/address/{address}")
async def get_address_info(address: str, api_key: APIKey = Depends(get_api_key)) -> Any:
    """Look up an address — confirmed/unconfirmed balance, transaction counts.

    Useful for verifying cold storage deposits arrived or checking
    a destination address before sending funds.
    """
    _validate_address(address)
    info, error = await mempool_fee_service.get_address(address)
    if error:
        raise HTTPException(status_code=404, detail="Address not found or Mempool Explorer unavailable")
    return info


@router.get("/address/{address}/utxos")
async def get_address_utxos(address: str, api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get unspent transaction outputs (UTXOs) for an address.

    Returns each UTXO with txid, output index, value in sats, and confirmation status.
    """
    _validate_address(address)
    utxos, error = await mempool_fee_service.get_address_utxos(address)
    if error:
        raise HTTPException(status_code=404, detail="Address not found or Mempool Explorer unavailable")
    assert utxos is not None
    return {"address": address, "utxo_count": len(utxos), "utxos": utxos}


# ─── Mempool Statistics ──────────────────────────────────────────────


@router.get("/stats")
async def get_mempool_stats(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get current mempool congestion statistics (cached 30s).

    Returns pending transaction count, total virtual size, total fees,
    and a fee-rate histogram. Useful for AI agents to decide optimal
    timing for on-chain transactions.
    """
    stats, error = await mempool_fee_service.get_mempool_stats()
    if error:
        raise HTTPException(status_code=503, detail="Unable to fetch mempool statistics")
    return stats


# ─── Block Height ─────────────────────────────────────────────────────


@router.get("/block/tip/height")
async def get_block_tip_height(api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get the current blockchain tip height.

    Useful for monitoring Boltz swap timeouts — swaps have a
    timeout_block_height after which the counterparty can refund.
    Compare this value against swap.timeout_block_height to assess urgency.
    """
    height, error = await mempool_fee_service.get_block_tip_height()
    if error:
        raise HTTPException(status_code=503, detail="Unable to fetch block tip height")
    return {"height": height}


@router.get("/block/{height}")
async def get_block_by_height(height: int, api_key: APIKey = Depends(get_api_key)) -> Any:
    """Get block header info at a specific height.

    Returns block hash, timestamp, transaction count, size, and weight.
    """
    if height < 0:
        raise HTTPException(status_code=400, detail="Block height must be non-negative")
    block, error = await mempool_fee_service.get_block_by_height(height)
    if error:
        raise HTTPException(status_code=404, detail="Block not found or Mempool Explorer unavailable")
    return block
