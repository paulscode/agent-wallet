# SPDX-License-Identifier: MIT
"""
Channel management API endpoints — open channels, connect peers.

Write operations require an admin API key.
"""

import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.idempotency import (
    get_idempotency_key,
    lookup_or_reserve,
    mark_pending,
    release_inflight,
    store_result,
)
from app.core.net_guard import validate_peer_host_not_internal
from app.core.rate_limit import check_payment_limits, rollback_payment_limits
from app.core.security import get_admin_key
from app.core.utils import lnd_broadcast_outcome_unknown, sanitize_upstream_error
from app.core.validation import MAX_SAT_PER_VBYTE, ONCHAIN_TX_VBYTE_ESTIMATE
from app.models.api_key import APIKey
from app.services.audit_service import log_action
from app.services.lnd_service import lnd_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{API_V1_PREFIX}/channels", tags=["channels"])


class ConnectPeerRequest(BaseModel):
    pubkey: str = Field(..., min_length=66, max_length=66, description="Hex-encoded node pubkey")
    host: str = Field(..., min_length=1, description="Host address (ip:port)")

    @field_validator("pubkey")
    @classmethod
    def validate_pubkey_hex(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{66}", v):
            raise ValueError("pubkey must be a 66-character hex string")
        return v.lower()

    @field_validator("host")
    @classmethod
    def validate_host_not_internal(cls, v: str) -> str:
        """Reject private/internal network addresses to prevent SSRF via LND."""
        return validate_peer_host_not_internal(v)


class OpenChannelRequest(BaseModel):
    node_pubkey: str = Field(..., min_length=66, max_length=66, description="Hex-encoded node pubkey")
    local_funding_amount: int = Field(..., gt=0, description="Channel capacity in sats")
    sat_per_vbyte: Optional[int] = Field(
        None,
        ge=1,
        le=MAX_SAT_PER_VBYTE,
        description=f"Fee rate for funding tx in sat/vB (1..{MAX_SAT_PER_VBYTE})",
    )
    push_sat: int = Field(0, ge=0, description="Amount to push to remote side")
    private: bool = Field(False, description="Private channel")

    @field_validator("node_pubkey")
    @classmethod
    def validate_pubkey_hex(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{66}", v):
            raise ValueError("node_pubkey must be a 66-character hex string")
        return v.lower()


@router.post("/connect-peer")
async def connect_peer(
    req: ConnectPeerRequest,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Connect to a Lightning Network peer."""
    data, error = await lnd_service.connect_peer(req.pubkey, req.host)
    if error:
        await log_action(
            db,
            api_key,
            "connect_peer",
            "lightning",
            details={"pubkey": req.pubkey, "host": req.host},
            success=False,
            error_message=error,
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))

    await log_action(
        db,
        api_key,
        "connect_peer",
        "lightning",
        details={"pubkey": req.pubkey, "host": req.host},
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "connected", "pubkey": req.pubkey}


@router.post("/open")
async def open_channel(
    req: OpenChannelRequest,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Open a new Lightning channel.

    Subject to per-payment safety limit, cumulative spend limit, and velocity breaker.
    Returns the funding transaction ID (channel is not yet confirmed).

    Clients may pass ``Idempotency-Key: <uuid>`` so a retried request returns
    the original funding transaction instead of opening a second channel.
    """
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

    # Tracks whether the in-flight marker is dropped on the way out. It is
    # cleared for an unknown funding-broadcast outcome so a retry is held
    # rather than committing a second channel.
    release_on_failure = True
    try:
        # Enforce per-payment safety limit
        max_sats = settings.lnd_max_payment_sats
        if max_sats != -1 and req.local_funding_amount > max_sats:
            raise HTTPException(
                status_code=400,
                detail=f"Channel size {req.local_funding_amount:,} sats exceeds "
                f"safety limit of {max_sats:,} sats. "
                f"Contact admin to adjust LND_MAX_PAYMENT_SATS.",
            )

        # Enforce cumulative spend + velocity limits. Fold the caller-controlled
        # funding-tx fee budget into the cumulative window (mirroring send-onchain)
        # so a small channel with a high ``sat_per_vbyte`` cannot drain the wallet
        # as miner fee outside the spend cap. The rate is already bounded by the
        # ``MAX_SAT_PER_VBYTE`` field clamp above.
        fee_budget = req.sat_per_vbyte * ONCHAIN_TX_VBYTE_ESTIMATE if req.sat_per_vbyte else 0
        allowed, limit_error, reservation = await check_payment_limits(
            req.local_funding_amount + fee_budget, str(api_key.id)
        )
        if not allowed:
            await log_action(
                db,
                api_key,
                "open_channel",
                "lightning",
                amount_sats=req.local_funding_amount,
                success=False,
                error_message=limit_error,
                ip_address=request.client.host if request.client else None,
            )
            raise HTTPException(status_code=429, detail=limit_error)

        data, error = await lnd_service.open_channel(
            req.node_pubkey,
            req.local_funding_amount,
            req.sat_per_vbyte,
            req.push_sat,
            req.private,
        )
        if error:
            await log_action(
                db,
                api_key,
                "open_channel",
                "lightning",
                amount_sats=req.local_funding_amount,
                details={"node_pubkey": req.node_pubkey},
                success=False,
                error_message=error,
                ip_address=request.client.host if request.client else None,
            )
            if lnd_broadcast_outcome_unknown(error):
                # The funding transaction may have been broadcast. Keep the
                # reservation and hold the slot so a same-key retry is rejected
                # rather than committing capacity to a second channel.
                if idem_key is not None:
                    release_on_failure = False
                    mark_pending(
                        api_key_id=str(api_key.id),
                        idem_key=idem_key,
                        request_body=req_body,
                        payment_hash="",
                    )
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Channel funding outcome is unknown and may have broadcast. "
                        "Retry the same Idempotency-Key once the chain state is clear; "
                        "do not re-open with a new key."
                    ),
                )
            await rollback_payment_limits(reservation)
            raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
        assert data is not None

        await log_action(
            db,
            api_key,
            "open_channel",
            "lightning",
            amount_sats=req.local_funding_amount,
            details={
                "node_pubkey": req.node_pubkey,
                "funding_txid": data.get("funding_txid"),
                "push_sat": req.push_sat,
                "private": req.private,
            },
            ip_address=request.client.host if request.client else None,
        )
        if idem_key is not None:
            store_result(
                api_key_id=str(api_key.id),
                idem_key=idem_key,
                request_body=req_body,
                response=data,
            )
        return data
    except BaseException:
        if idem_key is not None and release_on_failure:
            release_inflight(api_key_id=str(api_key.id), idem_key=idem_key)
        raise


@router.get("/pending/detail")
async def get_pending_channels_detail(
    api_key: APIKey = Depends(get_admin_key),
) -> Any:
    """Get detailed pending channel info (opening, closing, force-closing)."""
    result, error = await lnd_service.get_pending_channels_detail()
    if error:
        raise HTTPException(status_code=503, detail=sanitize_upstream_error(error, "LND"))
    return {"channels": result}
