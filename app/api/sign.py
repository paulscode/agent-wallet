# SPDX-License-Identifier: MIT
"""
Sign / Verify Message API endpoints.

Sign endpoints prove control of an on-chain address (BIP-322 / BIP-137)
or the LN node identity key (zbase32). They are gated on:

- the `ENABLE_SIGN_ADDRESS_API` / `ENABLE_SIGN_NODE_API` env flags
  (controlled at mount time in ``app/main.py``); and
- an admin API key (write privilege).

Verify endpoints require only a read API key — no funds are at risk and
the operation is idempotent.

A per-API-key sliding-hour rate limit caps sign operations
(`SIGN_RATE_LIMIT_PER_HOUR`, default 30/hour). Verify is uncapped.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.rate_limit import check_sign_rate_limit
from app.core.security import get_admin_key, get_api_key
from app.core.sign_validation import (
    audit_message_details,
    normalise_message,
    validate_signature,
)
from app.core.utils import sanitize_upstream_error
from app.core.validation import validate_bitcoin_address
from app.models.api_key import APIKey
from app.services.audit_service import log_action
from app.services.lnd_service import lnd_service

logger = logging.getLogger(__name__)

# Three separate routers so the two sign endpoints can be mounted
# conditionally on their respective `ENABLE_SIGN_*_API` flag, while the
# verify endpoints are always available. Disabled sign routers are not
# mounted at all → 404 to probes (the surface is invisible).
sign_address_router = APIRouter(prefix=f"{API_V1_PREFIX}/wallet", tags=["sign"])
sign_node_router = APIRouter(prefix=f"{API_V1_PREFIX}/wallet", tags=["sign"])
verify_router = APIRouter(prefix=f"{API_V1_PREFIX}/wallet", tags=["sign"])


# ─── Request models ──────────────────────────────────────────────────


class SignAddressRequest(BaseModel):
    address: str = Field(..., min_length=14, max_length=100)
    message: str = Field(..., min_length=1)

    @field_validator("address")
    @classmethod
    def _validate_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        return normalise_message(v)


class VerifyAddressRequest(BaseModel):
    address: str = Field(..., min_length=14, max_length=100)
    message: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1, max_length=256)

    @field_validator("address")
    @classmethod
    def _validate_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        return normalise_message(v)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        return validate_signature(v)


class SignNodeRequest(BaseModel):
    message: str = Field(..., min_length=1)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        return normalise_message(v)


class VerifyNodeRequest(BaseModel):
    message: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1, max_length=256)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        return normalise_message(v)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        return validate_signature(v)


# ─── Helpers ─────────────────────────────────────────────────────────


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


async def _enforce_sign_rate_limit(api_key: APIKey) -> None:
    allowed, error = await check_sign_rate_limit(
        identity=str(api_key.id),
        max_per_hour=settings.sign_rate_limit_per_hour,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=error or "Sign rate limit reached")


# ─── Sign endpoints (admin) ──────────────────────────────────────────


@sign_address_router.post("/sign/address")
async def sign_address(
    request: Request,
    body: SignAddressRequest,
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(get_admin_key),
) -> Any:
    """Sign a message with the private key of an on-chain address."""
    await _enforce_sign_rate_limit(api_key)

    data, error = await lnd_service.sign_message_with_address(body.address, body.message)
    ip = _client_ip(request)
    audit = audit_message_details(body.message)
    audit["address"] = body.address

    if error:
        await log_action(
            db,
            api_key,
            "sign_message",
            "wallet:address",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))

    assert data is not None
    audit["signature"] = data["signature"]
    audit["format"] = data["format"]
    audit["address_type"] = data["address_type"]
    await log_action(
        db,
        api_key,
        "sign_message",
        "wallet:address",
        details=audit,
        ip_address=ip,
    )
    return data


@verify_router.post("/verify/address")
async def verify_address(
    request: Request,
    body: VerifyAddressRequest,
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Verify a signature against an on-chain address."""
    data, error = await lnd_service.verify_message_with_address(body.address, body.message, body.signature)
    ip = _client_ip(request)
    audit = audit_message_details(body.message)
    audit["address"] = body.address
    audit["signature"] = body.signature

    if error:
        await log_action(
            db,
            api_key,
            "verify_message",
            "wallet:address",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))

    assert data is not None
    audit["valid"] = data["valid"]
    await log_action(
        db,
        api_key,
        "verify_message",
        "wallet:address",
        details=audit,
        ip_address=ip,
    )
    return data


@sign_node_router.post("/sign/node")
async def sign_node(
    request: Request,
    body: SignNodeRequest,
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(get_admin_key),
) -> Any:
    """Sign a message with the LN node identity key (zbase32)."""
    await _enforce_sign_rate_limit(api_key)

    data, error = await lnd_service.sign_message_node(body.message)
    ip = _client_ip(request)
    audit = audit_message_details(body.message)

    if error:
        await log_action(
            db,
            api_key,
            "sign_message",
            "wallet:node",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))

    assert data is not None
    audit["signature"] = data["signature"]
    audit["node_pubkey"] = data["node_pubkey"]
    audit["format"] = "zbase32"
    await log_action(
        db,
        api_key,
        "sign_message",
        "wallet:node",
        details=audit,
        ip_address=ip,
    )
    return data


@verify_router.post("/verify/node")
async def verify_node(
    request: Request,
    body: VerifyNodeRequest,
    db: AsyncSession = Depends(get_db),
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Verify a zbase32 LN-node-identity signature."""
    data, error = await lnd_service.verify_message_node(body.message, body.signature)
    ip = _client_ip(request)
    audit = audit_message_details(body.message)
    audit["signature"] = body.signature

    if error:
        await log_action(
            db,
            api_key,
            "verify_message",
            "wallet:node",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))

    assert data is not None
    audit["valid"] = data["valid"]
    await log_action(
        db,
        api_key,
        "verify_message",
        "wallet:node",
        details=audit,
        ip_address=ip,
    )
    return data
