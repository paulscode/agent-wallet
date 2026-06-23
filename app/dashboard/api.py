# SPDX-License-Identifier: MIT
"""
Dashboard JSON API endpoints.

All endpoints require dashboard session cookie authentication.
They proxy directly to the internal Python services (no API key needed).

Security Model
--------------
The dashboard is the node owner's direct management interface. It
intentionally does NOT enforce the API-layer payment safety limits
(LND_MAX_PAYMENT_SATS, spend rate limits, velocity breakers). Those
limits exist as guardrails for AI agent callers, which have a higher
risk of compromise or erroneous operation. The human operator should
have unrestricted control over their node, consistent with any native
Lightning node management tool. Session-level protections (cookie
security, login rate limiting, configurable timeout) are the
appropriate security controls for this interface.
"""

import asyncio
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.limiter import limiter
from app.core.net_guard import validate_peer_host_not_internal
from app.core.utils import _HEX64_PATTERN, sanitize_upstream_error
from app.core.validation import validate_bitcoin_address
from app.dashboard import DASHBOARD_KEY_ID
from app.dashboard.auth import (
    COOKIE_NAME,
    CSRF_BACKEND_UNAVAILABLE,
    CSRF_OK,
    check_csrf_token,
    check_login_lockout,
    clear_login_failures,
    clear_session_cookie,
    create_session_cookie,
    generate_login_nonce,
    record_login_failure,
    revoke_session,
    rotate_csrf_token,
    verify_login_nonce,
    verify_login_origin,
    verify_session,
    verify_token,
)
from app.models.audit_log import AuditLog
from app.services import api_key_service, utxo_service
from app.services.alert_service import send_alert
from app.services.api_key_service import DashboardActor
from app.services.audit_service import log_dashboard_action, reanchor_chain, verify_chain
from app.services.boltz_service import boltz_service
from app.services.lnd_service import lnd_service
from app.services.lnd_types import Outpoint
from app.services.lnurl_service import get_lnurl_service
from app.services.mempool_fee_service import mempool_fee_service

if TYPE_CHECKING:
    from app.services.anonymize.liquid_residual_recovery import ResidualRecoveryDeps

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard/api")


def _check_dashboard_payment_limit(amount_sats: int | None) -> None:
    """Raise 400 if amount exceeds DASHBOARD_MAX_PAYMENT_SATS (when set)."""
    limit = settings.dashboard_max_payment_sats
    if limit < 0 or amount_sats is None:
        return
    if amount_sats > limit:
        raise HTTPException(
            status_code=400,
            detail=f"Amount {amount_sats} sats exceeds dashboard limit of {limit} sats",
        )


# ── Auth dependency ──────────────────────────────────────────────────────


async def _require_auth(request: Request) -> None:
    """Dependency that rejects unauthenticated requests."""
    if not await verify_session(request):
        raise _unauth()


async def _require_auth_csrf(request: Request, response: Response) -> None:
    """Dependency for write endpoints: session auth + CSRF token check.

    Validates the X-CSRF-Token header against the server-side session
    token. Maps the granular result to either 403 (genuine violation)
    or 503 (backend outage) and fires a ``csrf_violation`` alert on
    real mismatches.

    On success this rotates the session's CSRF token and surfaces the
    new value via the ``X-CSRF-Token-Next`` response header — see

    (rotate-on-use defeats long-lived token replay).
    """
    if not await verify_session(request):
        raise _unauth()
    result = await check_csrf_token(request)
    if result == CSRF_OK:
        # Rotate-on-use: mint a new CSRF token for the next request
        # and expose it to the client. Best-effort — if rotation
        # fails (Redis unreachable) we still let the current request
        # through; ``check_csrf_token`` already proved the caller
        # held a valid token.
        next_token = await rotate_csrf_token(request)
        if next_token:
            # Stash on request.state so the security-headers middleware can
            # attach it to the *final* response. Setting it only on the
            # injected ``response`` here is lost whenever a handler returns
            # its own Response (FastAPI doesn't merge dependency headers onto
            # a directly-returned Response), which on error paths would drop
            # the rotated token and wedge the client at 403 on the next write.
            request.state.csrf_next = next_token
            response.headers["X-CSRF-Token-Next"] = next_token
        return
    if result == CSRF_BACKEND_UNAVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="CSRF verification unavailable. Please try again shortly.",
        )
    # Genuine violation — alert and reject with 403.
    ip = request.client.host if request.client else None
    try:
        await send_alert(
            "csrf_violation",
            f"Dashboard CSRF check failed ({result}) from {ip} on {request.url.path}",
        )
    except Exception:
        pass
    raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


def _unauth() -> HTTPException:
    from fastapi import HTTPException

    return HTTPException(status_code=401, detail="Not authenticated")


def _cookie_subject(request: Request) -> str:
    """Resolve the stable per-principal subject for quote-token binding.

    The dashboard session cookie is the principal identity; the quote
    layer HMACs this value so a token issued to one session cannot be
    replayed by another. These endpoints run behind ``_require_auth`` /
    ``_require_auth_csrf`` so the cookie is present and valid; refuse the
    request rather than fall back to a shared constant, which would make
    every caller share one subject and let one principal replay
    another's quote token.
    """
    subject = request.cookies.get(COOKIE_NAME)
    if not subject:
        raise _unauth()
    return subject


# ── Request models ───────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    # The dashboard authenticates with a shared password (rendered as
    # "Dashboard Password" in the UI). Older callers may still send
    # ``token`` — accept either for backward compatibility. Exactly
    # one of the two must be present.
    password: Optional[str] = None
    token: Optional[str] = None
    # Signed, time-bounded login nonce obtained from ``GET
    # /dashboard/api/login-nonce``. Required to defeat login-CSRF on the
    # JSON path, mirroring the hidden field on the HTML login form.
    login_nonce: Optional[str] = None

    @model_validator(mode="after")
    def _require_one(self) -> "LoginRequest":
        if not (self.password or self.token):
            raise ValueError("password (or legacy token) is required")
        return self

    @property
    def credential(self) -> str:
        return self.password or self.token or ""


class AddressRequest(BaseModel):
    address_type: str = "p2tr"
    purpose: str = ""

    @field_validator("purpose")
    @classmethod
    def _validate_purpose(cls, v: str) -> str:
        if v is None:
            return ""
        if len(v) > 80:
            raise ValueError("purpose exceeds 80 characters")
        return v


class InvoiceRequest(BaseModel):
    amount_sats: int = Field(gt=0)
    memo: str = ""
    expiry: int = Field(default=3600, ge=60, le=86400)


class DecodeRequest(BaseModel):
    payment_request: str


class PayRequest(BaseModel):
    payment_request: str
    fee_limit_sats: int = Field(default=100, ge=0, le=1_000_000)
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    # Optional outgoing-channel pin. When set, the dashboard routes the
    # payment via ``/v2/router/send`` (``send_payment_v2``) so the pin
    # is honoured — the legacy ``/v1/channels/transactions`` endpoint
    # cannot constrain the first hop.
    outgoing_chan_id: Optional[str] = Field(default=None, min_length=1, max_length=20)

    @field_validator("outgoing_chan_id")
    @classmethod
    def _validate_outgoing_chan_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not re.fullmatch(r"\d{1,20}", v):
            raise ValueError("outgoing_chan_id must be a numeric string")
        # uint64 bound.
        if int(v) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("outgoing_chan_id exceeds uint64 max")
        return v


class PayQuoteRequest(BaseModel):
    """Probe a route for a third-party invoice — read-only / dry-run."""

    payment_request: str
    fee_limit_sats: int = Field(default=1_000_000, ge=0, le=1_000_000)
    outgoing_chan_id: Optional[str] = Field(default=None, min_length=1, max_length=20)

    @field_validator("outgoing_chan_id")
    @classmethod
    def _validate_outgoing_chan_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not re.fullmatch(r"\d{1,20}", v):
            raise ValueError("outgoing_chan_id must be a numeric string")
        if int(v) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("outgoing_chan_id exceeds uint64 max")
        return v


class OutpointModel(BaseModel):
    """Single (txid, vout) reference for coin-control bodies."""

    txid_str: str = Field(..., min_length=64, max_length=64)
    output_index: int = Field(..., ge=0, lt=2**31)

    @field_validator("txid_str")
    @classmethod
    def _validate_txid(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError("txid_str must be a 64-char hex string")
        return v.lower()


class SendOnchainRequest(BaseModel):
    address: str
    amount_sats: int = Field(gt=0)
    # Bounded so a high fee rate cannot drain the wallet as miner fee; matches
    # the sibling consolidate / close-channel dashboard ceiling.
    sat_per_vbyte: Optional[int] = Field(default=None, ge=1, le=10_000)
    label: str = ""
    outpoints: Optional[list[OutpointModel]] = None

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)

    @field_validator("outpoints")
    @classmethod
    def _limit_outpoints(cls, v: Optional[list[OutpointModel]]) -> Optional[list[OutpointModel]]:
        if v is not None and len(v) > 200:
            raise ValueError("outpoints list cannot exceed 200 entries")
        return v


class EstimateFeeRequest(BaseModel):
    address: str
    amount_sats: int = Field(gt=0)
    target_conf: int = Field(default=6, ge=1, le=144)
    outpoints: Optional[list[OutpointModel]] = None

    @field_validator("outpoints")
    @classmethod
    def _limit_outpoints(cls, v: Optional[list[OutpointModel]]) -> Optional[list[OutpointModel]]:
        if v is not None and len(v) > 200:
            raise ValueError("outpoints list cannot exceed 200 entries")
        return v


class UtxoLabelUpdateRequest(BaseModel):
    label: str = ""

    @field_validator("label")
    @classmethod
    def _validate_label(cls, v: str) -> str:
        # Defer the bulk of the work to the service-layer normaliser
        # but provide an early bound check so we don't drag huge bodies
        # through Pydantic.
        if v is None:
            return ""
        if not isinstance(v, str):
            raise ValueError("label must be a string")
        if len(v) > 80:
            raise ValueError("label exceeds 80 characters")
        return v


class ConsolidateRequest(BaseModel):
    outpoints: list[OutpointModel] = Field(..., min_length=1, max_length=200)
    dest_address_type: str = "p2wkh"
    sat_per_vbyte: Optional[int] = Field(default=None, ge=1, le=10_000)
    label: str = ""

    @field_validator("dest_address_type")
    @classmethod
    def _validate_addr_type(cls, v: str) -> str:
        if v not in ("p2tr", "p2wkh", "np2wkh"):
            raise ValueError("dest_address_type must be one of p2tr/p2wkh/np2wkh")
        return v

    @field_validator("label")
    @classmethod
    def _validate_label(cls, v: str) -> str:
        if v is None:
            return ""
        if len(v) > 80:
            raise ValueError("label exceeds 80 characters")
        return v


class OpenChannelRequest(BaseModel):
    pubkey: str = Field(..., min_length=66, max_length=66)
    host: str = ""
    local_funding_amount: int = Field(gt=0)
    # Bounded so a high funding-tx fee rate cannot drain the wallet as miner
    # fee; matches the sibling consolidate / close-channel dashboard ceiling.
    sat_per_vbyte: Optional[int] = Field(default=None, ge=1, le=10_000)
    push_sat: int = 0
    private: bool = False

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
        if not v:
            return v
        return validate_peer_host_not_internal(v)


class CloseChannelRequest(BaseModel):
    # ``channel_point`` is the funding outpoint "txid:vout" as surfaced by
    # ``get_channels()``. Closing cooperatively needs the peer online;
    # ``force`` broadcasts our commitment for an offline peer (funds are
    # then time-locked until the channel's CSV matures).
    channel_point: str
    force: bool = False
    # Optional fee rate for the closing transaction. Defaulted/forward-
    # compatible: when omitted, LND picks a reasonable fee.
    sat_per_vbyte: Optional[int] = Field(default=None, ge=1, le=10_000)

    @field_validator("channel_point")
    @classmethod
    def validate_channel_point(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}:\d{1,5}", v):
            raise ValueError("channel_point must be 'txid:vout'")
        return v


class ColdStorageRequest(BaseModel):
    amount_sats: int = Field(gt=0)
    destination_address: str
    # Free-form discriminator surfaced in the audit log's ``details``
    # dict. The dashboard currently emits one of:
    #   * ``"cold_storage"`` — the original Cold Storage withdrawal flow.
    #   * ``"inbound_liquidity"`` — the Add-Receive-Capacity wizard.
    # Kept ``Optional`` so old clients that don't send the field continue
    # to work; defaults to ``"cold_storage"`` in the handler when absent
    # so a search for ``purpose=cold_storage`` audit rows isn't blind
    # to legacy entries.
    purpose: Optional[str] = Field(default=None, max_length=32)
    # Optional outgoing-channel pin. When set, the reverse-swap's
    # Lightning leg is forced to leave through this channel, draining its
    # local balance and raising its inbound (remote) balance — the
    # mechanism behind opening receive capacity on a chosen channel.
    outgoing_chan_id: Optional[str] = Field(default=None, min_length=1, max_length=20)

    @field_validator("destination_address")
    @classmethod
    def validate_dest_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)

    @field_validator("purpose")
    @classmethod
    def validate_purpose(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        # Accept only an explicit allow-list. Unknown values are
        # silently dropped to keep operator-facing audit queries
        # predictable.
        if v not in ("cold_storage", "inbound_liquidity"):
            return None
        return v

    @field_validator("outgoing_chan_id")
    @classmethod
    def validate_outgoing_chan_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if not re.fullmatch(r"\d{1,20}", v):
            raise ValueError("outgoing_chan_id must be a numeric string")
        # uint64 bound.
        if int(v) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("outgoing_chan_id exceeds uint64 max")
        return v


class RebalanceQuoteRequest(BaseModel):
    """Probe for a circular self-payment route — read-only / dry-run."""

    source_chan_id: str = Field(..., min_length=1, max_length=20)
    dest_chan_id: str = Field(..., min_length=1, max_length=20)
    amount_sats: int = Field(..., gt=0, le=1_000_000_000)
    fee_limit_sats: Optional[int] = Field(None, ge=0, le=1_000_000)

    @field_validator("source_chan_id", "dest_chan_id")
    @classmethod
    def validate_chan_id(cls, v: str) -> str:
        if not re.fullmatch(r"\d{1,20}", v):
            raise ValueError("chan_id must be a numeric string")
        # uint64 bound.
        if int(v) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("chan_id exceeds uint64 max")
        return v


class RebalanceRequest(BaseModel):
    """Execute a circular self-payment between two of our own channels."""

    source_chan_id: str = Field(..., min_length=1, max_length=20)
    dest_chan_id: str = Field(..., min_length=1, max_length=20)
    amount_sats: int = Field(..., gt=0, le=1_000_000_000)
    fee_limit_sats: int = Field(..., ge=0, le=1_000_000)
    timeout_seconds: int = Field(default=60, ge=5, le=300)

    @field_validator("source_chan_id", "dest_chan_id")
    @classmethod
    def validate_chan_id(cls, v: str) -> str:
        if not re.fullmatch(r"\d{1,20}", v):
            raise ValueError("chan_id must be a numeric string")
        if int(v) > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("chan_id exceeds uint64 max")
        return v

    @model_validator(mode="after")
    def _fee_must_not_exceed_amount(self) -> "RebalanceRequest":
        # Defensive cap: a rebalance should never burn more in fees
        # than the principal it moves. Plan.
        if self.fee_limit_sats > self.amount_sats:
            raise ValueError("fee_limit_sats must not exceed amount_sats")
        return self


class SignAddressDashRequest(BaseModel):
    address: str = Field(..., min_length=14, max_length=100)
    message: str = Field(..., min_length=1)

    @field_validator("address")
    @classmethod
    def _validate_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        from app.core.sign_validation import normalise_message

        return normalise_message(v)


class VerifyAddressDashRequest(BaseModel):
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
        from app.core.sign_validation import normalise_message

        return normalise_message(v)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        from app.core.sign_validation import validate_signature

        return validate_signature(v)


class SignNodeDashRequest(BaseModel):
    message: str = Field(..., min_length=1)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        from app.core.sign_validation import normalise_message

        return normalise_message(v)


class VerifyNodeDashRequest(BaseModel):
    message: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1, max_length=256)

    @field_validator("message")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        from app.core.sign_validation import normalise_message

        return normalise_message(v)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        from app.core.sign_validation import validate_signature

        return validate_signature(v)


class ParseSignedRequest(BaseModel):
    blob: str = Field(..., min_length=1, max_length=8192)


class Bolt12OfferInput(BaseModel):
    """Decode/import payload for a single BOLT 12 offer string."""

    offer: str = Field(..., min_length=1, max_length=8192)

    @field_validator("offer")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


# ── Auth endpoints ───────────────────────────────────────────────────────


@router.get("/login-nonce")
@limiter.limit("30/minute")
async def login_nonce(request: Request) -> Any:
    """Mint a signed, time-bounded login nonce for the JSON login path.

    Programmatic / SPA callers that POST to ``/dashboard/api/login`` must
    first fetch a nonce here and echo it back in the request body. The nonce
    is stateless (signed + TTL-bounded) so no server-side storage is needed;
    it exists to defeat login-CSRF when a client strips ``Origin``/``Referer``,
    mirroring the hidden field on the HTML login form.
    """
    return JSONResponse(content={"login_nonce": generate_login_nonce()})


@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)) -> Any:
    ip = request.client.host if request.client else None
    if ip and await check_login_lockout(ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many failed login attempts. Try again later."},
        )
    # Always perform the
    # constant-time password compare BEFORE branching on origin / nonce
    # so timing of the verify path is independent of whether the origin
    # was valid. `verify_token` already uses `hmac.compare_digest`; we
    # record the result and only return it after the cheaper checks.
    password_ok = verify_token(body.credential)

    # Reject cross-origin JSON login attempts and stale/forged login nonces
    # (defence-in-depth: SameSite cookies + CORS already block most cases, but
    # an explicit Origin/Referer mismatch is a clear signal of login-CSRF
    # abuse, and the nonce covers the residual case where a client strips both
    # Origin and Referer — for which ``verify_login_origin`` returns ``True``).
    # This brings the JSON path to parity with the HTML form login.
    if not verify_login_origin(request) or not verify_login_nonce(body.login_nonce or ""):
        if ip:
            await record_login_failure(ip)
        return JSONResponse(
            status_code=403,
            content={"detail": "Cross-origin or stale login request rejected"},
        )
    if not password_ok:
        if ip:
            await record_login_failure(ip)
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "dashboard_login_failed",
            "auth",
            success=False,
            error_message="Invalid dashboard password",
            ip_address=ip,
        )
        await send_alert("login_failed", f"Failed dashboard login from {ip}")
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid password"},
        )
    if ip:
        await clear_login_failures(ip)
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "dashboard_login",
        "auth",
        ip_address=ip,
    )
    # Do NOT mirror
    # the CSRF token into a JS-readable cookie. The dashboard SPA
    # reads it from this JSON response body (and from the
    # ``<meta name="csrf-token">`` tag rendered into the dashboard
    # HTML) and stashes it client-side; an XSS payload would now
    # have to mount a network round-trip to read it instead of a
    # one-line ``document.cookie`` read.
    # ``create_session_cookie`` sets the Set-Cookie header on the response
    # passed to it and returns the CSRF token. Build the throwaway only to
    # capture that header, then copy ONLY the Set-Cookie header(s) onto the
    # real response. Copying the throwaway's whole header dict would carry
    # its stale ``content-length`` (15, the length of ``{"status":"ok"}``)
    # and truncate the real body, dropping ``csrf_token`` for clients that
    # honour Content-Length.
    cookie_carrier = JSONResponse(content={"status": "ok"})
    csrf_token = await create_session_cookie(cookie_carrier, request)
    response = JSONResponse(content={"status": "ok", "csrf_token": csrf_token})
    for header_key, header_val in cookie_carrier.raw_headers:
        if header_key.lower() == b"set-cookie":
            response.raw_headers.append((header_key, header_val))
    return response


@router.post("/logout", dependencies=[Depends(_require_auth_csrf)])
async def logout(request: Request) -> Any:
    await revoke_session(request)
    response = JSONResponse(content={"status": "ok"})
    clear_session_cookie(response)
    return response


# ── Read endpoints ───────────────────────────────────────────────────────


@router.get("/summary", dependencies=[Depends(_require_auth)])
async def get_summary() -> Any:
    data, error = await lnd_service.get_wallet_summary()
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


@router.get("/tor-status", dependencies=[Depends(_require_auth)])
async def get_tor_status() -> Any:
    """Dashboard surface for Tor health. Same shape as the
    admin-authenticated ``/v1/status/tor`` endpoint, but gated by
    dashboard cookie auth so the SPA can read it without juggling
    API keys.
    """
    import time

    from app.services.anonymize.tor import (
        probe_entry_guards,
        probe_network_liveness,
        probe_tor_bootstrap_status,
        probe_tor_circuit_status,
    )
    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER
    from app.services.tor_event_stream import get_counters
    from app.services.tor_watchdog import _data_dir_used_mb, get_state

    # Probe Tor. Each one has its own short timeout; failures
    # surface as None so the SPA can render "unknown" rather than
    # raising a 500.
    try:
        boot = await probe_tor_bootstrap_status()
    except Exception:  # noqa: BLE001
        boot = None
    try:
        circuits, _ = await probe_tor_circuit_status()
    except Exception:  # noqa: BLE001
        circuits = []
    try:
        guards, _ = await probe_entry_guards()
    except Exception:  # noqa: BLE001
        guards = []
    try:
        net_live, _ = await probe_network_liveness()
    except Exception:  # noqa: BLE001
        net_live = None
    try:
        used_mb = await _data_dir_used_mb()
    except Exception:  # noqa: BLE001
        used_mb = None

    state = get_state()
    counters = get_counters()
    now = time.monotonic()

    return {
        "bootstrap_progress": boot.bootstrap_phase_progress if boot else None,
        "circuit_established": bool(boot.circuit_established) if boot else None,
        "control_port_reachable": (bool(boot.control_port_reachable) if boot else False),
        "active_circuits": len(circuits),
        "guards_total": len(guards),
        "guards_up": sum(1 for g in guards if g.status == "up"),
        "guards": [
            {
                "fingerprint": g.fingerprint,
                "nickname": g.nickname,
                "status": g.status,
            }
            for g in guards
        ],
        "network_liveness": ("up" if net_live is True else "down" if net_live is False else "unknown"),
        "tor_breaker_state": _TOR_BREAKER.state,
        "tor_breaker_failures": _TOR_BREAKER.consecutive_failures,
        "tor_breaker_last_error": _TOR_BREAKER.last_error,
        "lnd_breaker_state": _LND_BREAKER.state,
        # Split-mode flag + LND-pool Tor breaker. Always
        # present so the SPA can render unconditionally; in single
        # mode the LND-pool breaker stays closed (it's never bumped).
        "tor_split_mode_enabled": bool(getattr(settings, "tor_split_mode", False)),
        "tor_lnd_breaker_state": _get_lnd_pool_breaker_state(),
        "tor_lnd_breaker_failures": _get_lnd_pool_breaker_failures(),
        "tor_lnd_breaker_last_error": _get_lnd_pool_breaker_last_error(),
        "watchdog_alive": (state.last_tick_ts > 0 and (now - state.last_tick_ts) < 90),
        "watchdog_last_tick_age_s": ((now - state.last_tick_ts) if state.last_tick_ts else None),
        "watchdog_last_newnym_age_s": ((now - state.last_newnym_ts) if state.last_newnym_ts else None),
        "event_stream_connected": counters.stream_connected,
        "event_stream_circ_failed": counters.circ_failed,
        "event_stream_hs_desc_failed": counters.hs_desc_failed,
        "event_stream_guard_down": counters.guard_down,
        # Pattern-matched WARN/ERR payloads.
        "event_stream_guard_excluded": counters.guard_excluded_total,
        "event_stream_circuit_stuck": counters.circuit_stuck_total,
        "data_dir_used_mb": used_mb,
        # Per-listener health. Renders as a status table in
        # the dashboard panel; the watchdog updates one entry per
        # tick (round-robin across the 8 listeners).
        "listeners": _listener_snapshot(),
        # LND-side HS descriptor freshness, flattened so
        # the @alpinejs/csp build can render without dotted-chain
        # short-circuit hazards. ``checked=False`` until the
        # periodic task has run at least once.
        **_lnd_hs_descriptor_flat(),
        # LND Tor supervisor (staggered HSFETCH/NEWNYM/SIGHUP
        # recovery), flattened for the same Alpine-CSP reason.
        **_lnd_tor_supervisor_flat(),
    }


def _lnd_tor_supervisor_flat() -> dict:
    """Surface LND Tor supervisor state as flat top-level keys.

    Returns ``checked=False`` until the supervisor has ticked at
    least once. Mirrors the pattern used by
    :func:`_lnd_hs_descriptor_flat` so the @alpinejs/csp build can
    render values without dotted-chain short-circuit hazards (see
    feedback_alpine_csp_no_dotted_shortcircuit in user memory).
    """
    from app.services.lnd_tor_supervisor import get_state

    s = get_state()
    if s.last_tick_ts == 0.0:
        return {
            "lnd_tor_supervisor_checked": False,
            "lnd_tor_supervisor_alive": False,
            "lnd_tor_supervisor_incident_active": False,
            "lnd_tor_supervisor_cycles_24h": 0,
            "lnd_tor_supervisor_cycles_total": 0,
            "lnd_tor_supervisor_last_step_label": None,
            "lnd_tor_supervisor_last_cycle_cleared_at_step": None,
        }
    import time as _time

    now = _time.monotonic()
    last_cleared_step: int | None = None
    if s.cycles_cleared_by_step:
        # Highest-numbered step that ever cleared = the last cycle's
        # outcome (good or bad). For "last cycle specifically" use
        # last_cycle_steps below.
        last_cleared_step = max(s.cycles_cleared_by_step.keys())
    last_step_label: str | None = None
    if s.last_cycle_steps:
        last_step_label = s.last_cycle_steps[-1].get("step")
    return {
        "lnd_tor_supervisor_checked": True,
        "lnd_tor_supervisor_alive": (now - s.last_tick_ts) < 30,
        "lnd_tor_supervisor_last_tick_age_s": now - s.last_tick_ts,
        "lnd_tor_supervisor_incident_active": s.incident_start_ts > 0,
        "lnd_tor_supervisor_incident_age_s": ((now - s.incident_start_ts) if s.incident_start_ts else None),
        "lnd_tor_supervisor_current_step": (s.current_step if s.incident_start_ts > 0 else None),
        "lnd_tor_supervisor_cycles_total": s.cycles_started_total,
        "lnd_tor_supervisor_cycles_24h": len(s.recent_cycle_completions),
        "lnd_tor_supervisor_cycles_disabled_until_age_s": (
            (s.cycles_disabled_until_ts - now) if s.cycles_disabled_until_ts > now else None
        ),
        "lnd_tor_supervisor_last_step_label": last_step_label,
        "lnd_tor_supervisor_last_cycle_cleared_at_step": last_cleared_step,
    }


@router.post("/tor-reload", dependencies=[Depends(_require_auth_csrf)])
async def post_tor_reload() -> Any:
    """Dashboard-side ``SIGNAL HUP`` to reload Tor's torrc
    without restarting the process. Mirrors the admin-auth
    ``/v1/admin/tor/reload`` endpoint but is gated by dashboard
    cookie + CSRF so the operator can trigger it from the UI."""
    from app.services.anonymize.tor import signal_reload

    ok, err = await signal_reload()
    return {"ok": ok, "error": err}


def _get_lnd_pool_breaker_state() -> str:
    """Return the LND-pool Tor breaker state for the JSON
    endpoint. Lazy import to avoid a circular load of
    lnd_service at module-import time."""
    from app.services.lnd_service import _TOR_LND_BREAKER

    return _TOR_LND_BREAKER.state


def _get_lnd_pool_breaker_failures() -> int:
    from app.services.lnd_service import _TOR_LND_BREAKER

    return _TOR_LND_BREAKER.consecutive_failures


def _get_lnd_pool_breaker_last_error() -> str | None:
    from app.services.lnd_service import _TOR_LND_BREAKER

    return _TOR_LND_BREAKER.last_error


def _lnd_hs_descriptor_flat() -> dict:
    """Surface LND HS descriptor freshness as a flat set
    of top-level keys so the @alpinejs/csp build can render them
    without dotted-chain short-circuit hazards. ``lnd_hs_descriptor_checked``
    is False until the periodic task has run at least once."""
    from app.services.lnd_hs_descriptor_check import get_state

    s = get_state()
    if s.last_fetch_attempt_ts == 0.0:
        return {
            "lnd_hs_descriptor_checked": False,
            "lnd_hs_descriptor_ok": None,
            "lnd_hs_descriptor_consecutive_failures": 0,
            "lnd_hs_descriptor_last_error": None,
            "lnd_hs_descriptor_last_fetch_attempt_age_s": None,
            "lnd_hs_descriptor_last_fetch_ok_age_s": None,
        }
    import time as _time

    now = _time.monotonic()
    ok = s.consecutive_failures == 0 and s.last_fetch_ok_ts > 0
    return {
        "lnd_hs_descriptor_checked": True,
        "lnd_hs_descriptor_ok": ok,
        "lnd_hs_descriptor_consecutive_failures": s.consecutive_failures,
        "lnd_hs_descriptor_last_error": s.last_error,
        "lnd_hs_descriptor_last_fetch_attempt_age_s": (
            (now - s.last_fetch_attempt_ts) if s.last_fetch_attempt_ts else None
        ),
        "lnd_hs_descriptor_last_fetch_ok_age_s": ((now - s.last_fetch_ok_ts) if s.last_fetch_ok_ts else None),
    }


def _listener_snapshot() -> list[dict]:
    """Render the per-listener probe state as a stable-order list
    for the dashboard. Empty list until the watchdog has cycled
    through at least one probe."""
    from app.services.tor_per_listener_probe import get_snapshot

    snap = get_snapshot()
    out: list[dict] = []
    for name in sorted(snap.keys()):
        entry = snap[name]
        out.append(
            {
                "name": name,
                "port": entry["port"],
                "ok": entry["ok"],
                "last_probe_age_s": entry["last_probe_age_s"],
                "last_error": entry["last_error"],
            }
        )
    return out


async def _safe_channel_last_used() -> dict[str, int]:
    """``get_channel_last_used`` that never raises — returns ``{}`` on error.

    Lets the channels endpoint gather the enrichment concurrently with the
    channel list without a failing enrichment taking down the gather.
    """
    try:
        return await lnd_service.get_channel_last_used()
    except Exception:
        return {}


@router.get("/channels", dependencies=[Depends(_require_auth)])
async def get_channels() -> Any:
    # ``get_channels`` and ``get_channel_last_used`` are independent LND
    # reads (the latter never consumes the former's result), so fire them
    # concurrently rather than back-to-back. Over Tor each call is several
    # seconds; serialising them stacked the endpoint's latency high enough
    # to trip the browser's read timeout and surface a spurious "couldn't
    # load channels" — running them in parallel roughly halves the cold path.
    channels_res, last_used_res = await asyncio.gather(
        lnd_service.get_channels(),
        # Best-effort enrichment: any failure here must not break the
        # channel list, so swallow it and fall back to no enrichment.
        _safe_channel_last_used(),
    )
    data, error = channels_res
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    channels = list(data or [])
    last_used = last_used_res
    for ch in channels:
        ts = last_used.get(ch.get("chan_id", ""))
        if ts:
            ch["last_used"] = ts
    return channels


@router.get("/channels/pending", dependencies=[Depends(_require_auth)])
async def get_pending_channels() -> Any:
    data, error = await lnd_service.get_pending_channels_detail()
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data or []


@router.get("/payments", dependencies=[Depends(_require_auth)])
async def get_payments() -> Any:
    data, error = await lnd_service.get_recent_payments(50)
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    # Sort newest-first by creation_date so the table renders the
    # most recent activity at the top regardless of how LND happens
    # to order ``reversed=true`` results.
    items = list(data or [])
    items.sort(key=lambda p: int(p.get("creation_date") or 0), reverse=True)
    return items


@router.get("/invoices", dependencies=[Depends(_require_auth)])
async def get_invoices() -> Any:
    data, error = await lnd_service.get_recent_invoices(50)
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    items = list(data or [])
    items.sort(key=lambda inv: int(inv.get("creation_date") or 0), reverse=True)
    return items


@router.get("/invoice/{r_hash}", dependencies=[Depends(_require_auth)])
async def get_invoice_status(r_hash: str) -> Any:
    """Look up a single invoice by hex payment hash.

    Used by the Receive-Lightning dialog to poll for settlement so the
    UI can transition to a "paid" state in near real time without
    requiring a websocket subscription.
    """
    if not _HEX64_PATTERN.match(r_hash):
        raise HTTPException(status_code=400, detail="Invalid invoice hash")
    data, error = await lnd_service.lookup_invoice(r_hash)
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


@router.get("/transactions", dependencies=[Depends(_require_auth)])
async def get_transactions() -> Any:
    data, error = await lnd_service.get_onchain_transactions(50)
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    items = list(data or [])
    items.sort(key=lambda tx: int(tx.get("time_stamp") or 0), reverse=True)
    return items


@router.get("/fees", dependencies=[Depends(_require_auth)])
async def get_fees() -> Any:
    data, error = await mempool_fee_service.get_recommended_fees()
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "Mempool")})
    return data


@router.get("/info", dependencies=[Depends(_require_auth)])
async def get_info() -> Any:
    data, error = await lnd_service.get_info()
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


# ── Write endpoints ──────────────────────────────────────────────────────


@router.post("/address", dependencies=[Depends(_require_auth_csrf)])
async def generate_address(request: Request, body: AddressRequest, db: AsyncSession = Depends(get_db)) -> Any:
    data, error = await lnd_service.new_address(body.address_type)
    ip = request.client.host if request.client else None
    if error:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "new_address",
            "wallet",
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    address = data.get("address", "") if data else ""
    if address and body.purpose:
        try:
            await utxo_service.record_address_purpose(db, address, body.purpose)
        except ValueError as exc:
            # Don't fail the address generation; just log.
            logger.warning("address purpose rejected: %s", exc)
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "new_address",
        "wallet",
        details={
            "address_type": body.address_type,
            "address": address,
            "has_purpose": bool(body.purpose),
        },
        ip_address=ip,
    )
    return data


@router.post("/invoice", dependencies=[Depends(_require_auth_csrf)])
async def create_invoice(request: Request, body: InvoiceRequest, db: AsyncSession = Depends(get_db)) -> Any:
    data, error = await lnd_service.create_invoice(
        amount_sats=body.amount_sats,
        memo=body.memo,
        expiry=body.expiry,
    )
    ip = request.client.host if request.client else None
    if error:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "create_invoice",
            "lightning",
            amount_sats=body.amount_sats,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "create_invoice",
        "lightning",
        amount_sats=body.amount_sats,
        details={"memo": body.memo, "r_hash": (dict(data) if data else {}).get("r_hash")},
        ip_address=ip,
    )
    return data


@router.post("/decode", dependencies=[Depends(_require_auth_csrf)])
async def decode_invoice(body: DecodeRequest) -> Any:
    data, error = await lnd_service.decode_payment_request(body.payment_request)
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


@router.post("/pay", dependencies=[Depends(_require_auth_csrf)])
async def pay_invoice(request: Request, body: PayRequest, db: AsyncSession = Depends(get_db)) -> Any:
    # Decode invoice first to capture amount for audit trail.
    # If decoding fails (or returns no amount) and a payment cap is
    # configured, refuse the request: paying an undecodable invoice
    # would let the cap be bypassed silently because we cannot enforce
    # it without an amount. With no cap (limit < 0) we still allow the
    # payment so behaviour matches direct-API semantics.
    decoded, decode_error = await lnd_service.decode_payment_request(body.payment_request)
    amount_sats = int(decoded.get("num_satoshis", 0)) if decoded else None
    cap_configured = settings.dashboard_max_payment_sats >= 0
    if cap_configured and (decode_error or amount_sats is None):
        raise HTTPException(
            status_code=400,
            detail=("Cannot enforce dashboard payment cap: invoice could not be decoded"),
        )
    # Include fee_limit_sats in the dashboard payment cap so an
    # outsized fee cannot bypass DASHBOARD_MAX_PAYMENT_SATS.
    total_for_cap = (amount_sats or 0) + body.fee_limit_sats
    _check_dashboard_payment_limit(total_for_cap if amount_sats is not None else None)

    if body.outgoing_chan_id:
        # Pinning the outgoing channel requires the streaming router
        # endpoint — the legacy /v1 transactions endpoint cannot honour
        # the constraint. We disable allow_self_payment here because a
        # dashboard "send payment" is by definition outbound to a
        # third party (rebalance has its own dedicated endpoint).
        v2_result, error = await lnd_service.send_payment_v2(
            payment_request=body.payment_request,
            outgoing_chan_id=body.outgoing_chan_id,
            fee_limit_sats=body.fee_limit_sats,
            timeout_seconds=body.timeout_seconds,
            allow_self_payment=False,
        )
        # Reshape the streaming-API result into the SendPaymentResult
        # envelope the dashboard JS already expects.
        if v2_result is not None:
            data: Optional[dict[str, Any]] = {
                "payment_hash": v2_result.get("payment_hash", ""),
                "payment_preimage": v2_result.get("payment_preimage", ""),
                "payment_route": {
                    "total_amt": int(v2_result.get("amount_sats", 0)),
                    "total_fees": int(v2_result.get("fee_sats", 0)),
                    "total_amt_msat": int(v2_result.get("amount_sats", 0)) * 1000,
                    "total_fees_msat": int(v2_result.get("fee_msat", 0)),
                    "hops": int(v2_result.get("hops", 0)),
                },
            }
        else:
            data = None
    else:
        sync_result, error = await lnd_service.send_payment_sync(
            payment_request=body.payment_request,
            fee_limit_sats=body.fee_limit_sats,
            timeout_seconds=body.timeout_seconds,
        )
        data = dict(sync_result) if sync_result is not None else None
    ip = request.client.host if request.client else None
    data_dict: dict[str, Any] = dict(data) if data else {}
    decoded_dict: dict[str, Any] = dict(decoded) if decoded else {}
    audit_details: dict[str, Any] = {
        "fee_limit": body.fee_limit_sats,
        "payment_hash": data_dict.get("payment_hash"),
        "destination": decoded_dict.get("destination"),
        "description": decoded_dict.get("description"),
    }
    if body.outgoing_chan_id:
        audit_details["outgoing_chan_id"] = body.outgoing_chan_id
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "pay_invoice",
        "payment",
        amount_sats=amount_sats,
        details=audit_details,
        success=error is None,
        error_message=error,
        ip_address=ip,
    )
    if error:
        # Same UX-friendly mapping the rebalance endpoint uses: a
        # routing failure is a 400 with an actionable message rather
        # than a generic 502.
        if _is_no_route_error(error):
            return JSONResponse(
                status_code=400,
                content={
                    "detail": (
                        "No route found for this payment. Try a higher fee limit or clear the source-channel pin."
                    ),
                },
            )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


@router.post("/pay/quote", dependencies=[Depends(_require_auth_csrf)])
async def pay_quote(body: PayQuoteRequest) -> Any:
    """Probe a route for a BOLT 11 invoice via ``QueryRoutes``.

    Read-only. Does not move sats and does not write an audit row.
    Mirrors :func:`rebalance_quote` for the third-party-payment case.
    """
    decoded, decode_error = await lnd_service.decode_payment_request(body.payment_request)
    if decode_error or decoded is None:
        return JSONResponse(
            status_code=400,
            content={"detail": sanitize_upstream_error(decode_error or "decode failed", "LND")},
        )
    amount_sats = int(decoded.get("num_satoshis", 0))
    if amount_sats <= 0:
        return JSONResponse(
            status_code=400,
            content={
                "detail": (
                    "Route estimate requires a fixed-amount invoice. "
                    "Open-amount (zero-amount) invoices are not "
                    "supported by QueryRoutes."
                ),
            },
        )
    destination = decoded.get("destination") or ""
    if not destination:
        return JSONResponse(
            status_code=400,
            content={"detail": "Invoice is missing a destination pubkey"},
        )

    quote, q_err = await lnd_service.query_routes(
        dest_pubkey_hex=destination,
        amount_sats=amount_sats,
        outgoing_chan_id=body.outgoing_chan_id,
        fee_limit_sats=body.fee_limit_sats,
    )
    if q_err:
        if _is_no_route_error(q_err):
            return {
                "ok": False,
                "no_route": True,
                "amount_sats": amount_sats,
                "detail": (
                    "No route found for this invoice with the chosen "
                    "fee limit / source channel. Try a higher fee "
                    "limit or a different source channel."
                ),
            }
        return JSONResponse(
            status_code=502,
            content={"detail": sanitize_upstream_error(q_err, "LND")},
        )

    return {
        "ok": True,
        "amount_sats": amount_sats,
        "destination": destination,
        "route": quote,
    }


class LnurlResolveRequest(BaseModel):
    """Resolve a Lightning Address or LNURL bech32 string to pay params."""

    text: str = Field(..., min_length=1, max_length=2048)


class LnurlInvoiceRequest(BaseModel):
    """Mint a BOLT11 invoice from a previously-resolved LNURL handle."""

    handle: str = Field(..., min_length=32, max_length=32)
    amount_sats: int = Field(gt=0)
    comment: str = Field(default="", max_length=280)

    @field_validator("handle")
    @classmethod
    def _hex_handle(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{32}", v):
            raise ValueError("handle must be 32 lowercase hex chars")
        return v


def _truncate_for_audit(s: str, limit: int = 200) -> str:
    if len(s) <= limit:
        return s
    return s[: limit - len("...[truncated]")] + "...[truncated]"


@router.post("/lnurl/resolve", dependencies=[Depends(_require_auth_csrf)])
async def lnurl_resolve(request: Request, body: LnurlResolveRequest, db: AsyncSession = Depends(get_db)) -> Any:
    """Resolve a Lightning Address (``user@host``) or LNURL string."""
    svc = get_lnurl_service()
    result, error = await svc.resolve_recipient(body.text)
    ip = request.client.host if request.client else None
    if error or result is None:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "lnurl_resolve",
            "lightning",
            details={"input_kind": "lightning_address" if "@" in body.text else "lnurl"},
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(
            status_code=400,
            content={"detail": error or "resolve failed"},
        )
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "lnurl_resolve",
        "lightning",
        details={
            "source_kind": result["source_kind"],
            "callback_host": result["callback_host"],
        },
        ip_address=ip,
    )
    return result


@router.post("/lnurl/invoice", dependencies=[Depends(_require_auth_csrf)])
async def lnurl_invoice(request: Request, body: LnurlInvoiceRequest, db: AsyncSession = Depends(get_db)) -> Any:
    """Request a BOLT11 invoice from the recipient for ``amount_sats``."""
    _check_dashboard_payment_limit(body.amount_sats)
    svc = get_lnurl_service()
    result, error = await svc.request_invoice(body.handle, body.amount_sats, body.comment)
    ip = request.client.host if request.client else None
    if error or result is None:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "lnurl_request_invoice",
            "lightning",
            amount_sats=body.amount_sats,
            details={
                "handle": body.handle,
                "comment_len": len(body.comment or ""),
            },
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(
            status_code=400,
            content={"detail": error or "invoice request failed"},
        )
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "lnurl_request_invoice",
        "lightning",
        amount_sats=body.amount_sats,
        details={
            "handle": body.handle,
            "payment_hash": result["payment_hash"],
            "comment": _truncate_for_audit(body.comment) if body.comment else "",
            "comment_len": len(body.comment or ""),
            "cache_hit": result["cache_hit"],
        },
        ip_address=ip,
    )
    return result


@router.post("/send-onchain", dependencies=[Depends(_require_auth_csrf)])
async def send_onchain(request: Request, body: SendOnchainRequest, db: AsyncSession = Depends(get_db)) -> Any:
    _check_dashboard_payment_limit(body.amount_sats)
    outpoints_payload: Optional[list[Outpoint]] = (
        [Outpoint(txid_str=op.txid_str, output_index=op.output_index) for op in body.outpoints]
        if body.outpoints
        else None
    )
    data, error = await lnd_service.send_coins(
        address=body.address,
        amount_sats=body.amount_sats,
        sat_per_vbyte=body.sat_per_vbyte,
        label=body.label,
        outpoints=outpoints_payload,
    )
    ip = request.client.host if request.client else None
    coin_control = bool(outpoints_payload)
    input_count = len(outpoints_payload) if outpoints_payload else 0
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "send_onchain",
        "onchain",
        amount_sats=body.amount_sats,
        details={"coin_control": coin_control, "input_count": input_count},
        success=error is None,
        error_message=error,
        ip_address=ip,
    )
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    # Best-effort inherit-on-spend label propagation. We can't reliably
    # know which output index is "change" without parsing the broadcast
    # tx, so we skip change-inheritance for non-consolidate sends and
    # only stamp the parent rows as spent.
    txid = data.get("txid", "") if data else ""
    if outpoints_payload and txid:
        try:
            await utxo_service.inherit_on_spend(
                db,
                spent_outpoints=outpoints_payload,
                new_txid=txid,
                change_vout=None,
                consolidate=False,
            )
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("inherit_on_spend failed: %s", exc)
    return data


@router.post("/estimate-fee", dependencies=[Depends(_require_auth_csrf)])
async def estimate_fee(body: EstimateFeeRequest) -> Any:
    outpoints_payload: Optional[list[Outpoint]] = (
        [Outpoint(txid_str=op.txid_str, output_index=op.output_index) for op in body.outpoints]
        if body.outpoints
        else None
    )
    data, error = await lnd_service.estimate_fee(
        address=body.address,
        amount_sats=body.amount_sats,
        target_conf=body.target_conf,
        outpoints=outpoints_payload,
    )
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


@router.post("/channel/open", dependencies=[Depends(_require_auth_csrf)])
async def open_channel(request: Request, body: OpenChannelRequest, db: AsyncSession = Depends(get_db)) -> Any:
    _check_dashboard_payment_limit(body.local_funding_amount)
    # Connect to peer first if host is provided
    if body.host:
        _, connect_err = await lnd_service.connect_peer(body.pubkey, body.host)
        if connect_err:
            return JSONResponse(
                status_code=502,
                content={"detail": sanitize_upstream_error(f"Peer connect failed: {connect_err}", "LND")},
            )

    data, error = await lnd_service.open_channel(
        node_pubkey_hex=body.pubkey,
        local_funding_amount=body.local_funding_amount,
        sat_per_vbyte=body.sat_per_vbyte,
        push_sat=body.push_sat,
        private=body.private,
    )
    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "open_channel",
        "channel",
        amount_sats=body.local_funding_amount,
        details={"pubkey": body.pubkey},
        success=error is None,
        error_message=error,
        ip_address=ip,
    )
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    return data


@router.post("/channel/close", dependencies=[Depends(_require_auth_csrf)])
async def close_channel(request: Request, body: CloseChannelRequest, db: AsyncSession = Depends(get_db)) -> Any:
    """Close a single channel. The dashboard calls this once per selected
    channel so each close reports and audits independently.

    A cooperative close (``force=false``) needs the peer online; closing an
    offline peer requires ``force=true``. We refuse a cooperative close on
    an inactive channel up front with a clear message rather than letting
    the peer negotiation block until the request times out.
    """
    ip = request.client.host if request.client else None
    txid, vout = body.channel_point.split(":", 1)

    if not body.force:
        channels, _chan_err = await lnd_service.get_channels()
        match = next((c for c in (channels or []) if c.get("channel_point") == body.channel_point), None)
        if match is not None and not match.get("active", False):
            detail = "This channel's peer is offline, so it can't be closed cooperatively. Use a force close instead."
            logger.info("close_channel: refusing cooperative close of offline channel %s", body.channel_point)
            await log_dashboard_action(
                db,
                DASHBOARD_KEY_ID,
                "close_channel",
                "channel",
                details={"channel_point": body.channel_point, "force": False, "reason": "peer_offline"},
                success=False,
                error_message=detail,
                ip_address=ip,
            )
            return JSONResponse(status_code=400, content={"detail": detail})

    logger.info(
        "close_channel: requesting %s close of %s (sat_per_vbyte=%s)",
        "force" if body.force else "cooperative",
        body.channel_point,
        body.sat_per_vbyte,
    )
    _result, error = await lnd_service.close_channel(
        funding_txid=txid,
        output_index=int(vout),
        force=body.force,
        sat_per_vbyte=body.sat_per_vbyte,
    )
    if error:
        # The close stream can drop (notably over Tor) after LND has
        # already accepted the close. If the channel has since moved into
        # a closing bucket, the close *was* initiated — report success so
        # the user isn't told it failed for a channel that's closing.
        pending, _p_err = await lnd_service.get_pending_channels_detail()
        closing_points = {
            p.get("channel_point")
            for p in (pending or [])
            if p.get("type") in ("waiting_close", "pending_close", "force_closing")
        }
        if body.channel_point in closing_points:
            logger.info(
                "close_channel: stream errored but %s is now closing — treating as initiated", body.channel_point
            )
            error = None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "close_channel",
        "channel",
        details={"channel_point": body.channel_point, "force": body.force},
        success=error is None,
        error_message=error,
        ip_address=ip,
    )
    if error:
        logger.info("close_channel: LND rejected close of %s — %s", body.channel_point, error)
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    logger.info(
        "close_channel: LND accepted %s close of %s", "force" if body.force else "cooperative", body.channel_point
    )
    return {"ok": True, "channel_point": body.channel_point, "force": body.force}


# ── Rebalance (circular self-payment) endpoints ─────────────────────────


_REBALANCE_HEADROOM_PAD_SATS = 1_000


def _rebalance_max_sendable(ch: dict[str, Any]) -> int:
    """Headroom we can realistically push *out* of this channel.

    Beyond the channel reserve and in-flight HTLCs, the initiator must
    keep the commitment fee (which grows as the rebalance HTLC is added)
    and the anchor outputs funded, or LND rejects the route at execution
    time with "insufficient local balance". We reserve the live
    ``commit_fee`` (when we're the initiator) plus a fixed anchor/growth
    pad, keeping a 1% floor for large channels.
    """
    local = int(ch.get("local_balance", 0) or 0)
    reserve = int(ch.get("local_chan_reserve_sat", 0) or 0)
    unsettled = int(ch.get("unsettled_balance", 0) or 0)
    capacity = int(ch.get("capacity", 0) or 0)
    commit_fee = int(ch.get("commit_fee", 0) or 0) if ch.get("initiator") else 0
    headroom = max(capacity // 100, commit_fee + _REBALANCE_HEADROOM_PAD_SATS)
    return max(local - reserve - unsettled - headroom, 0)


def _rebalance_max_receivable(ch: dict[str, Any]) -> int:
    """Headroom that can land *back* on this channel's local side."""
    remote = int(ch.get("remote_balance", 0) or 0)
    reserve = int(ch.get("remote_chan_reserve_sat", 0) or 0)
    unsettled = int(ch.get("unsettled_balance", 0) or 0)
    capacity = int(ch.get("capacity", 0) or 0)
    safety = max(capacity // 100, 0)
    return max(remote - reserve - unsettled - safety, 0)


def _is_no_route_error(error: str) -> bool:
    """Detect LND's "no path to destination" routing outcome.

    These are expected failures when liquidity, fee limit, or
    pathfinding constraints simply can't be satisfied — distinct from
    an upstream/server fault. Match a few known phrasings across
    LND/router subserver versions.
    """
    if not error:
        return False
    low = error.lower()
    return (
        "unable to find a path" in low
        or "no route found" in low
        or "no_route" in low
        or "no_path" in low
        or "failurereason_no_route" in low
        # The source channel can't cover amount + fee right now. Like a
        # no-route outcome, the fix is a smaller amount, so surface it as
        # a friendly inline hint rather than a 502 "see server logs".
        or "insufficient local balance" in low
    )


async def _resolve_rebalance_channels(
    source_chan_id: str, dest_chan_id: str
) -> tuple[Optional[dict[str, Any]], Optional[dict[str, Any]], Optional[str]]:
    """Look up source + dest channels live and validate they're usable."""
    if source_chan_id == dest_chan_id:
        return None, None, "Source and destination channels must differ"
    channels, error = await lnd_service.get_channels()
    if error or channels is None:
        return None, None, sanitize_upstream_error(error or "channels unavailable", "LND")
    by_id = {ch["chan_id"]: ch for ch in channels}
    src = by_id.get(source_chan_id)
    dst = by_id.get(dest_chan_id)
    if not src:
        return None, None, "Source channel not found"
    if not dst:
        return None, None, "Destination channel not found"
    if not src.get("active"):
        return None, None, "Source channel is inactive"
    if not dst.get("active"):
        return None, None, "Destination channel is inactive"
    return dict(src), dict(dst), None


@router.post("/rebalance/quote", dependencies=[Depends(_require_auth_csrf)])
async def rebalance_quote(body: RebalanceQuoteRequest) -> Any:
    """Probe a circular rebalance route via ``QueryRoutes`` (no HTLCs).

    Returns route metadata plus live ``max_sendable_sats`` /
    ``max_receivable_sats`` so the UI can show why the Max button is
    what it is.
    """
    src, dst, err = await _resolve_rebalance_channels(body.source_chan_id, body.dest_chan_id)
    if err:
        return JSONResponse(status_code=400, content={"detail": err})
    assert src is not None and dst is not None

    max_send = _rebalance_max_sendable(src)
    max_recv = _rebalance_max_receivable(dst)

    if body.amount_sats > max_send:
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Amount exceeds max sendable on source ({max_send} sats)",
                "max_sendable_sats": max_send,
                "max_receivable_sats": max_recv,
            },
        )
    if body.amount_sats > max_recv:
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Amount exceeds max receivable on destination ({max_recv} sats)",
                "max_sendable_sats": max_send,
                "max_receivable_sats": max_recv,
            },
        )

    # ── QueryRoutes recipe for circular rebalances ────────────────────
    # LND's ``QueryRoutes`` does NOT reliably handle self-payments
    # (source == dest). It short-circuits and returns "unable to find
    # a path to destination" even when a perfectly good circular path
    # exists, because its pathfinder treats source==dest as a no-op.
    # The standard rebalance recipe (used by RTL, balanceofsatoshis,
    # and the lncli docs) is to instead probe a route from us to the
    # *destination channel's peer*, pinning the source channel as the
    # outgoing hop. The implicit final hop from dest_peer back to us
    # via the dest channel is free at the routing-fee layer (the last
    # hop never charges a forwarding fee), so the totals we surface
    # to the user accurately reflect what the real send_payment will
    # charge. ``send_payment_v2`` handles the self-payment leg fine.
    quote, q_err = await lnd_service.query_routes(
        dest_pubkey_hex=dst["remote_pubkey"],
        amount_sats=body.amount_sats,
        outgoing_chan_id=body.source_chan_id,
        fee_limit_sats=body.fee_limit_sats,
    )
    if q_err:
        # LND returns "unable to find a path to destination" when no
        # route satisfying the constraints exists. That's an expected
        # routing outcome (not a server fault), so surface a clear
        # message to the user instead of the generic "see server logs"
        # blanket and respond with 200 + ``no_route`` so the UI can
        # render an inline hint rather than treating it as an error.
        if _is_no_route_error(q_err):
            return {
                "ok": False,
                "no_route": True,
                "detail": (
                    "No route found for this amount with the chosen "
                    "source/destination. Try a smaller amount or a "
                    "higher fee limit."
                ),
                "max_sendable_sats": max_send,
                "max_receivable_sats": max_recv,
            }
        return JSONResponse(
            status_code=502,
            content={
                "detail": sanitize_upstream_error(q_err, "LND"),
                "max_sendable_sats": max_send,
                "max_receivable_sats": max_recv,
            },
        )

    return {
        "ok": True,
        "route": quote,
        "max_sendable_sats": max_send,
        "max_receivable_sats": max_recv,
        "source": {
            "chan_id": src["chan_id"],
            "peer_alias": src.get("peer_alias", ""),
            "remote_pubkey": src.get("remote_pubkey", ""),
        },
        "dest": {
            "chan_id": dst["chan_id"],
            "peer_alias": dst.get("peer_alias", ""),
            "remote_pubkey": dst.get("remote_pubkey", ""),
        },
    }


@router.post("/rebalance", dependencies=[Depends(_require_auth_csrf)])
async def rebalance(request: Request, body: RebalanceRequest, db: AsyncSession = Depends(get_db)) -> Any:
    """Execute a circular self-payment between two channels.

    The standard recipe: mint a local invoice for the desired amount,
    then call the router subserver with ``outgoing_chan_id`` pinning
    the source and ``last_hop_pubkey`` pinning the peer of the
    destination channel.
    """
    _check_dashboard_payment_limit(body.amount_sats + body.fee_limit_sats)

    src, dst, err = await _resolve_rebalance_channels(body.source_chan_id, body.dest_chan_id)
    if err:
        return JSONResponse(status_code=400, content={"detail": err})
    assert src is not None and dst is not None

    max_send = _rebalance_max_sendable(src)
    max_recv = _rebalance_max_receivable(dst)
    if body.amount_sats > max_send:
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Amount exceeds max sendable on source ({max_send} sats)",
            },
        )
    if body.amount_sats > max_recv:
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Amount exceeds max receivable on destination ({max_recv} sats)",
            },
        )

    # Mint an invoice on our own node — it's the payee for this
    # circular payment. Short expiry: rebalance is point-in-time.
    invoice, inv_err = await lnd_service.create_invoice(
        amount_sats=body.amount_sats,
        memo=f"rebalance {body.source_chan_id}->{body.dest_chan_id}",
        expiry=max(body.timeout_seconds + 60, 300),
    )
    if inv_err or not invoice:
        return JSONResponse(
            status_code=502,
            content={
                "detail": sanitize_upstream_error(inv_err or "invoice mint failed", "LND"),
            },
        )

    ip = request.client.host if request.client else None

    result, send_err = await lnd_service.send_payment_v2(
        payment_request=invoice["payment_request"],
        outgoing_chan_id=body.source_chan_id,
        last_hop_pubkey_hex=dst["remote_pubkey"],
        fee_limit_sats=body.fee_limit_sats,
        timeout_seconds=body.timeout_seconds,
        allow_self_payment=True,
    )

    log_details: dict[str, Any] = {
        "source_chan_id": body.source_chan_id,
        "dest_chan_id": body.dest_chan_id,
        "source_alias": src.get("peer_alias", ""),
        "dest_alias": dst.get("peer_alias", ""),
        "fee_limit_sats": body.fee_limit_sats,
        "payment_hash": invoice.get("r_hash", ""),
    }
    if result:
        log_details["fee_sats"] = result.get("fee_sats")
        log_details["hops"] = result.get("hops")
        log_details["duration_ms"] = result.get("duration_ms")

    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "rebalance_channel",
        "channel",
        amount_sats=body.amount_sats,
        details=log_details,
        success=send_err is None,
        error_message=send_err,
        ip_address=ip,
    )

    if send_err:
        # Same special-case as the quote endpoint: routing failures
        # surface as a user-facing 400 with a clear hint, while real
        # upstream faults stay 502 + sanitized.
        if _is_no_route_error(send_err):
            return JSONResponse(
                status_code=400,
                content={
                    "detail": (
                        "No route found for this rebalance. Try a smaller "
                        "amount, a higher fee limit, or a different "
                        "destination channel."
                    ),
                },
            )
        return JSONResponse(
            status_code=502,
            content={
                "detail": sanitize_upstream_error(send_err, "LND"),
            },
        )

    return {
        "ok": True,
        "result": result,
        "source": {
            "chan_id": src["chan_id"],
            "peer_alias": src.get("peer_alias", ""),
        },
        "dest": {
            "chan_id": dst["chan_id"],
            "peer_alias": dst.get("peer_alias", ""),
        },
    }


@router.get("/rebalance/recent", dependencies=[Depends(_require_auth)])
async def rebalance_recent(
    limit: int = Query(default=5, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Recent successful rebalances, surfaced in the dialog history.

    Sourced from the audit log so it reflects exactly what was
    executed (including amount + fee).
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.action == "rebalance_channel", AuditLog.success.is_(True))
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    res = await db.execute(stmt)
    rows = res.scalars().all()
    out: list[dict[str, Any]] = []
    for row in rows:
        details = row.details or {}
        out.append(
            {
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "amount_sats": row.amount_sats,
                "fee_sats": details.get("fee_sats"),
                "hops": details.get("hops"),
                "source_alias": details.get("source_alias"),
                "dest_alias": details.get("dest_alias"),
                "source_chan_id": details.get("source_chan_id"),
                "dest_chan_id": details.get("dest_chan_id"),
                "duration_ms": details.get("duration_ms"),
            }
        )
    return {"rebalances": out}


# ── Cold storage (Boltz) endpoints ───────────────────────────────────────


@router.get("/cold-storage/fees", dependencies=[Depends(_require_auth)])
async def cold_storage_fees() -> Any:
    data, error = await boltz_service.get_reverse_pair_info()
    if error:
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "Boltz")})
    return data


@router.post("/cold-storage/initiate", dependencies=[Depends(_require_auth_csrf)])
async def cold_storage_initiate(
    request: Request,
    body: ColdStorageRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    ip = request.client.host if request.client else None
    purpose = body.purpose or "cold_storage"
    _check_dashboard_payment_limit(body.amount_sats)
    # Check Lightning balance before creating swap. The Celery task
    # that pays the Boltz invoice does so with a routing fee limit
    # (default 3% — see app/tasks/boltz_tasks.py). We reserve the
    # same percentage as routing headroom in the pre-check so a
    # user with exactly ``amount_sats`` of local balance doesn't
    # pass this check only to have the LN payment fail at the
    # routing layer. The router's fee budget is per-payment, so
    # the safer cap is ``amount * (1 + fee_limit_pct)``.
    routing_fee_buffer_pct = 0.03  # mirrors boltz_tasks.py default
    needed = int(body.amount_sats * (1 + routing_fee_buffer_pct))

    async def _reject_insufficient(available: int, detail: str) -> JSONResponse:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "cold_storage_initiate",
            "swap",
            amount_sats=body.amount_sats,
            details={
                "purpose": purpose,
                "reason": "insufficient_balance",
                "destination_address": body.destination_address,
                "available_sats": available,
                "outgoing_chan_id": body.outgoing_chan_id,
            },
            success=False,
            error_message=detail,
            ip_address=ip,
        )
        return JSONResponse(status_code=400, content={"detail": detail})

    if body.outgoing_chan_id:
        # Pinned to a single channel: the Lightning leg must fit through
        # this one channel (an outgoing-channel pin confines every part
        # of the payment to that first hop, so other channels' balances
        # can't help). Validate against the channel's own spendable —
        # local minus its reserve, unsettled HTLCs, and a 1% safety
        # margin — matching the dashboard's max-freeable math. This turns
        # a late, opaque "no route" into an early, clear message.
        channels, _ch_err = await lnd_service.get_channels()
        chan = next((c for c in (channels or []) if c.get("chan_id") == body.outgoing_chan_id), None)
        if chan is None:
            detail = "That channel is no longer open. Refresh and try again."
            return await _reject_insufficient(0, detail)
        if not chan.get("active", False):
            detail = "That channel is offline right now, so it can't send. Try again once it reconnects."
            return await _reject_insufficient(0, detail)
        cap = int(chan.get("capacity", 0))
        spendable = max(
            int(chan.get("local_balance", 0))
            - int(chan.get("local_chan_reserve_sat", 0))
            - int(chan.get("unsettled_balance", 0))
            - cap // 100,
            0,
        )
        if spendable < needed:
            detail = (
                f"This channel only has {spendable:,} sats free to move right now "
                f"(you asked for {body.amount_sats:,} sats plus "
                f"~{int(body.amount_sats * routing_fee_buffer_pct):,} sats of routing-fee headroom). "
                "Try a smaller amount."
            )
            return await _reject_insufficient(spendable, detail)
    else:
        # Unpinned: the payment may be split across all channels, so the
        # total local balance is the right ceiling.
        channel_balance, _bal_err = await lnd_service.get_channel_balance()
        if channel_balance:
            local_balance = int(channel_balance.get("local_balance_sat", 0))
            if local_balance < needed:
                detail = (
                    f"Insufficient Lightning balance: {local_balance:,} sats available, "
                    f"{body.amount_sats:,} sats + ~{int(body.amount_sats * routing_fee_buffer_pct):,} "
                    "sats routing-fee headroom requested."
                )
                return await _reject_insufficient(local_balance, detail)

    swap, error = await boltz_service.create_reverse_swap(
        db=db,
        api_key_id=DASHBOARD_KEY_ID,
        invoice_amount_sats=body.amount_sats,
        destination_address=body.destination_address,
        outgoing_chan_id=body.outgoing_chan_id,
    )
    if error:
        # Boltz rejected the swap (e.g. amount out of range, peer
        # unreachable). Audit the failure so operators reviewing
        # the log can correlate user-reported "couldn't start a
        # swap" tickets without log-grepping the Celery worker.
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "cold_storage_initiate",
            "swap",
            amount_sats=body.amount_sats,
            details={
                "purpose": purpose,
                "reason": "boltz_rejected",
                "destination_address": body.destination_address,
            },
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=400, content={"detail": sanitize_upstream_error(error, "Boltz")})
    assert swap is not None

    # Schedule the Celery background task to pay the Boltz invoice
    from app.tasks.boltz_tasks import process_boltz_swap

    process_boltz_swap.delay(str(swap.id))

    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "cold_storage_initiate",
        "swap",
        amount_sats=body.amount_sats,
        details={
            "swap_id": str(swap.id),
            "purpose": purpose,
            # Operators reviewing the audit log need to see *where*
            # the funds went without cross-referencing the swap_id
            # against the swap table (which retains the field, but
            # is purged separately on a different schedule).
            "destination_address": body.destination_address,
            # Present when the swap drains a specific channel to open its
            # receive capacity; absent for a plain withdrawal.
            "outgoing_chan_id": body.outgoing_chan_id,
        },
        ip_address=ip,
    )

    return {
        "id": str(swap.id),
        "boltz_swap_id": swap.boltz_swap_id,
        "status": swap.status.value,
        "invoice": swap.boltz_invoice,
        "onchain_amount_sats": swap.onchain_amount_sats,
    }


@router.get("/cold-storage/swaps", dependencies=[Depends(_require_auth)])
async def cold_storage_swaps(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[dict[str, Any]]:
    from app.models.boltz_swap import BoltzSwap

    result = await db.execute(select(BoltzSwap).order_by(BoltzSwap.created_at.desc()).limit(limit))
    swaps = result.scalars().all()
    return [
        {
            "id": str(s.id),
            "boltz_swap_id": s.boltz_swap_id,
            "status": s.status.value,
            "invoice_amount_sats": s.invoice_amount_sats,
            "onchain_amount_sats": s.onchain_amount_sats,
            "destination_address": s.destination_address,
            "claim_txid": s.claim_txid,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in swaps
    ]


async def _build_session_recovery(
    db: AsyncSession,
    *,
    swap_ids: list[Any],
    session_status: Optional[str],
    session_updated_at: Any,
    session_pipeline_json: Any,
) -> dict[str, Any] | None:
    """Aggregate a recovery hint for a session that has up to two
    underlying ``BoltzSwap`` legs.

    Loads each non-None swap id, runs the per-swap classifier, then
    folds in a session-level hint (today: ``awaiting_liquid_dwell``
    stuck longer than the configured upper bound). The worst-severity
    hint is returned in the same shape the cold-storage serializer
    emits, so the dashboard banner template renders identically
    across Cold Storage, Braiins, and Anonymize.

    Returns ``None`` on no swap rows AND no session-level hint, so
    callers can suppress the ``recovery`` field entirely.
    """
    from app.models.boltz_swap import BoltzSwap
    from app.services.boltz_recovery import (
        aggregate_recovery_hints,
        classify_recovery_state,
        classify_session_recovery_state,
    )

    tip = mempool_fee_service.cached_tip_height

    hints: list[Any] = []
    seen: set[Any] = set()
    for sid in swap_ids:
        if sid is None or sid in seen:
            continue
        seen.add(sid)
        try:
            res = await db.execute(select(BoltzSwap).where(BoltzSwap.id == sid))
            swap = res.scalar_one_or_none()
        except Exception:  # noqa: BLE001
            logger.exception("session recovery: swap lookup failed for %s", sid)
            continue
        if swap is None:
            continue

        claim_confs: int | None = None
        if swap.claim_txid:
            try:
                confs = await mempool_fee_service.optional_confirmations(swap.claim_txid)
                if confs is not None:
                    claim_confs = confs.get("confirmations")
            except Exception:  # noqa: BLE001
                logger.exception(
                    "session recovery: claim-confs fetch failed for %s",
                    swap.claim_txid,
                )

        try:
            hints.append(
                classify_recovery_state(
                    swap,
                    btc_tip_height=tip,
                    claim_confirmations=claim_confs,
                )
            )
        except Exception:  # noqa: BLE001
            logger.exception("session recovery: classifier failed for %s", sid)

    # Session-level rule: awaiting_liquid_dwell stuck. Probe electrs-
    # liquid reachability so the hint copy can distinguish "indexer
    # is down" from "dwell just running long".
    indexer_reachable: bool | None = None
    try:
        if settings.anonymize_liquid_enabled:
            from app.services.anonymize.liquid_fee_oracle import (
                is_liquid_indexer_reachable,
            )

            indexer_reachable = is_liquid_indexer_reachable()
    except Exception:  # noqa: BLE001
        indexer_reachable = None

    try:
        session_hint = classify_session_recovery_state(
            status=str(session_status or ""),
            updated_at=session_updated_at,
            pipeline_json=session_pipeline_json if isinstance(session_pipeline_json, dict) else None,
            liquid_indexer_reachable=indexer_reachable,
        )
    except Exception:  # noqa: BLE001
        logger.exception("session recovery: session-level classifier failed")
        session_hint = None
    if session_hint is not None:
        hints.append(session_hint)

    worst = aggregate_recovery_hints(hints)
    if worst is None:
        return None
    return worst.to_dict()


@router.get("/cold-storage/swaps/{swap_id}", dependencies=[Depends(_require_auth)])
async def cold_storage_swap_detail(
    swap_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    swap = await boltz_service.get_swap_by_id(db, swap_id)
    if not swap:
        return JSONResponse(status_code=404, content={"detail": "Swap not found"})
    resp: dict[str, Any] = {
        "id": str(swap.id),
        "boltz_swap_id": swap.boltz_swap_id,
        "status": swap.status.value,
        "boltz_status": swap.boltz_status,
        "invoice_amount_sats": swap.invoice_amount_sats,
        "onchain_amount_sats": swap.onchain_amount_sats,
        "destination_address": swap.destination_address,
        "claim_txid": swap.claim_txid,
        "timeout_block_height": swap.timeout_block_height,
        "error_message": swap.error_message,
        "status_history": swap.status_history,
        "created_at": swap.created_at.isoformat() if swap.created_at else None,
        "completed_at": swap.completed_at.isoformat() if swap.completed_at else None,
    }
    # Best-effort enrichment (silently no-op without electrum).
    claim_confirmations: int | None = None
    if swap.claim_txid:
        confs = await mempool_fee_service.optional_confirmations(swap.claim_txid)
        if confs is not None:
            claim_confirmations = confs.get("confirmations")
            resp["claim_confirmations"] = claim_confirmations
            resp["claim_block_height"] = confs.get("block_height")
    tip = mempool_fee_service.cached_tip_height
    if tip is not None:
        resp["current_block_height"] = tip
        if swap.timeout_block_height is not None:
            resp["blocks_until_timeout"] = swap.timeout_block_height - tip

    # Recovery hint — pure classifier; same source of truth used by
    # the public v1 ``/cold-storage/swaps/{id}`` endpoint and the
    # dashboard recovery banner. Surfaces ``state``, ``severity``,
    # ``headline``, ``detail``, ``actions`` and ``metadata``.
    try:
        from app.services.boltz_recovery import classify_recovery_state

        resp["recovery"] = classify_recovery_state(
            swap,
            btc_tip_height=tip,
            claim_confirmations=claim_confirmations,
        ).to_dict()
    except Exception:  # noqa: BLE001
        logger.exception("Recovery classifier failed for swap %s", swap.id)
    return resp


@router.get("/tx/{txid}/confirmations", dependencies=[Depends(_require_auth)])
async def dashboard_tx_confirmations(txid: str) -> Any:
    """Lightweight confirmation count for a TX, used by HTMX/Alpine pollers.

    Best-effort: returns ``{confirmations: null, available: false}`` when
    the chain backend can't answer (Electrum down + Mempool HTTP down,
    or strict mode and Electrum down). Never 5xx — pollers must keep
    rendering the existing "see explorer" fallback.
    """
    if not re.fullmatch(r"[0-9a-fA-F]{64}", txid):
        return JSONResponse(status_code=400, content={"detail": "txid must be 64 hex chars"})
    confs = await mempool_fee_service.optional_confirmations(txid.lower())
    if confs is None:
        return {"available": False, "txid": txid.lower()}
    return {
        "available": True,
        "txid": txid.lower(),
        "confirmed": bool(confs.get("confirmed")),
        "confirmations": confs.get("confirmations"),
        "block_height": confs.get("block_height"),
    }


@router.post("/cold-storage/swaps/{swap_id}/cancel", dependencies=[Depends(_require_auth_csrf)])
async def cold_storage_cancel(
    request: Request,
    swap_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    swap = await boltz_service.get_swap_by_id(db, swap_id)
    if not swap:
        return JSONResponse(status_code=404, content={"detail": "Swap not found"})
    ok, error = await boltz_service.cancel_swap(db, swap)
    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "cold_storage_cancel",
        "swap",
        details={"swap_id": str(swap_id)},
        success=ok,
        error_message=error,
        ip_address=ip,
    )
    if not ok:
        return JSONResponse(
            status_code=400, content={"detail": sanitize_upstream_error(error or "Cancel failed", "Boltz")}
        )
    return {"status": "cancelled"}


@router.post(
    "/cold-storage/swaps/{swap_id}/cooperative-claim",
    dependencies=[Depends(_require_auth_csrf)],
)
async def cold_storage_cooperative_claim(
    request: Request,
    swap_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator-driven retry of the cooperative Taproot claim.

    Mirrors the v1 ``/cold-storage/swaps/{id}/cooperative-claim``
    endpoint but uses the dashboard's cookie-auth + CSRF surface so
    the SPA can drive it from the recovery banner.
    """
    swap = await boltz_service.get_swap_by_id(db, swap_id)
    if not swap:
        return JSONResponse(status_code=404, content={"detail": "Swap not found"})

    txid, error = await boltz_service.retry_cooperative_claim(db, swap)

    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "cold_storage_cooperative_claim",
        "swap",
        details={
            "swap_id": str(swap_id),
            "boltz_swap_id": swap.boltz_swap_id,
            "claim_txid": txid,
            "recovery_count": swap.recovery_count or 0,
        },
        success=txid is not None,
        error_message=error,
        ip_address=ip,
    )

    if error:
        return JSONResponse(
            status_code=502,
            content={"detail": sanitize_upstream_error(error, "Boltz")},
        )
    return {"status": "claimed", "claim_txid": txid}


@router.post(
    "/cold-storage/swaps/{swap_id}/unilateral-claim",
    dependencies=[Depends(_require_auth_csrf)],
)
async def cold_storage_unilateral_claim(
    request: Request,
    swap_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator-driven unilateral script-path claim.

    Mirrors the v1 ``/cold-storage/swaps/{id}/unilateral-claim``
    endpoint. Refuses to run unless the Boltz lockup timeout has
    already passed.
    """
    swap = await boltz_service.get_swap_by_id(db, swap_id)
    if not swap:
        return JSONResponse(status_code=404, content={"detail": "Swap not found"})

    tip = mempool_fee_service.cached_tip_height
    txid, error = await boltz_service.retry_unilateral_claim(
        db,
        swap,
        btc_tip_height=tip,
    )

    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "cold_storage_unilateral_claim",
        "swap",
        details={
            "swap_id": str(swap_id),
            "boltz_swap_id": swap.boltz_swap_id,
            "claim_txid": txid,
            "recovery_count": swap.recovery_count or 0,
            "current_block_height": tip,
            "timeout_block_height": swap.timeout_block_height,
        },
        success=txid is not None,
        error_message=error,
        ip_address=ip,
    )

    if error:
        # Safety-check failures (timeout not yet reached, wrong
        # status, etc.) are 4xx so the banner can render them
        # inline; upstream failures stay 502.
        is_safety = "timeout has not passed" in error or "only valid" in error or "no recorded timeout" in error
        return JSONResponse(
            status_code=400 if is_safety else 502,
            content={"detail": sanitize_upstream_error(error, "Boltz")},
        )
    return {"status": "claimed", "claim_txid": txid}


# ── Activity / Audit log endpoint ────────────────────────────────────────


@router.get("/activity", dependencies=[Depends(_require_auth)])
async def get_activity(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Any:
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(min(limit, 200))
    )
    logs = result.scalars().all()

    count_result = await db.execute(select(func.count(AuditLog.id)))
    total = count_result.scalar() or 0

    return {
        "total": total,
        "items": [
            {
                "id": str(log.id),
                "api_key_name": log.api_key_name,
                "action": log.action,
                "resource": log.resource,
                "details": log.details,
                "amount_sats": log.amount_sats,
                "success": log.success,
                "error_message": log.error_message,
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
    }


# ── Sign / Verify Message endpoints ──────────────────────────────────────


@router.get("/sign/config", dependencies=[Depends(_require_auth)])
async def sign_config() -> Any:
    """Static config for the dashboard Sign/Verify UI."""
    return {
        "max_chars": settings.sign_message_max_chars,
        "autocomplete": settings.sign_address_autocomplete,
    }


# Process-wide caches.
#
# 1. Endpoint-availability flags. Once we've learned this LND build
#    doesn't expose a given WalletKit RPC (returns 404), skip the
#    probe for the rest of the process lifetime. Without these flags
#    every ownership check would re-probe missing endpoints and
#    pollute the log with ``LND API error 404`` plus a spurious LND
#    health-failure record. Reset only by a process restart.
# 2. Per-address positive cache. Once we've confirmed an address is
#    owned, we don't need to re-verify — derived/imported addresses
#    don't lose ownership at runtime. NEGATIVE results are
#    intentionally not cached: a transient probe failure could
#    otherwise pollute the cache with a false "not owned" verdict.
_is_our_address_supported: Optional[bool] = None
_list_addresses_supported: Optional[bool] = None
_sign_as_probe_supported: Optional[bool] = None
_owned_address_cache: set[str] = set()

# Probe message used by the sign-as-ownership-probe fallback. Stable
# (so the same address always produces the same probe signature —
# BIP-322/137 are deterministic anyway) and self-identifying so it's
# obvious in any wallet-side log that this is an internal probe.
_OWNERSHIP_PROBE_MESSAGE = "agent-wallet ownership probe"


def _is_404_error(error: Optional[str]) -> bool:
    """True iff the LND-service error string indicates an endpoint
    missing from the build (HTTP 404). The ``_request`` helper formats
    these as ``LND error (404): <body>``."""
    return bool(error) and "(404)" in str(error)


def _is_semantic_lnd_error(error: Optional[str]) -> bool:
    """True iff the LND-service error string is a semantic (LND-side)
    error rather than a transient transport failure. ``_request``
    formats semantic errors as ``LND error (XXX): <body>`` and
    transport failures as ``Connection failed: ...`` /
    ``Request failed: ...`` / circuit-breaker messages. We use this to
    decide whether a failed sign-as-probe means "address not in wallet"
    (a semantic answer worth trusting) versus "LND was unreachable"
    (transient — must not be cached as ``owned: false``)."""
    if not error:
        return False
    return str(error).startswith("LND error (")


@router.get("/sign/owns-address", dependencies=[Depends(_require_auth)])
async def sign_owns_address(address: str) -> Any:
    """Check whether ``address`` is controlled by the wallet's keys.

    Used by the Offers tab to decide whether to surface a "Sign payout
    message" shortcut for OCEAN-prefixed offers — when the payout
    address is owned by this wallet we can pre-fill the address in a
    streamlined sign-message UI.

    Three-state return:

    * ``{"owned": true,  "address": str}``  — definitively owned
    * ``{"owned": false, "address": str}``  — definitively NOT owned
    * ``{"owned": null,  "address": str, "reason": str}``  — couldn't
      verify (LND build lacks both ``IsOurAddress`` and
      ``ListAddresses`` — happens on stripped-down or non-standard
      LND deployments)

    The null third state matters: a strict 502 here would hide the
    shortcut for users whose LND deployment doesn't expose either
    probe RPC, even when their address really IS theirs. The dashboard
    treats null as "show the button optimistically" so the feature
    still works on minimal LND builds — if the address truly isn't
    derivable, the sign attempt itself will surface a clear error.

    Implementation tries three checks in order, falling through on a
    404 (RPC missing from this LND build):

    1. ``WalletKit.IsOurAddress`` — O(1), key-derivability check.
    2. ``WalletKit.ListAddresses`` — scan the derived-address pool.
    3. ``WalletKit.SignMessageWithAddr`` — sign a benign probe
       message; if the call succeeds, the wallet owns the key.

    Verdicts about endpoint availability are cached process-wide so a
    stripped LND doesn't re-probe missing endpoints on every check.
    Positive ownership results are also cached per-address (derived
    addresses don't lose ownership at runtime). 502 is still returned
    for actual LND errors (5xx, network failures) so a transient
    outage doesn't quietly answer "couldn't verify" forever.
    """
    global _is_our_address_supported, _list_addresses_supported
    global _sign_as_probe_supported

    # Trivial input shape check — LND would reject malformed addresses
    # anyway but we keep query strings bounded so a malicious caller
    # can't pump arbitrary bytes through the gRPC channel.
    a = (address or "").strip()
    if not a or len(a) > 128:
        raise HTTPException(status_code=400, detail="Invalid address")

    # ── Per-address positive cache ──
    if a in _owned_address_cache:
        return {"owned": True, "address": a}

    # ── Primary: WalletKit.IsOurAddress ──
    last_error: Optional[str] = None
    if _is_our_address_supported is not False:
        data, error = await lnd_service._request(  # noqa: SLF001
            "POST",
            "/v2/wallet/address/ours",
            json={"addr": a},
        )
        if error is None and isinstance(data, dict) and "is_our_address" in data:
            _is_our_address_supported = True
            owned = bool(data.get("is_our_address"))
            if owned:
                _owned_address_cache.add(a)
            return {"owned": owned, "address": a}
        if _is_404_error(error):
            if _is_our_address_supported is None:
                logger.info(
                    "sign_owns_address: LND build does not expose "
                    "WalletKit.IsOurAddress (404). Falling back to "
                    "ListAddresses scan."
                )
            _is_our_address_supported = False
        else:
            last_error = error

    # ── Fallback 1: WalletKit.ListAddresses ──
    if _list_addresses_supported is not False:
        list_data, list_err = await lnd_service._request(  # noqa: SLF001
            "GET",
            "/v1/wallet/addresses",
        )
        if list_err is None and list_data is not None:
            _list_addresses_supported = True
            for acct in list_data.get("account_with_addresses", []):
                for entry in acct.get("addresses", []):
                    if entry.get("address") == a:
                        _owned_address_cache.add(a)
                        return {"owned": True, "address": a}
            return {"owned": False, "address": a}
        if _is_404_error(list_err):
            if _list_addresses_supported is None:
                logger.info(
                    "sign_owns_address: LND build does not expose "
                    "WalletKit.ListAddresses (404). Falling back to "
                    "the sign-as-ownership-probe path."
                )
            _list_addresses_supported = False
        else:
            last_error = list_err

    # ── Fallback 2: WalletKit.SignMessageWithAddr (probe) ──
    #
    # Sign a benign self-identifying probe message. If LND signs
    # without error, the wallet owns the address's private key — the
    # only way SignMessageWithAddr can succeed. The probe signature is
    # discarded (we don't return or store it; BIP-322/137 signatures
    # are deterministic anyway so sharing wouldn't leak anything).
    if _sign_as_probe_supported is not False:
        probe_data, probe_err = await lnd_service.sign_message_with_address(
            a,
            _OWNERSHIP_PROBE_MESSAGE,
        )
        if probe_err is None and probe_data is not None:
            _sign_as_probe_supported = True
            _owned_address_cache.add(a)
            return {"owned": True, "address": a}
        if _is_404_error(probe_err):
            # Could be "endpoint missing" OR "address-not-in-wallet"
            # returned as 404 — we can't reliably tell from the error
            # body alone. Either way, the user couldn't sign on this
            # LND build for this address, so reporting ``owned: false``
            # is the right outcome (the button stays hidden). We don't
            # mark the endpoint unavailable globally — a sibling
            # address on the same wallet might still succeed, and
            # marking it unavailable would break that.
            return {"owned": False, "address": a}
        if _is_semantic_lnd_error(probe_err):
            # Non-404 semantic error from LND (e.g. 400 "address not
            # in wallet"). The endpoint is working; this answer is
            # authoritative for THIS address: not owned. Don't cache
            # the negative — re-probing on retry is cheap and avoids
            # poisoning the cache on a one-off oddity.
            _sign_as_probe_supported = True
            return {"owned": False, "address": a}
        # Transient transport failure (connection refused, breaker
        # open, etc.). Don't classify as ``owned: false`` — the next
        # call should retry. Fall through to the last_error /
        # null-or-502 decision below.
        last_error = probe_err

    # All paths exhausted. Decide between "couldn't verify" (every
    # probe 404'd — return null with a reason) and "actual LND error"
    # (5xx / network — return 502 so callers know this is transient).
    if last_error and not _is_404_error(last_error):
        return JSONResponse(
            status_code=502,
            content={"detail": sanitize_upstream_error(last_error, "LND")},
        )
    return {
        "owned": None,
        "address": a,
        "reason": "endpoints_unavailable",
    }


@router.get("/sign/addresses", dependencies=[Depends(_require_auth)])
async def sign_addresses() -> Any:
    """List candidate on-chain addresses for the Sign combobox.

    Source is controlled by SIGN_ADDRESS_AUTOCOMPLETE:
    - "txn_history": dedup addresses from recent on-chain transactions
    - "wallet_addresses": full LND-known address list (heavier)
    - "off": empty list
    """
    mode = settings.sign_address_autocomplete
    if mode == "off":
        return {"mode": mode, "addresses": []}

    if mode == "wallet_addresses":
        data, error = await lnd_service._request("GET", "/v1/wallet/addresses")  # noqa: SLF001
        if error or not data:
            return {"mode": mode, "addresses": [], "error": sanitize_upstream_error(error or "no data", "LND")}
        seen: dict[str, dict] = {}
        for acct in data.get("account_with_addresses", []):
            for addr in acct.get("addresses", []):
                a = addr.get("address")
                if a and a not in seen:
                    seen[a] = {"address": a, "is_internal": bool(addr.get("is_internal"))}
        return {"mode": mode, "addresses": list(seen.values())[:500]}

    # Default: txn_history — read raw to access dest_addresses
    data, error = await lnd_service._request("GET", "/v1/transactions")  # noqa: SLF001
    if error or not data:
        return {
            "mode": "txn_history",
            "addresses": [],
            "error": (sanitize_upstream_error(error, "LND") if error else None),
        }
    seen_addrs: dict[str, dict] = {}
    for tx in data.get("transactions", [])[:200]:
        for out_addr in tx.get("dest_addresses", []) or []:
            if out_addr and out_addr not in seen_addrs:
                seen_addrs[out_addr] = {"address": out_addr, "last_used": tx.get("time_stamp")}
    return {"mode": "txn_history", "addresses": list(seen_addrs.values())[:200]}


async def _enforce_dashboard_sign_rate_limit() -> None:
    from app.core.rate_limit import check_sign_rate_limit

    allowed, error = await check_sign_rate_limit(
        identity="dashboard",
        max_per_hour=settings.sign_rate_limit_dashboard_per_hour,
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=error or "Sign rate limit reached")


@router.post("/sign/address", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_sign_address(
    request: Request,
    body: SignAddressDashRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Sign a message with the private key of an on-chain address."""
    from app.core.sign_validation import audit_message_details

    await _enforce_dashboard_sign_rate_limit()

    data, error = await lnd_service.sign_message_with_address(body.address, body.message)
    ip = request.client.host if request.client else None
    audit = audit_message_details(body.message)
    audit["address"] = body.address
    if error:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "sign_message",
            "wallet:address",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    assert data is not None
    audit["signature"] = data["signature"]
    audit["format"] = data["format"]
    audit["address_type"] = data["address_type"]
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "sign_message",
        "wallet:address",
        details=audit,
        ip_address=ip,
    )
    return data


@router.post("/verify/address", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_verify_address(
    request: Request,
    body: VerifyAddressDashRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    from app.core.sign_validation import audit_message_details

    data, error = await lnd_service.verify_message_with_address(body.address, body.message, body.signature)
    ip = request.client.host if request.client else None
    audit = audit_message_details(body.message)
    audit["address"] = body.address
    audit["signature"] = body.signature
    if error:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "verify_message",
            "wallet:address",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    assert data is not None
    audit["valid"] = data["valid"]
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "verify_message",
        "wallet:address",
        details=audit,
        ip_address=ip,
    )
    return data


@router.post("/sign/node", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_sign_node(
    request: Request,
    body: SignNodeDashRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    from app.core.sign_validation import audit_message_details

    await _enforce_dashboard_sign_rate_limit()
    data, error = await lnd_service.sign_message_node(body.message)
    ip = request.client.host if request.client else None
    audit = audit_message_details(body.message)
    if error:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "sign_message",
            "wallet:node",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    assert data is not None
    audit["signature"] = data["signature"]
    audit["node_pubkey"] = data["node_pubkey"]
    audit["format"] = "zbase32"
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "sign_message",
        "wallet:node",
        details=audit,
        ip_address=ip,
    )
    return data


@router.post("/verify/node", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_verify_node(
    request: Request,
    body: VerifyNodeDashRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    from app.core.sign_validation import audit_message_details

    data, error = await lnd_service.verify_message_node(body.message, body.signature)
    ip = request.client.host if request.client else None
    audit = audit_message_details(body.message)
    audit["signature"] = body.signature
    if error:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "verify_message",
            "wallet:node",
            details=audit,
            success=False,
            error_message=error,
            ip_address=ip,
        )
        return JSONResponse(status_code=502, content={"detail": sanitize_upstream_error(error, "LND")})
    assert data is not None
    audit["valid"] = data["valid"]
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "verify_message",
        "wallet:node",
        details=audit,
        ip_address=ip,
    )
    return data


@router.post("/sign/parse", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_parse_signed(body: ParseSignedRequest) -> Any:
    """Server-side parser for pasted signed-message blobs.

    Returns a normalised structure the UI can use to populate the
    Verify form. Kept on the server so the dashboard JS doesn't need
    to ship a parser, and so the same code path is used for both
    autofill and the (future) API caller.
    """
    from app.core.sign_formats import parse_signed_message

    try:
        parsed = parse_signed_message(body.blob)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "identity": parsed.identity,
        "address": parsed.address,
        "message": parsed.message,
        "signature": parsed.signature,
    }


# ─── BOLT 12 ─────────────────────────────────────────────────────────


def _bolt12_offer_to_json(row: "Any") -> dict[str, Any]:
    """Public-safe projection of a stored offer for the dashboard."""
    return {
        "id": str(row.id),
        "bolt12": row.bolt12,
        "description": row.description,
        "amount_msat": row.amount_msat,
        "currency": row.currency,
        "issuer": row.issuer,
        "issuer_id_hex": row.issuer_id_hex,
        "status": row.status.value,
        "source": row.source.value,
        "quantity_max": row.quantity_max,
        "is_default_receive": bool(getattr(row, "is_default_receive", False)),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_paid_at": row.last_paid_at.isoformat() if row.last_paid_at else None,
    }


@router.get("/bolt12/offers", dependencies=[Depends(_require_auth)])
async def dashboard_list_bolt12_offers(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    source: Optional[str] = Query(
        None,
        description=("Filter by provenance. Comma-separated subset of 'issued', 'imported', 'paid'."),
    ),
) -> Any:
    """List stored BOLT 12 offers (newest first), excluding hard-deleted rows."""
    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource

    stmt = select(Bolt12Offer).where(Bolt12Offer.deleted_at.is_(None))
    if source is not None:
        try:
            sources = [Bolt12OfferSource(s.strip()) for s in source.split(",") if s.strip()]
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Unknown source: {exc}")
        if sources:
            stmt = stmt.where(Bolt12Offer.source.in_(sources))
    stmt = stmt.order_by(Bolt12Offer.created_at.desc()).limit(limit)

    rows = (await db.execute(stmt)).scalars().all()
    return [_bolt12_offer_to_json(r) for r in rows]


@router.post("/bolt12/decode", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_decode_bolt12_offer(body: Bolt12OfferInput) -> Any:
    """Decode a BOLT 12 offer string for preview before import.

    Read-only: never touches the database. All decoder errors are
    surfaced as 400 (caller-input problem) with a sanitised message.
    """
    from app.services.bolt12 import (
        Bolt12Error,
        Offer,
    )
    from app.services.bolt12 import (
        decode as decode_bolt12,
    )

    try:
        wire = decode_bolt12(
            body.offer,
            max_records=settings.bolt12_max_tlv_records or None,
            max_value_bytes=settings.bolt12_max_tlv_value_bytes or None,
        )
        parsed = Offer.parse(wire)
    except Bolt12Error as exc:
        raise HTTPException(status_code=400, detail=f"Invalid offer: {exc}") from exc

    return {
        "offer": body.offer,
        "description": parsed.description,
        "amount_msat": parsed.amount,
        "currency": parsed.currency,
        "issuer": parsed.issuer,
        "issuer_id_hex": parsed.issuer_id.hex() if parsed.issuer_id else None,
        "quantity_max": parsed.quantity_max,
        "absolute_expiry": parsed.absolute_expiry,
    }


@router.post("/bolt12/offers", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_import_bolt12_offer(
    request: Request,
    body: Bolt12OfferInput,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Persist a BOLT 12 offer for tracking.

    Idempotent on the canonical bech32 string: re-importing returns
    the existing row without duplicating. Audit-logged.
    """
    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource
    from app.services.bolt12 import (
        Bolt12Error,
        Offer,
    )
    from app.services.bolt12 import (
        decode as decode_bolt12,
    )

    try:
        wire = decode_bolt12(
            body.offer,
            max_records=settings.bolt12_max_tlv_records or None,
            max_value_bytes=settings.bolt12_max_tlv_value_bytes or None,
        )
        parsed = Offer.parse(wire)
    except Bolt12Error as exc:
        raise HTTPException(status_code=400, detail=f"Invalid offer: {exc}") from exc

    existing = (await db.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == body.offer))).scalar_one_or_none()
    ip = request.client.host if request.client else None
    if existing is not None:
        return _bolt12_offer_to_json(existing)

    row = Bolt12Offer(
        api_key_id=DASHBOARD_KEY_ID,
        bolt12=body.offer,
        description=parsed.description,
        amount_msat=parsed.amount,
        currency=parsed.currency,
        issuer=parsed.issuer,
        issuer_id_hex=parsed.issuer_id.hex() if parsed.issuer_id else None,
        quantity_max=parsed.quantity_max,
        source=Bolt12OfferSource.IMPORTED,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "import_offer",
        "bolt12_offer",
        details={"offer_id": str(row.id)},
        ip_address=ip,
    )
    return _bolt12_offer_to_json(row)


@router.delete(
    "/bolt12/offers/{offer_id}",
    status_code=204,
    response_model=None,
    dependencies=[Depends(_require_auth_csrf)],
)
async def dashboard_disable_bolt12_offer(
    offer_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Remove a stored offer.

    Issued offers (``source=ISSUED``) are soft-disabled
    (``status=DISABLED``) so the orchestrator stops accepting new
    invreqs against them but historical invreq/invoice rows still
    render correctly. Imported / paid offers (the dashboard's
    "payees") are soft-deleted (``deleted_at``) — the user removed
    them from their address book; they were never anything we
    served.
    """
    from datetime import datetime, timezone

    from app.models.bolt12_offer import (
        Bolt12Offer,
        Bolt12OfferSource,
        Bolt12OfferStatus,
    )

    row = (await db.execute(select(Bolt12Offer).where(Bolt12Offer.id == offer_id))).scalar_one_or_none()
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Offer not found")

    if row.source == Bolt12OfferSource.ISSUED:
        row.status = Bolt12OfferStatus.DISABLED
        action = "disable_offer"
    else:
        row.deleted_at = datetime.now(timezone.utc)
        action = "remove_payee"
    await db.commit()

    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        action,
        "bolt12_offer",
        details={"offer_id": str(offer_id)},
        ip_address=ip,
    )


# ── Dashboard issue / pay ───────────────────────────────────────


async def _load_dashboard_api_key(db: AsyncSession) -> Any:
    """Load the sentinel ``__dashboard__`` APIKey row.

    The dashboard's BOLT 12 issue/pay handlers reuse the public
    ``app.api.bolt12`` core helpers, which expect a real ``APIKey``
    instance for FK + audit-log purposes. The sentinel row is
    inserted by Alembic migration ``002_dashboard_sentinel_key`` and
    is guaranteed to exist in any properly migrated DB. If it is
    missing we fail loudly because the absence indicates a broken
    install rather than a user error.
    """
    from app.models.api_key import APIKey

    row = (await db.execute(select(APIKey).where(APIKey.id == DASHBOARD_KEY_ID))).scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=500,
            detail="Dashboard sentinel API key missing; run alembic upgrade",
        )
    return row


@router.post(
    "/bolt12/offers/issue",
    status_code=201,
    dependencies=[Depends(_require_auth_csrf)],
)
async def dashboard_issue_bolt12_offer(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Mint + persist a BOLT 12 offer signed by this wallet.

    Thin wrapper around :func:`app.api.bolt12._perform_issue_offer`
    that swaps the actor identity to the dashboard sentinel key.
    Audit rows land under ``__dashboard__`` so the dashboard
    Activity tab surfaces them alongside other dashboard actions.
    """
    from app.api.bolt12 import IssueOfferRequest, _perform_issue_offer

    body = await request.json()
    try:
        req = IssueOfferRequest.model_validate(body)
    except Exception as exc:  # noqa: BLE001 — pydantic raises ValidationError subclass
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    api_key = await _load_dashboard_api_key(db)
    ip = request.client.host if request.client else None
    return await _perform_issue_offer(req, api_key=api_key, db=db, ip=ip)


@router.get("/bolt12/receive", dependencies=[Depends(_require_auth)])
async def dashboard_get_receive_offer(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return (and on first call, mint) the dashboard's default receive offer.

    Wraps :func:`app.api.bolt12._get_or_create_default_receive` and
    :func:`app.api.bolt12._build_receive_panel_payload` so the Issue
    tab can render its top-of-tab "your receive offer" panel from one
    request. Audit rows land under the dashboard sentinel key.
    """
    from app.api.bolt12 import (
        _build_receive_panel_payload,
        _get_or_create_default_receive,
    )

    api_key = await _load_dashboard_api_key(db)
    ip = request.client.host if request.client else None
    offer = await _get_or_create_default_receive(api_key=api_key, db=db, ip=ip)
    return await _build_receive_panel_payload(offer)


@router.post(
    "/bolt12/receive/configure",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dashboard_configure_receive_offer(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Replace the dashboard's default receive offer with one whose
    description matches the requirements of a specific payer (e.g.
    the Ocean mining pool's ``"OCEAN Payouts for bc1...address"``
    format).

    Wraps :func:`app.api.bolt12._reconfigure_default_receive` and
    :func:`app.api.bolt12._build_receive_panel_payload` so the panel
    can re-render in one round-trip.
    """
    from app.api.bolt12 import (
        ConfigureReceiveOfferRequest,
        _build_receive_panel_payload,
        _reconfigure_default_receive,
    )

    body = await request.json()
    try:
        req = ConfigureReceiveOfferRequest.model_validate(body)
    except Exception as exc:  # noqa: BLE001 — pydantic raises ValidationError subclass
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    api_key = await _load_dashboard_api_key(db)
    ip = request.client.host if request.client else None
    offer = await _reconfigure_default_receive(
        description=req.description,
        api_key=api_key,
        db=db,
        ip=ip,
    )
    return await _build_receive_panel_payload(offer)


@router.post(
    "/bolt12/receive/auto-peer",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dashboard_auto_peer_for_receive(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Dashboard mirror of ``POST /v1/bolt12/receive/auto-peer``.

    Powers the "Connect to a public node" button surfaced on the
    receive panel when the gateway has no publicly-routable
    onion-message-capable peer. Iterates the well-known-payers
    registry until one dial succeeds. Returns the same payload shape
    as the public endpoint so the dashboard can toast the outcome
    directly.
    """
    from app.api.bolt12 import auto_peer_for_receive as _impl

    api_key = await _load_dashboard_api_key(db)
    return await _impl(request=request, api_key=api_key, db=db)


@router.post(
    "/bolt12/offers/{offer_id}/set-default",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dashboard_set_default_receive_offer(
    offer_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Promote an existing issued offer to be the dashboard's default."""
    from app.api.bolt12 import _set_default_receive

    api_key = await _load_dashboard_api_key(db)
    ip = request.client.host if request.client else None
    row = await _set_default_receive(offer_id, api_key=api_key, db=db, ip=ip)
    return _bolt12_offer_to_json(row)


@router.post("/bolt12/pay", dependencies=[Depends(_require_auth_csrf)])
async def dashboard_pay_bolt12_offer(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Send an invreq + persist the resulting invoice.

    Thin wrapper around :func:`app.api.bolt12._perform_pay_offer`.
    Inherits the same 400/502/503/504 failure modes from the public
    route.
    """
    from app.api.bolt12 import PayOfferRequest, _perform_pay_offer

    body = await request.json()
    try:
        req = PayOfferRequest.model_validate(body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    api_key = await _load_dashboard_api_key(db)
    ip = request.client.host if request.client else None
    return await _perform_pay_offer(req, api_key=api_key, db=db, ip=ip)


# ── UTXO management endpoints ────────────────────────────────────────────
#
# These back the dashboard "UTXOs" tab. All endpoints inherit
# the same session-cookie / CSRF model as the rest of this file.


def _hash_label_for_audit(label: str) -> str:
    """Audit-safe representation of a label.

    Labels can contain personally-meaningful operational notes
    (counterparty names, exchange identifiers). We don't want to
    persist them verbatim in the audit log, but we *do* want a stable
    fingerprint so an investigator can correlate ``utxo_label_set``
    rows. SHA-256 truncated to 16 hex chars is plenty.
    """
    import hashlib

    if not label:
        return ""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()[:16]


@router.get("/utxos", dependencies=[Depends(_require_auth)])
async def list_utxos(
    request: Request,
    min_confs: int = Query(default=0, ge=0, le=10_000),
    q: str = Query(default="", max_length=128),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List the live on-chain UTXO set joined with stored labels."""
    result = await utxo_service.list_utxos_with_labels(db, min_confs=min_confs, search=q)
    if "error" in result and result.get("error"):
        return JSONResponse(
            status_code=502,
            content={"detail": sanitize_upstream_error(result["error"], "LND")},
        )
    return result


@router.get("/utxos/recently-spent", dependencies=[Depends(_require_auth)])
async def list_recently_spent_utxos(db: AsyncSession = Depends(get_db)) -> Any:
    rows = await utxo_service.list_recently_spent(db, days=30)
    return {"recently_spent": rows}


@router.patch(
    "/utxos/{txid}/{vout}/label",
    dependencies=[Depends(_require_auth_csrf)],
)
async def update_utxo_label(
    request: Request,
    txid: str,
    vout: int,
    body: UtxoLabelUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    if vout < 0 or vout >= 2**31:
        raise HTTPException(status_code=422, detail="vout out of range")
    try:
        if body.label.strip() == "":
            await utxo_service.clear_label(db, txid, vout)
            action = "utxo_label_clear"
            label_hash = ""
        else:
            row = await utxo_service.set_label(db, txid, vout, body.label)
            action = "utxo_label_set"
            label_hash = _hash_label_for_audit(row.label)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        action,
        "wallet",
        details={"txid": txid, "vout": vout, "label_hash": label_hash},
        ip_address=ip,
    )
    return {"ok": True}


@router.post("/utxos/reconcile", dependencies=[Depends(_require_auth_csrf)])
async def reconcile_utxos(request: Request, db: AsyncSession = Depends(get_db)) -> Any:
    counters = await utxo_service.reconcile(db)
    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "utxo_reconcile",
        "wallet",
        details=counters,
        success=not counters.get("error"),
        ip_address=ip,
    )
    if counters.get("error"):
        return JSONResponse(
            status_code=502,
            content={"detail": "LND list_unspent failed"},
        )
    return counters


@router.post("/consolidate", dependencies=[Depends(_require_auth_csrf)])
async def consolidate_utxos(
    request: Request,
    body: ConsolidateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Sweep a chosen set of UTXOs into a single fresh output.

    Strategy:

    1. Generate a fresh receive address of the requested type.
    2. Call ``send_coins(outpoints=…, send_all=True, address=…)``.
    3. On success, write an ``inherited`` label
       ``"Consolidated: N inputs"`` onto the new output (vout 0 by
       LND convention for sweeps) and stamp parents as spent.

    A vsize sanity bound of 100 kvB is enforced upstream in LND, but
    we also reject obviously-pathological calls here.
    """
    if len(body.outpoints) > 200:
        raise HTTPException(status_code=400, detail="Too many outpoints (max 200)")

    addr_data, addr_err = await lnd_service.new_address(body.dest_address_type)
    if addr_err or not addr_data:
        return JSONResponse(
            status_code=502,
            content={"detail": sanitize_upstream_error(addr_err or "no address", "LND")},
        )
    address = addr_data.get("address", "") if addr_data else ""
    if not address:
        return JSONResponse(status_code=502, content={"detail": "LND returned empty address"})

    outpoints_payload: list[Outpoint] = [
        Outpoint(txid_str=op.txid_str, output_index=op.output_index) for op in body.outpoints
    ]

    data, error = await lnd_service.send_coins(
        address=address,
        amount_sats=None,
        sat_per_vbyte=body.sat_per_vbyte,
        label=body.label or "Consolidate UTXOs",
        outpoints=outpoints_payload,
        send_all=True,
    )
    ip = request.client.host if request.client else None
    txid = data.get("txid", "") if data else ""
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "consolidate",
        "onchain",
        details={
            "input_count": len(outpoints_payload),
            "dest_address_type": body.dest_address_type,
            "txid": txid,
        },
        success=error is None,
        error_message=error,
        ip_address=ip,
    )
    if error:
        return JSONResponse(
            status_code=502,
            content={"detail": sanitize_upstream_error(error, "LND")},
        )

    if txid:
        try:
            await utxo_service.inherit_on_spend(
                db,
                spent_outpoints=outpoints_payload,
                new_txid=txid,
                change_vout=0,
                consolidate=True,
            )
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("inherit_on_spend (consolidate) failed: %s", exc)
    return {"txid": txid, "address": address, "input_count": len(outpoints_payload)}


# ── API key management (dashboard-side proxy to api_key_service) ─────────
#
# The dashboard is the human operator's privileged interface; it doesn't
# carry an admin API key, so we expose the same CRUD as
# /api/v1/admin/api-keys here, gated by the dashboard session cookie +
# CSRF token. All mutations go through ``app.services.api_key_service``
# so validation, self-protection, retention-window gating, and audit-log
# emission stay byte-identical with the admin REST surface.


_DASHBOARD_ACTOR = DashboardActor(DASHBOARD_KEY_ID)


class DashCreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    # ``scope`` is canonical (monitor | spend | admin); ``is_admin`` is a
    # defaulted alias mapping to admin/monitor for forward compatibility.
    scope: Optional[str] = None
    is_admin: Optional[bool] = None
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650)


class DashUpdateAPIKeyRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    is_active: Optional[bool] = None
    scope: Optional[str] = None
    is_admin: Optional[bool] = None


def _serialize_api_key_with_status(k: Any) -> dict[str, Any]:
    """Server-computed status pill so client + server agree on the label."""
    payload = api_key_service.serialize_key(k)
    now = datetime.now(timezone.utc)
    expires_at = k.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if k.deleted_at is not None:
        status = "revoked"
    elif not k.is_active:
        status = "disabled"
    elif expires_at is not None and expires_at <= now:
        status = "expired"
    elif expires_at is not None and (expires_at - now) <= timedelta(days=14):
        status = "expiring"
    else:
        status = "active"
    payload["status"] = status

    # Compute purge eligibility for the UI ("Purge available in N days").
    retention_days = settings.audit_log_retention_days
    purge_eligible_at: Optional[datetime] = None
    if k.deleted_at is not None and retention_days > 0:
        deleted_at = k.deleted_at
        assert deleted_at is not None  # guarded by k.deleted_at is not None above
        if deleted_at.tzinfo is None:
            deleted_at = deleted_at.replace(tzinfo=timezone.utc)
        purge_eligible_at = deleted_at + timedelta(days=retention_days)
    elif k.deleted_at is not None and retention_days == 0:
        purge_eligible_at = k.deleted_at
        assert purge_eligible_at is not None  # guarded by k.deleted_at is not None above
        if purge_eligible_at.tzinfo is None:
            purge_eligible_at = purge_eligible_at.replace(tzinfo=timezone.utc)
    payload["purge_eligible_at"] = purge_eligible_at.isoformat() if purge_eligible_at else None
    return payload


@router.get("/api-keys", dependencies=[Depends(_require_auth)])
async def dash_list_api_keys(db: AsyncSession = Depends(get_db)) -> Any:
    keys = await api_key_service.list_keys(db)
    return {"keys": [_serialize_api_key_with_status(k) for k in keys]}


@router.post("/api-keys", dependencies=[Depends(_require_auth_csrf)])
async def dash_create_api_key(
    body: DashCreateAPIKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    api_key, raw_key = await api_key_service.create_key(
        db,
        actor=_DASHBOARD_ACTOR,
        name=body.name,
        scope=body.scope,
        is_admin=body.is_admin,
        expires_in_days=body.expires_in_days,
        ip_address=request.client.host if request.client else None,
    )
    payload = _serialize_api_key_with_status(api_key)
    payload["key"] = raw_key  # plaintext — shown once
    payload["warning"] = "Store this key securely — it cannot be retrieved later."
    return payload


@router.patch("/api-keys/{key_id}", dependencies=[Depends(_require_auth_csrf)])
async def dash_update_api_key(
    key_id: str,
    body: DashUpdateAPIKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    target, changes = await api_key_service.update_key(
        db,
        actor=_DASHBOARD_ACTOR,
        key_id=key_id,
        name=body.name,
        is_active=body.is_active,
        scope=body.scope,
        is_admin=body.is_admin,
        ip_address=request.client.host if request.client else None,
    )
    return {
        "status": "updated",
        "changes": changes,
        "key": _serialize_api_key_with_status(target),
    }


@router.delete("/api-keys/{key_id}", dependencies=[Depends(_require_auth_csrf)])
async def dash_delete_api_key(
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    target = await api_key_service.soft_delete_key(
        db,
        actor=_DASHBOARD_ACTOR,
        key_id=key_id,
        ip_address=request.client.host if request.client else None,
    )
    return {
        "status": "deleted",
        "soft_delete": True,
        "key": _serialize_api_key_with_status(target),
    }


@router.post("/api-keys/{key_id}/purge", dependencies=[Depends(_require_auth_csrf)])
async def dash_purge_api_key(
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    await api_key_service.purge_key(
        db,
        actor=_DASHBOARD_ACTOR,
        key_id=key_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "purged"}


# ── Audit log viewer (read-only) ─────────────────────────────────────────
#
# Cursor-paginated walk of the audit log. The cursor is server-issued
# and validated as ``"<iso8601>|<uuid>"``; clients must echo it back
# unchanged. We never trust client-supplied cursors beyond their
# structural shape — values get parsed into typed objects before being
# bound to the SQL query.


_AUDIT_ACTION_RE = re.compile(r"^[a-zA-Z_]+$")
_AUDIT_NAME_RE = re.compile(r"^[A-Za-z0-9 ._\-+@:/()]+$")


def _encode_audit_cursor(entry: AuditLog) -> str:
    created = entry.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return f"{created.isoformat()}|{entry.id}"


def _decode_audit_cursor(cursor: str) -> tuple[datetime, UUID]:
    try:
        iso, uid = cursor.split("|", 1)
        when = datetime.fromisoformat(iso)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when, UUID(uid)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid cursor")


@router.get("/audit-log", dependencies=[Depends(_require_auth)])
async def dash_get_audit_log(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[str] = Query(default=None, max_length=128),
    action: Optional[str] = Query(default=None, max_length=50),
    api_key_name: Optional[str] = Query(default=None, max_length=128),
    since: Optional[str] = Query(default=None, max_length=64),
    until: Optional[str] = Query(default=None, max_length=64),
) -> Any:
    """Paginated audit-log viewer for the dashboard.

    Filters are applied server-side; ``action`` and ``api_key_name``
    are constrained to safe character classes before reaching SQL
    (defence in depth on top of SQLAlchemy parameter binding).
    """
    from sqlalchemy import and_, or_

    if action is not None and not _AUDIT_ACTION_RE.match(action):
        raise HTTPException(status_code=400, detail="Invalid action filter")
    if api_key_name is not None and not _AUDIT_NAME_RE.match(api_key_name):
        raise HTTPException(status_code=400, detail="Invalid api_key_name filter")

    def _parse_ts(label: str, value: Optional[str]) -> Optional[datetime]:
        if value is None:
            return None
        try:
            when = datetime.fromisoformat(value)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid {label} timestamp")
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when

    since_ts = _parse_ts("since", since)
    until_ts = _parse_ts("until", until)

    query = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())

    if action:
        query = query.where(AuditLog.action == action)
    if api_key_name:
        query = query.where(AuditLog.api_key_name.ilike(f"%{api_key_name}%"))
    if since_ts is not None:
        query = query.where(AuditLog.created_at >= since_ts)
    if until_ts is not None:
        query = query.where(AuditLog.created_at <= until_ts)
    if cursor:
        c_when, c_id = _decode_audit_cursor(cursor)
        # Strict less-than on (created_at, id) for a stable, gap-free
        # cursor walk under the desc ordering.
        query = query.where(
            or_(
                AuditLog.created_at < c_when,
                and_(AuditLog.created_at == c_when, AuditLog.id < c_id),
            )
        )

    # Fetch limit+1 so we know whether there's a next page without an
    # extra COUNT round-trip.
    result = await db.execute(query.limit(limit + 1))
    rows = list(result.scalars().all())
    has_more = len(rows) > limit
    page = rows[:limit]
    next_cursor = _encode_audit_cursor(page[-1]) if has_more and page else None

    return {
        "entries": [
            {
                "id": str(e.id),
                "api_key_name": e.api_key_name,
                "action": e.action,
                "resource": e.resource,
                "details": e.details,
                "amount_sats": e.amount_sats,
                "success": e.success,
                "error_message": e.error_message,
                "ip_address": e.ip_address,
                "created_at": e.created_at.isoformat(),
            }
            for e in page
        ],
        "next_cursor": next_cursor,
    }


@router.get("/audit-log/verify", dependencies=[Depends(_require_auth)])
async def dash_verify_audit_log(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Walk the entire audit chain and report any tamper evidence."""
    from app.services.audit_service import current_anchor

    result = await verify_chain(db, limit=None, batch_size=1000)
    # Surface the current externally-anchorable head/count so a dashboard
    # operator can reconcile it against retained signed ``audit_anchor`` events
    # (front-truncation spot-check), matching the admin API.
    result["anchor"] = await current_anchor(db)
    return result


@router.post("/audit-log/reanchor", dependencies=[Depends(_require_auth_csrf)])
async def dash_reanchor_audit_log(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Re-anchor the audit chain under the current key.

    Used to recover after a database restore or SECRET_KEY rotation, when
    verification fails and retention pruning is paused. The re-anchor is
    recorded as its own audit entry.
    """
    return await reanchor_chain(db, DASHBOARD_KEY_ID, "__dashboard__")


@router.get("/audit-log/actions", dependencies=[Depends(_require_auth)])
async def dash_audit_log_actions(db: AsyncSession = Depends(get_db)) -> Any:
    """Distinct action names, for the action-filter dropdown.

    Bounded by the ``action`` column's ``[a-zA-Z_]+`` constraint that
    the rest of the system enforces, so the result is always a small
    enum-like set rather than unbounded user input.
    """
    from sqlalchemy import distinct

    result = await db.execute(select(distinct(AuditLog.action)).order_by(AuditLog.action.asc()))
    return {"actions": [row[0] for row in result.all() if row[0]]}


# ── Anonymize ─────────────────────────────────────────────────────────────
#
# Dashboard Anonymize tab endpoints. The actual orchestrator
# logic lives in ``app.services.anonymize.service``; these endpoints are
# the dashboard surface.
#
# Endpoints surface a ``503`` when the service is unavailable. When
# ``settings.anonymize_enabled`` is False the entire surface returns
# ``404`` so the tab can be hidden.


@router.get(
    "/anonymize/sessions",
    dependencies=[Depends(_require_auth)],
)
async def dash_anonymize_sessions(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List active + recent (last 30 d) anonymize sessions."""
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import or_, select

    from app.models.anonymize_session import (
        ANONYMIZE_TERMINAL_STATUSES,
        AnonymizeSession,
    )
    from app.services.anonymize.projections import project_session_summary

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stmt = (
        select(AnonymizeSession)
        .where(AnonymizeSession.deleted_at.is_(None))
        .where(
            or_(
                AnonymizeSession.status.notin_(list(ANONYMIZE_TERMINAL_STATUSES)),
                AnonymizeSession.completed_at >= cutoff,
            )
        )
        .order_by(AnonymizeSession.created_at.desc())
        .limit(200)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return {"sessions": [project_session_summary(s) for s in rows]}


@router.get(
    "/anonymize/sessions/{session_id}",
    dependencies=[Depends(_require_auth)],
)
async def dash_anonymize_session_detail(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Session detail + state log."""
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    from uuid import UUID

    from sqlalchemy import select

    from app.models.anonymize_session import (
        AnonymizeSession,
        AnonymizeSessionEvent,
    )
    from app.services.anonymize.projections import project_session_detail

    try:
        sid = UUID(session_id)
    except ValueError:
        # Refuse to leak shape — same 404 as an unknown id.
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    sess = (
        await db.execute(
            select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sess is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    events = list(
        (
            await db.execute(
                select(AnonymizeSessionEvent)
                .where(AnonymizeSessionEvent.session_id == sid)
                .order_by(AnonymizeSessionEvent.ts.asc())
                .limit(500)
            )
        )
        .scalars()
        .all()
    )

    body = project_session_detail(sess, events=events)

    # Attach the aggregated recovery hint when the session has any
    # underlying BoltzSwap legs (LN↔on-chain or Liquid round-trip),
    # or when the session-level classifier surfaces a hint (e.g.
    # awaiting_liquid_dwell stuck). The dashboard banner reads
    # ``recovery.state`` / ``severity`` to decide whether to render.
    try:
        recovery = await _build_session_recovery(
            db,
            swap_ids=[sess.submarine_swap_id, sess.reverse_swap_id],
            session_status=sess.status,
            session_updated_at=sess.updated_at,
            session_pipeline_json=sess.pipeline_json,
        )
        if recovery is not None:
            body["recovery"] = recovery
    except Exception:  # noqa: BLE001
        logger.exception(
            "anonymize session recovery enrichment failed for %s",
            sid,
        )

    return body


@router.post(
    "/anonymize/quote",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_quote(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Dry-run pipeline build.

     quote network silence: this endpoint reads only local
    caches (operator pair-info, fee bands). It never sends the
    destination address, amount, or selected operators to any
    external service.

    Returns a signed quote token bound to the cookie subject + the
    canonical request body (#7). The SPA passes the token back
    into ``POST /anonymize/sessions`` to commit the quote.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from app.services.anonymize.chain import is_trusted_local_chain_backend
    from app.services.anonymize.quote_builder import (
        QuoteBuildError,
        QuoteRequest,
        build_quote,
        result_to_dict,
    )
    from app.services.anonymize.quote_token import (
        load_quote_token_keyset,
    )
    from app.services.anonymize.responses import (
        destination_rejected_response,
    )

    keyset = load_quote_token_keyset()
    if keyset is None:
        # Lifespan canary should have caught this; surface as 503 if
        # the deployment is mid-rotation with no active key.
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_quote_unavailable"},
        )

    # Capture raw body bytes BEFORE pydantic parsing so the bound
    # canonical_request_body_hash matches exactly what the SPA sent.
    body_bytes = await request.body()
    try:
        import json as _json

        body = _json.loads(body_bytes or b"{}")
    except Exception as _exc:  # noqa: BLE001
        # Operator-side observability — the HTTP response stays
        # byte-pinned, but the server log records the
        # rejection class so failures don't show up as opaque 422s
        # in the operator journal. The user-supplied body is NOT
        # logged (— error paths must not preserve PII /
        # destination addresses); only the exception class.
        logger.warning(
            "anonymize quote rejected: invalid_json (%s)",
            type(_exc).__name__,
        )
        return destination_rejected_response()

    source_kind = str(body.get("source_kind", ""))
    destination_address = str(body.get("destination_address", ""))
    try:
        requested_amount_sat = int(body.get("requested_amount_sat", 0))
    except (TypeError, ValueError):
        logger.warning(
            "anonymize quote rejected: requested_amount_sat not coercible to int",
        )
        return destination_rejected_response()
    # Option C — per-quote opt-in for the Liquid round-trip
    # hop. Coerced to a strict bool so truthy strings ("yes", "1")
    # are NOT silently accepted — the SPA must send JSON ``true``.
    prefer_liquid = body.get("prefer_liquid", False) is True
    # Per-quote ext-lightning deposit method. ``None`` falls
    # back to the operator-wide
    # ``ANONYMIZE_EXT_LIGHTNING_DEPOSIT_METHOD`` setting in the
    # builder.
    deposit_method_raw = body.get("deposit_method")
    deposit_method: str | None
    if isinstance(deposit_method_raw, str) and deposit_method_raw:
        deposit_method = deposit_method_raw
    else:
        deposit_method = None

    # When the input is a ``user@domain`` BIP-353 handle,
    # resolve it via DoH-over-Tor before the (synchronous)
    # quote-builder runs. Build-time uses the resolved on-chain
    # address; the original handle is preserved for audit + the
    # ``settlement`` block of the response so the SPA can render
    # what was resolved. A Lightning-only handle is refused with
    # the same generic shape as a malformed address.
    from app.services.anonymize.address import (
        DestinationRejectedError,
        is_bip353_handle,
        resolve_anonymize_destination,
    )

    resolved_bip353 = None
    if is_bip353_handle(destination_address):
        try:
            resolved = await resolve_anonymize_destination(destination_address)
        except DestinationRejectedError as _exc:
            logger.warning(
                "anonymize quote rejected: bip353_resolver (%s)",
                _exc,
            )
            return destination_rejected_response()
        destination_address = resolved.address
        resolved_bip353 = resolved

    # Cookie subject for the quote-token binding — the dashboard's
    # session cookie, HMAC-opaqued by the quote layer.
    cookie_subject = _cookie_subject(request)

    # Propagate the resolved exit kind. For BIP-353 handles
    # that publish only a BOLT 12 offer, the resolver returns
    # ``exit_kind="bolt12_pay"`` and the builder constructs a
    # Lightning-exit pipeline instead of a reverse-swap exit.
    exit_kind: str = "reverse"
    bolt12_offer: str | None = None
    bip353_handle: str | None = None
    if resolved_bip353 is not None:
        exit_kind = resolved_bip353.exit_kind
        bolt12_offer = resolved_bip353.bolt12_offer
        bip353_handle = resolved_bip353.bip353_handle

    # Explicit per-session consent flag for single-operator
    # fallback. Defaults to False so a request that didn't go through
    # the modal cannot silently degrade.
    allow_single_operator_fallback = bool(body.get("allow_single_operator_fallback", False))

    qreq = QuoteRequest(
        source_kind=source_kind,
        destination_address=destination_address,
        requested_amount_sat=requested_amount_sat,
        cookie_subject=cookie_subject,
        canonical_request_body=body_bytes,
        prefer_liquid=prefer_liquid,
        exit_kind=exit_kind,  # type: ignore[arg-type]
        bolt12_offer=bolt12_offer,
        bip353_handle=bip353_handle,
        deposit_method=deposit_method,  # type: ignore[arg-type]
        allow_single_operator_fallback=allow_single_operator_fallback,
    )

    health: dict[str, Any] = getattr(request.app.state, "anonymize_health", {}) or {}

    # For on-chain sources, pre-compute the operator selection
    # via the async selector. The result (or sentinel) is interpreted
    # below and mapped to either an HTTP 409 / 503 or a successful
    # build_quote call.
    #
    # URL-pin bypass: when either ``BOLTZ_SUBMARINE_ONION_URL`` or
    # ``BOLTZ_REVERSE_ONION_URL`` is set, the chain selector is
    # suppressed and the legacy single-operator flow takes over per
    # plan. The pinned URLs are read by the swap egress code
    # directly via ``resolve_*_leg_url`` at session execute time;
    # no selector / probe runs at quote time.
    selection_obj = None
    url_pins_active = bool(
        getattr(settings, "boltz_submarine_onion_url", "") or getattr(settings, "boltz_reverse_onion_url", "")
    )
    if source_kind in {"onchain-self", "ext-onchain"} and not url_pins_active:
        from app.services.anonymize.operator_selection import (
            ReverseProbeFailed,
            SubmarineChainExhausted,
            emit_reverse_probe_failed_audit,
            select_operators_for_onchain_session,
        )
        from app.services.anonymize.operators import (
            load_signed_operator_registry,
        )

        try:
            registry = load_signed_operator_registry()
        except Exception:  # noqa: BLE001
            registry = []
        if registry:
            try:
                selection_obj = await select_operators_for_onchain_session(
                    registry=registry,
                    bin_amount_sat=int(requested_amount_sat),
                    allow_single_operator_fallback=allow_single_operator_fallback,
                    db=db,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "anonymize quote: operator selection failed: %s",
                    exc,
                )
                # Surface as a destination_rejected so the SPA gets the
                # generic-failure UX rather than a 500.
                return destination_rejected_response()

            if isinstance(selection_obj, SubmarineChainExhausted):
                return JSONResponse(
                    status_code=409,
                    content={
                        "code": "submarine_chain_exhausted",
                        "attempted": [
                            {"operator_id": a.operator_id, "status": a.status} for a in selection_obj.chain_attempted
                        ],
                        "single_operator_fallback_available": (selection_obj.single_operator_fallback_available),
                    },
                )
            if isinstance(selection_obj, ReverseProbeFailed):
                # Audit-log emission for the v2-trigger metric. Done
                # before returning so the row is persisted regardless
                # of whether the client retries.
                try:
                    await emit_reverse_probe_failed_audit(
                        db,
                        operator_id=selection_obj.operator_id,
                        status=selection_obj.status,
                    )
                except Exception:  # noqa: BLE001
                    pass
                code = (
                    "all_submarine_operators_unreachable"
                    if selection_obj.from_single_operator_fallback
                    else "reverse_probe_failed"
                )
                return JSONResponse(
                    status_code=503,
                    content={
                        "code": code,
                        "operator_id": selection_obj.operator_id,
                    },
                )

    try:
        result = build_quote(
            qreq,
            keyset=keyset,
            operator_registry_size=int(health.get("operator_registry_size", 0)),
            egress_endpoints_onion_only=bool(health.get("egress_endpoints_onion_only", True)),
            tor_process_shared_with_lnd=False,  # gate refuses otherwise
            # A trusted local backend is not "public" — no third-party observer,
            # so it does not trigger the scorer's weak cap.
            public_chain_backend_enabled=(
                bool(settings.anonymize_allow_public_chain_backend) and not is_trusted_local_chain_backend()
            ),
            selection=selection_obj,  # type: ignore[arg-type]
        )
    except QuoteBuildError as _exc:
        # ``QuoteBuildError`` carries the specific validator class
        # (destination format, network mismatch, script type cap,
        # amount-bin range, unsupported source kind, etc.). The HTTP
        # response stays byte-pinned; the operator log
        # records the reason so a wedged session can be triaged
        # without re-running the request with a debugger.
        logger.warning(
            "anonymize quote rejected: build_quote (%s)",
            _exc,
        )
        return destination_rejected_response()

    out = result_to_dict(result)
    if resolved_bip353 is not None:
        # Surface what was resolved so the SPA can render the
        # confirmation step before the user commits to the quote.
        # ``exit_kind="reverse"`` resolutions carry the on-chain
        # ``resolved_address``; ``exit_kind="bolt12_pay"`` resolutions
        # carry the resolved BOLT 12 offer instead and leave the
        # address empty.
        out["bip353"] = {
            "handle": resolved_bip353.bip353_handle,
            "exit_kind": resolved_bip353.exit_kind,
            "resolved_address": resolved_bip353.address,
            "bolt12_offer": resolved_bip353.bolt12_offer,
        }
    return out


@router.post(
    "/anonymize/sessions",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_create_session(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a session from a quote token.

    The SPA passes the ``quote_token`` returned by ``POST /anonymize/quote``;
    the orchestrator decodes the bound payload, runs the admission
    gate, persists the row, and spawns the per-session task.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from app.services.anonymize.admission import (
        AdmissionInputs,
        count_in_flight_sessions,
        count_sessions_created_in_window,
        decide_session_create_admission,
    )
    from app.services.anonymize.projections import (
        project_session_detail,
    )
    from app.services.anonymize.quote_builder import _hmac_cookie_subject
    from app.services.anonymize.quote_token import (
        QuoteTokenError,
        decode_quote_token,
        load_quote_token_keyset,
    )
    from app.services.anonymize.responses import (
        creation_unavailable_response,
        destination_rejected_response,
        quote_expired_response,
    )
    from app.services.anonymize.service import get_anonymize_service

    keyset = load_quote_token_keyset()
    if keyset is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_create_unavailable"},
        )

    import json as _json

    try:
        body = _json.loads(await request.body() or b"{}")
    except Exception:  # noqa: BLE001
        return destination_rejected_response()

    token = body.get("quote_token")
    if not isinstance(token, str) or not token:
        return destination_rejected_response()

    # Cookie subject for the quote-token binding — the dashboard's
    # session cookie, HMAC-opaqued by the quote layer.
    cookie_subject = _cookie_subject(request)
    expected_cookie_hmac = _hmac_cookie_subject(
        cookie_subject,
        keyset.active_key,
    )

    try:
        bound = decode_quote_token(
            token,
            keyset=keyset,
            expected_cookie_subject_hmac=expected_cookie_hmac,
        )
    except QuoteTokenError as exc:
        # Distinguish TTL expiry (byte-pinned 409) from every other
        # invalidity (byte-pinned 422 destination_rejected to deny
        # enumeration of bound-cookie / replay attempts).
        if "expired" in str(exc):
            return quote_expired_response()
        return destination_rejected_response()

    # Refuse session creation when the clock-skew probe is
    # warming up (no measurement yet) or has measured the local clock
    # outside the threshold. The four-state ``clock_skew_status``
    # machine distinguishes warming_up (transient, retry shortly) from
    # unhealthy (operator action required) so the wizard can render
    # friendly copy.
    health: dict[str, Any] = getattr(request.app.state, "anonymize_health", {}) or {}
    clock_status = health.get("clock_skew_status")
    if clock_status in ("unknown", "warming_up"):
        completes_at = health.get("clock_skew_warmup_completes_at_unix_s")
        seconds_remaining: int | None = None
        if completes_at is not None:
            try:
                seconds_remaining = max(0, int(float(completes_at) - time.time()))
            except (TypeError, ValueError):
                seconds_remaining = None
        return JSONResponse(
            status_code=503,
            content={
                "detail": "anonymize_clock_warming_up",
                "seconds_remaining": seconds_remaining,
            },
        )
    if clock_status == "unhealthy" or (clock_status is None and health.get("clock_skew_within_threshold") is False):
        # ``clock_status is None`` is the legacy-state fallback for
        # the brief window between this code shipping and the next
        # probe tick populating the new field. The boolean still
        # reflects the truth in that window.
        return JSONResponse(
            status_code=503,
            content={
                "detail": "anonymize_clock_skew_unhealthy",
                "measured_skew_ms": health.get("clock_skew_ms"),
                "threshold_ms": health.get("clock_skew_threshold_ms"),
            },
        )
    # Admission gate. Refuse to create a session
    # when Tor isn't fully bootstrapped. Uses the *effective* signal —
    # the dedicated control-port probe OR a successful clock-skew
    # probe (which proves SOCKS + Tor circuits + onion round-trip all
    # work). Deployments without an exposed Tor ControlPort rely on
    # the clock-skew derivation; see
    # :func:`compute_effective_tor_ready` for the precise rule.
    from app.services.anonymize.tor import compute_effective_tor_ready as _compute_tor_ready

    if not _compute_tor_ready(health):
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_tor_not_bootstrapped"},
        )

    # Three-budget per-cookie/user/IP limiter. Runs before
    # the DB-state gate so a flood from one cookie can't even reach
    # the (more expensive) count queries below.
    svc = get_anonymize_service()
    limiter = svc.create_rate_limiter()
    source_ip = request.client.host if request.client is not None else None
    from app.services.anonymize.rate_limit import RequestIdentity

    identity = RequestIdentity(
        cookie_id=cookie_subject,
        authenticated_user_id=None,
        source_ip=source_ip,
    )
    rl_decision = limiter.check_and_consume_with_reason(identity)
    if not rl_decision.admitted:
        # Log which budget tripped so a 429 is diagnosable. A null
        # ``exhausted_bucket`` means the request resolved to *no*
        # identity key (cookie missing + coarse-IP identity disabled) —
        # which fail-closes every create regardless of count.
        logger.warning(
            "anonymize create refused by reuse limiter: exhausted_bucket=%s "
            "(null = empty identity / no resolvable key)",
            rl_decision.exhausted_bucket,
        )
        return creation_unavailable_response()

    # admission gate — DB-state-based in-flight count
    # + creation rate within a rolling 1h window. Buckets
    # every active session under the ``weak`` tier when the scorer-
    # populated tier column is absent; otherwise reads
    # the per-session tier.
    # Serialize the count→insert critical section so concurrent creates
    # can't all observe the same pre-insert count and bypass the cap.
    from app.services.anonymize.admission import acquire_admission_lock

    await acquire_admission_lock(db)
    in_flight_total = await count_in_flight_sessions(db)
    created_in_window = await count_sessions_created_in_window(db)
    decision = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="weak",
            in_flight_count_by_tier={"weak": in_flight_total},
            sessions_created_in_window_count=created_in_window,
            window_max=int(settings.anonymize_create_window_max_per_hour),
        )
    )
    if decision != "admit":
        # Distinguish the two admission caps in the logs: rolling-window
        # creation rate vs concurrent in-flight tier cap.
        logger.warning(
            "anonymize create refused by admission gate: decision=%s in_flight=%d created_in_window=%d window_max=%d",
            decision,
            in_flight_total,
            created_in_window,
            int(settings.anonymize_create_window_max_per_hour),
        )
        return creation_unavailable_response()

    # Persist the row in CREATED status. The orchestrator's per-
    # session task drives forward from here. Source-kind-specific
    # fields (deposit_invoice / deposit_address) land in follow-on
    # hop-execution PRs.
    from uuid import uuid4

    from app.models.anonymize_session import (
        AnonymizeSession,
        AnonymizeStatus,
    )
    from app.services.anonymize.crypto import encrypt_destination_address

    bound_pipeline_json = bound["canonical_pipeline_json"]
    bin_amount = int(bound["bin_amount_sat"])

    # Third validation point. The destination was checked
    # at quote-time and the token MAC guarantees it hasn't changed,
    # but we re-validate here against the running config so a
    # network-changed deployment doesn't silently admit an old token.
    pipeline_obj = _json.loads(bound_pipeline_json)
    dest_addr = pipeline_obj["exit"]["destination_address"]
    exit_kind = pipeline_obj["exit"].get("kind", "reverse")
    bip353_handle = pipeline_obj["exit"].get("bip353_handle")
    bolt12_offer = pipeline_obj["exit"].get("bolt12_offer")

    # BOLT 12 exit has no on-chain destination to re-validate.
    # The destination identity is the BIP-353 handle bound in the
    # pipeline; we use that for the encrypted column + reuse-detection
    # hash so the hard-block still applies (so a later
    # session with the same handle but a re-resolved offer still
    # collides on the handle).
    if exit_kind == "bolt12_pay":
        if not (bolt12_offer or "").strip():
            return destination_rejected_response()
        if not (bip353_handle or "").strip():
            # A BOLT 12 exit without a BIP-353 handle has no stable
            # identity for reuse detection. Refuse uniformly.
            return destination_rejected_response()
        script_type = "bolt12"
        reuse_subject = str(bip353_handle)
        enc_subject = str(bip353_handle)
    else:
        try:
            from app.services.anonymize.address import (
                DestinationRejectedError,
                parse_and_validate_destination,
            )

            _dest_addr, script_type = parse_and_validate_destination(dest_addr)
        except DestinationRejectedError:
            return destination_rejected_response()
        reuse_subject = dest_addr
        enc_subject = dest_addr

    # destination-reuse hard-block. Hashes the candidate
    # against every loaded key generation; a match against a prior
    # session row triggers the byte-pinned 422 ``destination_rejected``
    # response. The blake2b_keyed column we persist for *this* row
    # uses the active key so the rotation framework can
    # purge it on horizon expiry.
    from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL
    from app.services.anonymize.reuse_detection import (
        is_destination_reused,
        load_reuse_detection_keyset,
    )

    reuse_keyset = load_reuse_detection_keyset()
    if reuse_keyset is not None:
        if await is_destination_reused(
            db,
            candidate_address=reuse_subject,
            keyset=reuse_keyset,
        ):
            # Pay the same key-derivation cost the accept path incurs at
            # ``encrypt_destination_address`` (PBKDF2) before returning,
            # so the reuse hard-block is not separable from an accepted
            # create by response time — closing the destination-already-
            # used timing oracle. The ciphertext is discarded.
            _ = encrypt_destination_address(reuse_subject)
            return destination_rejected_response()
        reuse_hash = reuse_keyset.hash_active(reuse_subject)
        reuse_generation = reuse_keyset.active_generation
    else:
        # Lightning-only deployments without a configured reuse key fall
        # back to the sentinel so the partial index excludes
        # the row from future reuse lookups.
        reuse_hash = REUSE_DETECTION_SENTINEL
        reuse_generation = 0

    # For ext-lightning sources, mint a deposit
    # primitive the depositor pays. The token-bound ``deposit_method``
    # selects between BOLT 11 (legacy single-use invoice) and BOLT 12
    # (per-session offer + optional BIP-353 handle). Either way the
    # resulting strings land in ``pipeline_json["source"]`` so the
    # per-session task observer reads them.
    if pipeline_obj["source"]["kind"] == "ext-lightning":
        deposit_method = pipeline_obj["source"].get("deposit_method") or "bolt11"
        import logging as _logging

        from app.services.anonymize.metadata import ANONYMIZE_LOGGER_NAME

        _deposit_logger = _logging.getLogger(ANONYMIZE_LOGGER_NAME)

        if deposit_method == "bolt12":
            from app.dashboard import DASHBOARD_KEY_ID
            from app.models.api_key import APIKey
            from app.services.anonymize.deposit_offer import (
                DepositOfferError,
                issue_ext_lightning_deposit_offer,
            )

            # Pre-flight: the per-session BOLT 12 offer row
            # is FK-bound to ``DASHBOARD_KEY_ID``. A deployment that
            # never created the sentinel row (or had it deleted) would
            # get a cryptic IntegrityError on the offer insert; refuse
            # the mint early with a clear log line instead.
            dashboard_key = await db.get(APIKey, DASHBOARD_KEY_ID)
            if dashboard_key is None:
                _deposit_logger.warning(
                    "anonymize: BOLT 12 deposit-offer mint skipped — "
                    "DASHBOARD_KEY_ID row missing; falling back to "
                    "no-deposit session. Operator: ensure the sentinel "
                    "API key row exists at startup."
                )
            else:
                bip353_domain = (
                    getattr(
                        settings,
                        "anonymize_bip353_deposit_domain",
                        "",
                    )
                    or ""
                ).strip() or None
                try:
                    offer = await issue_ext_lightning_deposit_offer(
                        amount_msat=bin_amount * 1000,
                        description=f"anonymize-{uuid4().hex[:8]}",
                        api_key_id=DASHBOARD_KEY_ID,
                        db=db,
                        bip353_domain=bip353_domain,
                    )
                    src_block = pipeline_obj.setdefault("source", {})
                    src_block["deposit_bolt12_offer"] = offer.bolt12_offer
                    src_block["deposit_offer_id"] = offer.offer_id
                    if offer.bip353_handle:
                        src_block["deposit_bip353_handle"] = offer.bip353_handle
                        src_block["deposit_bip353_txt_record"] = offer.bip353_txt_record
                except DepositOfferError as exc:
                    # Same forward-fallback semantics as the BOLT 11
                    # path: the orchestrator can retry the issue on
                    # a later tick. Log so operator alerting can
                    # surface the cause (refused amount, malformed
                    # BIP-353 domain, etc.).
                    _deposit_logger.warning(
                        "anonymize: BOLT 12 deposit-offer mint refused: %s",
                        exc,
                    )
                except Exception:  # noqa: BLE001
                    _deposit_logger.exception(
                        "anonymize: BOLT 12 deposit-offer mint failed with unexpected error",
                    )
        else:
            from app.services.anonymize.deposit_invoice import (
                DepositInvoiceError,
                issue_ext_lightning_deposit_invoice,
            )

            try:
                inv = await issue_ext_lightning_deposit_invoice(
                    amount_msat=bin_amount * 1000,
                    memo=f"anonymize-{uuid4().hex[:8]}",
                )
                pipeline_obj.setdefault("source", {})["deposit_invoice"] = inv.payment_request
            except DepositInvoiceError as exc:
                # Fall through with no invoice — the depositor sees
                # the session in CREATED with no invoice. Operator
                # alerting surfaces the LND-side reason; we don't
                # 503 the create request because the orchestrator
                # can retry the issue on a later tick.
                _deposit_logger.warning(
                    "anonymize: BOLT 11 deposit-invoice issue refused: %s",
                    exc,
                )
            except Exception:  # noqa: BLE001
                # LND service genuinely unreachable; same fallback.
                _deposit_logger.exception(
                    "anonymize: BOLT 11 deposit-invoice issue failed with unexpected error",
                )

    # On-chain inbound pre-flight (mirrors the Braiins on-chain deposit
    # gate). An on-chain source's mandated first hop is a submarine swap,
    # which needs THIS node to RECEIVE the bin amount over Lightning from
    # the provider. If our inbound capacity can't cover it, the session
    # is structurally un-completable (it would lock on-chain then refund
    # ~30 min later) — refuse now, BEFORE any funds move and before the
    # ext-onchain deposit-address derivation below. Purely local (reads
    # our own channels); no third-party egress. The reason is logged
    # server-side only and the response is the byte-pinned generic 429
    # so it can't be fingerprinted apart from the other cap-class
    # refusals.
    from app.services.anonymize.inbound_preflight import (
        inbound_preflight,
        source_requires_inbound_preflight,
    )

    if source_requires_inbound_preflight(pipeline_obj["source"]["kind"]):
        pf_refusal, pf_warning = await inbound_preflight(
            receive_sats=bin_amount,
        )
        if pf_refusal is not None:
            logger.info(
                "anonymize create: inbound pre-flight refused (%s)",
                pf_refusal,
            )
            return creation_unavailable_response()
        if pf_warning is not None:
            logger.info(
                "anonymize create: inbound pre-flight advisory (%s)",
                pf_warning,
            )

    # For ext-onchain sources, issue a fresh wallet-controlled
    # P2TR address + bind the amount-lock and dwell-window metadata
    # into pipeline_json. The depositor receives the address +
    # required amount via the wizard; the per-session loop refuses
    # mismatched deposits and waits for the dwell window before
    # consuming the deposit UTXO as the submarine source.
    if pipeline_obj["source"]["kind"] == "ext-onchain":
        from app.services.anonymize.ext_onchain_deposit import (
            issue_ext_onchain_deposit_address,
        )
        from app.services.lnd_service import lnd_service as _lnd

        try:
            addr_result, _addr_err = await _lnd.new_address(
                address_type="p2tr",
            )
            address = (
                (addr_result or {}).get("address", "")
                if isinstance(addr_result, dict)
                else getattr(addr_result, "address", "")
            )
        except Exception:  # noqa: BLE001
            address = ""
        if address:
            # ``expiry_unix_s`` = create_at + retention window.
            from datetime import datetime as _dt
            from datetime import timezone as _tz

            retention_s = int(settings.anonymize_destination_retention_days) * 86400
            expiry_unix_s = _dt.now(_tz.utc).timestamp() + retention_s
            try:
                instr = await issue_ext_onchain_deposit_address(
                    bin_amount_sat=bin_amount,
                    expiry_unix_s=expiry_unix_s,
                    derivation_index=0,
                    address=address,
                )
                pipeline_obj.setdefault("source", {})["deposit_address"] = instr.address
                pipeline_obj["source"]["deposit_amount_sat"] = instr.amount_sat
                pipeline_obj["source"]["deposit_expiry_unix_s"] = instr.expiry_unix_s
            except Exception:  # noqa: BLE001
                pass

    # Option C — persist the per-quote Liquid opt-in into the
    # session's pipeline_json so :func:`default_hop_step_fn` routes
    # the HOPPING legs through the Liquid hop body. The flag is bound
    # into the quote token (decoded into ``bound`` above), so a
    # tampered create-body cannot flip the route here.
    liquid_blinding_seed_enc: bytes | None = None
    if bool(bound.get("uses_liquid", False)):
        pipeline_obj["uses_liquid"] = True
        # Assign a fresh per-session SLIP-77 derivation
        # index and persist it Fernet-wrapped so the leg-1 claim
        # adapter can derive a wallet-owned CT destination address.
        from app.services.anonymize.liquid_seed import (
            encrypt_session_blinding_seed_index,
            generate_session_blinding_seed_index,
        )

        liquid_blinding_seed_enc = encrypt_session_blinding_seed_index(
            generate_session_blinding_seed_index(),
        )

    # Pull the bound
    # operator IDs from the verified quote token so the session row
    # carries them in dedicated columns (the hop_dispatcher also
    # reads them from pipeline_json as a fallback).
    bound_submarine_op = bound.get("submarine_operator_id")
    bound_reverse_op = bound.get("reverse_operator_id")
    bound_selection_source = str(bound.get("selection_source") or "")

    sess = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.CREATED.value,
        source_kind=pipeline_obj["source"]["kind"],
        requested_amount_sat=bin_amount,
        bin_amount_sat=bin_amount,
        pipeline_json=pipeline_obj,
        quote_hmac=expected_cookie_hmac,
        destination_address_enc=encrypt_destination_address(enc_subject),
        destination_script_type=script_type,
        pipeline_schema_version=int(pipeline_obj.get("schema_version", 10)),
        destination_address_blake2b_keyed=reuse_hash,
        destination_reuse_key_generation=reuse_generation,
        liquid_blinding_seed_enc=liquid_blinding_seed_enc,
        submarine_operator_id=bound_submarine_op,
        reverse_operator_id=bound_reverse_op,
    )
    # Single-use: a quote token authorizes exactly one create. Consumed
    # here — inside the admission advisory-lock window and as the
    # last step before the insert — so a replay is rejected while a
    # transient rejection (tier cap, clock-skew, deposit-mint error) does
    # NOT burn the token.
    from app.services.anonymize.quote_token import consume_quote_token_single_use

    if not await consume_quote_token_single_use(token, ttl_s=int(bound.get("ttl_s", 0))):
        return destination_rejected_response()
    db.add(sess)
    # UTC-day-quantized ``feature_enabled_at_day`` is set
    # idempotently on the first session-create per deployment. The
    # trigger in migration 017 ensures the stored value is quantized
    # to the day boundary regardless of how the row gets there.
    from app.services.anonymize.settings_store import (
        set_feature_enabled_at_day_if_unset,
    )

    await set_feature_enabled_at_day_if_unset(db)
    await db.commit()

    # Emit per-session selection audit-log rows. Done after
    # the session row is committed so the audit chain reflects a
    # persisted decision, not a transient pre-commit attempt. The
    # helper falls through cleanly when either operator_id is None
    # (which happens for LN-only sessions with single-operator
    # deployments).
    try:
        from app.services.anonymize.operator_selection import (
            emit_operator_selection_audit_events,
        )

        await emit_operator_selection_audit_events(
            db,
            submarine_operator_id=bound_submarine_op,
            reverse_operator_id=bound_reverse_op,
            selection_source=bound_selection_source or "primary",
        )
    except Exception:  # noqa: BLE001
        # The selection audit-log row is a diagnostic / metric
        # surface, not load-bearing. Swallow + log so a transient
        # audit-chain hiccup doesn't break the session-create.
        logger.warning(
            "anonymize session %s: selection audit emission failed",
            sess.id,
            exc_info=True,
        )

    # Spawn the per-session task using the production session factory.
    # The router dispatches to a per-source-kind observation collector
    # AND a per-source-kind hop-step fn that issues the actual Boltz
    # reverse swap + cooperative claim ceremony.
    from app.core.database import get_session_maker
    from app.services.anonymize.hop_dispatcher import default_hop_step_fn
    from app.services.anonymize.observation_router import (
        default_observation_fn,
    )

    svc.spawn_session_task(
        session_id=sess.id,
        session_factory=get_session_maker(),
        observation_fn=default_observation_fn,
        hop_step_fn=default_hop_step_fn(),
    )

    # Return the detail shape (which includes the
    # ``deposit`` block) so the wizard renders the BOLT 11 invoice /
    # BOLT 12 offer / BIP-353 handle without a follow-up fetch. The
    # event log is empty here (no events for a newly-CREATED row)
    # so the response stays compact.
    return project_session_detail(sess, events=[])


@router.post(
    "/anonymize/sessions/{session_id}/cancel",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_cancel_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Cancel a session before point-of-no-return.

    Legal from ``created``, ``sourcing``, or ``funding`` per the
    transition graph. The orchestrator's per-session task observes
    the new status on its next tick.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _transition_session_endpoint(
        db,
        session_id=session_id,
        to_status="cancelled",
        reason="user_cancel",
    )


@router.post(
    "/anonymize/sessions/{session_id}/refund",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_refund_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Force-refund path. Valid in ``ln_holding`` / ``delaying`` / ``hopping``.

    The dashboard surfaces this as a "refund now" button on a session
    whose funds are locked but whose pipeline hasn't reached the
    point-of-no-return.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _transition_session_endpoint(
        db,
        session_id=session_id,
        to_status="refunding",
        reason="user_refund_request",
    )


# ── Reconciliation actions ────────────────────────────────────────────
#
# The four endpoints below let the operator resolve a session parked
# in AWAITING_RECONCILIATION. Step-up nonce gating: only
# the fund-moving action (Refund) requires re-auth; Retry / Fail /
# Cancel target terminal-or-resume states that don't move funds.


@router.post(
    "/anonymize/sessions/{session_id}/reconciliation/retry",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_reconciliation_retry(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """User-friendly "Try again" — resume a parked session to its
    ``pre_reconciliation_status``.

    Returns 409 when the row isn't in AWAITING_RECONCILIATION or when
    ``pre_reconciliation_status`` is missing (legacy rows parked
    before the resume-target field was recorded; a startup heuristic
    backfills these). No step-up — idempotent + reversible.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _reconciliation_retry(
        db,
        session_id=session_id,
        request=request,
    )


@router.post(
    "/anonymize/sessions/{session_id}/reconciliation/fail",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_reconciliation_fail(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator force-fail — transition AWAITING_RECONCILIATION → FAILED.

    Used for reasons where no funds moved but the cancel-edge
    classifier doesn't admit "Cancel" copy (e.g.
    ``pipeline_schema_below_min_supported``, unknown reasons).
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _reconciliation_terminal(
        db,
        session_id=session_id,
        request=request,
        to_status="failed",
        audit_kind="reconciliation_manual_fail",
        require_cancellable=False,
    )


@router.post(
    "/anonymize/sessions/{session_id}/reconciliation/cancel",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_reconciliation_cancel(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """User-friendly "Cancel" — for AWAITING_RECONCILIATION rows where
    the reason is in the no-funds-moved set (classifier /
     state edge). Returns 409 with operator-readable copy when
    the reason isn't cancellable.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _reconciliation_terminal(
        db,
        session_id=session_id,
        request=request,
        to_status="cancelled",
        audit_kind="reconciliation_manual_cancel",
        require_cancellable=True,
    )


@router.post(
    "/anonymize/sessions/{session_id}/reconciliation/refund",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_reconciliation_refund(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Operator-initiated refund from AWAITING_RECONCILIATION.

    Body: ``{"stepup_nonce": "..."}``. Verified against the
    ``anonymize_reconciliation_refund`` scope. The
    transition itself is ``AWAITING_RECONCILIATION → REFUNDING``
    (already a legal edge).
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    return await _reconciliation_refund(
        db,
        session_id=session_id,
        request=request,
    )


async def _reconciliation_retry(
    db: AsyncSession,
    *,
    session_id: str,
    request: Request,
) -> Any:
    """Shared body for the retry endpoint."""
    from uuid import UUID

    from sqlalchemy import select

    from app.models.anonymize_session import (
        AnonymizeSession,
        AnonymizeSessionEvent,
        AnonymizeStatus,
    )
    from app.services.anonymize.projections import project_session_summary
    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.state_machine import (
        IllegalStateTransitionError,
        legal_next_statuses,
    )

    try:
        sid = UUID(session_id)
    except ValueError:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    sess = (
        await db.execute(
            select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sess is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if sess.status != AnonymizeStatus.AWAITING_RECONCILIATION.value:
        return JSONResponse(
            status_code=409,
            content={
                "code": "not_awaiting_reconciliation",
                "status": sess.status,
                "detail": "This session isn't parked in awaiting_reconciliation.",
            },
        )

    target = sess.pre_reconciliation_status
    if not target:
        return JSONResponse(
            status_code=409,
            content={
                "code": "no_pre_reconciliation_status",
                "detail": (
                    "This session was parked before resume-target "
                    "recording landed; no resume target was recorded. Use Refund "
                    "(if funds may be at risk) or Stop trying."
                ),
            },
        )

    svc = get_anonymize_service()
    previous_attempts = int(sess.reconciliation_attempts or 0)
    try:
        await svc.transition_session(
            db,
            sess,
            to_status=target,
            reason=f"reconciliation_manual_retry:{sess.awaiting_reconciliation_reason or ''}",
        )
    except IllegalStateTransitionError:
        return JSONResponse(
            status_code=409,
            content={
                "code": "illegal_state_transition",
                "from_status": AnonymizeStatus.AWAITING_RECONCILIATION.value,
                "to_status": target,
                "legal_next_statuses": sorted(legal_next_statuses(sess.status)),
            },
        )

    # Reset attempts so auto-retry treats this as a fresh start.
    sess.reconciliation_attempts = 0
    sess.last_reconciliation_attempt_ts = None

    db.add(
        AnonymizeSessionEvent(
            session_id=sess.id,
            kind="reconciliation_manual_retry",
            detail_json={
                "previous_attempts": previous_attempts,
                "reason": sess.awaiting_reconciliation_reason or "",
                "target_status": target,
            },
        )
    )
    await db.commit()
    return project_session_summary(sess)


async def _reconciliation_terminal(
    db: AsyncSession,
    *,
    session_id: str,
    request: Request,
    to_status: str,
    audit_kind: str,
    require_cancellable: bool,
) -> Any:
    """Shared body for the fail + cancel endpoints. ``to_status`` is
    either ``"failed"`` or ``"cancelled"``; ``require_cancellable``
    enforces the classifier gate for the cancel path.
    """
    from uuid import UUID

    from sqlalchemy import select

    from app.models.anonymize_session import (
        AnonymizeSession,
        AnonymizeSessionEvent,
        AnonymizeStatus,
    )
    from app.services.anonymize.projections import project_session_summary
    from app.services.anonymize.reconciliation_classify import is_cancellable
    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.state_machine import (
        IllegalStateTransitionError,
        legal_next_statuses,
    )

    try:
        sid = UUID(session_id)
    except ValueError:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    sess = (
        await db.execute(
            select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sess is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if sess.status != AnonymizeStatus.AWAITING_RECONCILIATION.value:
        return JSONResponse(
            status_code=409,
            content={
                "code": "not_awaiting_reconciliation",
                "status": sess.status,
                "detail": "This session isn't parked in awaiting_reconciliation.",
            },
        )

    reason = sess.awaiting_reconciliation_reason or ""
    if require_cancellable and not is_cancellable(reason):
        return JSONResponse(
            status_code=409,
            content={
                "code": "reason_not_cancellable",
                "reason": reason,
                "detail": ("This session has funds in flight. Use Refund or Stop trying instead."),
            },
        )

    svc = get_anonymize_service()
    try:
        await svc.transition_session(
            db,
            sess,
            to_status=to_status,
            reason=audit_kind,
        )
    except IllegalStateTransitionError:
        return JSONResponse(
            status_code=409,
            content={
                "code": "illegal_state_transition",
                "from_status": AnonymizeStatus.AWAITING_RECONCILIATION.value,
                "to_status": to_status,
                "legal_next_statuses": sorted(legal_next_statuses(sess.status)),
            },
        )

    db.add(
        AnonymizeSessionEvent(
            session_id=sess.id,
            kind=audit_kind,
            detail_json={
                "reason": reason,
                "to_status": to_status,
            },
        )
    )
    await db.commit()
    return project_session_summary(sess)


async def _reconciliation_refund(
    db: AsyncSession,
    *,
    session_id: str,
    request: Request,
) -> Any:
    """Shared body for the refund endpoint. Verifies the step-up
    nonce before applying the transition.
    """
    from uuid import UUID

    from sqlalchemy import select

    from app.models.anonymize_session import (
        AnonymizeSession,
        AnonymizeSessionEvent,
        AnonymizeStatus,
    )
    from app.services.anonymize.projections import project_session_summary
    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.state_machine import (
        IllegalStateTransitionError,
        legal_next_statuses,
    )
    from app.services.anonymize.stepup import verify_stepup_nonce

    try:
        sid = UUID(session_id)
    except ValueError:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    try:
        body = await request.json()
    except Exception:
        body = {}
    transport_nonce = str(body.get("stepup_nonce", "")).strip()
    if not transport_nonce:
        return JSONResponse(
            status_code=400,
            content={"detail": "stepup_nonce_required"},
        )

    sess = (
        await db.execute(
            select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sess is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if sess.status != AnonymizeStatus.AWAITING_RECONCILIATION.value:
        return JSONResponse(
            status_code=409,
            content={
                "code": "not_awaiting_reconciliation",
                "status": sess.status,
                "detail": "This session isn't parked in awaiting_reconciliation.",
            },
        )

    # Bind the nonce to the dashboard's actual session
    # cookie (not the literal "session" string).
    cookie_subject = _cookie_subject(request)
    ok = await verify_stepup_nonce(
        db,
        cookie_subject=cookie_subject,
        scope="anonymize_reconciliation_refund",
        transport_nonce=transport_nonce,
        binding=str(sid),
    )
    if not ok:
        return JSONResponse(
            status_code=403,
            content={"detail": "stepup_required"},
        )

    svc = get_anonymize_service()
    try:
        await svc.transition_session(
            db,
            sess,
            to_status="refunding",
            reason="reconciliation_manual_refund",
        )
    except IllegalStateTransitionError:
        return JSONResponse(
            status_code=409,
            content={
                "code": "illegal_state_transition",
                "from_status": AnonymizeStatus.AWAITING_RECONCILIATION.value,
                "to_status": "refunding",
                "legal_next_statuses": sorted(legal_next_statuses(sess.status)),
            },
        )

    db.add(
        AnonymizeSessionEvent(
            session_id=sess.id,
            kind="reconciliation_manual_refund",
            detail_json={
                "reason": sess.awaiting_reconciliation_reason or "",
                "stepup_nonce_present": True,
            },
        )
    )
    await db.commit()
    return project_session_summary(sess)


@router.post(
    "/anonymize/stepup/issue",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_stepup_issue(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Issue a step-up re-auth nonce.

    Body: ``{"scope": "anonymize_decoy_spend_override" |
    "anonymize_refund_spend_override" | "anonymize_reconciliation_refund",
    "session_id": "<uuid>"}``. ``session_id`` binds the nonce to the
    specific session it will authorize so it cannot be replayed against a
    different session in the same scope.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    from app.services.anonymize.stepup import issue_stepup_nonce

    try:
        body = await request.json()
    except Exception:
        body = {}
    scope = str(body.get("scope", "")).strip()
    if scope not in (
        "anonymize_decoy_spend_override",
        "anonymize_refund_spend_override",
        # Refund-from-AWAITING_RECONCILIATION moves real funds
        # (transitions to REFUNDING) so it gets step-up re-auth.
        "anonymize_reconciliation_refund",
    ):
        return JSONResponse(
            status_code=400,
            content={"detail": "invalid_scope"},
        )
    # Bind the nonce to the target session id when supplied. Validated as
    # a UUID so a malformed value can't smuggle binding separators.
    binding: str | None = None
    raw_sid = str(body.get("session_id", "")).strip()
    if raw_sid:
        from uuid import UUID

        try:
            binding = str(UUID(raw_sid))
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid_session_id"})
    # Cookie subject for the quote-token binding — the dashboard's
    # session cookie, HMAC-opaqued by the quote layer.
    cookie_subject = _cookie_subject(request)
    nonce = await issue_stepup_nonce(
        db,
        cookie_subject=cookie_subject,
        scope=scope,
        binding=binding,
    )
    await db.commit()
    return {
        "nonce": nonce,
        "ttl_s": int(settings.anonymize_stepup_nonce_ttl_s),
    }


@router.post(
    "/anonymize/sessions/{session_id}/spend-override",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_spend_override(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Verify step-up nonce + emit audit event for
    a non-anonymize spend that touches an ``auto:anonymize-*`` UTXO.

    Body: ``{"outpoint": "...", "label": "...", "stepup_nonce": "..."}``.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    from uuid import UUID

    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSession
    from app.services.anonymize.coin_control import (
        check_anonymize_spend_eligibility,
        emit_spend_override_event,
        spend_override_event_kind,
    )
    from app.services.anonymize.stepup import verify_stepup_nonce

    try:
        sid = UUID(session_id)
    except ValueError:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    try:
        body = await request.json()
    except Exception:
        body = {}
    outpoint = str(body.get("outpoint", "")).strip()
    label = str(body.get("label", "")).strip()
    transport_nonce = str(body.get("stepup_nonce", "")).strip()
    if not outpoint or not label or not transport_nonce:
        return JSONResponse(
            status_code=400,
            content={"detail": "missing_fields"},
        )

    eligibility = check_anonymize_spend_eligibility(label)
    if eligibility == "admit":
        return JSONResponse(
            status_code=400,
            content={"detail": "label_does_not_require_stepup"},
        )
    if eligibility == "refuse":
        return JSONResponse(
            status_code=403,
            content={"detail": "spend_override_refused"},
        )

    scope = spend_override_event_kind(label)
    if scope is None:
        return JSONResponse(
            status_code=400,
            content={"detail": "label_does_not_require_stepup"},
        )

    sess = (
        await db.execute(
            select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sess is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    # Cookie subject for the quote-token binding — the dashboard's
    # session cookie, HMAC-opaqued by the quote layer.
    cookie_subject = _cookie_subject(request)
    ok = await verify_stepup_nonce(
        db,
        cookie_subject=cookie_subject,
        scope=scope,
        transport_nonce=transport_nonce,
        binding=str(sid),
    )
    if not ok:
        return JSONResponse(
            status_code=403,
            content={"detail": "stepup_required"},
        )

    await emit_spend_override_event(
        db,
        session_id=sess.id,
        outpoint=outpoint,
        label=label,
        stepup_nonce_id=transport_nonce[:16],
    )
    await db.commit()
    return {"ok": True}


@router.post(
    "/anonymize/quote/multi",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_quote_multi(request: Request) -> Any:
    """Dry-run quote for a multi-output session.

    Body: ``{"source_kind": "...", "destinations": [{"address": "...",
    "amount_sat": N}, ...]}``. Returns a signed quote token covering
    the whole batch + the per-output bin amounts; the SPA passes the
    token back into ``POST /anonymize/sessions/multi``.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    import json as _json

    from app.services.anonymize.multi_output_plan import (
        MultiOutputPlanError,
        MultiOutputQuoteRequest,
        build_multi_output_quote,
    )
    from app.services.anonymize.quote_token import load_quote_token_keyset
    from app.services.anonymize.responses import (
        destination_rejected_response,
    )

    keyset = load_quote_token_keyset()
    if keyset is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_quote_unavailable"},
        )

    body_bytes = await request.body()
    try:
        body = _json.loads(body_bytes or b"{}")
    except Exception:  # noqa: BLE001
        return destination_rejected_response()

    source_kind = str(body.get("source_kind", ""))
    raw_destinations = body.get("destinations", [])
    if not isinstance(raw_destinations, list) or not raw_destinations:
        return destination_rejected_response()
    destinations: list[tuple[str, int]] = []
    for d in raw_destinations:
        if not isinstance(d, dict):
            return destination_rejected_response()
        addr = d.get("address", "")
        try:
            amount = int(d.get("amount_sat", 0))
        except (TypeError, ValueError):
            return destination_rejected_response()
        if not isinstance(addr, str) or not addr or amount <= 0:
            return destination_rejected_response()
        destinations.append((addr, amount))

    # Cookie subject for the quote-token binding — the dashboard's
    # session cookie, HMAC-opaqued by the quote layer.
    cookie_subject = _cookie_subject(request)
    req = MultiOutputQuoteRequest(
        source_kind=source_kind,
        destinations=destinations,
        cookie_subject=cookie_subject,
        canonical_request_body=body_bytes,
    )
    try:
        result = build_multi_output_quote(req, keyset=keyset)
    except MultiOutputPlanError:
        return destination_rejected_response()
    return {
        "quote_token": result.quote_token,
        "bin_amounts_sat": result.bin_amounts_sat,
        "issued_at_unix_s": result.issued_at_unix_s,
        "ttl_s": result.ttl_s,
    }


@router.post(
    "/anonymize/sessions/multi",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_create_multi_output_session(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a multi-output session from a signed quote_token.

    Body: ``{"quote_token": "..."}``. The token is issued by
    ``POST /anonymize/quote/multi`` and binds the destinations + per-
    output amounts + cookie subject + canonical request body.

    The endpoint runs the same admission gates as the single-output
    flow (clock skew, Tor bootstrap, rate limit, in-flight cap),
    re-validates per-destination reuse-detection, picks per-output
    schedule offsets, persists the parent :class:`AnonymizeSession`
    row mirroring output 0 in the singular columns, and writes one
    :class:`AnonymizeSessionOutput` row per destination.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    import json as _json
    from uuid import uuid4

    from app.models.anonymize_session import (
        AnonymizeSession,
        AnonymizeStatus,
    )
    from app.services.anonymize.admission import (
        AdmissionInputs,
        count_in_flight_sessions,
        count_sessions_created_in_window,
        decide_session_create_admission,
    )
    from app.services.anonymize.crypto import encrypt_destination_address
    from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL
    from app.services.anonymize.multi_output_plan import (
        MultiOutputPlan,
        MultiOutputPlanError,
        parse_multi_output_canonical_pipeline_json,
        persist_outputs,
        sample_schedule_offsets_s,
        validate_multi_output_plan,
    )
    from app.services.anonymize.projections import project_session_summary
    from app.services.anonymize.quote_builder import _hmac_cookie_subject
    from app.services.anonymize.quote_token import (
        QuoteTokenError,
        decode_quote_token,
        load_quote_token_keyset,
    )
    from app.services.anonymize.rate_limit import RequestIdentity
    from app.services.anonymize.responses import (
        creation_unavailable_response,
        destination_rejected_response,
        quote_expired_response,
    )
    from app.services.anonymize.reuse_detection import (
        is_destination_reused,
        load_reuse_detection_keyset,
    )
    from app.services.anonymize.service import get_anonymize_service

    keyset = load_quote_token_keyset()
    if keyset is None:
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_create_unavailable"},
        )

    try:
        body = _json.loads(await request.body() or b"{}")
    except Exception:  # noqa: BLE001
        return destination_rejected_response()
    token = body.get("quote_token")
    if not isinstance(token, str) or not token:
        return destination_rejected_response()

    # Cookie subject for the quote-token binding — the dashboard's
    # session cookie, HMAC-opaqued by the quote layer.
    cookie_subject = _cookie_subject(request)
    expected_cookie_hmac = _hmac_cookie_subject(
        cookie_subject,
        keyset.active_key,
    )
    try:
        bound = decode_quote_token(
            token,
            keyset=keyset,
            expected_cookie_subject_hmac=expected_cookie_hmac,
        )
    except QuoteTokenError as exc:
        if "expired" in str(exc):
            return quote_expired_response()
        return destination_rejected_response()

    canonical = bound["canonical_pipeline_json"].encode("utf-8")
    try:
        source_kind, output_specs = parse_multi_output_canonical_pipeline_json(canonical)
    except MultiOutputPlanError:
        return destination_rejected_response()

    session_id = uuid4()
    plan = MultiOutputPlan(session_id=session_id, outputs=output_specs)
    try:
        validate_multi_output_plan(plan)
    except MultiOutputPlanError:
        return destination_rejected_response()

    health: dict[str, Any] = getattr(request.app.state, "anonymize_health", {}) or {}
    if health.get("clock_skew_within_threshold") is False:
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_clock_skew_unhealthy"},
        )
    from app.services.anonymize.tor import compute_effective_tor_ready as _compute_tor_ready

    if not _compute_tor_ready(health):
        return JSONResponse(
            status_code=503,
            content={"detail": "anonymize_tor_not_bootstrapped"},
        )

    svc = get_anonymize_service()
    limiter = svc.create_rate_limiter()
    source_ip = request.client.host if request.client is not None else None
    identity = RequestIdentity(
        cookie_id=cookie_subject,
        authenticated_user_id=None,
        source_ip=source_ip,
    )
    rl_decision = limiter.check_and_consume_with_reason(identity)
    if not rl_decision.admitted:
        return creation_unavailable_response()

    # Serialize the count→insert critical section.
    from app.services.anonymize.admission import acquire_admission_lock

    await acquire_admission_lock(db)
    in_flight_total = await count_in_flight_sessions(db)
    created_in_window = await count_sessions_created_in_window(db)
    decision = decide_session_create_admission(
        AdmissionInputs(
            requested_tier="weak",
            in_flight_count_by_tier={"weak": in_flight_total},
            sessions_created_in_window_count=created_in_window,
        )
    )
    if decision != "admit":
        return creation_unavailable_response()

    reuse_keyset = load_reuse_detection_keyset()
    if reuse_keyset is not None:
        for spec in plan.outputs:
            if await is_destination_reused(
                db,
                candidate_address=spec.destination_address,
                keyset=reuse_keyset,
            ):
                # Match the accept path's per-output key-derivation cost
                # (PBKDF2 in ``encrypt_destination_address``) before the
                # reuse hard-block returns, so a rejected destination is
                # not separable from an accepted one by response time.
                _ = encrypt_destination_address(spec.destination_address)
                return destination_rejected_response()

    def _addr_enc(addr: str) -> bytes:
        return encrypt_destination_address(addr)

    def _addr_hash(addr: str) -> bytes:
        if reuse_keyset is not None:
            return reuse_keyset.hash_active(addr)
        return REUSE_DETECTION_SENTINEL

    reuse_generation = reuse_keyset.active_generation if reuse_keyset is not None else 0

    schedule_offsets = sample_schedule_offsets_s(len(plan.outputs))

    primary = plan.outputs[0]
    sess = AnonymizeSession(
        id=session_id,
        status=AnonymizeStatus.CREATED.value,
        source_kind=str(source_kind),
        requested_amount_sat=sum(s.bin_amount_sat for s in plan.outputs),
        bin_amount_sat=primary.bin_amount_sat,
        pipeline_json={
            "schema_version": 10,
            "multi_output": True,
            "output_count": len(plan.outputs),
        },
        quote_hmac=expected_cookie_hmac,
        destination_address_enc=_addr_enc(primary.destination_address),
        destination_script_type=primary.destination_script_type,
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=_addr_hash(primary.destination_address),
        destination_reuse_key_generation=reuse_generation,
    )
    # Single-use consume — inside the admission lock window, just before
    # the insert, so a replay is rejected without burning the token on a
    # transient rejection.
    from app.services.anonymize.quote_token import consume_quote_token_single_use

    if not await consume_quote_token_single_use(token, ttl_s=int(bound.get("ttl_s", 0))):
        return destination_rejected_response()
    db.add(sess)
    await db.flush()
    await persist_outputs(
        db,
        plan=plan,
        encrypt_address=_addr_enc,
        blake2b_keyed=_addr_hash,
        reuse_key_generation=reuse_generation,
        schedule_offsets_unix_s=schedule_offsets,
    )
    await db.commit()

    summary = project_session_summary(sess)
    summary["output_count"] = len(plan.outputs)
    return summary


async def _transition_session_endpoint(
    db: AsyncSession,
    *,
    session_id: str,
    to_status: str,
    reason: str,
) -> Any:
    """Shared body for cancel/refund — looks up the session, applies
    the transition through:class:`AnonymizeService`, returns
    the projected summary.

    Failure cases:
    * Malformed UUID → ``404 Not Found`` (same shape as unknown id).
    * Unknown / soft-deleted id → ``404 Not Found``.
    * Illegal transition from the current status → ``409 Conflict``
      with the legal next-status set.
    """
    from uuid import UUID

    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSession
    from app.services.anonymize.projections import project_session_summary
    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.state_machine import (
        IllegalStateTransitionError,
        legal_next_statuses,
    )

    try:
        sid = UUID(session_id)
    except ValueError:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    sess = (
        await db.execute(
            select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
        )
    ).scalar_one_or_none()
    if sess is None:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    svc = get_anonymize_service()
    try:
        await svc.transition_session(
            db,
            sess,
            to_status=to_status,
            reason=reason,
        )
    except IllegalStateTransitionError:
        return JSONResponse(
            status_code=409,
            content={
                "code": "illegal_state_transition",
                "from_status": sess.status,
                "to_status": to_status,
                "legal_next_statuses": sorted(legal_next_statuses(sess.status)),
            },
        )
    await db.commit()
    return project_session_summary(sess)


# ── Residual L-BTC recovery (Liquid hop tail) ─────────────────────────
#
# When the LN->L-BTC leg of a Liquid hop succeeds but the L-BTC->LN
# leg is unrecoverable through cooperative + unilateral channels,
# wallet-controlled L-BTC accumulates at the per-session SLIP-77
# address. ``scan_residual_liquid_balances`` (app/tasks/...) detects
# this and upserts rows into ``liquid_residual_outputs``. The three
# endpoints below let the operator drive the recovery flow from the
# dashboard:
#
# * ``GET ../liquid-residuals``   — list rows for the banner.
# * ``POST .../swap-out``         — one-shot L-BTC->LN sweep.
# * ``POST .../acknowledge-dust`` — silence sub-threshold rows.
# * ``POST .../unacknowledge-dust`` — reverse the above.


def _residual_to_dict(row: Any) -> dict[str, Any]:
    """Project a ``LiquidResidualOutput`` ORM row to a JSON dict."""
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    return {
        "id": str(row.id),
        "session_id": str(row.session_id) if row.session_id else None,
        "txid": row.txid,
        "vout": int(row.vout),
        "asset_id": row.asset_id,
        "value_sat": int(row.value_sat),
        "address": row.address,
        "derivation_path": row.derivation_path,
        "discovered_at": row.discovered_at.isoformat() if row.discovered_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "recovered_at": row.recovered_at.isoformat() if row.recovered_at else None,
        "recovered_swap_id": row.recovered_swap_id,
        "dust_acknowledged_at": (row.dust_acknowledged_at.isoformat() if row.dust_acknowledged_at else None),
        "is_dust": int(row.value_sat) < threshold,
        "dust_threshold_sat": threshold,
    }


@router.get(
    "/anonymize/liquid-residuals",
    dependencies=[Depends(_require_auth)],
)
async def dash_anonymize_liquid_residuals_list(
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List residual L-BTC rows that still need operator attention.

    The dashboard banner queries this. ``include_resolved=true`` is
    deliberately NOT supported here — the audit-history view is a
    separate concern. We return rows that are either recoverable
    (above-dust, not yet swept) or dust (still surfaced so the
    operator can acknowledge them) and exclude already-recovered
    or already-acknowledged rows.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from sqlalchemy import select as _select

    from app.models.anonymize_session import LiquidResidualOutput

    rows = (
        (
            await db.execute(
                _select(LiquidResidualOutput)
                .where(LiquidResidualOutput.recovered_at.is_(None))
                .where(LiquidResidualOutput.dust_acknowledged_at.is_(None))
                .order_by(LiquidResidualOutput.discovered_at.asc())
            )
        )
        .scalars()
        .all()
    )

    threshold = int(settings.liquid_residual_dust_threshold_sat)
    recoverable = [r for r in rows if int(r.value_sat) >= threshold]
    return {
        "rows": [_residual_to_dict(r) for r in rows],
        "total_value_sat": sum(int(r.value_sat) for r in rows),
        "recoverable_count": len(recoverable),
        "recoverable_value_sat": sum(int(r.value_sat) for r in recoverable),
        "dust_threshold_sat": threshold,
    }


def _residual_recovery_deps_factory() -> "Optional[ResidualRecoveryDeps]":
    """Indirection point so tests can monkey-patch the factory.

    Production callers go straight to
    :func:`build_default_residual_recovery_deps`; tests bind a
    fixture-built ``ResidualRecoveryDeps`` here.
    """
    from app.services.anonymize.liquid_residual_recovery import (
        build_default_residual_recovery_deps,
    )

    return build_default_residual_recovery_deps()


async def _load_residual_row(db: AsyncSession, residual_id: str) -> Any:
    """Load a residual row by string UUID or raise ``HTTPException(404)``."""
    from uuid import UUID

    from sqlalchemy import select as _select

    from app.models.anonymize_session import LiquidResidualOutput

    try:
        rid = UUID(residual_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="not found")
    row = (await db.execute(_select(LiquidResidualOutput).where(LiquidResidualOutput.id == rid))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return row


async def _emit_residual_audit(
    db: AsyncSession,
    *,
    row: Any,
    kind: str,
    detail_json: dict[str, Any],
) -> None:
    """Record a residual-recovery action on the session's event log.

    No-op when the originating session has been retention-purged
    (``session_id`` is NULL) — there's nowhere to attach the event.
    """
    if row.session_id is None:
        return
    from app.models.anonymize_session import AnonymizeSessionEvent

    db.add(
        AnonymizeSessionEvent(
            session_id=row.session_id,
            kind=kind,
            detail_json={"residual_id": str(row.id), **detail_json},
        )
    )


@router.post(
    "/anonymize/liquid-residuals/{residual_id}/swap-out",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_liquid_residual_swap_out(
    residual_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """One-shot L-BTC->LN swap-out for a residual output.

    Driven by :func:`initiate_residual_recovery`. On success the
    row's ``recovered_swap_id`` is stamped and a Boltz submarine
    swap is in flight; the operator pays the LN invoice and the
    wallet observes settlement on the next polling tick (or via
    the synchronous post-broadcast check on this same call when
    Boltz happens to settle inside the regtest window).
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from app.services.anonymize.liquid_residual_recovery import (
        ResidualRecoveryError,
        ResidualRecoveryNotEligibleError,
        ResidualRecoveryNotFoundError,
        initiate_residual_recovery,
    )

    row = await _load_residual_row(db, residual_id)
    deps = _residual_recovery_deps_factory()
    if deps is None:
        return JSONResponse(
            status_code=409,
            content={
                "code": "liquid_disabled",
                "detail": (
                    "Liquid hop is not enabled or required configuration "
                    "is missing; cannot drive an L-BTC recovery swap."
                ),
            },
        )

    try:
        result = await initiate_residual_recovery(
            db=db,
            residual_id=row.id,
            deps=deps,
        )
    except ResidualRecoveryNotFoundError:
        return JSONResponse(status_code=404, content={"detail": "not found"})
    except ResidualRecoveryNotEligibleError as exc:
        return JSONResponse(
            status_code=409,
            content={"code": "not_eligible", "detail": str(exc)},
        )
    except ResidualRecoveryError as exc:
        return JSONResponse(
            status_code=502,
            content={"code": "recovery_failed", "detail": str(exc)},
        )

    await _emit_residual_audit(
        db,
        row=row,
        kind="liquid_residual_swap_out_initiated",
        detail_json={
            "swap_id": result.swap_id,
            "lockup_address": result.lockup_address,
            "lockup_txid": result.lockup_txid,
            "expected_amount_sat": result.expected_amount_sat,
            "recovered_at_set": result.recovered_at_set,
        },
    )
    await db.commit()
    return {
        "residual_id": str(result.residual_id),
        "swap_id": result.swap_id,
        "lockup_address": result.lockup_address,
        "lockup_txid": result.lockup_txid,
        "expected_amount_sat": result.expected_amount_sat,
        "recovered_at_set": result.recovered_at_set,
    }


@router.post(
    "/anonymize/liquid-residuals/{residual_id}/acknowledge-dust",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_liquid_residual_acknowledge_dust(
    residual_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Mark a sub-threshold residual as acknowledged-dust.

    The row stays in the table for audit purposes; it just stops
    contributing to the banner total. Refuses to acknowledge a row
    that is at-or-above the dust threshold — those are recoverable
    and shouldn't be silenced.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    row = await _load_residual_row(db, residual_id)
    if row.recovered_at is not None:
        return JSONResponse(
            status_code=409,
            content={
                "code": "already_recovered",
                "detail": (
                    "residual was recovered at "
                    f"{row.recovered_at.isoformat()}; acknowledge is "
                    "only meaningful on un-recovered rows"
                ),
            },
        )
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    if int(row.value_sat) >= threshold:
        return JSONResponse(
            status_code=409,
            content={
                "code": "above_threshold",
                "detail": (
                    f"residual value {row.value_sat} sat is at or above "
                    f"the dust threshold {threshold} sat; this row is "
                    "recoverable via swap-out — refusing to acknowledge"
                ),
            },
        )
    if row.dust_acknowledged_at is not None:
        return _residual_to_dict(row)
    from datetime import datetime, timezone

    row.dust_acknowledged_at = datetime.now(timezone.utc)
    await _emit_residual_audit(
        db,
        row=row,
        kind="liquid_residual_dust_acknowledged",
        detail_json={"value_sat": int(row.value_sat)},
    )
    await db.commit()
    return _residual_to_dict(row)


@router.post(
    "/anonymize/liquid-residuals/{residual_id}/unacknowledge-dust",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_liquid_residual_unacknowledge_dust(
    residual_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Reverse a prior dust-acknowledgement.

    Useful when fee dynamics shift such that a previously-dust
    residual is now economically recoverable — clearing the
    acknowledgement re-surfaces the row in the banner.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    row = await _load_residual_row(db, residual_id)
    if row.dust_acknowledged_at is None:
        return _residual_to_dict(row)
    row.dust_acknowledged_at = None
    await _emit_residual_audit(
        db,
        row=row,
        kind="liquid_residual_dust_unacknowledged",
        detail_json={"value_sat": int(row.value_sat)},
    )
    await db.commit()
    return _residual_to_dict(row)


# ── Liquid swap recovery endpoints ────────────────────────────────────
#
# Out-of-band levers for in-flight Liquid swaps that cannot make
# forward progress under the hop loop. Each addresses the swap by
# ``(session_id, leg)`` rather than swap_id because Liquid sessions
# do not produce ``BoltzSwap`` rows — per-leg state lives in
# ``pipeline_json["liquid_swap_state_enc"]``.


async def _load_anonymize_session_for_recovery(
    db: AsyncSession,
    session_id: str,
    *,
    lock: bool = False,
) -> Any:
    """Load + return an ``AnonymizeSession`` row for a recovery action.

    Returns the row, or raises ``HTTPException(404)`` on a malformed
    id / missing / soft-deleted row. The caller emits the audit
    event on the session id.

    Pass ``lock=True`` on a broadcasting action to hold the row under
    ``FOR UPDATE`` for the life of the transaction: a concurrent refund/claim
    for the same session blocks here until the first commits its progress
    marker, then re-reads it and is rejected before broadcasting a second
    spend. (SQLite cannot lock rows, so it falls back to a plain read.)
    """
    from sqlalchemy import select as _select

    from app.models.anonymize_session import AnonymizeSession

    try:
        sid = UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Not Found")
    stmt = _select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
    if lock:
        try:
            row = (await db.execute(stmt.with_for_update())).scalar_one_or_none()
        except Exception:  # noqa: BLE001 — dialect without row locking (SQLite)
            row = (await db.execute(stmt)).scalar_one_or_none()
    else:
        row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return row


async def _emit_liquid_recovery_audit(
    db: AsyncSession,
    *,
    session: Any,
    kind: str,
    detail_json: dict[str, Any],
) -> None:
    """Stamp a session-level event row for a Liquid recovery action."""
    from app.models.anonymize_session import AnonymizeSessionEvent

    db.add(
        AnonymizeSessionEvent(
            session_id=session.id,
            kind=kind,
            detail_json=dict(detail_json),
        )
    )


async def _finalize_liquid_submarine_refund(
    db: AsyncSession,
    *,
    session: Any,
    txid: Any,
) -> None:
    """Terminalize a session whose Liquid leg-2 lockup was just refunded.

    The refund tx returns the wallet's L-BTC, but the round-trip can no
    longer complete, so the session must leave ``awaiting_liquid_dwell``:
    otherwise the per-session loop keeps polling for a settlement that
    will never arrive and the dashboard keeps offering the (now
    spent-UTXO) refund button. We record the refund txid as a marker
    (the recovery classifier stops offering the levers once it's set)
    and move the session to FAILED with a clear reason. The transition
    is best-effort — a session in an unexpected status still gets the
    marker and a successful refund response."""
    from app.models.anonymize_session import AnonymizeStatus
    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.state_machine import IllegalStateTransitionError

    pj = dict(session.pipeline_json or {})
    pj["liquid_submarine_refund_txid"] = str(txid or "")
    session.pipeline_json = pj
    session.last_error = "Liquid round-trip leg refunded to your wallet; the mix was aborted."
    try:
        await get_anonymize_service().transition_session(
            db,
            session,
            to_status=AnonymizeStatus.FAILED.value,
            reason="liquid_submarine_refunded",
        )
    except IllegalStateTransitionError:
        logger.warning(
            "liquid refund: session %s could not be terminalized from status %s",
            getattr(session, "id", "?"),
            getattr(session, "status", "?"),
        )


def _mark_liquid_reverse_unilateral_claim(session: Any, *, txid: Any) -> None:
    """Record that a post-timeout unilateral claim was broadcast for the
    leg-1 reverse swap. The recovery classifier stops re-offering the
    claim once this marker is set (so the operator can't double-broadcast
    while it confirms). No status change is made — the pipeline resumes on
    its own: ``_step_observe_claim_confirmation`` watches the wallet credit
    by swap id, not a specific claim txid, so the unilateral claim's
    L-BTC landing is observed and the session advances normally."""
    pj = dict(session.pipeline_json or {})
    pj["liquid_reverse_unilateral_claim_txid"] = str(txid or "")
    session.pipeline_json = pj


def _liquid_recovery_error_response(exc: Exception) -> JSONResponse:
    """Translate a recovery-module exception into a JSON error."""
    from app.services.anonymize.liquid_swap_recovery import (
        LiquidRecoveryOperatorMissingError,
        LiquidRecoveryStateMissingError,
        LiquidRecoveryUnknownLegError,
    )

    if isinstance(exc, LiquidRecoveryUnknownLegError):
        return JSONResponse(
            status_code=400,
            content={"code": "unknown_leg", "detail": str(exc)},
        )
    if isinstance(exc, LiquidRecoveryStateMissingError):
        return JSONResponse(
            status_code=409,
            content={"code": "state_missing", "detail": str(exc)},
        )
    if isinstance(exc, LiquidRecoveryOperatorMissingError):
        return JSONResponse(
            status_code=409,
            content={"code": "operator_missing", "detail": str(exc)},
        )
    return JSONResponse(
        status_code=502,
        content={"code": "recovery_failed", "detail": str(exc)},
    )


@router.post(
    "/anonymize/sessions/{session_id}/liquid-recovery/submarine/cooperative-refund",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_liquid_cooperative_refund(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Cooperative MuSig2 refund of the wallet's L-BTC submarine lockup.

    Works while Boltz is reachable and willing to co-sign. Does NOT
    require ``timeoutBlockHeight`` to have passed; for the post-
    timeout fallback see the unilateral-refund endpoint.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from app.services.anonymize.liquid_swap_recovery import (
        LiquidRecoveryError,
        cooperative_refund_submarine_leg,
    )

    sess = await _load_anonymize_session_for_recovery(db, session_id, lock=True)
    if (sess.pipeline_json or {}).get("liquid_submarine_refund_txid"):
        return JSONResponse(
            status_code=409,
            content={"code": "already_refunded", "detail": "A submarine-leg refund has already been broadcast."},
        )
    try:
        result = await cooperative_refund_submarine_leg(session=sess)
    except LiquidRecoveryError as exc:
        return _liquid_recovery_error_response(exc)
    except Exception as exc:  # subprocess / upstream failure
        return JSONResponse(
            status_code=502,
            content={
                "code": "subprocess_failed",
                "detail": sanitize_upstream_error(str(exc), "liquid-recovery"),
            },
        )

    await _emit_liquid_recovery_audit(
        db,
        session=sess,
        kind="liquid_swap_cooperative_refund_initiated",
        detail_json={
            "leg": result.leg,
            "boltz_swap_id": result.boltz_swap_id,
            "txid": result.txid,
            "mode": result.mode,
            "operator_id": result.operator_id,
        },
    )
    await _finalize_liquid_submarine_refund(db, session=sess, txid=result.txid)
    await db.commit()
    return {
        "session_id": result.session_id,
        "leg": result.leg,
        "boltz_swap_id": result.boltz_swap_id,
        "txid": result.txid,
        "mode": result.mode,
        "operator_id": result.operator_id,
    }


@router.post(
    "/anonymize/sessions/{session_id}/liquid-recovery/submarine/unilateral-refund",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_liquid_unilateral_refund(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Post-timeout script-path refund of the L-BTC submarine lockup.

    Used when Boltz refuses to cooperate AND the lockup's
    ``timeoutBlockHeight`` has been reached on the Liquid chain.
    The JS subprocess is the authority on the timeout check.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from app.services.anonymize.liquid_swap_recovery import (
        LiquidRecoveryError,
        unilateral_refund_submarine_leg,
    )

    sess = await _load_anonymize_session_for_recovery(db, session_id, lock=True)
    if (sess.pipeline_json or {}).get("liquid_submarine_refund_txid"):
        return JSONResponse(
            status_code=409,
            content={"code": "already_refunded", "detail": "A submarine-leg refund has already been broadcast."},
        )
    try:
        result = await unilateral_refund_submarine_leg(session=sess)
    except LiquidRecoveryError as exc:
        return _liquid_recovery_error_response(exc)
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={
                "code": "subprocess_failed",
                "detail": sanitize_upstream_error(str(exc), "liquid-recovery"),
            },
        )

    await _emit_liquid_recovery_audit(
        db,
        session=sess,
        kind="liquid_swap_unilateral_refund_initiated",
        detail_json={
            "leg": result.leg,
            "boltz_swap_id": result.boltz_swap_id,
            "txid": result.txid,
            "mode": result.mode,
            "operator_id": result.operator_id,
        },
    )
    await _finalize_liquid_submarine_refund(db, session=sess, txid=result.txid)
    await db.commit()
    return {
        "session_id": result.session_id,
        "leg": result.leg,
        "boltz_swap_id": result.boltz_swap_id,
        "txid": result.txid,
        "mode": result.mode,
        "operator_id": result.operator_id,
    }


@router.post(
    "/anonymize/sessions/{session_id}/liquid-recovery/reverse/unilateral-claim",
    dependencies=[Depends(_require_auth_csrf)],
)
async def dash_anonymize_liquid_unilateral_claim(
    session_id: str,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Post-timeout script-path claim of Boltz's reverse-swap lockup.

    Used when the wallet revealed the preimage but the cooperative
    claim never landed AND the lockup's ``timeoutBlockHeight`` has
    been reached. The JS subprocess broadcasts the script-path
    claim directly via electrs-liquid so this works even if Boltz
    is offline.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    from app.services.anonymize.liquid_swap_recovery import (
        LiquidRecoveryError,
        unilateral_claim_reverse_leg,
    )

    sess = await _load_anonymize_session_for_recovery(db, session_id, lock=True)
    if (sess.pipeline_json or {}).get("liquid_reverse_unilateral_claim_txid"):
        return JSONResponse(
            status_code=409,
            content={"code": "already_claimed", "detail": "A reverse-leg unilateral claim has already been broadcast."},
        )
    try:
        result = await unilateral_claim_reverse_leg(session=sess)
    except LiquidRecoveryError as exc:
        return _liquid_recovery_error_response(exc)
    except Exception as exc:
        return JSONResponse(
            status_code=502,
            content={
                "code": "subprocess_failed",
                "detail": sanitize_upstream_error(str(exc), "liquid-recovery"),
            },
        )

    await _emit_liquid_recovery_audit(
        db,
        session=sess,
        kind="liquid_swap_unilateral_claim_initiated",
        detail_json={
            "leg": result.leg,
            "boltz_swap_id": result.boltz_swap_id,
            "txid": result.txid,
            "mode": result.mode,
            "operator_id": result.operator_id,
        },
    )
    _mark_liquid_reverse_unilateral_claim(sess, txid=result.txid)
    await db.commit()
    return {
        "session_id": result.session_id,
        "leg": result.leg,
        "boltz_swap_id": result.boltz_swap_id,
        "txid": result.txid,
        "mode": result.mode,
        "operator_id": result.operator_id,
    }


@router.get(
    "/anonymize/policy",
    dependencies=[Depends(_require_auth)],
)
async def dash_anonymize_policy(request: Request) -> Any:
    """Server-side limits + enabled hop kinds + amount bins."""
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    from app.services.anonymize.disclosures import disclosures_for_source_kind
    from app.services.anonymize.liquid_fee_oracle import is_liquid_indexer_reachable
    from app.services.anonymize.operators import (
        has_distinct_legs_configured,
        load_signed_operator_registry,
    )

    def _is_liquid_indexer_reachable_safe() -> bool:
        if not (settings.anonymize_liquid_enabled and settings.anonymize_liquid_integration_verified):
            return False
        try:
            return is_liquid_indexer_reachable()
        except Exception:  # noqa: BLE001
            return False

    # Does this deployment have two distinct Boltz operator
    # URLs configured? When False, on-chain sessions are admitted but
    # the scorer caps them at ``moderate``; the SPA surfaces an
    # advisory banner (with a Learn more link) so users understand
    # they are trusting a single operator's correlation policy.
    distinct_operators = has_distinct_legs_configured()
    try:
        operator_registry_size = len(load_signed_operator_registry())
    except Exception:  # noqa: BLE001 — registry-load failure non-fatal here
        operator_registry_size = 0

    # Clock-skew probe status. The wizard reads this on open
    # and polls it during ``warming_up`` to render the calibrating
    # banner + skew-out-of-range diagnostic.
    health: dict[str, Any] = getattr(request.app.state, "anonymize_health", {}) or {}
    clock_skew_payload = {
        "status": health.get("clock_skew_status", "unknown"),
        "measured_skew_ms": health.get("clock_skew_ms"),
        "threshold_ms": health.get(
            "clock_skew_threshold_ms",
            int(settings.anonymize_max_clock_skew_ms),
        ),
        "samples_collected": int(health.get("clock_skew_samples_collected", 0) or 0),
        "samples_target": int(
            health.get(
                "clock_skew_samples_target",
                settings.anonymize_clock_skew_samples_per_tick,
            )
            or 0
        ),
        "warmup_completes_at_unix_s": health.get("clock_skew_warmup_completes_at_unix_s"),
    }

    # Tor bootstrap state, surfaced so the wizard can render
    # a distinct "Connecting through Tor…" banner separate from the
    # clock-skew calibration. Uses the *effective* signal so wallets
    # that don't expose a Tor ControlPort (e.g. the stock Docker
    # tor-proxy image) aren't blocked when SOCKS traffic is actually
    # working — see :func:`compute_effective_tor_ready` for the rule.
    from app.services.anonymize.tor import compute_effective_tor_ready

    tor_bootstrap_ready = compute_effective_tor_ready(health)

    return {
        "min_sat": settings.anonymize_min_sat,
        "max_sat": settings.anonymize_max_sat,
        "amount_bins_sat": settings.anonymize_amount_bins_list,
        # Surfaced so the SPA can render network-specific address
        # hints + run pre-flight client-side validation against the
        # same network the server's ``parse_and_validate_destination``
        # uses. Without this, the SPA can only show an opaque
        # ``destination_rejected`` after the round-trip.
        "bitcoin_network": settings.bitcoin_network,
        "tier_concurrency_cap": settings.anonymize_tier_cap_dict,
        # Currently-enabled hop kinds; submarine, priv_channel, and
        # liquid are surfaced here when those hops are enabled.
        "enabled_hop_kinds": ["ln_self_pay", "reverse"],
        "enabled_source_kinds": [
            "lightning-self",
            "ext-lightning",
            "onchain-self",
            "ext-onchain",
        ],
        "default_delay": {
            "min_s": settings.anonymize_default_delay_min_s,
            "max_s": settings.anonymize_default_delay_max_s,
        },
        "operator_registry_size": int(operator_registry_size),
        # Liquid hop availability. The SPA reads this to hide the
        # "Route through Liquid" checkbox + its info-tip when the
        # operator has not enabled the Liquid hop. Hidden also when
        # the operator-side verification gate is closed (i.e. the
        # deployment opted into Liquid but flagged the integration
        # unverified). Without these UI-side gates the wizard
        # would show a checkbox whose backend silently no-ops.
        "liquid_available": bool(settings.anonymize_liquid_enabled and settings.anonymize_liquid_integration_verified),
        # Best-effort signal that the electrs-liquid indexer is
        # currently responsive. Sourced from the Liquid fee-oracle's
        # cache freshness: when the periodic refresh has succeeded
        # within its TTL, the indexer is reachable. ``False`` when
        # Liquid is disabled or when the indexer has gone silent —
        # the SPA renders a recovery banner in the latter case so
        # operators know hops will stall until connectivity returns.
        "liquid_indexer_reachable": _is_liquid_indexer_reachable_safe(),
        # Operator-diversity advisory. The SPA reads
        # ``distinct_operators`` to decide whether to surface the
        # single-operator banner on the wizard's source-kind step.
        # ``learn_more_url`` is a stable wiki/docs link the banner's
        # Learn more anchor points at; absent any link, the SPA
        # falls back to a plain text disclosure.
        "operator_diversity": {
            "distinct_operators_configured": bool(distinct_operators),
            "learn_more_url": ("/dashboard/static/help/anonymize_operator_diversity.html"),
        },
        # item 41 + related — pinned wizard copy fetched per source
        # kind. The SPA renders verbatim; tests assert exact wording.
        "disclosures": {
            "lightning-self": disclosures_for_source_kind("lightning-self"),
            "ext-lightning": disclosures_for_source_kind("ext-lightning"),
            "onchain-self": disclosures_for_source_kind("onchain-self"),
            "ext-onchain": disclosures_for_source_kind("ext-onchain"),
        },
        "clock_skew": clock_skew_payload,
        "tor_bootstrap_ready": tor_bootstrap_ready,
        # Countdown switchover threshold, surfaced so the
        # SPA can render an exact countdown when the next retry is
        # within this window and a calmer "Retrying when network
        # recovers" message when it's beyond.
        "reconciliation_countdown_threshold_s": int(settings.anonymize_reconciliation_countdown_threshold_s),
        # Confirming-status label renders "X/Y" where Y is the
        # operator-configured minimum confirmations. Surfaced so the
        # SPA can render the target instead of guessing.
        "claim_min_confirmations": int(settings.anonymize_claim_min_confirmations),
    }


@router.get(
    "/anonymize/health",
    dependencies=[Depends(_require_auth)],
)
async def dash_anonymize_health(
    request: Request,
    detail: Optional[str] = Query(default=None),
) -> Any:
    """Health card data (coarsened by default).

    Default response body is boolean-only. ``?detail=full`` adds numeric
    detail. Any timestamp it surfaces is quantized to a coarse bucket so a
    freely-polling caller cannot reconstruct the exact background-sweep
    schedule or fine-grained liveness cadence. Returns a stable boolean shape
    when the underlying probes have not reported.
    """
    if not settings.anonymize_enabled:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})
    # Read the startup-gate snapshot from app state (populated in
    # ``app.main.lifespan``); fall back to all-False until the gates
    # have run (e.g. during a unit-test FastAPI test client without
    # the lifespan).
    cached: dict[str, Any] = getattr(request.app.state, "anonymize_health", {}) or {}
    body: dict[str, Any] = {
        "tor_ok": cached.get("anonymize_tor_distinct_from_lnd", False),
        "clock_skew_within_threshold": bool(cached.get("clock_skew_within_threshold", False)),
        "operators_loaded": bool(cached.get("operators_loaded", False)),
        "quote_cache_fresh": bool(cached.get("quote_cache_fresh", False)),
        "egress_endpoints_onion_only": cached.get("egress_endpoints_onion_only", False),
        "anonymize_tor_distinct_from_lnd": cached.get("anonymize_tor_distinct_from_lnd", False),
    }
    if detail == "full":
        # Surface ``last_successful_gc_at`` from runtime_state so the operator
        # can see roughly when the recurring GC sweep last ran. The value is
        # quantized down to a coarse bucket (the hour) so polling the endpoint
        # cannot harvest the exact sweep schedule / liveness cadence.
        try:
            from app.core.database import get_session_maker
            from app.services.anonymize.runtime_state import (
                read_runtime_state,
            )

            async with get_session_maker()() as db:
                raw = await read_runtime_state(
                    db,
                    key="last_successful_gc_at",
                )
            if isinstance(raw, dict) and "value" in raw:
                body["last_successful_gc_at_unix_s"] = _quantize_unix_s(float(raw["value"]))
            else:
                body["last_successful_gc_at_unix_s"] = None
        except Exception:  # noqa: BLE001
            body["last_successful_gc_at_unix_s"] = None
    return body


# Health-detail timestamps are rounded down to this many seconds so a caller
# polling ``?detail=full`` cannot reconstruct the fine-grained background-sweep
# schedule from the disclosed value.
_HEALTH_DETAIL_QUANTIZE_S = 3600


def _quantize_unix_s(value: float) -> float:
    """Round a unix timestamp DOWN to the coarse health-detail bucket."""
    return float(int(value // _HEALTH_DETAIL_QUANTIZE_S) * _HEALTH_DETAIL_QUANTIZE_S)


# ── Braiins Deposit ──────────────────────────────────────────────────
#
# Round-amount deposit to Braiins Hashpower. The handlers are thin
# adapters over ``BraiinsDepositService`` — quote / create / list /
# detail / cancel / retry-send.


_BRAIINS_DEPOSIT_SOURCE_KINDS = (
    "lightning",
    "onchain",
    "ext_lightning",
    "ext_onchain",
)

_BRAIINS_DEPOSIT_FUNDING_STRATEGIES = ("swap", "channel")


class BraiinsDepositQuoteRequest(BaseModel):
    amount_sats: int = Field(gt=0, le=100_000_000)
    # Self-sourced "lightning" / "onchain".
    # Externally-sourced "ext_lightning" / "ext_onchain".
    source_kind: str = Field(default="lightning")
    # User-chosen send mode. ``True`` (default) = dust-safe
    # no-change send (absorbs extras into the deposit output).
    # ``False`` = exact-amount send (returns the remainder as a
    # change UTXO; may be unspendable at high fees). The quote
    # response shape varies on this flag: when False the
    # ``arrival_*`` projection collapses to the bin amount and
    # ``expected_change_sats`` carries the projected change.
    include_extras: bool = Field(default=True)
    # "swap" (default; submarine) or "channel" (open a channel to
    # Megalithic instead). Applies only to on-chain sources.
    funding_strategy: str = Field(default="swap")

    @field_validator("source_kind")
    @classmethod
    def _validate_source_kind(cls, v: str) -> str:
        if v not in _BRAIINS_DEPOSIT_SOURCE_KINDS:
            raise ValueError("source_kind must be one of " + ", ".join(_BRAIINS_DEPOSIT_SOURCE_KINDS))
        return v

    @field_validator("funding_strategy")
    @classmethod
    def _validate_funding_strategy(cls, v: str) -> str:
        if v not in _BRAIINS_DEPOSIT_FUNDING_STRATEGIES:
            raise ValueError("funding_strategy must be one of " + ", ".join(_BRAIINS_DEPOSIT_FUNDING_STRATEGIES))
        return v


class BraiinsDepositQuoteBatchRequest(BaseModel):
    # Batch shape so the wizard's per-bin quote cache (all preset
    # amounts × current source-kind + include-extras) refreshes
    # in a single HTTP request instead of N. Without this, the
    # 60 s poller burns ~10 requests per tick against the global
    # 60/minute IP rate limit — enough that any concurrent
    # dashboard activity (balances, sessions, channel polling)
    # quickly trips 429.
    amount_sats_list: list[int] = Field(..., min_length=1, max_length=32)
    source_kind: str = Field(default="lightning")
    include_extras: bool = Field(default=True)
    funding_strategy: str = Field(default="swap")

    @field_validator("amount_sats_list")
    @classmethod
    def _validate_amounts(cls, v: list[int]) -> list[int]:
        for amt in v:
            if amt <= 0 or amt > 100_000_000:
                raise ValueError("each amount_sats must be in (0, 100_000_000]")
        return v

    @field_validator("source_kind")
    @classmethod
    def _validate_source_kind(cls, v: str) -> str:
        if v not in _BRAIINS_DEPOSIT_SOURCE_KINDS:
            raise ValueError("source_kind must be one of " + ", ".join(_BRAIINS_DEPOSIT_SOURCE_KINDS))
        return v

    @field_validator("funding_strategy")
    @classmethod
    def _validate_funding_strategy(cls, v: str) -> str:
        if v not in _BRAIINS_DEPOSIT_FUNDING_STRATEGIES:
            raise ValueError("funding_strategy must be one of " + ", ".join(_BRAIINS_DEPOSIT_FUNDING_STRATEGIES))
        return v


class BraiinsDepositSessionCreateRequest(BaseModel):
    amount_sats: int = Field(gt=0, le=100_000_000)
    destination_address: str = Field(..., min_length=14, max_length=128)
    # Self-sourced "lightning" / "onchain", externally-sourced
    # "ext_lightning" / "ext_onchain". Defaults to "lightning" so
    # Lightning-source callers continue to work unchanged.
    source_kind: str = Field(default="lightning")
    # See ``BraiinsDepositQuoteRequest.include_extras``. Persisted
    # on the session row at create time and consumed by the
    # broadcast path to pick between dust-safe no-change send and
    # legacy with-change send.
    include_extras: bool = Field(default=True)
    # "swap" (default) or "channel" (open a channel to Megalithic
    # instead of a submarine swap). Validated against the source kind +
    # operator flag in the service layer.
    funding_strategy: str = Field(default="swap")
    # The wizard echoes the total-fee number from its most
    # recent quote so the server can detect quote drift between Step 2
    # and Start. Optional: legacy callers without the field skip the
    # drift check and just see the latest server-side numbers.
    expected_total_fee_sats: Optional[int] = Field(default=None, ge=0, le=10_000_000)

    @field_validator("amount_sats")
    @classmethod
    def _validate_bin_amount(cls, v: int) -> int:
        # The whole feature is premised on
        # the round BIN_AMOUNTS the Braiins anti-fraud algorithm reliably
        # clears, and downstream guards (dust-safe send floor, channel
        # sizing) treat the bin as the signed-off amount. Reject
        # arbitrary off-preset amounts at the boundary so a non-round
        # send can't trip Braiins' fraud detection and freeze the
        # deposit.
        from app.services.braiins_deposit_service import BIN_AMOUNTS

        if v not in BIN_AMOUNTS:
            raise ValueError(
                "amount_sats must be one of the supported deposit amounts: " + ", ".join(f"{a:,}" for a in BIN_AMOUNTS)
            )
        return v

    @field_validator("source_kind")
    @classmethod
    def _validate_source_kind(cls, v: str) -> str:
        if v not in _BRAIINS_DEPOSIT_SOURCE_KINDS:
            raise ValueError("source_kind must be one of " + ", ".join(_BRAIINS_DEPOSIT_SOURCE_KINDS))
        return v

    @field_validator("funding_strategy")
    @classmethod
    def _validate_funding_strategy(cls, v: str) -> str:
        if v not in _BRAIINS_DEPOSIT_FUNDING_STRATEGIES:
            raise ValueError("funding_strategy must be one of " + ", ".join(_BRAIINS_DEPOSIT_FUNDING_STRATEGIES))
        return v

    @field_validator("destination_address")
    @classmethod
    def _validate_destination(cls, v: str) -> str:
        addr = validate_bitcoin_address(v)
        # Heuristic stays in the green band only for modern address
        # types. Braiins issues bech32 / P2SH addresses; reject legacy
        # P2PKH (`1…`) so the user can't shoot themselves.
        if addr.startswith("1"):
            raise ValueError(
                "Braiins uses modern address formats (bc1… or 3…). Please double-check the address you copied."
            )
        return addr


class BraiinsDepositRefundRequest(BaseModel):
    """User-supplied refund address for ext-OC."""

    refund_address: str = Field(..., min_length=14, max_length=128)

    @field_validator("refund_address")
    @classmethod
    def _validate_refund_address(cls, v: str) -> str:
        # Service layer also validates, but failing fast at the API
        # boundary returns a 422 with a cleaner error structure.
        return validate_bitcoin_address(v)


def _braiins_serialize(session: Any) -> dict[str, Any]:
    """Render a BraiinsDepositSession row for the dashboard JSON
    surface. Pulls in the linked BoltzSwap claim_txid when present.
    """
    source_kind_val: Any = getattr(session, "source_kind", None)
    if hasattr(source_kind_val, "value"):
        source_kind_val = source_kind_val.value
    out: dict[str, Any] = {
        "id": str(session.id),
        "status": session.status.value,
        "source_kind": source_kind_val or "lightning",
        "deposit_amount_sats": session.deposit_amount_sats,
        "destination_address": session.destination_address,
        # Per-session send mode picked at create time. Defaults
        # to True (dust-safe no-change send). Pre-feature rows
        # backfill to True via the migration's server default.
        "include_extras": bool(getattr(session, "include_extras", True)),
        # Channel-open funding strategy ("swap" default | "channel"). The
        # SPA reads this to gate the post-refund "retry via channel" action
        # and to render channel-specific progress. Enum → its value.
        "funding_strategy": (getattr(getattr(session, "funding_strategy", None), "value", None) or "swap"),
        "channel_peer_pubkey": getattr(session, "channel_peer_pubkey", None),
        "channel_open_txid": getattr(session, "channel_open_txid", None),
        "channel_capacity_sats": getattr(session, "channel_capacity_sats", None),
        "fresh_address": session.fresh_address,
        "fresh_utxo_txid": session.fresh_utxo_txid,
        "fresh_utxo_vout": session.fresh_utxo_vout,
        "fresh_utxo_amount_sats": session.fresh_utxo_amount_sats,
        "send_txid": session.send_txid,
        # Dust prevention — the amount actually broadcast to
        # Braiins. May differ from ``deposit_amount_sats`` (the bin)
        # because the no-change send absorbs the network fee into
        # the output. ``None`` for pre-dust-prevention rows; the
        # SPA falls back to ``deposit_amount_sats`` for those.
        "actual_sent_sats": getattr(session, "actual_sent_sats", None),
        # Layer 4 — reason a session is parked in AWAITING_FEE_REDUCTION.
        "send_infeasible_reason": getattr(
            session,
            "send_infeasible_reason",
            None,
        ),
        # Layer 4 — the maximum sat/vB at which the dust-safe send
        # could broadcast without underpaying the bin. Operators
        # watching a parked session use this as the "wait until
        # fees drop to ≤ N" target. Computed from the UTXO size
        # and the bin amount; doesn't require any network call.
        "resume_threshold_sat_per_vbyte": _braiins_resume_threshold(session),
        "send_confirmations": session.send_confirmations,
        "broadcast_block_height": session.broadcast_block_height,
        # Submarine-leg fields.
        "submarine_lockup_address": getattr(session, "submarine_lockup_address", None),
        "submarine_lockup_amount_sats": getattr(session, "submarine_lockup_amount_sats", None),
        "submarine_funding_txid": getattr(session, "submarine_funding_txid", None),
        # External-source fields.
        "ext_intake_address": getattr(session, "ext_intake_address", None),
        "ext_intake_amount_sats": getattr(session, "ext_intake_amount_sats", None),
        "ext_intake_received_sats": getattr(session, "ext_intake_received_sats", None) or 0,
        "ext_intake_txids": getattr(session, "ext_intake_txids", None) or [],
        # Confirmations an ext-onchain deposit needs before the session
        # advances — drives the wizard's "detected, waiting for confs
        # (X/Y)" message.
        "ext_oc_confirmations_required": max(1, int(settings.braiins_deposit_ext_oc_confirmations)),
        "ext_funds_received_at": (
            session.ext_funds_received_at.isoformat() if getattr(session, "ext_funds_received_at", None) else None
        ),
        "refund_address": getattr(session, "refund_address", None),
        "refund_txid": getattr(session, "refund_txid", None),
        "error_message": session.error_message,
        "status_history": session.status_history or [],
        "created_at": session.created_at.isoformat() if session.created_at else None,
        "updated_at": session.updated_at.isoformat() if session.updated_at else None,
        "completed_at": (session.completed_at.isoformat() if session.completed_at else None),
    }
    return out


def _braiins_resume_threshold(session: Any) -> int | None:
    """Layer 4 — return the maximum sat/vB at which the dust-safe
    send could broadcast without underpaying the bin amount.

    Operator-watchable target for parked sessions: "fees need to
    drop to ≤ N sat/vB before this resumes." Returns ``None`` when
    the session isn't in a state where the threshold is meaningful
    (no fresh UTXO recorded yet) or when the UTXO can never
    broadcast at any positive fee rate (math says it'd underpay
    even at 1 sat/vB — operator should investigate).
    """
    utxo = getattr(session, "fresh_utxo_amount_sats", None)
    bin_amount = getattr(session, "deposit_amount_sats", None)
    if utxo is None or bin_amount is None:
        return None
    # `arrived_at_destination = utxo_value - vbytes * sat_per_vbyte`
    # must be >= bin. Solving for the max feerate:
    #   sat_per_vbyte_max = (utxo_value - bin) / vbytes
    # Use the same 140-vbyte default the send path uses.
    from app.services.dust_safe_send import _DEFAULT_ESTIMATED_VBYTES

    headroom = int(utxo) - int(bin_amount)
    if headroom <= 0:
        return None
    threshold = headroom // _DEFAULT_ESTIMATED_VBYTES
    return max(1, threshold) if threshold > 0 else None


def _braiins_enabled_or_404() -> None:
    if not settings.braiins_deposit_enabled:
        raise HTTPException(status_code=404, detail="Braiins Deposit is disabled")


@router.get(
    "/braiins-deposit/presets",
    dependencies=[Depends(_require_auth)],
)
async def braiins_deposit_presets() -> Any:
    """Return the preset amounts + the user's current LN and on-chain
    balances.

    The wizard uses both balances to (a) grey-out preset chips whose
    required source amount exceeds the available balance for the
    selected source, and (b) auto-select the default source: prefer
    Lightning when sufficient, fall back to on-chain.
    """
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import BIN_AMOUNTS

    channel_balance, _err = await lnd_service.get_channel_balance()
    local_balance = 0
    if channel_balance:
        local_balance = int(channel_balance.get("local_balance_sat", 0))
    wallet_balance, _werr = await lnd_service.get_wallet_balance()
    onchain_confirmed = 0
    if wallet_balance:
        onchain_confirmed = int(wallet_balance.get("confirmed_balance", 0))
    return {
        "preset_amounts": list(BIN_AMOUNTS),
        "lightning_local_balance_sats": local_balance,
        "onchain_confirmed_balance_sats": onchain_confirmed,
        # Surfaces the ext kill switch so the wizard can
        # hide the External Source radios when the operator has
        # disabled them.
        "ext_enabled": bool(settings.braiins_deposit_ext_enabled),
        "ext_ln_invoice_ttl_s": int(settings.braiins_deposit_ext_ln_invoice_ttl_s),
        # Channel-open alternative kill switch — lets the wizard offer the
        # "open a channel instead" advanced toggle on on-chain sources.
        "channel_open_enabled": bool(settings.braiins_deposit_channel_open_enabled),
    }


class BraiinsDepositChannelPeerCheckRequest(BaseModel):
    amount_sats: int = Field(gt=0, le=100_000_000)


@router.post(
    "/braiins-deposit/channel-peer-check",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_channel_peer_check(
    body: BraiinsDepositChannelPeerCheckRequest,
) -> Any:
    """Connect-peer preflight (D2/C): is the channel-open peer reachable
    for this amount right now? The wizard calls this lazily when the user
    surfaces the channel option, so we never dangle an action that would
    fail at open time. Best-effort and advisory — the deposit's own
    open-channel step still retries transiently if the peer drops later.
    """
    _braiins_enabled_or_404()
    if not settings.braiins_deposit_channel_open_enabled:
        return {"available": False, "reachable": False, "reason": "disabled"}

    from app.services import braiins_channel_peers as _peers
    from app.services.braiins_deposit_service import braiins_deposit_service

    # Size the channel for this amount → which peer would we use?
    quote, qerr = await braiins_deposit_service.quote(
        amount_sats=body.amount_sats,
        source_kind="onchain",
        funding_strategy="channel",
    )
    if qerr or quote is None or not quote.channel_eligible:
        return {
            "available": True,
            "reachable": False,
            "reason": (quote.channel_ineligible_reason if quote else None) or "not eligible for channel open",
        }
    peer = _peers.select_peer_for_capacity(int(quote.channel_capacity_sats))
    if peer is None:
        return {"available": True, "reachable": False, "reason": "no peer for this size"}

    # connect_peer tolerates "already connected" and only errors on a real
    # failure, so success ⇒ reachable. Bound it tightly: this is an
    # advisory UI preflight, so a slow/hung connect over Tor must resolve
    # to "not reachable right now" fast rather than tie up an LND request
    # or make the wizard wait on the full client timeout.
    import asyncio

    try:
        _conn, conn_err = await asyncio.wait_for(
            lnd_service.connect_peer(peer.pubkey, peer.host),
            timeout=8.0,
        )
    except Exception:  # noqa: BLE001  (incl. asyncio.TimeoutError)
        conn_err = "timed out reaching peer"
    if conn_err:
        return {
            "available": True,
            "reachable": False,
            "peer_label": peer.label,
            "reason": "peer unreachable",
        }
    return {"available": True, "reachable": True, "peer_label": peer.label}


@router.post(
    "/braiins-deposit/quote",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_quote(body: BraiinsDepositQuoteRequest) -> Any:
    """Compute the fee breakdown for a target deposit amount + source
    kind. Pure; no DB write, no side effects.
    """
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    quote, err = await braiins_deposit_service.quote(
        amount_sats=body.amount_sats,
        source_kind=body.source_kind,
        include_extras=body.include_extras,
        funding_strategy=body.funding_strategy,
    )
    if err or quote is None:
        return JSONResponse(
            status_code=502 if "rates" in (err or "") else 400,
            content={"detail": sanitize_upstream_error(err or "quote failed", "Boltz")},
        )
    body_out = quote.as_dict()
    # Plan.c — surface the ext-LN invoice display TTL on the
    # quote response so the wizard can render the countdown ceiling
    # without a separate presets round-trip. Self-source quotes carry
    # the same field for shape consistency.
    body_out["ext_ln_invoice_ttl_s"] = int(settings.braiins_deposit_ext_ln_invoice_ttl_s)
    return body_out


@router.post(
    "/braiins-deposit/quotes-batch",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_quotes_batch(body: BraiinsDepositQuoteBatchRequest) -> Any:
    """Compute fee breakdowns for a list of target amounts under one
    (source_kind, include_extras) combination.

    The wizard's per-bin adaptive-disable feature needs a quote per
    preset to decide which chips to grey out at the current fee
    rate. Doing those N calls one-by-one from the browser easily
    trips the 60/minute IP rate limit (see
    ``BraiinsDepositQuoteBatchRequest`` docstring). This endpoint
    returns ``{ "<amount>": <quote-dict-or-null>, ... }`` so the
    wizard refreshes the whole cache in one request.

    Pure; no DB write, no side effects.
    """
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    ttl_s = int(settings.braiins_deposit_ext_ln_invoice_ttl_s)
    out: dict[str, Any] = {}
    for amt in body.amount_sats_list:
        quote, err = await braiins_deposit_service.quote(
            amount_sats=amt,
            source_kind=body.source_kind,
            include_extras=body.include_extras,
            funding_strategy=body.funding_strategy,
        )
        if err or quote is None:
            # Mirror the single-quote handler's policy: individual
            # bin failures are non-fatal here — the wizard just
            # doesn't get adaptive-disable for that bin.
            out[str(amt)] = None
            continue
        q = quote.as_dict()
        q["ext_ln_invoice_ttl_s"] = ttl_s
        out[str(amt)] = q
    return {"quotes": out}


@router.post(
    "/braiins-deposit/sessions",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_create_session(
    request: Request,
    body: BraiinsDepositSessionCreateRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a new Braiins-Deposit session and kick off the swap."""
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    ip = request.client.host if request.client else None
    _check_dashboard_payment_limit(body.amount_sats)

    # Server-side re-quote so we can refuse if the user's relevant
    # balance has slipped below the required threshold since they
    # opened Step 2 of the wizard.
    quote, qerr = await braiins_deposit_service.quote(
        amount_sats=body.amount_sats,
        source_kind=body.source_kind,
        include_extras=body.include_extras,
        funding_strategy=body.funding_strategy,
    )
    if qerr or quote is None:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "braiins_deposit_create_rejected",
            "braiins_deposit",
            amount_sats=body.amount_sats,
            details={
                "purpose": "braiins_deposit",
                "source_kind": body.source_kind,
                "reason": "quote_failed",
                "destination_address": body.destination_address,
            },
            success=False,
            error_message=qerr,
            ip_address=ip,
        )
        return JSONResponse(status_code=400, content={"detail": qerr or "quote failed"})

    # Channel-open eligibility: reject up front if this amount can't be
    # funded by a channel open (outside the peer's accepted size range,
    # or below the swap minimum). The service would refuse later anyway;
    # this gives a clear, immediate reason.
    if body.funding_strategy == "channel" and not quote.channel_eligible:
        detail = "This amount can't be deposited by opening a channel" + (
            f": {quote.channel_ineligible_reason}." if quote.channel_ineligible_reason else "."
        )
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "braiins_deposit_create_rejected",
            "braiins_deposit",
            amount_sats=body.amount_sats,
            details={
                "purpose": "braiins_deposit",
                "source_kind": body.source_kind,
                "funding_strategy": "channel",
                "reason": "channel_ineligible",
                "destination_address": body.destination_address,
            },
            success=False,
            error_message=detail,
            ip_address=ip,
        )
        return JSONResponse(status_code=400, content={"detail": detail})

    # Quote-staleness drift detection. If the wizard sent us
    # the total-fee number from its most recent quote, compare it
    # to the freshly computed one. Refuse with 409 + fresh quote if
    # drift exceeds the configured percentage; the wizard re-renders
    # the review step so the user can confirm at the new numbers.
    if body.expected_total_fee_sats is not None and body.expected_total_fee_sats > 0:
        threshold_pct = max(0, int(settings.braiins_deposit_quote_staleness_pct))
        if threshold_pct > 0:
            fresh = int(quote.total_fee_sats)
            submitted = int(body.expected_total_fee_sats)
            drift = abs(fresh - submitted)
            tolerance = (submitted * threshold_pct) // 100
            if drift > tolerance:
                await log_dashboard_action(
                    db,
                    DASHBOARD_KEY_ID,
                    "braiins_deposit_create_rejected",
                    "braiins_deposit",
                    amount_sats=body.amount_sats,
                    details={
                        "purpose": "braiins_deposit",
                        "reason": "quote_stale",
                        "submitted_total_fee_sats": submitted,
                        "fresh_total_fee_sats": fresh,
                        "drift_pct_threshold": threshold_pct,
                        "destination_address": body.destination_address,
                    },
                    success=False,
                    ip_address=ip,
                )
                return JSONResponse(
                    status_code=409,
                    content={
                        "detail": "quote_stale",
                        "submitted_total_fee_sats": submitted,
                        "fresh_quote": quote.as_dict(),
                    },
                )

    # External sources skip the Agent-Wallet balance check
    # entirely: the user is funding the deposit from another wallet,
    # so we have no balance to gate on. The user's intake amount is
    # surfaced via the quote's ``required_external_deposit_sats`` for
    # display only.
    if body.source_kind in ("ext_lightning", "ext_onchain"):
        if not settings.braiins_deposit_ext_enabled:
            return JSONResponse(
                status_code=403,
                content={"detail": "External sources are disabled"},
            )
    # Balance gate: check the relevant balance per source_kind.
    elif body.source_kind == "onchain":
        wallet_balance, _wbal_err = await lnd_service.get_wallet_balance()
        onchain_balance = 0
        if wallet_balance:
            onchain_balance = int(wallet_balance.get("confirmed_balance", 0))
        if onchain_balance < quote.required_onchain_balance_sats:
            detail = (
                f"Insufficient on-chain balance: {onchain_balance:,} sats "
                f"confirmed, {quote.required_onchain_balance_sats:,} sats required."
            )
            await log_dashboard_action(
                db,
                DASHBOARD_KEY_ID,
                "braiins_deposit_create_rejected",
                "braiins_deposit",
                amount_sats=body.amount_sats,
                details={
                    "purpose": "braiins_deposit",
                    "source_kind": "onchain",
                    "reason": "insufficient_balance",
                    "destination_address": body.destination_address,
                },
                success=False,
                error_message=detail,
                ip_address=ip,
            )
            return JSONResponse(status_code=400, content={"detail": detail})
    else:
        channel_balance, _bal_err = await lnd_service.get_channel_balance()
        local_balance = 0
        if channel_balance:
            local_balance = int(channel_balance.get("local_balance_sat", 0))
        if local_balance < quote.required_lightning_balance_sats:
            detail = (
                f"Insufficient Lightning balance: {local_balance:,} sats available, "
                f"{quote.required_lightning_balance_sats:,} sats required."
            )
            await log_dashboard_action(
                db,
                DASHBOARD_KEY_ID,
                "braiins_deposit_create_rejected",
                "braiins_deposit",
                amount_sats=body.amount_sats,
                details={
                    "purpose": "braiins_deposit",
                    "source_kind": "lightning",
                    "reason": "insufficient_balance",
                    "destination_address": body.destination_address,
                },
                success=False,
                error_message=detail,
                ip_address=ip,
            )
            return JSONResponse(status_code=400, content={"detail": detail})

    session, err = await braiins_deposit_service.create_session(
        db,
        api_key_id=DASHBOARD_KEY_ID,
        amount_sats=body.amount_sats,
        destination_address=body.destination_address,
        source_kind=body.source_kind,
        include_extras=body.include_extras,
        funding_strategy=body.funding_strategy,
    )
    if err == "in_flight_session_exists":
        # Return the existing session so the wizard reopens to its
        # progress view rather than confusing the user with an error.
        from app.models.braiins_deposit_session import (
            NON_TERMINAL_STATUSES,
            BraiinsDepositSession,
        )

        existing_q = (
            select(BraiinsDepositSession)
            .where(BraiinsDepositSession.api_key_id == DASHBOARD_KEY_ID)
            .where(BraiinsDepositSession.status.in_([s.value for s in NON_TERMINAL_STATUSES]))
            .limit(1)
        )
        existing = (await db.execute(existing_q)).scalar_one_or_none()
        if existing is not None:
            return JSONResponse(
                status_code=409,
                content={
                    "detail": "A deposit is already in progress.",
                    "session": _braiins_serialize(existing),
                },
            )
        return JSONResponse(status_code=409, content={"detail": "Already in progress"})
    if err or session is None:
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            "braiins_deposit_create_rejected",
            "braiins_deposit",
            amount_sats=body.amount_sats,
            details={
                "purpose": "braiins_deposit",
                "reason": "create_failed",
                "destination_address": body.destination_address,
            },
            success=False,
            error_message=err,
            ip_address=ip,
        )
        # D1(a) contextual recommendation: when a SWAP-strategy on-chain
        # deposit is refused because the node can't receive over Lightning
        # (the inbound gate/probe), and channel-open is enabled, tell the
        # wizard so it can offer "open a channel instead".
        content: dict = {"detail": err or "create failed"}
        if (
            settings.braiins_deposit_channel_open_enabled
            and body.funding_strategy == "swap"
            and body.source_kind in ("onchain", "ext_onchain")
            and err
            and ("inbound capacity" in err.lower() or "lightning route" in err.lower() or "receive ~" in err.lower())
        ):
            content["channel_open_suggested"] = True
        return JSONResponse(status_code=400, content=content)

    # Audit the creation BEFORE advancing so the audit-log timeline
    # is ordered chronologically: ``session_created`` precedes the
    # ``session_swapping`` row emitted by ``advance()``.
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "braiins_deposit_session_created",
        "braiins_deposit",
        amount_sats=body.amount_sats,
        details={
            "session_id": str(session.id),
            "purpose": "braiins_deposit",
            "destination_address": body.destination_address,
            "status": session.status.value,
            "include_extras": bool(getattr(session, "include_extras", True)),
        },
        ip_address=ip,
    )

    # Drive the first state-machine step inline so the response
    # already shows status=SWAPPING + the linked Boltz swap. Failures
    # here are captured into the session row and surfaced to the
    # caller via the response body — the row already exists.
    await braiins_deposit_service.advance(db, session.id)
    await db.refresh(session)

    return _braiins_serialize(session)


@router.get(
    "/braiins-deposit/sessions",
    dependencies=[Depends(_require_auth)],
)
async def braiins_deposit_list_sessions(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
) -> Any:
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    sessions = await braiins_deposit_service.list_recent_sessions(db, api_key_id=DASHBOARD_KEY_ID, limit=limit)
    return [_braiins_serialize(s) for s in sessions]


# Per-process throttle for the braiins detail-read advance.
# Maps session-id → last monotonic advance time so a tight
# detail poll doesn't drive advance()'s Tor round-trips on every tick.
_BRAIINS_DETAIL_ADVANCE_LAST: dict[str, float] = {}


def _should_advance_braiins_detail(
    session_id: Any,
    *,
    now: Optional[float] = None,
) -> bool:
    """Return True iff the detail endpoint should drive ``advance()`` for
    ``session_id`` on this read, throttled to at most once per
    ``braiins_deposit_detail_advance_min_interval_s`` per session.

    Records the advance time when it returns True. ``now`` is injectable
    (monotonic seconds) for tests. An interval of 0 disables throttling.
    """
    interval = max(
        0,
        int(getattr(settings, "braiins_deposit_detail_advance_min_interval_s", 3)),
    )
    if interval <= 0:
        return True
    t = now if now is not None else time.monotonic()
    key = str(session_id)
    last = _BRAIINS_DETAIL_ADVANCE_LAST.get(key, 0.0)
    if (t - last) < interval:
        return False
    _BRAIINS_DETAIL_ADVANCE_LAST[key] = t
    # Opportunistic prune so the map can't grow unbounded over a
    # long-lived process — drop entries not touched in a long while.
    if len(_BRAIINS_DETAIL_ADVANCE_LAST) > 1024:
        cutoff = t - max(60.0, interval * 20)
        for k in [k for k, v in _BRAIINS_DETAIL_ADVANCE_LAST.items() if v < cutoff]:
            _BRAIINS_DETAIL_ADVANCE_LAST.pop(k, None)
    return True


@router.get(
    "/braiins-deposit/sessions/{session_id}",
    dependencies=[Depends(_require_auth)],
)
async def braiins_deposit_session_detail(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    session = await braiins_deposit_service.get_session_by_id(db, session_id)
    if session is None:
        return JSONResponse(status_code=404, content={"detail": "Session not found"})
    # Best-effort: drive a forward tick on detail reads so an operator
    # who keeps the wizard open without the Celery worker still sees
    # progress. Errors absorbed by ``advance``. RATE-LIMITED: the
    # Celery beat ticker is the primary advancer, so we skip the
    # detail-read advance when this session was advanced within the
    # configured window — a tight 5 s poll must not issue redundant
    # get_channels / confirmation lookups over Tor on every tick.
    if _should_advance_braiins_detail(session_id):
        _adv_t0 = time.monotonic()
        await braiins_deposit_service.advance(db, session.id)
        # Observability: surface a slow advance (LND get_channels
        # + mempool confirmation lookups over Tor) so ops can see
        # slow-backend episodes rather than only user reports.
        _adv_dt = time.monotonic() - _adv_t0
        if _adv_dt > float(getattr(settings, "dashboard_slow_call_warn_s", 5.0)):
            logger.warning(
                "braiins detail advance slow: %.1fs (session=%s)",
                _adv_dt,
                session_id,
            )
        await db.refresh(session)
    body = _braiins_serialize(session)

    # Enrich with confirmation counts for every relevant txid when
    # the chain backend can provide them (audit-friendly view).
    if session.fresh_utxo_txid:
        c = await mempool_fee_service.optional_confirmations(session.fresh_utxo_txid)
        if c is not None:
            body["fresh_utxo_confirmations"] = c.get("confirmations")
    if session.send_txid:
        c = await mempool_fee_service.optional_confirmations(session.send_txid)
        if c is not None:
            body["send_confirmations_live"] = c.get("confirmations")
    # Submarine funding tx. Useful for users who want to see
    # their wallet's send to Boltz's lockup landing on chain.
    submarine_funding = getattr(session, "submarine_funding_txid", None)
    if submarine_funding:
        c = await mempool_fee_service.optional_confirmations(submarine_funding)
        if c is not None:
            body["submarine_funding_confirmations"] = c.get("confirmations")
    # Channel-open funding tx: live confirmation count + the activation
    # target, so the wizard can show "N / M confirmations" while the
    # channel opens.
    channel_open = getattr(session, "channel_open_txid", None)
    if channel_open:
        body["channel_activation_confs"] = int(settings.braiins_deposit_channel_activation_confs)
        c = await mempool_fee_service.optional_confirmations(channel_open)
        if c is not None:
            body["channel_open_confirmations"] = c.get("confirmations")
    # ext-LN: surface the Boltz reverse-swap invoice + its
    # expiry so the wizard can render the QR + countdown.
    source_kind_val: Any = getattr(session, "source_kind", None)
    if hasattr(source_kind_val, "value"):
        source_kind_val = source_kind_val.value
    if source_kind_val == "ext_lightning" and session.boltz_swap_id is not None:
        from datetime import timedelta

        from app.models.boltz_swap import BoltzSwap

        res = await db.execute(select(BoltzSwap).where(BoltzSwap.id == session.boltz_swap_id))
        swap = res.scalar_one_or_none()
        if swap is not None:
            body["ext_ln_invoice"] = getattr(swap, "boltz_invoice", None)
            # Derive a display expiry from swap.created_at + configured
            # TTL. The actual Boltz-side expiry is encoded in the
            # BOLT 11 invoice itself; this value is for the wizard's
            # countdown ceiling and may be slightly conservative.
            swap_created = getattr(swap, "created_at", None)
            if swap_created is not None:
                ttl = max(60, int(settings.braiins_deposit_ext_ln_invoice_ttl_s))
                body["ext_ln_invoice_expires_at"] = (swap_created + timedelta(seconds=ttl)).isoformat()
            body["ext_ln_boltz_status"] = getattr(swap, "boltz_status", None)
    # ext-OC: enrich each intake-tx with a live confirmation
    # count so the wizard can render per-deposit progress dots.
    intake_txids = body.get("ext_intake_txids") or []
    if intake_txids:
        enriched = []
        for entry in intake_txids:
            if not isinstance(entry, dict):
                continue
            new_entry = dict(entry)
            txid = entry.get("txid")
            if txid:
                c = await mempool_fee_service.optional_confirmations(txid)
                if c is not None:
                    new_entry["confirmations_live"] = c.get("confirmations")
            enriched.append(new_entry)
        body["ext_intake_txids"] = enriched
    # Recovery hint — aggregates across the reverse-leg and (if
    # present) the submarine-leg ``BoltzSwap`` rows so the wizard
    # banner can surface stuck-claim / timeout-imminent / unilateral-
    # available states using the same shape as Cold Storage.
    try:
        recovery = await _build_session_recovery(
            db,
            swap_ids=[
                getattr(session, "boltz_swap_id", None),
                getattr(session, "submarine_boltz_swap_id", None),
            ],
            session_status=getattr(session, "status", None) and (getattr(session.status, "value", session.status)),
            session_updated_at=getattr(session, "updated_at", None),
            session_pipeline_json=None,
        )
        if recovery is not None:
            body["recovery"] = recovery
    except Exception:  # noqa: BLE001
        logger.exception(
            "braiins session recovery enrichment failed for %s",
            session.id,
        )
    return body


@router.post(
    "/braiins-deposit/sessions/{session_id}/cancel",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_session_cancel(
    request: Request,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    ok, err = await braiins_deposit_service.cancel_session(db, session_id)
    ip = request.client.host if request.client else None
    # Record the user-action attempt. The service emits its own
    # ``braiins_deposit_session_cancelled`` state-transition row when
    # the cancel actually succeeds (avoids a duplicate); on failure
    # only this row exists, which still gives operators visibility
    # into rejected cancel attempts.
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "braiins_deposit_cancel_attempted",
        "braiins_deposit",
        details={"session_id": str(session_id), "purpose": "braiins_deposit"},
        success=ok,
        error_message=err,
        ip_address=ip,
    )
    if not ok:
        return JSONResponse(status_code=400, content={"detail": err or "cancel failed"})
    session = await braiins_deposit_service.get_session_by_id(db, session_id)
    if session is None:
        return JSONResponse(status_code=404, content={"detail": "Session not found"})
    return _braiins_serialize(session)


@router.post(
    "/braiins-deposit/sessions/{session_id}/retry-send",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_session_retry_send(
    request: Request,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    # ``accept_underpay`` (query param ``accept_underpay=true``)
    # overrides the dust-prevention floor. Used when an operator
    # decides waiting for fees to drop isn't worth the delay and
    # explicitly accepts the slightly-under-bin arrival.
    accept_underpay = request.query_params.get("accept_underpay", "").lower() in ("true", "1")
    ok, err = await braiins_deposit_service.retry_send(
        db,
        session_id,
        accept_underpay=accept_underpay,
    )
    ip = request.client.host if request.client else None
    # User-action audit. State-transition rows (``session_broadcast``,
    # ``session_completed``, etc.) follow from ``advance()`` below.
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "braiins_deposit_retry_send_attempted",
        "braiins_deposit",
        details={
            "session_id": str(session_id),
            "purpose": "braiins_deposit",
            "accept_underpay": accept_underpay,
        },
        success=ok,
        error_message=err,
        ip_address=ip,
    )
    if not ok:
        return JSONResponse(status_code=400, content={"detail": err or "retry failed"})
    # Kick the state machine once so the response reflects the new
    # state (FUNDED -> SENDING -> BROADCAST or back to FAILED).
    await braiins_deposit_service.advance(db, session_id)
    session = await braiins_deposit_service.get_session_by_id(db, session_id)
    if session is None:
        return JSONResponse(status_code=404, content={"detail": "Session not found"})
    return _braiins_serialize(session)


@router.post(
    "/braiins-deposit/sessions/{session_id}/regenerate-invoice",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_session_regenerate_invoice(
    request: Request,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Re-mint the Boltz reverse-swap invoice for an
    ext-LN session whose original invoice has expired or is close to
    expiring. The service cooperatively disposes the prior swap and
    surfaces a fresh invoice via the next session-detail poll.
    """
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    ok, err = await braiins_deposit_service.regenerate_ext_lightning_invoice(db, session_id)
    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "braiins_deposit_regenerate_invoice_attempted",
        "braiins_deposit",
        details={"session_id": str(session_id), "purpose": "braiins_deposit"},
        success=ok,
        error_message=err,
        ip_address=ip,
    )
    if not ok:
        return JSONResponse(status_code=400, content={"detail": err or "regenerate failed"})
    session = await braiins_deposit_service.get_session_by_id(db, session_id)
    if session is None:
        return JSONResponse(status_code=404, content={"detail": "Session not found"})
    return _braiins_serialize(session)


@router.post(
    "/braiins-deposit/sessions/{session_id}/submit-refund",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_session_submit_refund(
    request: Request,
    session_id: UUID,
    body: BraiinsDepositRefundRequest,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Send the ext-OC intake amount back to the
    address supplied by the user on the failure-screen refund panel.
    """
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    ok, err = await braiins_deposit_service.submit_refund_address(db, session_id, body.refund_address)
    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "braiins_deposit_submit_refund_attempted",
        "braiins_deposit",
        details={
            "session_id": str(session_id),
            "purpose": "braiins_deposit",
            "refund_address": body.refund_address,
        },
        success=ok,
        error_message=err,
        ip_address=ip,
    )
    if not ok:
        # 422 for validation errors so the wizard can distinguish them
        # from "session not eligible" (400). The address-validation
        # branch carries the "Invalid refund address" prefix.
        status = 422 if "Invalid refund address" in (err or "") else 400
        return JSONResponse(status_code=status, content={"detail": err or "refund failed"})
    session = await braiins_deposit_service.get_session_by_id(db, session_id)
    if session is None:
        return JSONResponse(status_code=404, content={"detail": "Session not found"})
    return _braiins_serialize(session)


@router.post(
    "/braiins-deposit/sessions/{session_id}/cooperative-refund",
    dependencies=[Depends(_require_auth_csrf)],
)
async def braiins_deposit_session_cooperative_refund(
    request: Request,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Manual Musig2 cooperative refund retry for a self-funded
    (LIGHTNING / ONCHAIN) submarine session whose Boltz swap ended
    in ``invoice.failedToPay``, ``swap.expired``, or
    ``transaction.failed``. Funds locked in the Boltz HTLC are
    refunded to a fresh wallet-controlled P2TR address; the
    session is projected to ``REFUNDED`` on success.
    """
    _braiins_enabled_or_404()
    from app.services.braiins_deposit_service import braiins_deposit_service

    refund_txid, err = await braiins_deposit_service.recover_submarine_refund(db, session_id)
    ip = request.client.host if request.client else None
    await log_dashboard_action(
        db,
        DASHBOARD_KEY_ID,
        "braiins_deposit_cooperative_refund_attempted",
        "braiins_deposit",
        details={
            "session_id": str(session_id),
            "purpose": "braiins_deposit",
            "refund_txid": refund_txid,
        },
        success=refund_txid is not None,
        error_message=err,
        ip_address=ip,
    )
    if refund_txid is None:
        return JSONResponse(status_code=400, content={"detail": err or "refund failed"})
    session = await braiins_deposit_service.get_session_by_id(db, session_id)
    if session is None:
        return JSONResponse(status_code=404, content={"detail": "Session not found"})
    return _braiins_serialize(session)
