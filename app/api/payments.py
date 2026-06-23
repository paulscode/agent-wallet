# SPDX-License-Identifier: MIT
"""
Payment API endpoints — invoices, Lightning payments, on-chain sends.

Write operations require an admin API key.
Safety limits (max_payment_sats, rate limiting, velocity breaker) are enforced.
"""

import logging
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.idempotency import (
    get_idempotency_key,
    lookup_or_reserve,
    mark_pending,
    peek,
    release_inflight,
    release_pending,
    store_result,
)
from app.core.rate_limit import check_payment_limits, reconcile_spend_limit, rollback_payment_limits
from app.core.security import get_api_key, get_spend_key
from app.core.utils import _HEX64_PATTERN, lnd_broadcast_outcome_unknown, sanitize_upstream_error
from app.core.validation import (
    MAX_SAT_PER_VBYTE,
    ONCHAIN_TX_VBYTE_ESTIMATE,
    validate_bitcoin_address,
)
from app.models.api_key import APIKey
from app.services.audit_service import log_action
from app.services.lnd_service import lnd_service
from app.services.mempool_fee_service import mempool_fee_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{API_V1_PREFIX}/payments", tags=["payments"])

# ``MAX_SAT_PER_VBYTE`` / ``ONCHAIN_TX_VBYTE_ESTIMATE`` are shared across every
# on-chain send path — see ``app/core/validation.py`` for the rationale. The
# fee budget is only folded into the cap when the caller controls the rate
# (explicit ``sat_per_vbyte`` or ``fee_priority``); automatic sends use LND's
# market rate, which is not attacker-controlled and is not folded in.


# ─── Request Models ───────────────────────────────────────────────────


class NewAddressRequest(BaseModel):
    address_type: Literal["p2wkh", "np2wkh", "p2tr"] = Field("p2tr", description="Address type: p2wkh, np2wkh, p2tr")


class CreateInvoiceRequest(BaseModel):
    amount_sats: int = Field(..., ge=0, description="Invoice amount in sats (0 = any-amount)")
    memo: str = Field("", max_length=256, description="Description on the invoice")
    expiry: int = Field(3600, ge=60, le=86400, description="Seconds until expiry")


class PayInvoiceRequest(BaseModel):
    payment_request: str = Field(..., min_length=1, description="BOLT11 payment request")
    fee_limit_sats: Optional[int] = Field(
        None,
        ge=0,
        le=1_000_000,
        description="Max routing fee in sats (defence-in-depth cap: 1,000,000 sats)",
    )
    timeout_seconds: int = Field(60, ge=5, le=300, description="Payment timeout")


class DecodePaymentRequest(BaseModel):
    payment_request: str = Field(..., min_length=1, description="BOLT11 payment request string")


class SendOnchainRequest(BaseModel):
    address: str = Field(..., min_length=1, description="Bitcoin address")
    amount_sats: int = Field(..., gt=0, description="Amount in satoshis")
    sat_per_vbyte: Optional[int] = Field(
        None,
        ge=1,
        le=MAX_SAT_PER_VBYTE,
        description=f"Fee rate in sat/vB (1..{MAX_SAT_PER_VBYTE}; None = automatic)",
    )
    fee_priority: Optional[str] = Field(None, description="Fee priority: low, medium, high")
    label: str = Field("", max_length=256, description="Optional label")

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)


class EstimateFeeRequest(BaseModel):
    address: str = Field(..., min_length=1, description="Target Bitcoin address")
    amount_sats: int = Field(..., gt=0, description="Amount in satoshis")
    target_conf: int = Field(6, ge=1, le=144, description="Target confirmations")

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        return validate_bitcoin_address(v)


# ─── Safety Check ─────────────────────────────────────────────────────


def _check_payment_limit(amount_sats: int) -> None:
    """Enforce per-payment safety limit."""
    max_sats = settings.lnd_max_payment_sats
    if max_sats == -1:
        return  # No limit
    if amount_sats > max_sats:
        raise HTTPException(
            status_code=400,
            detail=f"Payment of {amount_sats:,} sats exceeds safety limit of {max_sats:,} sats. "
            f"Contact admin to adjust LND_MAX_PAYMENT_SATS.",
        )


# ─── Endpoints ────────────────────────────────────────────────────────


@router.post("/address")
async def new_address(
    req: NewAddressRequest,
    request: Request,
    # Receiving moves funds in, not out — available to any active key
    # (the monitor floor tier and above).
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Generate a new on-chain receive address."""
    data, error = await lnd_service.new_address(req.address_type)
    if error:
        await log_action(db, api_key, "new_address", "wallet", success=False, error_message=error)
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
    assert data is not None
    await log_action(
        db,
        api_key,
        "new_address",
        "wallet",
        details={"address_type": req.address_type, "address": data["address"]},
        ip_address=request.client.host if request.client else None,
    )
    return data


@router.post("/invoice")
async def create_invoice(
    req: CreateInvoiceRequest,
    request: Request,
    # Receiving moves funds in, not out — available to any active key
    # (the monitor floor tier and above).
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Create a Lightning invoice (BOLT11 payment request)."""
    data, error = await lnd_service.create_invoice(req.amount_sats, req.memo, req.expiry)
    if error:
        await log_action(
            db,
            api_key,
            "create_invoice",
            "lightning",
            amount_sats=req.amount_sats,
            success=False,
            error_message=error,
        )
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
    assert data is not None
    await log_action(
        db,
        api_key,
        "create_invoice",
        "lightning",
        amount_sats=req.amount_sats,
        details={"memo": req.memo, "r_hash": data["r_hash"]},
        ip_address=request.client.host if request.client else None,
    )
    return data


@router.post("/decode")
async def decode_payment_request(
    req: DecodePaymentRequest,
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Decode a BOLT11 Lightning payment request."""
    data, error = await lnd_service.decode_payment_request(req.payment_request)
    if error:
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
    return data


# A Lightning send result is only a definitive failure when LND itself
# reports a terminal ``payment_error`` — surfaced by ``send_payment_sync``
# as a ``"Payment failed: …"`` string. Every other error (timeout, dropped
# connection, 5xx, circuit-breaker) ends the HTTP call without LND
# confirming the HTLC was rejected, and LND does not cancel an in-flight
# HTLC when its caller disconnects. Such an outcome is *ambiguous*: the
# payment may still settle, so the idempotency slot is held pending
# reconciliation rather than released for an immediate retry.
_LN_TERMINAL_ERROR_PREFIX = "Payment failed:"


def _is_terminal_ln_error(error: str | None) -> bool:
    """True when a Lightning send error means LND will not settle the HTLC."""
    return bool(error) and error.startswith(_LN_TERMINAL_ERROR_PREFIX)




async def _reconcile_pending_lightning_payment(
    *, api_key_id: str, idem_key: str, request_body: Any
) -> Optional[dict[str, Any]]:
    """Resolve a pending idempotency slot left by an earlier ambiguous send.

    When a prior attempt timed out with its HTLC possibly in flight, the
    slot holds the payment hash. On a same-key retry this looks the payment
    up against the node:

    * settled  → store the real result so the retry returns it (no re-send);
    * failed   → release the slot so the retry executes a fresh attempt;
    * unknown / still in flight → leave the slot pending (the retry then
      receives 409 until the outcome resolves).

    Returns the resolved response dict when the payment settled, else
    ``None`` (caller proceeds to ``lookup_or_reserve``).
    """
    record = peek(api_key_id=api_key_id, idem_key=idem_key)
    if not record or record.get("state") != "pending":
        return None
    payment_hash = record.get("payment_hash")
    if not payment_hash:
        return None

    lookup, err = await lnd_service.lookup_payment(payment_hash)
    if err or lookup is None:
        return None  # cannot resolve now — slot stays pending

    status = (lookup.get("status") or "").upper()
    if status == "SUCCEEDED":
        result = {
            "payment_hash": payment_hash,
            "payment_preimage": lookup.get("payment_preimage", ""),
            "payment_route": {
                "total_amt": int(lookup.get("value_sat", 0)),
                "total_fees": int(lookup.get("fee_sat", 0)),
            },
        }
        store_result(
            api_key_id=api_key_id,
            idem_key=idem_key,
            request_body=request_body,
            response=result,
        )
        return result
    if status == "FAILED":
        release_pending(api_key_id=api_key_id, idem_key=idem_key)
    return None


@router.post("/pay")
async def pay_invoice(
    req: PayInvoiceRequest,
    request: Request,
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Pay a Lightning invoice.

    Subject to per-payment safety limit (LND_MAX_PAYMENT_SATS),
    cumulative spend limit, and velocity breaker.

    Clients may pass ``Idempotency-Key: <uuid>`` to make this
    POST safely retryable. The first 2xx response is cached for 24 h
    keyed by ``(api_key_id, idempotency_key)``.
    """
    # Optional Idempotency-Key short-circuits replays.
    idem_key = get_idempotency_key(request)
    req_body = req.model_dump()
    if idem_key is not None:
        # If a prior attempt left a pending slot (its HTLC outcome was
        # unknown), resolve it against the node before reserving. A settled
        # payment returns its stored result without a second send.
        resolved = await _reconcile_pending_lightning_payment(
            api_key_id=str(api_key.id), idem_key=idem_key, request_body=req_body
        )
        if resolved is not None:
            return resolved
        cached = lookup_or_reserve(
            api_key_id=str(api_key.id),
            idem_key=idem_key,
            request_body=req_body,
            inflight_ttl=req.timeout_seconds + 60,
        )
        if cached is not None:
            return cached

    # Tracks whether the in-flight marker should be dropped on the way out.
    # It is cleared for an ambiguous send outcome so a retry is held until
    # reconciliation resolves the payment, rather than re-sending it.
    release_on_failure = True
    try:
        # Decode first to get the amount
        decoded, decode_err = await lnd_service.decode_payment_request(req.payment_request)
        if decode_err:
            raise HTTPException(status_code=400, detail=f"Cannot decode payment request: {decode_err}")
        assert decoded is not None

        amount_sats = decoded.get("num_satoshis", 0)

        # Require an amount-bearing invoice. An amountless invoice decodes
        # to zero, which the safety cap and spend window would read as a
        # free payment; the caller cannot supply the amount here, so reject
        # it outright rather than let the settled value escape the limits.
        if amount_sats <= 0:
            raise HTTPException(
                status_code=400,
                detail="Amountless invoices are not supported; use an invoice with a fixed amount.",
            )

        # Include fee_limit_sats in the safety cap and rate-limit ledger
        # so an outsized fee_limit cannot bypass LND_MAX_PAYMENT_SATS or
        # the spend window. When unset, fall back to 5% of the invoice
        # amount (matches typical routing-fee budgets) as the worst case.
        fee_limit_for_check = req.fee_limit_sats if req.fee_limit_sats is not None else max(1, int(amount_sats * 0.05))
        total_sats = amount_sats + fee_limit_for_check
        _check_payment_limit(total_sats)

        # When the caller omits
        # ``fee_limit_sats`` we reserve the 5% estimate above, but the
        # actual payment must be bounded to that same number — otherwise
        # LND applies its own (potentially larger) default routing budget
        # and true outflow could briefly exceed the per-payment ceiling
        # we checked. Pass the reserved bound as the effective fee limit.
        effective_fee_limit_sats = fee_limit_for_check

        # Check cumulative spend + velocity limits against worst-case spend
        allowed, limit_error, reservation = await check_payment_limits(total_sats, str(api_key.id))
        if not allowed:
            await log_action(
                db,
                api_key,
                "pay_invoice",
                "lightning",
                amount_sats=amount_sats,
                success=False,
                error_message=limit_error,
                ip_address=request.client.host if request.client else None,
            )
            raise HTTPException(status_code=429, detail=limit_error)

        data, error = await lnd_service.send_payment_sync(
            req.payment_request, effective_fee_limit_sats, req.timeout_seconds
        )
        if error:
            terminal = _is_terminal_ln_error(error)
            await log_action(
                db,
                api_key,
                "pay_invoice",
                "lightning",
                amount_sats=amount_sats,
                success=False,
                error_message=error,
                ip_address=request.client.host if request.client else None,
            )
            if terminal:
                # LND rejected the HTLC: nothing left the wallet, so the
                # reservation is released and the key may be retried freely.
                await rollback_payment_limits(reservation)
                raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
            # Ambiguous outcome: the HTLC may still settle. Keep the
            # worst-case reservation (the sats may yet leave) and hold the
            # idempotency slot pending against the payment hash so a retry
            # is reconciled rather than re-sent.
            if idem_key is not None:
                release_on_failure = False
                mark_pending(
                    api_key_id=str(api_key.id),
                    idem_key=idem_key,
                    request_body=req_body,
                    payment_hash=decoded.get("payment_hash", ""),
                )
            raise HTTPException(
                status_code=502,
                detail=(
                    "Payment outcome is pending and being reconciled. "
                    "Retry the same Idempotency-Key to resolve it; do not re-send with a new key."
                ),
            )
        assert data is not None

        # Reconcile the worst-case reservation with what actually left the
        # wallet (amount + real routing fee) so the spend window reflects
        # true outflow rather than the pre-flight fee estimate.
        route = data.get("payment_route")
        settled_sats = int(route["total_amt"]) if route and route.get("total_amt") else amount_sats
        routing_fee_sats = int(route["total_fees"]) if route else 0
        await reconcile_spend_limit(reservation, settled_sats)

        await log_action(
            db,
            api_key,
            "pay_invoice",
            "lightning",
            amount_sats=settled_sats,
            details={
                "payment_hash": data.get("payment_hash"),
                "destination": decoded.get("destination"),
                "description": decoded.get("description"),
                "routing_fee_sats": routing_fee_sats,
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
        # Release the in-flight marker so the client can retry on a
        # definitive failure (DB error, decode error, LND-rejected HTLC).
        # An ambiguous send outcome clears ``release_on_failure`` and holds
        # the slot pending instead, so a retry is reconciled against the
        # payment hash rather than re-sending. A successful 2xx already
        # replaced the marker via store_result, making release a no-op.
        if idem_key is not None and release_on_failure:
            release_inflight(api_key_id=str(api_key.id), idem_key=idem_key)
        raise


@router.post("/send-onchain")
async def send_onchain(
    req: SendOnchainRequest,
    request: Request,
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Send on-chain Bitcoin to an address.

    Subject to per-payment safety limit, cumulative spend limit, and velocity breaker.
    Supports fee_priority (low/medium/high) for Mempool-based fee estimation.

    Clients may pass ``Idempotency-Key: <uuid>`` to make this
    POST safely retryable.
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

    release_on_failure = True
    try:
        # Resolve the effective fee rate up front so the miner fee can be
        # folded into the spend-cap accounting below. ``fee_priority`` is only
        # consulted when no explicit rate was given; the mempool-derived rate is
        # clamped to the same ceiling as a caller-supplied rate so an anomalous
        # fee estimate cannot drain the wallet either.
        sat_per_vbyte = req.sat_per_vbyte
        if not sat_per_vbyte and req.fee_priority:
            mempool_rate = await mempool_fee_service.get_fee_for_priority(req.fee_priority)
            if mempool_rate:
                sat_per_vbyte = min(int(mempool_rate), MAX_SAT_PER_VBYTE)

        # The per-payment safety limit is an *amount* ceiling, so it is checked
        # against ``amount_sats`` alone. The on-chain miner fee — which a caller
        # could otherwise inflate via ``sat_per_vbyte`` to drain the wallet
        # invisibly — is bounded primarily by the ``MAX_SAT_PER_VBYTE`` clamp on
        # the rate, and is additionally charged (as a realistic estimate) against
        # the cumulative spend window below so repeated high-fee sends accumulate
        # toward the rolling cap. Automatic sends (no caller rate) use LND's
        # market-rate estimate, which is not attacker-controlled and is not
        # folded in. Unlike Lightning, the fee is intentionally kept out of the
        # per-payment ceiling so that ordinary small sends with a normal fee rate
        # are not blocked by it.
        _check_payment_limit(req.amount_sats)

        # Check cumulative spend + velocity limits, folding in the bounded
        # caller-controlled fee budget so the rolling spend window reflects fee
        # outflow rather than ignoring it.
        fee_budget = sat_per_vbyte * ONCHAIN_TX_VBYTE_ESTIMATE if sat_per_vbyte else 0
        cap_amount = req.amount_sats + fee_budget
        allowed, limit_error, reservation = await check_payment_limits(cap_amount, str(api_key.id))
        if not allowed:
            await log_action(
                db,
                api_key,
                "send_onchain",
                "bitcoin",
                amount_sats=req.amount_sats,
                success=False,
                error_message=limit_error,
                ip_address=request.client.host if request.client else None,
            )
            raise HTTPException(status_code=429, detail=limit_error)

        data, error = await lnd_service.send_coins(req.address, req.amount_sats, sat_per_vbyte, req.label)
        if error:
            await log_action(
                db,
                api_key,
                "send_onchain",
                "bitcoin",
                amount_sats=req.amount_sats,
                success=False,
                error_message=error,
                ip_address=request.client.host if request.client else None,
            )
            if lnd_broadcast_outcome_unknown(error):
                # The transaction may have been broadcast. Keep the worst-case
                # reservation and hold the idempotency slot so a same-key retry
                # is rejected rather than selecting fresh inputs and sending a
                # second transaction.
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
                        "Send outcome is unknown and may have broadcast. "
                        "Retry the same Idempotency-Key once the chain state is clear; "
                        "do not re-send with a new key."
                    ),
                )
            # Definitive pre-broadcast failure: nothing left the wallet.
            await rollback_payment_limits(reservation)
            raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
        assert data is not None

        await log_action(
            db,
            api_key,
            "send_onchain",
            "bitcoin",
            amount_sats=req.amount_sats,
            details={
                "address": req.address,
                "txid": data.get("txid"),
                "fee_priority": req.fee_priority,
                "sat_per_vbyte": sat_per_vbyte,
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
        # Release the marker on a definitive failure; an unknown broadcast
        # outcome clears ``release_on_failure`` and holds the slot pending so
        # a retry is rejected rather than sending a second transaction.
        if idem_key is not None and release_on_failure:
            release_inflight(api_key_id=str(api_key.id), idem_key=idem_key)
        raise


@router.post("/estimate-fee")
async def estimate_fee(
    req: EstimateFeeRequest,
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Estimate on-chain transaction fee."""
    data, error = await lnd_service.estimate_fee(req.address, req.amount_sats, req.target_conf)
    if error:
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
    return data


@router.get("/lookup/{payment_hash}")
async def lookup_payment(
    payment_hash: str,
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Look up an outgoing payment by its payment hash."""
    if not _HEX64_PATTERN.match(payment_hash):
        raise HTTPException(status_code=400, detail="Invalid payment hash (must be 64 hex characters)")
    data, error = await lnd_service.lookup_payment(payment_hash)
    if error:
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
    if not data:
        raise HTTPException(status_code=404, detail="Payment not found")
    return data


@router.get("/invoice/{r_hash}")
async def lookup_invoice(
    r_hash: str,
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Look up a specific invoice by its payment hash."""
    if not _HEX64_PATTERN.match(r_hash):
        raise HTTPException(status_code=400, detail="Invalid invoice hash (must be 64 hex characters)")
    data, error = await lnd_service.lookup_invoice(r_hash)
    if error:
        raise HTTPException(status_code=502, detail=sanitize_upstream_error(error, "LND"))
    return data
