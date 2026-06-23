# SPDX-License-Identifier: MIT
"""BOLT 12 REST API router.

Exposes codec-level decode + persistence/listing of offers
and their associated invoice_request / invoice rows. The flows that
require the orchestrator + gateway (issuing fresh offers from
scratch, sending invreqs, accepting inbound invreqs) run through that
stack; this router covers the offline + persistence surface:

* Decode any third-party BOLT 12 offer string offline (no LND, no
  gateway).
* Import / persist offers into the wallet (e.g. paste-from-QR), then
  list / retrieve / disable them.
* Read back stored invoice_request and invoice rows.

Every write op is audit-logged with the same ``actor / action /
resource`` shape that ``payments.py`` uses, so the existing
audit-log retention + chain-repair plumbing covers BOLT 12 too.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.encryption import encrypt_field
from app.core.idempotency import (
    get_idempotency_key,
    lookup_or_reserve,
    mark_pending,
    peek,
    release_inflight,
    release_pending,
    store_result,
)
from app.core.limiter import limiter
from app.core.rate_limit import (
    check_payment_limits,
    reconcile_spend_limit,
    rollback_payment_limits,
)
from app.core.security import get_admin_key, get_api_key, get_spend_key
from app.core.utils import sanitize_upstream_error
from app.models.api_key import APIKey
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)
from app.models.bolt12_offer import (
    Bolt12Offer,
    Bolt12OfferSource,
    Bolt12OfferStatus,
)
from app.services.audit_service import log_action
from app.services.bolt12 import (
    Bolt12Error,
    Bolt12FormatError,
    CoincurveSigner,
    Invoice,
    InvoiceRequest,
    InvoiceRequestTimeoutError,
    InvreqBuildContext,
    Offer,
    ReplyPathSpec,
    SendDestination,
    SendPlan,
    sign_invoice_request,
    verify_bip340,
)
from app.services.bolt12 import (
    decode as decode_bolt12,
)
from app.services.bolt12 import (
    encode as encode_bolt12,
)
from app.services.bolt12.chain_hash import (
    MAINNET_CHAIN_HASH,
    chain_hash_for,
)
from app.services.bolt12.codec import Bolt12String
from app.services.bolt12.lnd_paths import decode_invoice_paths
from app.services.bolt12.runtime import get_bolt12_service
from app.services.bolt12.tlv import decode_stream as tlv_decode_stream
from app.services.bolt12.tlv import encode_stream as tlv_encode_stream
from app.services.bolt12.well_known_payers import (
    WellKnownPayer,
    bootstrap_om_peer_node_ids,
    well_known_payer_node_ids,
)
from app.services.bolt12.well_known_payers import (
    match_for_description as match_well_known_payer,
)
from app.services.lnd_service import lnd_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{API_V1_PREFIX}/bolt12", tags=["bolt12"])


# ─── Constants ─────────────────────────────────────────────────────────

# Reasonable upper bounds for raw bech32 strings to keep request
# bodies and DB columns small. BOLT 12 offers are theoretically
# unbounded but real-world offers (with paths/issuer info) sit well
# under this. A hard cap also limits DoS from oversized payloads.
_MAX_BOLT12_LEN = 8192


# ─── Request / response models ────────────────────────────────────────


class DecodeOfferRequest(BaseModel):
    """Decode an offer string without touching persistent state."""

    offer: str = Field(..., min_length=1, max_length=_MAX_BOLT12_LEN)


class ImportOfferRequest(BaseModel):
    """Persist a third-party offer string into our DB.

    The offer string is the canonical identity (UNIQUE in the
    schema). Decoded fields are denormalised into indexable columns
    so the dashboard can render summaries without parsing on every
    read.
    """

    offer: str = Field(..., min_length=1, max_length=_MAX_BOLT12_LEN)

    @field_validator("offer")
    @classmethod
    def _normalise_offer(cls, v: str) -> str:
        # Strip whitespace + lowercase the bech32 prefix; bech32
        # strings are case-sensitive but conventionally lowercase.
        return v.strip()


class OfferResponse(BaseModel):
    """Public projection of a stored offer row."""

    id: UUID
    bolt12: str
    description: Optional[str]
    amount_msat: Optional[int]
    currency: Optional[str]
    issuer: Optional[str]
    issuer_id_hex: Optional[str]
    status: str
    source: str
    quantity_max: Optional[int]
    is_default_receive: bool = False
    created_at: Any  # ISO datetime
    last_paid_at: Any = None  # ISO datetime or None

    @classmethod
    def from_orm_row(cls, row: Bolt12Offer) -> "OfferResponse":
        return cls(
            id=row.id,
            bolt12=row.bolt12,
            description=row.description,
            amount_msat=row.amount_msat,
            currency=row.currency,
            issuer=row.issuer,
            issuer_id_hex=row.issuer_id_hex,
            status=row.status.value,
            source=row.source.value,
            quantity_max=row.quantity_max,
            is_default_receive=bool(row.is_default_receive),
            created_at=row.created_at,
            last_paid_at=row.last_paid_at,
        )


class InvoiceRequestResponse(BaseModel):
    id: UUID
    offer_id: Optional[UUID]
    direction: str
    status: str
    amount_msat: Optional[int]
    payer_note: Optional[str]
    created_at: Any
    completed_at: Any

    @classmethod
    def from_orm_row(cls, row: Bolt12InvoiceRequest) -> "InvoiceRequestResponse":
        return cls(
            id=row.id,
            offer_id=row.offer_id,
            direction=row.direction.value,
            status=row.status.value,
            amount_msat=row.amount_msat,
            payer_note=row.payer_note,
            created_at=row.created_at,
            completed_at=row.completed_at,
        )


class InvoiceResponse(BaseModel):
    id: UUID
    invoice_request_id: UUID
    direction: str
    status: str
    amount_msat: int
    payment_hash_hex: str
    node_id_hex: Optional[str]
    created_at: Any
    paid_at: Any

    @classmethod
    def from_orm_row(cls, row: Bolt12Invoice) -> "InvoiceResponse":
        return cls(
            id=row.id,
            invoice_request_id=row.invoice_request_id,
            direction=row.direction.value,
            status=row.status.value,
            amount_msat=row.amount_msat,
            payment_hash_hex=row.payment_hash_hex,
            node_id_hex=row.node_id_hex,
            created_at=row.created_at,
            paid_at=row.paid_at,
        )


# ─── Helpers ──────────────────────────────────────────────────────────


def _decode_offer_or_400(raw: str) -> Offer:
    """Decode ``raw`` into an :class:`Offer` or raise ``HTTPException``.

    All BOLT 12 codec errors are surfaced as ``400 Bad Request`` —
    they are caller-input problems, not server faults. Detailed
    parser internals are intentionally **not** echoed back to the
    caller (that information is only useful to a fuzzer); we log
    the full exception at INFO so operators can still triage from
    the structured logs.
    """
    try:
        # ``raw`` is caller-supplied; apply the TLV record/value caps so a
        # hostile offer string cannot flood the decoder with records or
        # oversized values (the bech32 length bound alone does not cap record
        # count).
        wire = decode_bolt12(
            raw,
            max_records=settings.bolt12_max_tlv_records or None,
            max_value_bytes=settings.bolt12_max_tlv_value_bytes or None,
        )
    except Bolt12FormatError as exc:
        logger.info("BOLT 12 decode rejected (format): %s", exc)
        raise HTTPException(status_code=400, detail="Invalid BOLT 12 string") from exc
    except Bolt12Error as exc:
        logger.info("BOLT 12 decode rejected (codec): %s", exc)
        raise HTTPException(status_code=400, detail="Invalid BOLT 12 string") from exc

    try:
        return Offer.parse(wire)
    except Bolt12Error as exc:
        logger.info("BOLT 12 decode rejected (offer parse): %s", exc)
        raise HTTPException(status_code=400, detail="Invalid BOLT 12 string") from exc


async def _require_offer_owner(
    offer_id: UUID,
    api_key: APIKey,
    db: AsyncSession,
    *,
    request: Optional[Request] = None,
) -> Bolt12Offer:
    """Load an offer row and assert the caller owns it.

    Cross-tenant lookups return **404, not 403**, so an attacker
    cannot enumerate which offer ids exist for other tenants. The
    unauthorised-access attempt is logged via the audit chain so
    incident response can grep for it later.
    """
    row = (await db.execute(select(Bolt12Offer).where(Bolt12Offer.id == offer_id))).scalar_one_or_none()
    if row is None or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Offer not found")
    if row.api_key_id != api_key.id:
        # Distinct audit action so we can grep for cross-tenant
        # access attempts; the response itself is identical to a
        # genuine 404 to avoid leaking existence.
        try:
            await log_action(
                db,
                api_key,
                "unauthorized_offer_access",
                "bolt12_offer",
                details={"offer_id": str(offer_id)},
                ip_address=(request.client.host if request is not None and request.client else None),
            )
            await db.commit()
        except Exception:  # noqa: BLE001 — audit must never block the 404
            logger.exception("failed to log unauthorized_offer_access")
        raise HTTPException(status_code=404, detail="Offer not found")
    return row


def _offer_summary(offer: Offer) -> dict[str, Any]:
    """Public-safe projection of a parsed offer for API responses."""
    return {
        "description": offer.description,
        "amount_msat": offer.amount,
        "currency": offer.currency,
        "issuer": offer.issuer,
        "issuer_id_hex": offer.issuer_id.hex() if offer.issuer_id else None,
        "quantity_max": offer.quantity_max,
        "absolute_expiry": offer.absolute_expiry,
    }


# ─── Endpoints ────────────────────────────────────────────────────────


@router.get("/status")
async def runtime_status(
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Diagnostic snapshot of the BOLT 12 runtime.

    Reports whether BOLT 12 is enabled in config, whether the
    gateway client + orchestrator are connected and dispatching, and
    the most recent startup/dispatch error if any. Available to any
    authenticated key — useful for ops dashboards.
    """
    from app.services.bolt12.runtime import get_bolt12_runtime_state

    state = get_bolt12_runtime_state()
    return {
        "enabled": state.enabled,
        "running": state.running,
        "target": state.target,
        "last_error": state.last_error,
        "last_probe_at": state.last_probe_at.isoformat() if state.last_probe_at else None,
        "last_probe_peer_count": state.last_probe_peer_count,
        "last_probe_node_id_hex": state.last_probe_node_id_hex,
        "consecutive_probe_failures": state.consecutive_probe_failures,
        "metrics": state.metrics,
        "permanently_disabled": state.permanently_disabled,
        "reconnect_count": state.reconnect_count,
        "last_inbound_mint_at": (state.last_inbound_mint_at.isoformat() if state.last_inbound_mint_at else None),
        "last_inbound_error": state.last_inbound_error,
        "last_inbound_error_at": (state.last_inbound_error_at.isoformat() if state.last_inbound_error_at else None),
        "node_address_cache_size": state.node_address_cache_size,
        "node_address_last_push_at": (
            state.node_address_last_push_at.isoformat() if state.node_address_last_push_at else None
        ),
        "node_address_last_push_accepted": state.node_address_last_push_accepted,
    }


# Counter help/type metadata mirroring the dataclass fields. Kept
# next to the endpoint so adding a counter requires touching one
# place. ``last_probe_peer_count`` and ``consecutive_probe_failures``
# are emitted as gauges (current point-in-time values).
_COUNTER_HELP: dict[str, str] = {
    "outbound_invreq_sent_total": "send_onion_message calls that returned successfully for an outbound invoice_request",
    "inbound_invoice_received_total": "Inbound stream messages dispatched as a paying-invoice reply",
    "inbound_invreq_received_total": "Inbound stream messages routed to the InvoiceResponder",
    "invoice_request_timeout_total": "request_invoice calls that exited via InvoiceRequestTimeoutError",
    "gateway_send_failure_total": "send_onion_message errors raised by the gateway client",
    "inbound_unmatched_total": "Inbound invoices that did not match any in-flight correlation token",
    "inbound_dropped_no_responder_total": "Inbound invreqs dropped because no responder is configured",
    "inbound_dropped_no_reply_path_total": "Inbound invreqs dropped because the gateway supplied no reply_path",
    "pending_capacity_exceeded_total": "request_invoice calls rejected because the in-flight cap was reached",
    "inbound_oversized_payload_total": "Inbound onion-message payloads dropped pre-decode for exceeding the size cap",
    "inbound_concurrent_mint_throttled_total": "Inbound invreqs dropped because the concurrent-mint semaphore was saturated",
    "inbound_rate_limit_drops_total": "Inbound invreqs dropped by the per-peer or global rate limiter",
    "inbound_invoice_replied_total": "Outbound invoice replies the gateway accepted for transmission",
    "inbound_adaptive_depth_flips_total": "Mints where the breaker triggered a retry at the alternative num_hops",
}


@router.get("/metrics", response_class=PlainTextResponse)
async def runtime_metrics(
    api_key: APIKey = Depends(get_api_key),
) -> str:
    """Prometheus text-format metrics for the BOLT 12 runtime.

    Exposes the same counters as ``/status`` but in
    ``text/plain; version=0.0.4`` exposition format suitable for a
    Prometheus scrape config. Counters share the ``bolt12_`` prefix
    and are emitted as ``# TYPE counter`` so PromQL ``rate()`` and
    ``increase()`` work as expected.
    """
    from app.services.bolt12.runtime import get_bolt12_runtime_state

    state = get_bolt12_runtime_state()
    lines: list[str] = []

    # Up gauge: 1 when runtime running, 0 otherwise. Standard idiom
    # so dashboards can detect process flap without parsing strings.
    lines.append("# HELP bolt12_runtime_up 1 if the BOLT 12 runtime is running, 0 otherwise")
    lines.append("# TYPE bolt12_runtime_up gauge")
    lines.append(f"bolt12_runtime_up {1 if state.running else 0}")

    lines.append("# HELP bolt12_runtime_enabled 1 if BOLT 12 is enabled in config")
    lines.append("# TYPE bolt12_runtime_enabled gauge")
    lines.append(f"bolt12_runtime_enabled {1 if state.enabled else 0}")

    lines.append("# HELP bolt12_consecutive_probe_failures Health-probe failure streak since last success")
    lines.append("# TYPE bolt12_consecutive_probe_failures gauge")
    lines.append(f"bolt12_consecutive_probe_failures {state.consecutive_probe_failures}")

    if state.last_probe_peer_count is not None:
        lines.append("# HELP bolt12_connected_peers Peers connected to the gateway at last probe")
        lines.append("# TYPE bolt12_connected_peers gauge")
        lines.append(f"bolt12_connected_peers {state.last_probe_peer_count}")

    metrics = state.metrics or {}
    for name, help_text in _COUNTER_HELP.items():
        value = int(metrics.get(name, 0))
        full = f"bolt12_{name}"
        lines.append(f"# HELP {full} {help_text}")
        lines.append(f"# TYPE {full} counter")
        lines.append(f"{full} {value}")

    return "\n".join(lines) + "\n"


@router.get("/diagnostics/path-snapshot")
async def diagnostics_path_snapshot(
    amount_msat: int = 3_345_000,
    api_key: APIKey = Depends(get_admin_key),
) -> Any:
    """Probe inspector for the BOLT 12 receive-path policy.

    Builds a snapshot of every open channel comparing the gossiped
    inbound ``max_htlc_msat`` (what payers' pathfinders see) against
    the live ``remote_balance`` (what we can actually receive).
    Optionally mints a probe blinded invoice at ``amount_msat`` and
    surfaces LND's chosen per-path policy alongside the channel
    drift table.

    Returned shape (truncated):

    .. code-block:: json

        {
          "amount_msat": 3345000,
          "our_pubkey": "02abc…",
          "channels": [
            {"chan_id":"…","peer_alias":"Megalithic backup",
             "capacity_sat":60000, "local_balance_sat":40000,
             "remote_balance_sat":20000,
             "gossiped_inbound_max_htlc_sat":60000,
             "ratio_advertised_to_receivable": 3.0}
          ],
          "blinded_paths": [
            {"intro_prefix":"02a98c","real_hops":2,
             "base_fee_msat":1000,"ppm":150,"cltv_delta":359,
             "htlc_min_msat":1000,"htlc_max_msat":60000000}
          ],
          "blinded_paths_error": null
        }

    Useful for confirming the over-claim hypothesis BEFORE the next
    payer attempt — no need to wait for the failure to recur.

    ``amount_msat`` defaults to 3,345,000 msat (a typical Ocean
    payout) but operators can pass any in-bounds value.
    """
    from app.services.bolt12.path_diagnostics import (
        collect_channel_drift_snapshot,
    )
    from app.services.lnd_service import lnd_service

    if amount_msat <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="amount_msat must be > 0",
        )

    rows = await collect_channel_drift_snapshot(lnd_service)
    info, _ = await lnd_service.get_info()
    our_pubkey = info.get("identity_pubkey", "") if isinstance(info, dict) else ""

    # Probe mint to inspect what LND would advertise NOW. This is a
    # read-only inspection: the invoice is built, decoded, and
    # discarded — no peer reply, no DB persistence.
    blinded_paths_summary: list[dict] = []
    blinded_paths_error: str | None = None
    try:
        primary_num_hops = max(1, settings.bolt12_blinded_path_min_real_hops)
        max_num_paths = max(1, min(8, settings.bolt12_blinded_path_max_paths))
        omit_pubkeys = settings.bolt12_blinded_path_omit_pubkeys
        probe_result, probe_err = await lnd_service.add_blinded_invoice(
            amount_msat,
            memo="bolt12-diagnostics-probe",
            expiry=60,  # short — this is throwaway
            num_hops=primary_num_hops,
            max_num_paths=max_num_paths,
            node_omission_pubkeys=omit_pubkeys,
        )
        if probe_err is not None or probe_result is None:
            blinded_paths_error = probe_err or "add_blinded_invoice returned no result"
        else:
            blinded_paths_summary = _summarise_blinded_paths(probe_result.get("blinded_paths") or [])
            # Best-effort: cancel the probe so the r_hash slot is
            # released. If cancel isn't supported by this LND
            # build, the invoice will expire naturally in 60 s.
            r_hash = probe_result.get("r_hash") or ""
            if r_hash:
                try:
                    await lnd_service.cancel_invoice(r_hash)
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "bolt12 diagnostics: probe cancel_invoice failed (invoice will expire naturally)",
                    )
    except Exception as exc:  # noqa: BLE001
        blinded_paths_error = f"{type(exc).__name__}: {exc}"

    return {
        "amount_msat": amount_msat,
        "our_pubkey": our_pubkey,
        "drift_alert_ratio": settings.bolt12_htlc_max_drift_ratio_alert,
        "channels": [r.to_dict() for r in rows],
        "blinded_paths": blinded_paths_summary,
        "blinded_paths_error": blinded_paths_error,
    }


def _summarise_blinded_paths(lnd_paths: list) -> list[dict]:
    """Extract the per-path policy fields from LND's
    ``add_blinded_invoice`` response in the same shape used by the
    Item-3 INFO log line — so operators get one canonical view of
    LND-chosen path state."""
    import base64 as _b64

    summary: list[dict] = []
    for bp in lnd_paths:
        if not isinstance(bp, dict):
            continue
        inner = bp.get("blinded_path") if isinstance(bp.get("blinded_path"), dict) else {}
        intro_b64 = inner.get("introduction_node", "") if isinstance(inner, dict) else ""
        try:
            intro_prefix = _b64.b64decode(intro_b64)[:8].hex() if intro_b64 else None
        except (ValueError, TypeError):
            intro_prefix = None
        blinded_hops = inner.get("blinded_hops") if isinstance(inner, dict) else None
        real_hops = max(0, len(blinded_hops or []) - 1)
        summary.append(
            {
                "intro_prefix": intro_prefix,
                "real_hops": real_hops,
                "base_fee_msat": bp.get("base_fee_msat"),
                "ppm": bp.get("proportional_fee_rate"),
                "cltv_delta": bp.get("total_cltv_delta"),
                "htlc_min_msat": bp.get("htlc_min_msat"),
                "htlc_max_msat": bp.get("htlc_max_msat"),
            }
        )
    return summary


@router.post("/decode")
async def decode_offer(
    req: DecodeOfferRequest,
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Decode a BOLT 12 offer string.

    Read-only. Available to any authenticated key. Does not touch
    the database — purely codec-level.
    """
    offer = _decode_offer_or_400(req.offer)
    return {"offer": req.offer, **_offer_summary(offer)}


@router.post("/offers", status_code=201)
async def import_offer(
    req: ImportOfferRequest,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Persist a BOLT 12 offer for tracking.

    Idempotent on ``bolt12``: re-importing the same string returns
    the existing row (200) instead of inserting a duplicate. New
    rows are returned with 201.
    """
    parsed = _decode_offer_or_400(req.offer)

    # Idempotent insert: the unique constraint on ``bolt12`` means a
    # second import would 23505 at the DB level; we check first so
    # we can return the existing row cleanly.
    existing = (await db.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == req.offer))).scalar_one_or_none()
    if existing is not None:
        # Idempotent re-import — already present, signal with 200.
        return JSONResponse(
            status_code=200,
            content=OfferResponse.from_orm_row(existing).model_dump(mode="json"),
        )

    row = Bolt12Offer(
        api_key_id=api_key.id,
        bolt12=req.offer,
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

    await log_action(
        db,
        api_key,
        "import_offer",
        "bolt12_offer",
        details={"offer_id": str(row.id)},
        ip_address=request.client.host if request.client else None,
    )
    return OfferResponse.from_orm_row(row).model_dump(mode="json")


class IssueOfferRequest(BaseModel):
    """Mint a new BOLT 12 offer signed by this wallet's LND identity.

    The wallet's LND node-id is used as ``offer_issuer_id``. The
    resulting bech32 string is suitable for sharing as a QR code or
    via BIP-353. A fresh 16-byte ``offer_metadata`` is generated for
    every issued offer to guarantee uniqueness against the
    ``bolt12_offers.bolt12`` UNIQUE constraint.

    Sender flows requiring blinded ``offer_paths`` (recipient privacy)
    require the recipient to be onion-message-reachable at
    ``offer_issuer_id`` directly.
    """

    description: str = Field(..., min_length=1, max_length=640)
    amount_msat: Optional[int] = Field(default=None, ge=1, le=21_000_000 * 100_000_000 * 1_000)
    currency: Optional[str] = Field(default=None, max_length=8)
    issuer: Optional[str] = Field(default=None, max_length=256)
    quantity_max: Optional[int] = Field(default=None, ge=1)
    absolute_expiry: Optional[int] = Field(
        default=None,
        ge=1,
        description="Unix-seconds expiry; offer is unusable past this time.",
    )

    @field_validator("description", "issuer")
    @classmethod
    def _strip(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v

    @field_validator("currency")
    @classmethod
    def _ascii_currency(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().upper()
        if not v.isascii() or not v.isalpha():
            raise ValueError("currency must be ASCII letters only (e.g. 'USD')")
        return v


@router.post("/offers/issue", status_code=201)
async def issue_offer(
    req: IssueOfferRequest,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Mint and persist a new BOLT 12 offer signed by this wallet.

    Pulls the LND node identity to use as ``offer_issuer_id``,
    constructs an :class:`Offer` with the caller-supplied fields
    plus a fresh 16-byte ``metadata`` for uniqueness, encodes it
    into the canonical ``lno1…`` bech32 string, and stores it.

    The offer is signed with a fresh wallet-side BIP-340 issuer
    key, generated per offer. The 32-byte private seed is
    Fernet-encrypted at rest in ``encrypted_metadata`` and reloaded
    by the inbound responder when minting invoices for this offer.
    Decoupling the issuer key from the LND identity keeps every
    offer's payee identity unlinkable across receipts (BOLT 12 §1.3
    privacy goal).

    Failure modes:

    * **500** — codec/encoding error (should be impossible with
      validated inputs; surfaces as 500 to make the bug visible).
    """
    return await _perform_issue_offer(
        req,
        api_key=api_key,
        db=db,
        ip=request.client.host if request.client else None,
    )


def _is_publicly_routable_peer_address(addr: str) -> bool:
    """Heuristic: would a public-network payer be able to reach this
    socket address?

    The BOLT 12 gateway records each peer's ``socket_address`` as the
    address it dialled (or accepted). For introduction-node purposes
    a peer is only useful if **public** payers — CLN, LND, etc., with
    no Tor egress — can connect to it. The cheap proxy for that is
    "the address isn't a ``.onion`` hidden service". Empty addresses
    (LDK records ``None`` as empty here) fail the same check; we
    have no way to reach a peer whose address we never recorded.

    Caveat: a peer we dialled via Tor might still publish clearnet
    addresses in its gossip ``node_announcement`` that public payers
    can use. The gateway's ``NetworkGraph`` is deliberately empty
    (we don't consume gossip), so we can't see those. This filter
    therefore has false negatives — it may exclude peers that are in
    fact publicly routable. The tradeoff is worth it: every false
    negative just means we pick a different (still onion-message-
    capable) peer or surface the dashboard hint; every false positive
    (advertising a Tor-only peer as an introduction node) silently
    breaks every BOLT 12 payout from a public payer.
    """
    if not addr:
        return False
    # LDK ``SocketAddress::Display`` always emits ``host:port`` and
    # wraps IPv6 in brackets. ``rsplit`` on the last colon peels the
    # port off cleanly for every variant.
    host = addr.rsplit(":", 1)[0]
    return not host.lower().endswith(".onion")


async def _refresh_sticky_peers_post_default_change() -> None:
    """Trigger an out-of-band sticky-peer refresh so a state change
    to a default-receive offer takes effect on the gateway right
    away.

    Best-effort + bounded: a misbehaving reconciler must never break
    an offer-mint response. Runs inline rather than as a fire-and-
    forget task so concurrent test assertions can observe the
    post-refresh state.
    """
    try:
        from app.services.bolt12.sticky_peer_reconciler import (
            refresh_sticky_set,
        )

        await refresh_sticky_set()
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12: sticky-peer refresh after default-receive change failed; the next periodic tick will catch up"
        )


def _min_real_hops_override_for_description(
    description: Optional[str],
) -> Optional[int]:
    """Compute the ``min_real_hops_override`` value to stamp on a
    newly-issued offer based on whether its description matches a
    well-known payer with ``requires_privacy=False``.

    Returns ``1`` for non-privacy-sensitive payers (Ocean) — a
    1-real-hop blinded path eliminates the intermediate hop where
    the 2026-06-06 Ocean failure occurred.

    Returns ``None`` for privacy-sensitive payers AND for offers
    that don't match any known payer (the default ``min_real_hops``
    setting applies).
    """
    if not description:
        return None
    payer = match_well_known_payer(
        description,
        network=settings.bitcoin_network,
    )
    if payer is None:
        return None
    if getattr(payer, "requires_privacy", True):
        return None
    return 1


async def _maybe_auto_peer_for_description(description: Optional[str]) -> None:
    """Proactively dial a well-known payer's LN node when the offer
    description signals it'll be paid by that payer.

    See :mod:`app.services.bolt12.well_known_payers` for the registry
    and the OCEAN-payouts background.

    Best-effort: every error path logs a warning and returns. The
    surrounding offer creation must continue regardless — a failed
    auto-peer at worst means the offer is issued with the existing
    candidate set (which may already be sufficient if the gateway is
    peered with another reachable onion-message-capable node).
    """
    if not settings.bolt12_auto_peer_well_known_payers:
        return
    payer = match_well_known_payer(
        description,
        network=settings.bitcoin_network,
    )
    if payer is None:
        return
    await _connect_well_known_payer(payer)


# Bounded wait after auto-peer for the BOLT 1 init handshake to
# complete. ``connect_peer`` returns as soon as the TCP+Noise
# connection is up; the feature-bit exchange (which decides whether
# the peer advertises onion messages — bits 38/39) happens a few
# hundred ms later. Without waiting, the next ``get_identity()``
# call inside the same request may see the peer with
# ``advertises_onion_messages=False`` (or not at all), which leaves
# ``_build_offer_paths_for_issuance`` skipping it as an introduction
# candidate AND surfaces the stale "no peer supports BOLT 12
# routing" warning on the receive panel. A 5 s budget is generous
# for a healthy clearnet handshake while still keeping the API
# request snappy for genuinely uncooperative peers.
_AUTO_PEER_HANDSHAKE_WAIT_S = 5.0
_AUTO_PEER_POLL_INTERVAL_S = 0.25


async def _wait_for_om_capable_peer(
    service: Any,
    node_id: bytes,
    *,
    timeout_s: float = _AUTO_PEER_HANDSHAKE_WAIT_S,
    poll_interval_s: float = _AUTO_PEER_POLL_INTERVAL_S,
) -> bool:
    """Poll the gateway's peer list until ``node_id`` appears with
    ``advertises_onion_messages=True``, or the timeout elapses.

    Returns ``True`` when the peer was observed OM-capable. Returns
    ``False`` on timeout — the caller can still proceed (the offer
    will be issued without ``offer_paths``, and the receive panel
    warning will surface), but at least the request waited long
    enough that a healthy peer's init handshake had a chance to land.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ident = await service._gateway.get_identity()  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return False
        for p in ident.peers:
            if p.node_id == node_id and p.advertises_onion_messages:
                return True
        await asyncio.sleep(poll_interval_s)
    return False


async def _connect_well_known_payer(payer: WellKnownPayer) -> None:
    """Dial ``payer``'s LN node via the BOLT 12 gateway.

    Idempotent — the gateway's ``ConnectPeer`` returns
    ``already_connected=True`` when we're already peered, so calling
    this on every matching offer creation is cheap. Never raises.
    """
    try:
        service = get_bolt12_service()
    except HTTPException:
        logger.warning(
            "bolt12 issue: gateway runtime not running; skipping auto-peer with %s (%s)",
            payer.label,
            payer.node_id_hex,
        )
        return
    try:
        node_id = bytes.fromhex(payer.node_id_hex)
    except ValueError:
        logger.warning(
            "bolt12 issue: %s well-known payer node_id_hex is not valid hex (%r); auto-peer skipped",
            payer.label,
            payer.node_id_hex,
        )
        return
    if len(node_id) != 33:
        logger.warning(
            "bolt12 issue: %s well-known payer node_id must decode to 33 bytes (got %d); auto-peer skipped",
            payer.label,
            len(node_id),
        )
        return
    if not payer.address:
        logger.warning(
            "bolt12 issue: %s well-known payer address is empty; auto-peer skipped",
            payer.label,
        )
        return
    try:
        result = await service._gateway.connect_peer(  # noqa: SLF001
            node_id=node_id,
            address=payer.address,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "bolt12 issue: auto-peer with %s (%s@%s) failed (%s) — "
            "offer will be issued anyway and may still route via another "
            "introduction node",
            payer.label,
            payer.node_id_hex,
            payer.address,
            exc,
        )
        return
    if result.already_connected:
        logger.info(
            "bolt12 issue: %s peer (%s) already connected; auto-peer is a no-op",
            payer.label,
            payer.node_id_hex,
        )
    else:
        logger.info(
            "bolt12 issue: dialed %s peer (%s@%s) for offer issuance",
            payer.label,
            payer.node_id_hex,
            payer.address,
        )

    # Wait for the BOLT 1 init handshake to complete so the peer
    # shows up in subsequent ``get_identity`` calls as OM-capable.
    # Skipping this lets the downstream offer-path builder + receive
    # panel warning observe a stale "no OM peers" state even though
    # the dial just succeeded — the symptom users see as "I just
    # configured an OCEAN offer and the no-peer warning is still
    # there". For already-connected peers the handshake is long done,
    # so the first poll returns immediately.
    ok = await _wait_for_om_capable_peer(service, node_id)
    if not ok:
        logger.warning(
            "bolt12 issue: %s peer (%s) did not advertise onion "
            "messages within %.1fs — receive panel may surface a "
            "stale 'no OM peer' warning until the handshake "
            "completes",
            payer.label,
            payer.node_id_hex,
            _AUTO_PEER_HANDSHAKE_WAIT_S,
        )


async def _build_offer_paths_for_issuance() -> Optional[bytes]:
    """Build the ``offer_paths`` value (TLV 16) for a newly-issued offer.

    BOLT 12 §"Sending an invoice_request": when an offer carries
    ``offer_paths``, the payer MUST route the ``invoice_request``
    onion message through one of the listed blinded paths' introduction
    nodes. When ``offer_paths`` is absent, the payer falls back to
    direct routing to ``offer_node_id`` (the offer's issuer_id).

    Our architecture (Option E with an LDK-based onion-message
    gateway) uses a **fresh per-offer ephemeral key** as
    ``issuer_id``. That key is NOT advertised in the public gossip
    graph — there's no LN node behind it. A payer that tries to fall
    back to direct routing therefore fails with "no address known for
    peer" (this is the symptom OCEAN's payouts report). Every issued
    offer MUST carry ``offer_paths`` pointing at a real,
    gossip-advertised onion-message-capable peer of the gateway.

    Returns the serialized BlindedPath bytes (already in the wire
    format used as ``offer_paths``'s value — a concatenation of
    BlindedPath subtypes; one entry here is sufficient). Returns
    ``None`` when no path is available, in which case the caller
    issues a direct offer + logs a clear warning. Direct offers are
    only useful in test/regtest where the issuer_id is reachable.
    """
    try:
        service = get_bolt12_service()  # 503 if runtime not running
    except HTTPException:
        logger.warning(
            "bolt12 issue: gateway runtime not running; issuing offer WITHOUT offer_paths (direct routing only)"
        )
        return None

    try:
        ident = await service._gateway.get_identity()  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "bolt12 issue: gateway get_identity failed (%s); issuing offer WITHOUT offer_paths",
            exc,
        )
        return None

    # Filter on three properties:
    # 1. ``advertises_onion_messages`` — peer negotiated the BOLT 1
    #    onion-message feature; required for the path to carry
    #    invoice_request traffic at all.
    # 2. ``_is_publicly_routable_peer_address`` — peer's recorded
    #    socket address isn't ``.onion`` and isn't empty. Without
    #    this, public payers (e.g. OCEAN's CLN) error with "no
    #    address known for peer" before they can attempt the route.
    # 3. NOT in ``well_known_payer_node_ids`` — a well-known payer's
    #    own node is kept as a peer for inbound reachability, but
    #    must never be used as the introduction node for an offer
    #    that payer will pay. The original OCEAN failure
    #    ("no address known for peer 029ef2…") was exactly this
    #    case: we picked OCEAN's own well-known node as the intro
    #    and OCEAN's payouts node had no usable address for it.
    om_capable = tuple(p for p in ident.peers if p.advertises_onion_messages)
    payer_nids = well_known_payer_node_ids(network=settings.bitcoin_network)
    boot_nids = bootstrap_om_peer_node_ids(network=settings.bitcoin_network)
    routable = tuple(
        p for p in om_capable if _is_publicly_routable_peer_address(p.address) and p.node_id not in payer_nids
    )
    # Rank bootstrap peers first so the gateway picks them as intro
    # when LDK has a free choice. The gateway treats the candidate
    # list as a preference order on the few candidates whose
    # ``next_hop`` ranks equally — putting bootstrap peers first
    # therefore biases the intro choice toward universally-gossiped
    # nodes without removing the others as fallback.
    candidates = tuple(p.node_id for p in routable if p.node_id in boot_nids) + tuple(
        p.node_id for p in routable if p.node_id not in boot_nids
    )
    if not candidates:
        # Distinguish the failure modes in logs so an operator
        # debugging an unreachable offer immediately knows which
        # invariant broke.
        if not om_capable:
            logger.warning(
                "bolt12 issue: gateway has no onion-message-capable peers; "
                "issuing offer WITHOUT offer_paths — payers will be unable "
                "to reach the per-offer issuer_id"
            )
        else:
            excluded_as_payer = [p.node_id.hex() for p in om_capable if p.node_id in payer_nids]
            tor_only = [
                p.node_id.hex()
                for p in om_capable
                if not _is_publicly_routable_peer_address(p.address) and p.node_id not in payer_nids
            ]
            logger.warning(
                "bolt12 issue: no usable introduction-node candidates "
                "(om_capable=%d, excluded_as_well_known_payer=%s, "
                "tor_only=%s); issuing offer WITHOUT offer_paths — "
                "public payers will be unable to reach the introduction "
                "node. Connect an OM-capable peer with a clearnet address "
                "to fix.",
                len(om_capable),
                excluded_as_payer or "[]",
                tor_only or "[]",
            )
        return None

    try:
        path_bytes = await service._gateway.create_blinded_path(  # noqa: SLF001
            introduction_node_candidates=candidates,
            # ``context`` is opaque per-path metadata. The responder
            # currently identifies offers by ``offer_issuer_id`` (set
            # inside the invreq by the payer per BOLT 12), so an empty
            # context here is fine — the offer→responder binding is
            # carried elsewhere.
            context=b"",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "bolt12 issue: create_blinded_path failed (%s); issuing offer WITHOUT offer_paths",
            exc,
        )
        return None
    return path_bytes


async def _perform_issue_offer(
    req: IssueOfferRequest,
    *,
    api_key: APIKey,
    db: AsyncSession,
    ip: Optional[str],
) -> Any:
    """Core issue-offer logic shared by the public + dashboard routes.

    The dashboard variant calls this with its sentinel ``APIKey`` row
    so audit + ownership land under the dashboard actor.
    """
    issuer_signer = CoincurveSigner.generate()
    issuer_id = issuer_signer.public_key

    # Advertise offer_chains explicitly on non-mainnet networks so
    # senders know the offer is testnet/signet/regtest. Per BOLT 12
    # an absent offer_chains is shorthand for "mainnet only".
    our_chain = chain_hash_for(settings.bitcoin_network)
    offer_chains: tuple[bytes, ...] = () if our_chain == MAINNET_CHAIN_HASH else (our_chain,)

    # Embed a blinded ``offer_paths`` so payers can reach us through
    # a gossiped onion-message-capable peer of the gateway. Without
    # this the per-offer ``issuer_id`` is the only routing handle, and
    # because that key is never gossiped a payer's CLN/LND will
    # report "no address known for peer" and abort (this is OCEAN's
    # observed failure mode).
    #
    # Auto-peer with the well-known payer (if any) BEFORE building the
    # paths so the newly-dialed peer shows up in the candidate set the
    # path builder queries from the gateway.
    await _maybe_auto_peer_for_description(req.description)
    offer_paths = await _build_offer_paths_for_issuance()

    offer_obj = Offer(
        chains=offer_chains,
        description=req.description,
        amount=req.amount_msat,
        currency=req.currency,
        issuer=req.issuer,
        quantity_max=req.quantity_max,
        absolute_expiry=req.absolute_expiry,
        issuer_id=issuer_id,
        paths=offer_paths,
        # 16 bytes of randomness — guarantees the encoded string is
        # globally unique even when other fields collide.
        metadata=secrets.token_bytes(16),
    )
    try:
        bolt12_str = encode_bolt12(offer_obj.to_bolt12_string())
    except Bolt12Error as exc:
        logger.exception("BOLT 12 encode failed for issued offer")
        raise HTTPException(status_code=500, detail=f"Failed to encode offer: {exc}") from exc

    row = Bolt12Offer(
        api_key_id=api_key.id,
        bolt12=bolt12_str,
        description=req.description,
        amount_msat=req.amount_msat,
        currency=req.currency,
        issuer=req.issuer,
        issuer_id_hex=issuer_id.hex(),
        quantity_max=req.quantity_max,
        source=Bolt12OfferSource.ISSUED,
        # Encrypted issuer signing seed — decrypted only when the
        # inbound responder needs to sign a fresh invoice mirroring
        # an inbound invreq for this offer.
        encrypted_metadata=encrypt_field(issuer_signer.secret.hex()),
        # Fix #3 (2026-06-06): auto-set 1-real-hop override for
        # offers issued to non-privacy-sensitive well-known payers
        # (Ocean today). Sets the override that the responder
        # reads at mint time.
        min_real_hops_override=_min_real_hops_override_for_description(
            req.description,
        ),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    await log_action(
        db,
        api_key,
        "issue_offer",
        "bolt12_offer",
        details={"offer_id": str(row.id), "amount_msat": req.amount_msat},
        ip_address=ip,
    )
    return OfferResponse.from_orm_row(row).model_dump(mode="json")


# ─── Default "receive" offer ──────────────────────────────────────────


# Description used when auto-minting the default receive offer
# on first GET. Phrased so users immediately recognise the panel
# and feel nudged to click "Configure" if their payer (e.g. the
# Ocean mining pool) requires a specific description format.
_DEFAULT_RECEIVE_DESCRIPTION = "Receive offer (configure for your payer)"

# Maximum length we accept on the configure endpoint. Mirrors
# ``IssueOfferRequest.description`` so the same validation applies.
_MAX_RECEIVE_DESCRIPTION_LEN = 640


# Inbound liquidity below this threshold is flagged as a likely
# cause of payout failures. Configurable via
# ``BOLT12_RECEIVE_INBOUND_WARN_SATS`` (see ``app.core.config``);
# default is conservative (1k sats) since mining-pool payouts for
# small ASICs are typically <1k sats and a high threshold would
# surface a perpetually-noisy warning. Set to 0 to disable.
def _inbound_liquidity_warn_sats() -> int:
    try:
        return max(0, int(settings.bolt12_receive_inbound_warn_sats))
    except (TypeError, ValueError):
        return 1_000


async def _mint_default_receive_offer(
    *,
    description: str,
    api_key: APIKey,
    db: AsyncSession,
    ip: Optional[str],
    audit_action: str = "issue_default_receive_offer",
    commit: bool = True,
) -> Bolt12Offer:
    """Mint a fresh BOLT 12 offer flagged as the default receive offer.

    The caller must already have demoted any existing default in the
    same DB session — this function does *not* clear the flag itself,
    so callers can wrap mint + demote in a single transaction.

    When ``commit=False`` the row is added + flushed but **not**
    committed; the caller is responsible for the surrounding
    transaction boundary. The audit row is also deferred to the
    caller's commit so demote + mint + audit land atomically.
    """
    issuer_signer = CoincurveSigner.generate()
    issuer_id = issuer_signer.public_key
    our_chain = chain_hash_for(settings.bitcoin_network)
    offer_chains: tuple[bytes, ...] = () if our_chain == MAINNET_CHAIN_HASH else (our_chain,)
    # See :func:`_build_offer_paths_for_issuance` for the rationale —
    # without ``offer_paths`` the default receive offer is unreachable
    # from any sender that requires a gossiped introduction node
    # (CLN, LND-with-onion-message-routing). OCEAN payouts in
    # particular hit this — they refuse with "no address known for
    # peer" when ``offer_paths`` is missing.
    #
    # Auto-peer with the well-known payer (if any) BEFORE building the
    # paths so the newly-dialed peer shows up in the candidate set the
    # path builder queries from the gateway.
    await _maybe_auto_peer_for_description(description)
    offer_paths = await _build_offer_paths_for_issuance()
    offer_obj = Offer(
        chains=offer_chains,
        description=description,
        amount=None,
        currency=None,
        issuer=None,
        quantity_max=None,
        absolute_expiry=None,
        issuer_id=issuer_id,
        paths=offer_paths,
        metadata=secrets.token_bytes(16),
    )
    try:
        bolt12_str = encode_bolt12(offer_obj.to_bolt12_string())
    except Bolt12Error as exc:
        logger.exception("BOLT 12 encode failed for default receive offer")
        raise HTTPException(status_code=500, detail=f"Failed to encode offer: {exc}") from exc
    row = Bolt12Offer(
        api_key_id=api_key.id,
        bolt12=bolt12_str,
        description=description,
        amount_msat=None,
        currency=None,
        issuer=None,
        issuer_id_hex=issuer_id.hex(),
        quantity_max=None,
        source=Bolt12OfferSource.ISSUED,
        is_default_receive=True,
        encrypted_metadata=encrypt_field(issuer_signer.secret.hex()),
        # Fix #3 (2026-06-06): see comment in /offers/issue site.
        min_real_hops_override=_min_real_hops_override_for_description(
            description,
        ),
    )
    db.add(row)
    if commit:
        await db.commit()
        await db.refresh(row)
    else:
        await db.flush()

    await log_action(
        db,
        api_key,
        audit_action,
        "bolt12_offer",
        details={"offer_id": str(row.id), "description": description},
        ip_address=ip,
    )
    return row


async def _get_or_create_default_receive(
    *,
    api_key: APIKey,
    db: AsyncSession,
    ip: Optional[str],
) -> Bolt12Offer:
    """Return the API key's default receive offer, minting one on first call.

    Used by both the public ``GET /v1/bolt12/receive`` route and the
    dashboard wrapper. The auto-mint path uses
    :data:`_DEFAULT_RECEIVE_DESCRIPTION`; users with a payer-specific
    description requirement (e.g. the Ocean mining pool) should call
    ``POST /v1/bolt12/receive/configure`` to mint a replacement with
    the correct description.

    Concurrency: the SELECT-then-INSERT pattern is racy under
    concurrent callers (browser tab opened twice, retry after slow
    proxy, dashboard auto-refresh racing with manual refresh). The
    partial unique index ``uq_bolt12_offers_default_receive_per_key``
    guarantees at most one default per key; we recover from a lost
    race via a single optimistic retry that re-reads and returns the
    winning row.
    """
    select_existing = (
        select(Bolt12Offer)
        .where(
            Bolt12Offer.api_key_id == api_key.id,
            Bolt12Offer.is_default_receive.is_(True),
            Bolt12Offer.deleted_at.is_(None),
        )
        .limit(1)
    )

    existing = (await db.execute(select_existing)).scalar_one_or_none()
    if existing is not None:
        # Auto-revive a default that was somehow disabled — operators
        # who hit "disable" on their default offer almost certainly
        # didn't mean to nuke their receive address.
        if existing.status != Bolt12OfferStatus.ACTIVE:
            existing.status = Bolt12OfferStatus.ACTIVE
            await db.commit()
            await db.refresh(existing)
            # Status flipped back to ACTIVE — the offer is back in
            # the reconciler's desired-set query result, so any
            # well-known payer it points at should re-enter the
            # sticky set immediately.
            await _refresh_sticky_peers_post_default_change()
        return existing

    try:
        row = await _mint_default_receive_offer(
            description=_DEFAULT_RECEIVE_DESCRIPTION,
            api_key=api_key,
            db=db,
            ip=ip,
        )
    except IntegrityError:
        # Lost the race: another concurrent caller (or proxy retry)
        # minted the default first and tripped the partial unique
        # index. Roll back our INSERT and return the winning row.
        await db.rollback()
        winner = (await db.execute(select_existing)).scalar_one_or_none()
        if winner is None:
            # Should be impossible: an IntegrityError on the partial
            # unique index implies a competing row exists. Surface
            # as 500 rather than infinite-looping.
            raise
        return winner

    # Auto-mint default uses the generic
    # ``_DEFAULT_RECEIVE_DESCRIPTION`` which won't match any
    # well-known payer prefix today, so this refresh will normally
    # be a no-op push of an empty set. Still call it for parity with
    # the other default-change paths so future registry additions
    # are picked up without extra wiring.
    await _refresh_sticky_peers_post_default_change()
    return row


async def _reconfigure_default_receive(
    *,
    description: str,
    api_key: APIKey,
    db: AsyncSession,
    ip: Optional[str],
) -> Bolt12Offer:
    """Mint a new default receive offer with a payer-specific description.

    BOLT 12 offers are immutable — the description is part of the
    signed bech32 string — so "editing" the description means minting
    a brand-new offer and demoting the previous default. The previous
    default is kept as a non-default ``ISSUED`` row so historical
    invoice/invreq references render correctly and the user can
    re-promote it later if needed.

    Demote + mint + audit land in a **single transaction** so a
    crash/restart between the two writes can never wedge a tenant
    into the "no default offer" black hole.
    """
    description = description.strip()
    if not description:
        raise HTTPException(status_code=422, detail="description must not be empty")
    if len(description) > _MAX_RECEIVE_DESCRIPTION_LEN:
        raise HTTPException(
            status_code=422,
            detail=f"description must be \u2264 {_MAX_RECEIVE_DESCRIPTION_LEN} characters",
        )

    # Demote the current default (if any) and mint the replacement
    # in a single commit boundary. The partial unique index is
    # checked at COMMIT time only, so both writes succeed or fail
    # atomically. A concurrent /configure caller racing with us
    # will trip the unique index here; we recover by re-reading the
    # winning row and returning it (last-writer-wins is acceptable
    # \u2014 both callers chose "configure to whatever I want").
    try:
        await db.execute(
            update(Bolt12Offer)
            .where(
                Bolt12Offer.api_key_id == api_key.id,
                Bolt12Offer.is_default_receive.is_(True),
            )
            .values(is_default_receive=False)
        )
        row = await _mint_default_receive_offer(
            description=description,
            api_key=api_key,
            db=db,
            ip=ip,
            audit_action="reconfigure_default_receive_offer",
            commit=False,
        )
        await db.commit()
        await db.refresh(row)
    except IntegrityError:
        await db.rollback()
        # Conflict with a concurrent /configure or auto-mint;
        # surface as 409 so clients retry with their preferred
        # description if needed.
        raise HTTPException(
            status_code=409,
            detail="Default receive offer was modified by another request; please retry",
        )

    # Refresh the gateway's sticky-peer set so the freshly-configured
    # well-known payer (if any) becomes sticky immediately — without
    # this, the on-disconnect reconnect loop wouldn't watch the new
    # peer until the next periodic reconciler tick (up to 30 s).
    await _refresh_sticky_peers_post_default_change()
    return row


async def _set_default_receive(
    offer_id: UUID,
    *,
    api_key: APIKey,
    db: AsyncSession,
    ip: Optional[str],
) -> Bolt12Offer:
    """Promote an existing offer to be the API key's default receive offer.

    Clears the previous default for the same API key (if any) before
    flipping the new one. Both writes happen in the same transaction
    so the partial unique index in migration 012 cannot trip.
    """
    # Loads the row + enforces ownership in one shot. Cross-tenant
    # callers see a 404, identical to a genuine miss — no enumeration.
    row = await _require_offer_owner(offer_id, api_key, db)
    if row.source != Bolt12OfferSource.ISSUED:
        raise HTTPException(
            status_code=400,
            detail="Only offers issued by this wallet can be the default receive offer",
        )

    # Clear the previous default for this key.
    await db.execute(
        update(Bolt12Offer)
        .where(
            Bolt12Offer.api_key_id == api_key.id,
            Bolt12Offer.is_default_receive.is_(True),
            Bolt12Offer.id != row.id,
        )
        .values(is_default_receive=False)
    )
    row.is_default_receive = True
    if row.status != Bolt12OfferStatus.ACTIVE:
        row.status = Bolt12OfferStatus.ACTIVE
    await db.commit()
    await db.refresh(row)

    await log_action(
        db,
        api_key,
        "set_default_receive_offer",
        "bolt12_offer",
        details={"offer_id": str(row.id)},
        ip_address=ip,
    )

    # The promoted offer's description may match a well-known payer
    # that the demoted offer didn't — refresh so the sticky set
    # reflects the new default immediately.
    await _refresh_sticky_peers_post_default_change()
    return row


async def _build_receive_panel_payload(
    offer: Bolt12Offer,
) -> dict[str, Any]:
    """Wrap an offer with liquidity + gateway-runtime context for the dashboard.

    Both side-channels are best-effort:

    * If LND is unreachable we omit the liquidity numbers but still
      return the offer — the user can still copy the bech32 string.
    * If the runtime state can't be read we mark the runtime as
      ``unknown``; the dashboard renders that as a neutral banner.

    The point is to give the receive panel everything it needs in one
    round-trip so the UI can render fully on first load.
    """
    payload: dict[str, Any] = {
        "offer": OfferResponse.from_orm_row(offer).model_dump(mode="json"),
        "inbound_liquidity": None,
        "runtime": None,
        "warnings": [],
    }

    # Best-effort LND inbound capacity probe.
    try:
        from app.services.lnd_service import lnd_service  # avoid import cycles

        balance, err = await lnd_service.get_channel_balance()
    except Exception:  # noqa: BLE001 — LND can fail in many ways; never break /receive
        logger.exception("BOLT 12 receive panel: get_channel_balance crashed")
        balance, err = None, "lnd unreachable"
    if balance is not None:
        remote_sat = int(balance.get("remote_balance_sat", 0))
        warn_threshold = _inbound_liquidity_warn_sats()
        payload["inbound_liquidity"] = {
            "remote_balance_sat": remote_sat,
            "warn_threshold_sat": warn_threshold,
            "low": warn_threshold > 0 and remote_sat < warn_threshold,
        }
        if warn_threshold > 0 and remote_sat < warn_threshold:
            payload["warnings"].append(
                {
                    "code": "low_inbound_liquidity",
                    "message": (
                        f"Inbound capacity is only {remote_sat:,} sats. "
                        "Payouts larger than this will fail. Open a channel "
                        "or request inbound liquidity before sharing this offer."
                    ),
                }
            )
    elif err:
        payload["warnings"].append(
            {
                "code": "lnd_unreachable",
                "message": f"Could not check inbound liquidity: {err}",
            }
        )

    # Best-effort BOLT 12 runtime snapshot.
    try:
        from app.services.bolt12.runtime import get_bolt12_runtime_state

        state = get_bolt12_runtime_state()
        payload["runtime"] = {
            "enabled": state.enabled,
            "running": state.running,
            "consecutive_probe_failures": state.consecutive_probe_failures,
            "last_probe_at": (state.last_probe_at.isoformat() if state.last_probe_at else None),
            "last_error": state.last_error,
        }
        if state.enabled and not state.running:
            payload["warnings"].append(
                {
                    "code": "gateway_offline",
                    "message": (
                        "The BOLT 12 gateway is offline. The wallet will "
                        "automatically reconnect when it comes back; "
                        "inbound payouts queued by payers may still be "
                        "delivered, but new ones will fail until the "
                        "gateway is reachable."
                        if not state.permanently_disabled
                        else "The BOLT 12 gateway is misconfigured (see "
                        "wallet logs / /v1/bolt12/status for details). "
                        "Auto-reconnect is disabled — restart the wallet "
                        "after fixing the configuration."
                    ),
                }
            )
        elif state.enabled and state.consecutive_probe_failures >= 3:
            payload["warnings"].append(
                {
                    "code": "gateway_unhealthy",
                    "message": (
                        f"Gateway has missed {state.consecutive_probe_failures} "
                        "consecutive health probes. Inbound payouts may be at risk."
                    ),
                }
            )
        elif not state.enabled:
            payload["warnings"].append(
                {
                    "code": "bolt12_disabled",
                    "message": (
                        "BOLT 12 is disabled in this wallet's configuration. "
                        "Set BOLT12_ENABLED=true and BOLT12_GATEWAY_GRPC to receive payouts."
                    ),
                }
            )
    except Exception:  # noqa: BLE001
        logger.exception("BOLT 12 receive panel: runtime probe crashed")
        payload["runtime"] = {"enabled": None, "running": None}

    # Introduction-node reachability check. When the gateway has zero
    # onion-message-capable peers with a publicly-routable address,
    # every newly-issued offer's ``offer_paths`` will be empty and
    # public-network payouts (OCEAN, etc.) will be rejected with
    # "no address known for peer". Surface this as a warning with a
    # dedicated code so the dashboard can render the "Fix this" CTA
    # that triggers ``POST /v1/bolt12/receive/auto-peer``.
    #
    # Best-effort: skipped silently when the gateway isn't reachable
    # (the gateway_offline / bolt12_disabled warnings already cover
    # that case, so we'd just be duplicating noise).
    try:
        runtime_payload = payload.get("runtime") or {}
        if runtime_payload.get("running"):
            # Use the module-level binding so tests' monkeypatching
            # of ``bolt12_api.get_bolt12_service`` reaches this call
            # site too. A local re-import would bypass the patch.
            try:
                service = get_bolt12_service()
            except HTTPException:
                service = None
            if service is not None:
                try:
                    ident = await service._gateway.get_identity()  # noqa: SLF001
                except Exception:  # noqa: BLE001
                    ident = None
                if ident is not None:
                    om_capable = [p for p in ident.peers if p.advertises_onion_messages]
                    # Match the offer-path builder's intro filter:
                    # well-known-payer self-nodes never count as
                    # usable intros, even when OM-capable and
                    # clearnet. Otherwise the panel would falsely
                    # report "you have a usable peer" while every
                    # issued offer still ships with empty
                    # offer_paths because of the exclusion.
                    payer_nids = well_known_payer_node_ids(
                        network=settings.bitcoin_network,
                    )
                    routable = [
                        p
                        for p in om_capable
                        if _is_publicly_routable_peer_address(p.address) and p.node_id not in payer_nids
                    ]
                    if not routable:
                        if not om_capable:
                            message = (
                                "Your wallet isn't connected to any Lightning "
                                "peer that supports BOLT 12 routing. Payouts "
                                "from public payers will fail until you "
                                "connect one."
                            )
                        else:
                            message = (
                                "Your wallet's BOLT 12 peers are only "
                                "reachable over Tor. Public payers (mining "
                                "pools, exchanges) can't reach them, so "
                                "payouts will fail. Connect to a public "
                                "Lightning node to fix this."
                            )
                        payload["warnings"].append(
                            {
                                "code": "no_publicly_routable_om_peer",
                                "message": message,
                            }
                        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "BOLT 12 receive panel: introduction-node reachability probe crashed",
        )

    return payload


@router.get("/receive")
async def get_receive_offer(
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Return (and on first call, mint) the caller's default receive offer.

    Designed for the dashboard's Issue tab and for any operator
    integrating with a recurring payer (e.g. the Ocean mining pool)
    that needs **one** stable BOLT 12 offer to register against the
    wallet. Subsequent calls are idempotent — the same offer is
    returned every time until the user explicitly promotes a different
    one via ``POST /v1/bolt12/offers/{id}/set-default``.

    The response also bundles inbound-liquidity and gateway-runtime
    context so the dashboard can render warning banners on first load
    without extra round-trips.
    """
    ip = request.client.host if request.client else None
    offer = await _get_or_create_default_receive(api_key=api_key, db=db, ip=ip)
    return await _build_receive_panel_payload(offer)


class ConfigureReceiveOfferRequest(BaseModel):
    """Request body for ``POST /v1/bolt12/receive/configure``.

    Mints a new default receive offer with a payer-specified
    description. Examples of payer-specific descriptions:

    * Ocean mining pool: ``"OCEAN Payouts for bc1q...your_address"``
    * Generic mining pool / merchant: ``"Payouts for alice"``
    * Free-form: anything ≤ 640 chars is accepted.

    The previous default (if any) is demoted automatically; nothing
    is deleted, so historical invreq/invoice rows still resolve.
    """

    description: str = Field(..., min_length=1, max_length=640)

    @field_validator("description")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


@router.post("/receive/configure", status_code=200)
async def configure_receive_offer(
    body: ConfigureReceiveOfferRequest,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Replace the default receive offer with one carrying ``description``.

    BOLT 12 offers are immutable — the description is part of the
    signed bech32 string — so editing the description means minting a
    brand-new offer. The previous default is demoted to a regular
    issued offer (``is_default_receive=False``) and remains in the
    user's offer history.

    Returns the same shape as ``GET /v1/bolt12/receive``.
    """
    ip = request.client.host if request.client else None
    offer = await _reconfigure_default_receive(
        description=body.description,
        api_key=api_key,
        db=db,
        ip=ip,
    )
    return await _build_receive_panel_payload(offer)


@router.post("/receive/auto-peer", status_code=200)
async def auto_peer_for_receive(
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Iterate the well-known-payers registry and dial each entry until
    one connects.

    Powers the dashboard's "Fix this" button surfaced alongside the
    ``no_publicly_routable_om_peer`` warning on the BOLT 12 receive
    panel. The dashboard renders the warning when the gateway has no
    onion-message-capable peer with a publicly-routable address; the
    button kicks this endpoint, which attempts each candidate from
    :mod:`app.services.bolt12.well_known_payers` in registry order
    and stops at the first success.

    Response shape::

        {
          "connected": true | false,
          "peer": null | {"label", "node_id_hex", "address",
                          "already_connected"},
          "attempts": [
            {"label", "node_id_hex", "address",
             "ok": true|false, "already_connected": bool,
             "error": "..."}
          ]
        }

    Always 200 on a reachable gateway — caller checks ``connected``
    for the outcome. 503 only when the gateway runtime isn't running
    (the dial can't be attempted at all in that case).
    """
    ip = request.client.host if request.client else None
    from app.services.bolt12.well_known_payers import WELL_KNOWN_PAYERS

    # ``get_bolt12_service`` raises HTTPException(503) if the runtime
    # isn't up — let it propagate so the caller sees a clear status.
    service = get_bolt12_service()

    attempts: list[dict[str, Any]] = []
    successful: Optional[dict[str, Any]] = None

    for payer in WELL_KNOWN_PAYERS:
        if payer.mainnet_only and settings.bitcoin_network != "bitcoin":
            continue
        attempt: dict[str, Any] = {
            "label": payer.label,
            "node_id_hex": payer.node_id_hex,
            "address": payer.address,
            "ok": False,
            "already_connected": False,
            "error": "",
        }
        try:
            node_id = bytes.fromhex(payer.node_id_hex)
            if len(node_id) != 33:
                raise ValueError(f"node_id_hex must decode to 33 bytes (got {len(node_id)})")
        except ValueError as exc:
            attempt["error"] = f"invalid node_id_hex: {exc}"
            attempts.append(attempt)
            continue
        try:
            result = await service._gateway.connect_peer(  # noqa: SLF001
                node_id=node_id,
                address=payer.address,
            )
        except Exception as exc:  # noqa: BLE001
            attempt["error"] = str(exc) or type(exc).__name__
            attempts.append(attempt)
            continue
        attempt["ok"] = True
        attempt["already_connected"] = bool(result.already_connected)
        # Wait for the BOLT 1 init handshake to surface the
        # ``advertises_onion_messages`` flag. Without this, the
        # dashboard's follow-up ``fetchBolt12Receive`` call lands
        # before the handshake completes and re-renders the same
        # "no OM peer" warning the user just clicked Connect to
        # clear.
        await _wait_for_om_capable_peer(service, node_id)
        attempts.append(attempt)
        successful = attempt
        break

    await log_action(
        db,
        api_key,
        "bolt12_receive_auto_peer",
        "bolt12_receive",
        details={
            "connected": successful is not None,
            "peer_label": successful["label"] if successful else None,
            "attempts": len(attempts),
        },
        ip_address=ip,
    )

    return {
        "connected": successful is not None,
        "peer": successful,
        "attempts": attempts,
    }


@router.post("/offers/{offer_id}/set-default", status_code=200)
async def set_default_receive_offer_route(
    offer_id: UUID,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Promote ``offer_id`` to be the caller's default receive offer.

    Useful when a user has been minting one-shot offers via the
    legacy ``/offers/issue`` route and now wants to anchor the
    dashboard's Issue tab on a specific one. The previous default
    (if any) is demoted automatically.
    """
    ip = request.client.host if request.client else None
    row = await _set_default_receive(offer_id, api_key=api_key, db=db, ip=ip)
    return OfferResponse.from_orm_row(row).model_dump(mode="json")


@router.get("/offers")
async def list_offers(
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(
        None,
        description="Filter by offer status (active, disabled, expired)",
    ),
    source: Optional[str] = Query(
        None,
        description=("Filter by provenance. Comma-separated subset of 'issued', 'imported', 'paid'."),
    ),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List stored offers (newest first).

    Scoped to the caller's API key — each tenant only ever sees
    their own offers (see ``_require_offer_owner`` for the same
    isolation on per-offer routes).
    """
    stmt = select(Bolt12Offer).where(
        Bolt12Offer.api_key_id == api_key.id,
        Bolt12Offer.deleted_at.is_(None),
    )
    if status is not None:
        try:
            stmt = stmt.where(Bolt12Offer.status == Bolt12OfferStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown status: {status}")
    if source is not None:
        try:
            sources = [Bolt12OfferSource(s.strip()) for s in source.split(",") if s.strip()]
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Unknown source: {exc}")
        if sources:
            stmt = stmt.where(Bolt12Offer.source.in_(sources))
    stmt = stmt.order_by(Bolt12Offer.created_at.desc()).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).scalars().all()
    return {"offers": [OfferResponse.from_orm_row(r).model_dump(mode="json") for r in rows]}


@router.get("/offers/{offer_id}")
async def get_offer(
    offer_id: UUID,
    request: Request,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Fetch a single stored offer by id.

    404 if the offer doesn't exist **or** belongs to a different
    tenant — see ``_require_offer_owner``.
    """
    row = await _require_offer_owner(offer_id, api_key, db, request=request)
    return OfferResponse.from_orm_row(row).model_dump(mode="json")


@router.delete(
    "/offers/{offer_id}",
    status_code=204,
    response_model=None,
)
async def disable_offer(
    offer_id: UUID,
    request: Request,
    api_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-disable an offer.

    Marks ``status=DISABLED``. We preserve the row + the bech32
    string so historical invoice_request rows that point at it
    continue to render meaningfully on the dashboard.
    """
    row = await _require_offer_owner(offer_id, api_key, db, request=request)
    was_default_receive = bool(row.is_default_receive)

    row.status = Bolt12OfferStatus.DISABLED
    # If the user disabled their default receive offer, also clear
    # the flag so ``/v1/bolt12/receive`` doesn't auto-revive it on
    # the next call. They can promote any other issued offer to
    # default via ``POST /v1/bolt12/offers/{id}/set-default`` or
    # mint a fresh one via ``POST /v1/bolt12/receive/configure``.
    row.is_default_receive = False
    await db.commit()

    await log_action(
        db,
        api_key,
        "disable_offer",
        "bolt12_offer",
        details={
            "offer_id": str(offer_id),
            "was_default_receive": was_default_receive,
        },
        ip_address=request.client.host if request.client else None,
    )

    # Disabling a default-receive offer removes its description from
    # the active set, so a well-known payer that was sticky purely
    # because of THIS offer must be removed from the gateway's sticky
    # set right away. Without this refresh the Rust on-disconnect
    # loop would keep redialling a peer the wallet no longer cares
    # about for up to 30 s (until the next periodic tick).
    if was_default_receive:
        await _refresh_sticky_peers_post_default_change()


@router.get("/offers/{offer_id}/invoice-requests")
async def list_offer_invoice_requests(
    offer_id: UUID,
    request: Request,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List ``invoice_request`` rows associated with an offer."""
    await _require_offer_owner(offer_id, api_key, db, request=request)
    stmt = (
        select(Bolt12InvoiceRequest)
        .where(
            Bolt12InvoiceRequest.offer_id == offer_id,
            Bolt12InvoiceRequest.api_key_id == api_key.id,
        )
        .order_by(Bolt12InvoiceRequest.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return {"invoice_requests": [InvoiceRequestResponse.from_orm_row(r).model_dump(mode="json") for r in rows]}


@router.get("/offers/{offer_id}/invoices")
async def list_offer_invoices(
    offer_id: UUID,
    request: Request,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> Any:
    """List invoices generated against an offer (any direction)."""
    await _require_offer_owner(offer_id, api_key, db, request=request)
    # Invoices link to invreqs which link to offers. Both joins are
    # scoped to ``api_key.id`` for defence-in-depth even though the
    # owner check above already gates access.
    invreq_ids = (
        (
            await db.execute(
                select(Bolt12InvoiceRequest.id).where(
                    Bolt12InvoiceRequest.offer_id == offer_id,
                    Bolt12InvoiceRequest.api_key_id == api_key.id,
                )
            )
        )
        .scalars()
        .all()
    )
    if not invreq_ids:
        return {"invoices": []}

    stmt = (
        select(Bolt12Invoice)
        .where(
            Bolt12Invoice.invoice_request_id.in_(invreq_ids),
            Bolt12Invoice.api_key_id == api_key.id,
        )
        .order_by(Bolt12Invoice.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return {"invoices": [InvoiceResponse.from_orm_row(r).model_dump(mode="json") for r in rows]}


# ─── Selective-disclosure proofs ──────────────────────────────────────


class InvoiceProofRequest(BaseModel):
    """Request body for ``POST /v1/bolt12/invoices/{id}/proof``.

    ``reveal_types`` is the list of TLV record types the holder wants
    to disclose. Common picks for a payment receipt:

    * ``160`` — ``invoice_payment_hash``
    * ``170`` — ``invoice_amount``
    * ``172`` — ``invoice_created_at``
    * ``174`` — ``invoice_relative_expiry``

    Anything in 240..1000 (signature range) is silently ignored — the
    point of selective disclosure is to keep the signature intact and
    *omit* fields, not include the signature TLV.
    """

    reveal_types: list[int] = Field(default_factory=list)


@router.post("/invoices/{invoice_id}/proof")
async def build_invoice_proof(
    invoice_id: UUID,
    req: InvoiceProofRequest,
    api_key: APIKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Build a selective-disclosure Merkle proof of a stored invoice.

    The caller chooses which TLVs to reveal; everything else is
    replaced by its paired-hash so a verifier can reconstruct the
    Merkle root and check the original BIP-340 signature. Useful for
    payment receipts, dispute evidence, or third-party audit without
    handing over the full invoice.
    """
    from app.services.bolt12 import build_proof, decode

    row = await db.get(Bolt12Invoice, invoice_id)
    if row is None or row.api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="invoice not found")

    try:
        b12 = decode(row.invoice_bolt12)
    except Exception as exc:  # noqa: BLE001 — codec layer
        raise HTTPException(
            status_code=500,
            detail=f"stored invoice failed to decode: {exc}",
        ) from exc
    if b12.hrp != "lni":
        raise HTTPException(
            status_code=500,
            detail=f"stored invoice has unexpected hrp: {b12.hrp}",
        )

    proof = build_proof(
        list(b12.records),
        # Defence in depth: even though ``build_proof`` is the
        # author of the "signature TLVs are silently ignored"
        # invariant, the endpoint enforces it itself so a future
        # refactor of the lower layer cannot accidentally regress.
        # Type range 240..1000 is the BOLT 12 signature range.
        reveal_types={t for t in req.reveal_types if not (240 <= t <= 1000)},
        message_name="invoice",
    )
    return {
        "invoice_id": str(invoice_id),
        "proof": proof.to_json(),
    }


# ─── BIP-353 payment-handle endpoints ─────────────────────────────────


class Bip353ResolveRequest(BaseModel):
    """Resolve a ``user@domain`` BIP-353 handle to a payment URI."""

    handle: str = Field(min_length=3, max_length=255)
    require_dnssec: bool = True


class Bip353ZoneRecordRequest(BaseModel):
    """Build a publishable BIP-353 TXT zone-file fragment."""

    handle: str = Field(min_length=3, max_length=255)
    offer: Optional[str] = None
    bolt11: Optional[str] = None
    on_chain: Optional[str] = None
    ttl: int = Field(default=3600, ge=60, le=86400)


@router.post("/bip353/resolve")
@limiter.limit("20/minute")
async def bip353_resolve(
    request: Request,
    req: Bip353ResolveRequest,
    api_key: APIKey = Depends(get_api_key),
) -> Any:
    """Resolve a BIP-353 ``user@domain`` handle.

    Returns the ``bitcoin:`` URI, decomposed into ``offer``,
    ``bolt11``, and ``on_chain`` components. Network call — uses the
    system DNS resolver. ``require_dnssec`` defaults to ``True``;
    only set ``False`` for development (the response will fail closed
    if your resolver isn't validating).
    """
    from app.services.bolt12.bip353 import (
        Bolt12Bip353InsecureError,
        resolve_payment_handle,
    )

    try:
        result = resolve_payment_handle(
            req.handle,
            require_dnssec=req.require_dnssec,
        )
    except Bolt12Bip353InsecureError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — DNS errors vary
        # Generic message; full exception lands in structured logs
        # for operator triage. Verbose error returns assist fuzzing.
        logger.info("BIP-353 lookup failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="BIP-353 lookup failed",
        ) from exc

    return {
        "handle": req.handle,
        "fqdn": result.handle.fqdn,
        "bitcoin_uri": result.bitcoin_uri,
        "offer": result.offer,
        "bolt11": result.bolt11,
        "on_chain": result.on_chain,
    }


@router.post("/bip353/zone-record")
async def bip353_zone_record(
    req: Bip353ZoneRecordRequest,
    api_key: APIKey = Depends(get_admin_key),
) -> Any:
    """Emit an RFC1035 zone-file fragment for a payment handle.

    Admin-only because publishing a handle is a wallet-binding
    decision (operators must pair it with the matching offer in
    their DNS zone).
    """
    from app.services.bolt12.bip353 import PaymentHandle, build_zone_record

    try:
        h = PaymentHandle.parse(req.handle)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        record = build_zone_record(
            h,
            offer=req.offer,
            bolt11=req.bolt11,
            on_chain=req.on_chain,
            ttl=req.ttl,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "handle": req.handle,
        "fqdn": h.fqdn,
        "zone_record": record,
    }


# ─── Pay endpoint ─────────────────────────────────────────────────────


# Hard cap on how long the orchestrator will block waiting for a
# reply. Anything longer is almost certainly a routing dead-end and
# should be retried out-of-band.
_PAY_TIMEOUT_MAX_S = 90.0
_PAY_TIMEOUT_DEFAULT_S = 30.0


class PayOfferRequest(BaseModel):
    """Send an ``invoice_request`` for an offer, fetch the signed
    invoice, and **settle it** via LND ``SendToRouteV2``.

    This endpoint moves funds. Like every other fund-moving API path
    it is therefore subject to the configured payment safety limits
    (``LND_MAX_PAYMENT_SATS``, the cumulative spend window, and the
    velocity breaker) for API-key callers; the dashboard sentinel key
    bypasses them by design (human operator). See ``_perform_pay_offer``.
    """

    offer: str = Field(..., min_length=1, max_length=_MAX_BOLT12_LEN)
    amount_msat: Optional[int] = Field(
        default=None,
        ge=1,
        le=21_000_000 * 100_000_000 * 1_000,
        description=(
            "Amount to pay in millisatoshis. Required if the offer has no "
            "fixed amount; optional override otherwise (must be >= offer "
            "amount when provided)."
        ),
    )
    quantity: Optional[int] = Field(default=None, ge=1)
    payer_note: Optional[str] = Field(default=None, max_length=512)
    timeout_seconds: float = Field(
        default=_PAY_TIMEOUT_DEFAULT_S,
        gt=0,
        le=_PAY_TIMEOUT_MAX_S,
    )

    @field_validator("offer", "payer_note")
    @classmethod
    def _strip(cls, v: Optional[str]) -> Optional[str]:
        return v.strip() if isinstance(v, str) else v


def _resolve_pay_amount(offer: Offer, requested_msat: Optional[int]) -> int:
    """Decide the final amount to put on the invreq.

    Rules (per BOLT 12 §"Requirements for Invoice Request"):
      * If the offer fixes ``offer_amount`` and the caller passed
        nothing, mirror the offer amount.
      * If the offer fixes ``offer_amount`` and the caller passed a
        value, the value must be >= the offer amount.
      * If the offer has no ``offer_amount`` (variable-amount offer),
        the caller must supply one.
    """
    if offer.amount is not None:
        if requested_msat is None:
            return offer.amount
        if requested_msat < offer.amount:
            raise HTTPException(
                status_code=400,
                detail=(f"amount_msat ({requested_msat}) is below offer minimum ({offer.amount})"),
            )
        return requested_msat
    if requested_msat is None:
        raise HTTPException(
            status_code=400,
            detail="Offer has no fixed amount; amount_msat is required",
        )
    return requested_msat


@router.post("/pay")
async def pay_offer(
    req: PayOfferRequest,
    request: Request,
    # Paying a BOLT 12 offer is a fund-moving operation, so it accepts a
    # spend key (or admin) like the other payment endpoints — agents need
    # not hold a full admin key just to pay offers. Payment caps still
    # apply regardless of scope.
    api_key: APIKey = Depends(get_spend_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Send an invreq for ``offer`` and persist the resulting invoice.

    Failure modes:

    * **400** — offer parses but is unpayable (no ``issuer_id`` and
      no ``offer_paths``; missing required ``amount_msat``).
    * **502** — gateway/orchestrator transport failure, or invoice
      came back malformed / signature-invalid / amount mismatch.
    * **503** — BOLT 12 runtime not running.
    * **504** — no invoice reply within ``timeout_seconds``.

    Clients may pass ``Idempotency-Key: <uuid>`` so a retried request returns
    the original payment instead of fetching a fresh invoice and paying again.
    A prior attempt whose settlement outcome was unknown is reconciled against
    the node by payment hash before any re-send.
    """
    idem_key = get_idempotency_key(request)
    req_body = req.model_dump()
    api_key_id = str(api_key.id)
    if idem_key is not None:
        resolved = await _reconcile_pending_bolt12_payment(
            api_key_id=api_key_id, idem_key=idem_key, request_body=req_body
        )
        if resolved is not None:
            return resolved
        cached = lookup_or_reserve(
            api_key_id=api_key_id,
            idem_key=idem_key,
            request_body=req_body,
        )
        if cached is not None:
            return cached

    try:
        result = await _perform_pay_offer(
            req,
            api_key=api_key,
            db=db,
            ip=request.client.host if request.client else None,
        )
    except BaseException:
        # A raised error here is a pre-settlement failure (invoice fetch,
        # validation, caps): nothing settled, so the key may be retried.
        if idem_key is not None:
            release_inflight(api_key_id=api_key_id, idem_key=idem_key)
        raise

    if idem_key is not None:
        status = str(result.get("status") or "").lower()
        if status == Bolt12InvoiceStatus.PAID.value:
            store_result(api_key_id=api_key_id, idem_key=idem_key, request_body=req_body, response=result)
        elif status == Bolt12InvoiceStatus.OPEN.value:
            # Settlement outcome unknown — hold the slot against the payment
            # hash so a retry is reconciled, not re-paid.
            mark_pending(
                api_key_id=api_key_id,
                idem_key=idem_key,
                request_body=req_body,
                payment_hash=str(result.get("payment_hash_hex") or ""),
            )
        else:
            # Definitive non-settlement (e.g. no route): release for retry.
            release_inflight(api_key_id=api_key_id, idem_key=idem_key)
    return result


async def _reconcile_pending_bolt12_payment(
    *, api_key_id: str, idem_key: str, request_body: Any
) -> Optional[dict[str, Any]]:
    """Resolve a pending BOLT 12 pay slot left by an earlier ambiguous send.

    Looks the recorded payment hash up against the node: a settled payment is
    cached and returned (no re-pay); a failed one releases the slot for a fresh
    attempt; an unknown/in-flight one is left pending so the retry receives 409.
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
            "payment_hash_hex": payment_hash,
            "amount_msat": int(lookup.get("value_sat", 0)) * 1000,
            "status": Bolt12InvoiceStatus.PAID.value,
        }
        store_result(api_key_id=api_key_id, idem_key=idem_key, request_body=request_body, response=result)
        return result
    if status == "FAILED":
        release_pending(api_key_id=api_key_id, idem_key=idem_key)
    return None


def _check_bolt12_payment_limit(amount_sats: int) -> None:
    """Enforce the per-payment safety cap (LND_MAX_PAYMENT_SATS) for a
    BOLT 12 outbound payment. Mirrors ``payments._check_payment_limit``."""
    max_sats = settings.lnd_max_payment_sats
    if max_sats == -1:
        return  # No limit configured
    if amount_sats > max_sats:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Payment of {amount_sats:,} sats exceeds safety limit of "
                f"{max_sats:,} sats. Contact admin to adjust LND_MAX_PAYMENT_SATS."
            ),
        )


def _bolt12_settled_sats(htlc: Optional[dict[str, Any]], fallback_sats: int) -> int:
    """Best-effort true outflow (amount + routing fee) from the settled
    HTLC's route, falling back to the invoice amount when LND doesn't
    surface a route total."""
    if isinstance(htlc, dict):
        route = htlc.get("route")
        if isinstance(route, dict) and route.get("total_amt"):
            try:
                return int(route["total_amt"])
            except (TypeError, ValueError):
                pass
    return fallback_sats


class _Bolt12OutboundOutcome:
    """Tracks the result of a BOLT 12 outbound payment attempt.

    Stored as a plain class (not dataclass) because the failure-mode
    paths populate ``error`` lazily and the success path mirrors
    LND's ``HTLCAttempt`` JSON verbatim — easier to evolve as LND
    versions add fields than a fixed schema.
    """

    __slots__ = ("status", "error", "preimage_hex", "htlc", "ambiguous")

    def __init__(self) -> None:
        self.status: str = "pending"
        self.error: Optional[str] = None
        self.preimage_hex: Optional[str] = None
        self.htlc: Optional[dict[str, Any]] = None
        # True when the settlement outcome is unknown (transport failure with
        # the HTLC possibly in flight) rather than a definitive success/failure.
        self.ambiguous: bool = False


async def _settle_bolt12_outbound(
    *,
    invoice: Invoice,
    invoice_row: Bolt12Invoice,
    db: AsyncSession,
    fee_limit_msat: int | None = None,
) -> _Bolt12OutboundOutcome:
    """Pay a fetched BOLT 12 invoice via the LND blinded-path route.

    Mutates ``invoice_row.status`` + ``invoice_row.error_message`` +
    ``invoice_row.paid_at`` + ``invoice_row.encrypted_preimage`` to
    reflect the outcome. Returns the outcome for the caller to log /
    bubble back to the API client.
    """
    outcome = _Bolt12OutboundOutcome()

    # The invoice MUST carry both blinded-paths blobs; refuse early
    # if either is missing (a malformed invoice is the most common
    # cause — a recipient that only signs ``invoice_node_id`` direct-
    # path invoices is not supported by this code path because the
    # whole point of BOLT 12 is the blinded reply).
    if not invoice.paths or not invoice.blindedpay:
        invoice_row.status = Bolt12InvoiceStatus.FAILED
        invoice_row.error_message = (
            "BOLT 12 invoice missing blinded paths or blindedpay TLVs; refusing to pay over a non-blinded route"
        )
        outcome.status = "failed"
        outcome.error = invoice_row.error_message
        return outcome

    try:
        blinded_payment_paths = decode_invoice_paths(
            invoice.paths,
            invoice.blindedpay,
        )
    except (ValueError, TypeError) as exc:
        invoice_row.status = Bolt12InvoiceStatus.FAILED
        invoice_row.error_message = f"BOLT 12 invoice paths failed to decode: {exc}"
        outcome.status = "failed"
        outcome.error = invoice_row.error_message
        return outcome

    # Step 1 — ask LND for a route over the blinded paths. When the caller
    # is cap-enforced (an API-key caller), bound the routing fee to the
    # reserved budget so the true outflow can't exceed the per-payment cap
    # via an outsized routing fee. The dashboard/anonymize sentinel passes
    # None (unbounded), preserving its intentional cap bypass.
    routes_data, route_err = await lnd_service.query_routes_with_blinded_paths(
        amount_msat=int(invoice.amount or 0),
        blinded_payment_paths=blinded_payment_paths,
        fee_limit_msat=fee_limit_msat,
    )
    if route_err is not None or routes_data is None:
        invoice_row.status = Bolt12InvoiceStatus.FAILED
        invoice_row.error_message = f"QueryRoutes failed: {route_err}"
        outcome.status = "failed"
        outcome.error = invoice_row.error_message
        return outcome
    routes = routes_data.get("routes") or []
    if not routes:
        invoice_row.status = Bolt12InvoiceStatus.FAILED
        invoice_row.error_message = "QueryRoutes returned no routes for the blinded payment"
        outcome.status = "failed"
        outcome.error = invoice_row.error_message
        return outcome
    route = routes[0]

    # Step 2 — execute the payment.
    htlc, send_err = await lnd_service.send_to_route_v2(
        payment_hash_hex=invoice.payment_hash.hex() if invoice.payment_hash else "",
        route=route,
    )
    if send_err is not None or htlc is None:
        # A transport-level failure ends the call without LND confirming the
        # HTLC was rejected, and LND does not cancel an in-flight HTLC when its
        # caller disconnects. Leave the invoice OPEN and flag the outcome
        # ambiguous so the caller holds the idempotency slot for reconciliation
        # rather than marking the invoice failed and allowing an immediate
        # re-pay that would settle a second HTLC. A definitive routing failure
        # is reported by LND as an ``htlc`` with ``status=FAILED`` (handled
        # below), not as a transport error here.
        invoice_row.error_message = f"SendToRouteV2 outcome unknown: {send_err}"
        outcome.status = "in_flight"
        outcome.ambiguous = True
        outcome.error = invoice_row.error_message
        return outcome
    outcome.htlc = htlc

    status = str(htlc.get("status") or "").upper()
    if status == "SUCCEEDED":
        preimage_hex = str(htlc.get("preimage") or "")
        invoice_row.status = Bolt12InvoiceStatus.PAID
        invoice_row.paid_at = datetime.now(timezone.utc)
        if preimage_hex:
            invoice_row.encrypted_preimage = encrypt_field(preimage_hex)
            outcome.preimage_hex = preimage_hex
        outcome.status = "paid"
        return outcome

    # IN_FLIGHT shouldn't happen on a single-route send (LND blocks
    # until terminal), but treat it defensively as still-open AND ambiguous:
    # the HTLC may yet settle, so the caller must keep the spend reservation
    # and hold the idempotency slot pending rather than rolling back.
    if status == "IN_FLIGHT":
        outcome.status = "in_flight"
        outcome.ambiguous = True
        return outcome

    # FAILED — surface the structured failure reason.
    failure = htlc.get("failure") or {}
    failure_reason = failure.get("code") or "UNKNOWN"
    invoice_row.status = Bolt12InvoiceStatus.FAILED
    invoice_row.error_message = f"SendToRouteV2 returned status={status} failure={failure_reason}"
    outcome.status = "failed"
    outcome.error = invoice_row.error_message
    return outcome


async def _perform_pay_offer(
    req: PayOfferRequest,
    *,
    api_key: APIKey,
    db: AsyncSession,
    ip: Optional[str],
) -> Any:
    """Core pay-offer logic shared by the public + dashboard routes."""
    offer = _decode_offer_or_400(req.offer)
    if offer.issuer_id is None and offer.paths is None:
        raise HTTPException(
            status_code=400,
            detail="Offer has neither issuer_id nor blinded paths; unreachable",
        )
    final_amount_msat = _resolve_pay_amount(offer, req.amount_msat)

    # Payment safety caps. This endpoint settles real funds, so — like
    # every other fund-moving API path — API-key callers are bounded by
    # LND_MAX_PAYMENT_SATS, the cumulative spend window, and the velocity
    # breaker. The dashboard sentinel key (used by the human-operator
    # dashboard route and the anonymize hop, which has its own caps)
    # bypasses them by design.
    from app.dashboard import DASHBOARD_KEY_ID

    enforce_caps = api_key.id != DASHBOARD_KEY_ID
    # Round msat up to whole sats and add a worst-case routing-fee budget
    # (5% of amount, matching the BOLT 11 pay path's default) so an
    # outsized routing fee cannot slip past the cap.
    pay_amount_sats = (final_amount_msat + 999) // 1000
    pay_total_sats = pay_amount_sats + max(1, int(pay_amount_sats * 0.05))
    if enforce_caps:
        _check_bolt12_payment_limit(pay_total_sats)

    # Need an active orchestrator + gateway.
    service = get_bolt12_service()  # 503 if not running

    # Pull peer candidates for the blinded reply path. Without at
    # least one onion-message-capable peer we cannot receive the
    # reply at all, so fail loudly rather than building a path that
    # will silently never deliver.
    try:
        ident = await service._gateway.get_identity()  # noqa: SLF001 — gateway is ours
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=502,
            detail=sanitize_upstream_error(str(exc), "bolt12-gateway"),
        ) from exc
    candidates = tuple(p.node_id for p in ident.peers if p.advertises_onion_messages)
    if not candidates:
        raise HTTPException(
            status_code=503,
            detail="Gateway has no onion-message-capable peers for reply path",
        )

    # Generate a fresh transient payer key — BOLT 12 mandates
    # per-invreq unlinkability, so a new key per call is the
    # correct default.
    payer = CoincurveSigner.generate()
    invreq_metadata = secrets.token_bytes(16)

    # Capture the signed invreq so we can persist it after the
    # orchestrator returns.
    captured: dict[str, Any] = {}

    async def _builder(ctx: InvreqBuildContext) -> bytes:
        # The gateway has built us a blinded reply path; embed it
        # in the invreq's ``invreq_paths`` field so the recipient
        # knows where to send the invoice back.
        # Pin the chain hash for non-mainnet networks. Per BOLT 12
        # the field MUST be omitted on mainnet and present otherwise.
        our_chain = chain_hash_for(settings.bitcoin_network)
        invreq_chain = None if our_chain == MAINNET_CHAIN_HASH else our_chain
        unsigned = InvoiceRequest.from_offer(
            offer,
            metadata=invreq_metadata,
            payer_id=payer.public_key,
            amount=final_amount_msat,
            quantity=req.quantity,
            payer_note=req.payer_note,
            paths=ctx.reply_path,
            chain=invreq_chain,
        )
        signed = sign_invoice_request(unsigned, payer)
        captured["invreq"] = signed
        return tlv_encode_stream(signed.to_records())

    def _resolver(_offer_b12: Bolt12String) -> SendPlan:
        # Prefer offer_paths when present (BOLT 12 §"Sending an
        # invoice_request"): if the issuer published a blinded path
        # we MUST route through it. Some issuers (e.g. CLN with an
        # onion-message-capable peer) auto-publish offer_paths and
        # silently drop direct invreqs.
        if offer.paths is not None:
            destination = SendDestination(blinded_path=offer.paths)
        else:
            destination = SendDestination(direct_node_id=offer.issuer_id)
        return SendPlan(
            destination=destination,
            reply_path=ReplyPathSpec(introduction_node_candidates=candidates),
        )

    # Send + await the invoice reply.
    try:
        invoice_payload = await service.request_invoice(
            offer=offer.to_bolt12_string(),
            build_invreq=_builder,
            destination=_resolver,
            amount_msat=final_amount_msat,
            payer_note=req.payer_note,
            quantity=req.quantity,
            timeout_seconds=req.timeout_seconds,
        )
    except InvoiceRequestTimeoutError as exc:
        raise HTTPException(status_code=504, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Distinguish back-pressure (in-flight cap) from generic
        # gateway errors so clients can retry vs. fail fast.
        msg = str(exc)
        if "too many in-flight invoice requests" in msg:
            raise HTTPException(status_code=503, detail=msg) from exc
        logger.exception("BOLT 12 pay: gateway request failed")
        raise HTTPException(
            status_code=502,
            detail=sanitize_upstream_error(str(exc), "bolt12-gateway"),
        ) from exc

    # Decode the inner-TLV invoice payload + verify. ``invoice_payload`` is
    # attacker-controlled (returned by a remote recipient), so apply the same
    # record-count / value-size caps the responder uses on inbound invreqs —
    # the orchestrator already bounds total payload size, but the per-stream
    # caps keep record count and individual value sizes in check too.
    try:
        records = tlv_decode_stream(
            invoice_payload,
            max_records=settings.bolt12_max_tlv_records or None,
            max_value_bytes=settings.bolt12_max_tlv_value_bytes or None,
        )
        invoice = Invoice.parse(Bolt12String(hrp="lni", records=records))
    except Bolt12Error as exc:
        # The parse detail is recipient-controlled; keep it out of the
        # response and log it for operator triage.
        logger.info("BOLT 12 pay: recipient returned a malformed invoice: %s", exc)
        raise HTTPException(status_code=502, detail="Recipient returned a malformed invoice") from exc

    if invoice.payment_hash is None:
        raise HTTPException(status_code=502, detail="Invoice missing payment_hash")
    if invoice.signature is None:
        raise HTTPException(status_code=502, detail="Invoice missing signature")

    # Bind the inbound invoice to **our** invreq (BOLT 12 §"Invoice
    # received" MUSTs). The mirrored invreq fields embedded in the
    # invoice MUST match the ones we signed; otherwise a hostile
    # recipient could substitute a different invreq's payment_hash
    # or amount and trick us into committing the payment to them.
    if invoice.invreq.payer_id != payer.public_key:
        raise HTTPException(
            status_code=502,
            detail="Invoice payer_id does not mirror our invreq",
        )
    if invoice.invreq.metadata != invreq_metadata:
        raise HTTPException(
            status_code=502,
            detail="Invoice invreq_metadata does not mirror our invreq",
        )

    # Choose the key the invoice signature must verify against. For a
    # direct offer — one that advertises ``offer_issuer_id`` and carries
    # no blinded ``offer_paths`` — BOLT 12 requires the invoice to be
    # signed by that issuer key. A substituted ``invoice_node_id`` is only
    # legitimate when the issuer key was delivered inside the offer's
    # blinded path, so for direct offers we bind the signer to the offer
    # issuer and reject a mismatching ``invoice_node_id``. Otherwise we
    # verify against ``invoice_node_id`` (the blinded-path case).
    def _xonly(key: bytes) -> bytes:
        return key[1:] if len(key) == 33 else key

    verifying_key: bytes | None
    if offer.issuer_id is not None and offer.paths is None:
        if invoice.node_id is not None and _xonly(invoice.node_id) != _xonly(offer.issuer_id):
            raise HTTPException(
                status_code=502,
                detail="Invoice node_id does not match the offer's issuer_id",
            )
        verifying_key = offer.issuer_id
    else:
        verifying_key = invoice.node_id or offer.issuer_id
    if verifying_key is None or not verify_bip340(
        pubkey33=verifying_key,
        message32=invoice.signature_digest(),
        signature64=invoice.signature,
    ):
        raise HTTPException(status_code=502, detail="Invoice signature invalid")

    # The invoice's amount must mirror the invreq's. (Spec allows
    # equality only — the recipient does not get to bill for more.)
    if invoice.amount is None:
        raise HTTPException(status_code=502, detail="Invoice missing amount")
    if invoice.amount != final_amount_msat:
        raise HTTPException(
            status_code=502,
            detail=(f"Invoice amount ({invoice.amount}) does not match invreq ({final_amount_msat})"),
        )

    # Lookup matching stored offer by canonical bolt12 string. If
    # absent, insert a fresh row tagged ``PAID`` so this offer shows
    # up in the dashboard's Pay-tab payee list. If present and
    # imported, upgrade to ``PAID``; ``ISSUED`` rows (we paid our
    # own offer) keep their provenance. Always bump ``last_paid_at``.
    offer_row = (await db.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == req.offer))).scalar_one_or_none()
    paid_at = datetime.now(timezone.utc)
    if offer_row is None:
        offer_row = Bolt12Offer(
            api_key_id=api_key.id,
            bolt12=req.offer,
            description=offer.description,
            amount_msat=offer.amount,
            currency=offer.currency,
            issuer=offer.issuer,
            issuer_id_hex=offer.issuer_id.hex() if offer.issuer_id else None,
            quantity_max=offer.quantity_max,
            source=Bolt12OfferSource.PAID,
            last_paid_at=paid_at,
        )
        db.add(offer_row)
        await db.flush()
    else:
        if offer_row.source == Bolt12OfferSource.IMPORTED:
            offer_row.source = Bolt12OfferSource.PAID
        offer_row.last_paid_at = paid_at

    signed_invreq = captured["invreq"]
    invreq_row = Bolt12InvoiceRequest(
        api_key_id=api_key.id,
        offer_id=offer_row.id,
        direction=Bolt12Direction.OUTBOUND,
        offer_bolt12=req.offer,
        amount_msat=final_amount_msat,
        quantity=req.quantity,
        payer_note=req.payer_note,
        payer_id_hex=payer.public_key.hex(),
        encrypted_payer_secret=encrypt_field(payer.secret.hex()),
        invreq_bolt12=encode_bolt12(signed_invreq.to_bolt12_string()),
        status=Bolt12InvoiceRequestStatus.INVOICE_RECEIVED,
    )
    db.add(invreq_row)
    await db.flush()

    invoice_row = Bolt12Invoice(
        api_key_id=api_key.id,
        invoice_request_id=invreq_row.id,
        direction=Bolt12Direction.OUTBOUND,
        invoice_bolt12=encode_bolt12(invoice.to_bolt12_string()),
        amount_msat=invoice.amount,
        payment_hash_hex=invoice.payment_hash.hex(),
        node_id_hex=verifying_key.hex(),
        status=Bolt12InvoiceStatus.OPEN,
    )
    db.add(invoice_row)
    await db.commit()
    await db.refresh(invreq_row)
    await db.refresh(invoice_row)

    # J2 — pay the BOLT 12 invoice via the blinded paths.
    #
    # Path: parse the invoice's blinded-path blobs (TLVs 160 + 162)
    # into LND's :class:`BlindedPaymentPath` JSON shape, ask LND for
    # a route, and forward via ``SendToRouteV2``. This avoids the
    # BOLT 11 synthesis path that earlier designs explored;
    # by going directly through ``QueryRoutes`` + ``SendToRouteV2``
    # over REST we don't need a BOLT 11 encoder.
    #
    # Failure handling: a failed payment marks the invoice row
    # ``FAILED`` with ``error_message`` set and surfaces the error
    # to the caller. The orchestrator-side state is already
    # committed (the invoice row + invreq row) so this is a
    # state-machine transition, not a rollback.
    # Reserve the worst-case spend against the cumulative + velocity
    # limits immediately before settling. On rejection the invoice row is
    # marked FAILED and the caller gets 429 — no funds move.
    reservation: Optional[dict[str, Any]] = None
    if enforce_caps:
        allowed, limit_error, reservation = await check_payment_limits(pay_total_sats, str(api_key.id))
        if not allowed:
            invoice_row.status = Bolt12InvoiceStatus.FAILED
            invoice_row.error_message = limit_error
            await db.commit()
            raise HTTPException(status_code=429, detail=limit_error)

    # Bound the routing fee to the reserved budget (amount + 5% − amount)
    # for cap-enforced callers so a large routing fee can't push the true
    # outflow past LND_MAX_PAYMENT_SATS. Sentinel (dashboard/anonymize)
    # callers pass None and remain unbounded by design.
    settle_fee_limit_msat = (pay_total_sats - pay_amount_sats) * 1000 if enforce_caps else None
    pay_outcome = await _settle_bolt12_outbound(
        invoice=invoice,
        invoice_row=invoice_row,
        db=db,
        fee_limit_msat=settle_fee_limit_msat,
    )

    # Reconcile the reservation with the true outflow on success, keep the
    # worst-case reservation when the outcome is unknown (the sats may yet
    # leave), or release it entirely on a definitive non-settlement.
    if enforce_caps and reservation is not None:
        if pay_outcome.status == "paid":
            settled_sats = _bolt12_settled_sats(pay_outcome.htlc, pay_amount_sats)
            await reconcile_spend_limit(reservation, settled_sats)
        elif not pay_outcome.ambiguous:
            await rollback_payment_limits(reservation)

    await db.commit()
    await db.refresh(invoice_row)

    await log_action(
        db,
        api_key,
        "pay_offer",
        "bolt12_invoice",
        amount_sats=final_amount_msat // 1000,
        details={
            "invreq_id": str(invreq_row.id),
            "invoice_id": str(invoice_row.id),
            "payment_hash": invoice.payment_hash.hex(),
            "amount_msat": final_amount_msat,
            "settlement_status": pay_outcome.status,
            **({"settlement_error": pay_outcome.error} if pay_outcome.error else {}),
        },
        ip_address=ip,
    )

    return {
        "invoice_request_id": str(invreq_row.id),
        "invoice_id": str(invoice_row.id),
        "payment_hash_hex": invoice.payment_hash.hex(),
        "amount_msat": invoice.amount,
        "node_id_hex": verifying_key.hex(),
        "status": invoice_row.status.value,
        # The encoded invoice round-trips for audit / dashboard
        # display (``lni…``). With J2 wired below, the wallet now
        # also drives the HTLC settlement; ``status`` reflects the
        # outcome.
        "invoice_bolt12": invoice_row.invoice_bolt12,
        "settlement": {
            "status": pay_outcome.status,
            "error": pay_outcome.error,
        },
    }
