# SPDX-License-Identifier: MIT
"""Inbound ``invoice_request`` responder.

When a peer sends us an ``invoice_request`` for an offer we issued,
the orchestrator hands us the raw TLV stream and a blinded reply
path. Our job:

1. Parse + verify the invreq (BIP-340 over its merkle digest).
2. Look up the matching :class:`Bolt12Offer` row by its
   ``issuer_id_hex`` (the wallet-side offer key we generated when
   ``POST /v1/bolt12/offers/issue`` minted the offer). Reject the
   invreq if no active offer matches.
3. Validate amount / quantity policy (the invreq may set its own
   ``invreq_amount``; if the offer pinned an amount, the invreq
   amount must equal it).
4. Mint a payable LND blinded invoice for the resolved amount.
5. Build a BOLT 12 :class:`Invoice` mirroring the invreq, sign it
   with the offer's issuer key (loaded by decrypting the seed
   stored on the offer row), and return the encoded TLV bytes.
6. Persist a ``Bolt12InvoiceRequest`` (direction=INBOUND,
   status=INVOICE_SENT) and a ``Bolt12Invoice`` (direction=INBOUND,
   status=OPEN) for audit + lookup.

This module is **transport-agnostic**: it never touches the gateway
client. Wiring up the orchestrator's ``invoice_responder`` callback
is :mod:`app.services.bolt12.runtime`'s job.

Failure modes are *silent*: an unrecognised offer, a bad signature,
or an LND error all return ``None``. The orchestrator interprets
``None`` as "drop the message, do not reply" — exactly what BOLT 12
requires for an unauthenticated transport.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime, timezone
from typing import Any, cast
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db_context
from app.core.encryption import decrypt_field
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)
from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferStatus
from app.services.bolt12.chain_hash import accepts_chain
from app.services.bolt12.codec import Bolt12String
from app.services.bolt12.codec import decode as decode_bolt12
from app.services.bolt12.codec import encode as encode_bolt12
from app.services.bolt12.errors import Bolt12Error
from app.services.bolt12.fields import Invoice, InvoiceRequest
from app.services.bolt12.inbound_rate_limit import check_inbound_invreq_rate
from app.services.bolt12.lnd_paths import encode_invoice_paths
from app.services.bolt12.orchestrator import InboundInvreqContext
from app.services.bolt12.signing import (
    CoincurveSigner,
    sign_invoice,
    verify_invoice_request,
)
from app.services.bolt12.tlv import (
    decode_stream as tlv_decode_stream,
)
from app.services.bolt12.tlv import (
    encode_stream as tlv_encode_stream,
)
from app.services.lnd_service import _classify_tor_failure, lnd_service
from app.services.lnd_types import BlindedInvoiceResult

logger = logging.getLogger(__name__)


# Default expiry for the LND blinded invoice we mint in response
# (seconds). Same conservative default the wallet uses for BOLT 11
# invoices.
_DEFAULT_INVOICE_EXPIRY = 3600

# Hard ceiling on the invreq ``quantity`` for a fixed-price offer that
# didn't pin its own ``quantity_max``. Defensive bound so a peer can't
# inflate ``pinned * quantity`` without limit when the amount cap is
# disabled. Generous enough for any realistic
# multi-item offer.
_HARD_QUANTITY_MAX = 1_000_000

# Absolute, non-disablable ceiling (msat) on the resolved amount of any
# single inbound mint, regardless of offer type. The operator-tunable
# ``bolt12_inbound_max_amount_msat`` can be switched off (set to 0); this
# backstop bounds an unauthenticated peer's ability to drive an arbitrarily
# large blinded invoice regardless. 1 BTC is far above any realistic single
# inbound payment yet caps runaway exposure.
_HARD_MAX_INBOUND_AMOUNT_MSAT = 100_000_000_000


def _invoice_expired(invoice_row: "Bolt12Invoice") -> bool:
    """Return True if the stored invoice should NOT be replayed
    on a metadata-dedup hit (caller will mint fresh instead).

    BOLT 12 idempotency: the receiver MUST return the same invoice
    for repeated invreqs with the same ``invreq_metadata``. So
    PAID rows are replayed verbatim \u2014 the payer's CLN sees the
    duplicate ``payment_hash`` settle-already condition at LND and
    avoids double-payment. Only FAILED / EXPIRED rows trigger a
    fresh mint, because those statuses signal that the prior
    round-trip never resulted in a paid HTLC.

    Conservative: OPEN rows lacking ``expiry`` (legacy / NULL) are
    treated as **not expired** \u2014 we'd rather replay an old
    invoice than mint a duplicate. The application-layer
    ``status`` flag catches genuinely expired OPEN rows once the
    settlement-watcher / reconcile pass flips them.
    """
    if invoice_row.status == Bolt12InvoiceStatus.PAID:
        return False  # never "expired" \u2014 always replay
    if invoice_row.status in (
        Bolt12InvoiceStatus.FAILED,
        Bolt12InvoiceStatus.EXPIRED,
    ):
        return True  # treat as expired \u2014 mint fresh
    # OPEN: fall through to wall-clock expiry check.
    expiry = invoice_row.expiry
    if expiry is None:
        return False
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry <= datetime.now(timezone.utc)


def _log_blinded_path_policy(
    lnd_paths: list,
    *,
    offer_label: str,
    recv_id: str,
) -> None:
    """Emit one INFO line per blinded path with the policy fields
    LND chose. Operator-actionable signal when LND advertises an
    out-of-band ``htlc_max_msat`` or ``total_cltv_delta`` that
    might mislead a payer's pathfinder.

    Promoted from DEBUG to INFO on 2026-06-05 after the Ocean
    payout failure where the per-path policy was the only signal
    that would have explained CLN's "insufficient capacity" error
    — and we couldn't see it because INFO is the default log level.
    Volume is bounded by ``BOLT12_BLINDED_PATH_MAX_PATHS`` (default
    2, max 8) lines per mint; one Ocean payout per day yields at
    most 8 lines/day.
    """
    for i, bp in enumerate(lnd_paths):
        inner = bp.get("blinded_path", {}) if isinstance(bp, dict) else {}
        intro_b64 = inner.get("introduction_node", "") if isinstance(inner, dict) else ""
        # 8-byte prefix is enough for grep-ability without
        # leaking the full pubkey at INFO.
        try:
            intro_prefix = base64.b64decode(intro_b64)[:8].hex() if intro_b64 else "?"
        except (ValueError, TypeError):
            intro_prefix = "?"
        blinded_hops = inner.get("blinded_hops") if isinstance(inner, dict) else None
        real_hops = max(0, len(blinded_hops or []) - 1)
        htlc_max = bp.get("htlc_max_msat") if isinstance(bp, dict) else None
        # When the Item-6 postprocess clamped the htlc_max, the
        # original LND-advertised value is stashed under
        # ``_htlc_max_msat_advertised``. Surface both so operators
        # see "advertised X, clamped to Y" at a glance.
        advertised = bp.get("_htlc_max_msat_advertised") if isinstance(bp, dict) else None
        htlc_max_display: Any
        if advertised is not None and advertised != htlc_max:
            htlc_max_display = f"{htlc_max} (clamped from {advertised})"
        else:
            htlc_max_display = htlc_max
        logger.info(
            "bolt12 responder: minted path %d offer=%s recv_id=%s "
            "intro=%s real_hops=%d base_fee=%s ppm=%s cltv_delta=%s "
            "htlc_min=%s htlc_max=%s",
            i,
            offer_label,
            recv_id,
            intro_prefix,
            real_hops,
            bp.get("base_fee_msat") if isinstance(bp, dict) else None,
            bp.get("proportional_fee_rate") if isinstance(bp, dict) else None,
            bp.get("total_cltv_delta") if isinstance(bp, dict) else None,
            bp.get("htlc_min_msat") if isinstance(bp, dict) else None,
            htlc_max_display,
        )


async def _postprocess_paths(
    raw_paths: list[dict],
    *,
    amount_msat: int,
) -> tuple[list[dict], dict | None]:
    """Item 6 + Follow-ups #1-#4 pipeline. Runs the clamp /
    drop / probe / diversity / breaker chain on the LND-returned
    paths.

    Returns ``(final_paths, paths_summary)``. ``paths_summary`` is
    the JSON shape to persist on ``Bolt12Invoice.blinded_paths_summary``
    so the watchdog + subscriber can update the breaker without
    decoding the bech32 invoice blob. Best-effort: any failure
    returns the raw paths unchanged with ``summary=None`` so the
    mint hot path is never blocked by postprocess machinery.

    KNOWN INEFFICIENCY: this function calls
    ``collect_channel_drift_snapshot``, which internally fetches
    ``get_channels`` + ``get_info`` + per-channel
    ``get_channel_edge``. The responder ALSO calls
    ``_maybe_capture_channel_snapshot`` immediately after, which
    calls ``collect_channel_drift_snapshot`` again. For an Ocean-
    cadence wallet (1 mint/day) this redundancy is negligible.
    For high-volume operators it doubles the LND round-trip cost
    per mint (3-4× Tor RTT). A future refactor should collect the
    LND context once at the responder level and thread it through
    both helpers; tracked as follow-up perf work.
    """
    try:
        from app.services.bolt12.path_diagnostics import (
            collect_channel_drift_snapshot,
        )
        from app.services.bolt12.path_postprocess import (
            postprocess_blinded_paths,
        )

        # Gather channel context for the clamp + probe stages.
        channels_raw, _err = await lnd_service.get_channels()
        if not channels_raw:
            return raw_paths, None
        # The clamp/probe pipeline treats channel dicts as open,
        # mutable maps (it enriches them with a gossiped htlc field
        # below). Cast to plain dicts so the extra key + the
        # postprocess call type-check; this is a no-op at runtime.
        channels: list[dict[str, Any]] = cast("list[dict[str, Any]]", channels_raw)
        info, _err = await lnd_service.get_info()
        our_pubkey = info.get("identity_pubkey", "") if isinstance(info, dict) else ""
        # Enrich channel dicts with gossiped inbound max_htlc msat
        # so the clamp's terminal-channel identifier can match by
        # gossiped value.
        drift_rows = await collect_channel_drift_snapshot(lnd_service)
        gossip_by_chan = {r.chan_id: r.gossiped_inbound_max_htlc_sat for r in drift_rows}
        for ch in channels:
            gossiped_sat = gossip_by_chan.get(ch.get("chan_id", ""))
            ch["gossiped_inbound_max_htlc_msat"] = gossiped_sat * 1000 if gossiped_sat is not None else None

        result = await postprocess_blinded_paths(
            raw_paths,
            amount_msat=amount_msat,
            lnd=lnd_service,
            channels=channels,
            our_pubkey=our_pubkey,
            max_paths=settings.bolt12_blinded_path_max_paths,
        )
        if not result.paths and raw_paths:
            # Postprocess filtered everything (most commonly: every
            # path's clamped htlc_max is below the requested amount).
            # Falling back to raw paths is strictly worse than the
            # postprocessed set when paths exist, but it's strictly
            # better than silently failing to mint — the payer will
            # discover the failure with a concrete error rather than
            # a silent timeout. Audit the drop reasons so operators
            # can see why this happened.
            logger.warning(
                "bolt12 responder: postprocess pipeline filtered ALL "
                "paths (drops=%s); reverting to raw LND paths so the "
                "invoice is still mintable",
                result.drops,
            )
            return raw_paths, None
        return result.paths, result.summary
    except Exception:  # noqa: BLE001 — never block the mint hot path
        logger.exception("bolt12 responder: path postprocess failed; using raw LND paths")
        return raw_paths, None


async def _maybe_flip_to_alt_depth(
    *,
    result: BlindedInvoiceResult,
    lnd_paths: list[dict],
    payment_hash: bytes,
    postprocessed_summary: dict | None,
    primary_num_hops: int,
    amount_msat: int,
    memo: str,
    max_num_paths: int,
    omit_pubkeys: list[bytes],
    log_label: str,
) -> tuple[BlindedInvoiceResult, list[dict], bytes, dict | None]:
    """Option B-adaptive (2026-06-08): if the primary depth's paths
    are ALL marked open by the breaker, retry at the alternative
    depth and pick whichever set has at least one healthy intro.
    Returns the (possibly-swapped) tuple of mint state. Shared by
    the offer-bound and offer-less responder branches so both
    benefit from the breaker-driven depth flip.

    On flip: cancels the primary's LND invoice so its r_hash
    doesn't sit stranded until expiry. On abort (alt also bad or
    alt's r_hash malformed): cancels the alt's r_hash and keeps
    primary. Either way the caller is guaranteed exactly one
    settleable invoice's worth of state in the returned tuple.
    """
    if not settings.bolt12_adaptive_depth_fallback_enabled or not lnd_paths:
        return result, lnd_paths, payment_hash, postprocessed_summary

    from app.services.bolt12.path_postprocess import all_intros_open

    if not all_intros_open(lnd_paths):
        return result, lnd_paths, payment_hash, postprocessed_summary

    alt_depth = 2 if primary_num_hops == 1 else 1
    logger.warning(
        "bolt12 responder: primary depth=%d had ALL intros marked open by breaker; trying alternative depth=%d (%s)",
        primary_num_hops,
        alt_depth,
        log_label,
    )
    alt_result, alt_err = await lnd_service.add_blinded_invoice(
        amount_msat,
        memo=memo,
        expiry=_DEFAULT_INVOICE_EXPIRY,
        num_hops=alt_depth,
        max_num_paths=max_num_paths,
        node_omission_pubkeys=omit_pubkeys,
    )
    if alt_err is not None or not alt_result:
        # Alt mint failed at the LND layer. Nothing to clean up
        # since LND didn't allocate an r_hash for us. Stay with
        # primary.
        return result, lnd_paths, payment_hash, postprocessed_summary

    alt_paths = alt_result.get("blinded_paths") or []
    alt_summary: dict | None = None
    if alt_paths:
        alt_paths, alt_summary = await _postprocess_paths(
            alt_paths,
            amount_msat=amount_msat,
        )

    # Decide whether to flip. We must validate the alt's
    # payment_hash BEFORE any side effects (cancelling primary,
    # swapping result/paths), otherwise a malformed alt r_hash
    # would leave the caller with primary's payment_hash but
    # alt's blinded paths and no primary invoice to settle
    # against — an unpayable invoice.
    flip_ok = bool(alt_paths) and not all_intros_open(alt_paths)
    alt_payment_hash: bytes | None = None
    if flip_ok:
        try:
            alt_payment_hash = bytes.fromhex(alt_result["r_hash"])
        except (KeyError, ValueError):
            logger.error(
                "bolt12 responder: adaptive alt-depth result has invalid r_hash; staying with primary (%s)",
                log_label,
            )
            flip_ok = False
        else:
            if len(alt_payment_hash) != 32:
                logger.error(
                    "bolt12 responder: adaptive alt-depth payment_hash "
                    "must be 32 bytes, got %d; staying with primary (%s)",
                    len(alt_payment_hash),
                    log_label,
                )
                flip_ok = False

    if flip_ok:
        assert alt_payment_hash is not None  # narrowed by flip_ok branch
        primary_r_hash = result.get("r_hash", "")
        if primary_r_hash:
            cancel_ok, cancel_err = await lnd_service.cancel_invoice(
                primary_r_hash,
            )
            if not cancel_ok:
                logger.info(
                    "bolt12 responder: failed to cancel primary-depth orphan invoice %s: %s (will expire naturally)",
                    primary_r_hash,
                    cancel_err,
                )
        try:
            from app.services.bolt12.runtime import (
                mark_adaptive_depth_flip,
            )

            mark_adaptive_depth_flip()
        except Exception:  # noqa: BLE001
            pass
        logger.warning(
            "bolt12 responder: adaptive flip succeeded — now using depth=%d for this mint (r_hash=%s) (%s)",
            alt_depth,
            alt_payment_hash.hex(),
            log_label,
        )
        return alt_result, alt_paths, alt_payment_hash, alt_summary

    # Alt unusable (no paths, all intros open, or malformed
    # r_hash). Cancel the alt's r_hash and keep primary.
    alt_r_hash = alt_result.get("r_hash", "")
    if alt_r_hash:
        try:
            await lnd_service.cancel_invoice(alt_r_hash)
        except Exception:  # noqa: BLE001
            pass
    logger.info(
        "bolt12 responder: adaptive flip aborted — alt depth=%d had no healthy paths; staying with primary (%s)",
        alt_depth,
        log_label,
    )
    return result, lnd_paths, payment_hash, postprocessed_summary


async def _maybe_capture_channel_snapshot() -> dict | None:
    """Telemetry #2: snapshot every active channel's balance +
    gossiped policy at mint time. Gated on
    ``BOLT12_CHANNEL_SNAPSHOT_AT_MINT_ENABLED`` (default on).

    Best-effort: any error returns ``None`` so the mint hot path
    is never blocked by a misbehaving graph-edge lookup. A
    missing snapshot is no worse than the pre-2026-06-05 baseline
    (when we had no snapshot at all).
    """
    if not settings.bolt12_channel_snapshot_at_mint_enabled:
        return None
    try:
        from app.services.bolt12.path_diagnostics import (
            capture_mint_time_channel_snapshot,
        )

        return await capture_mint_time_channel_snapshot(lnd_service)
    except Exception:  # noqa: BLE001
        logger.exception("bolt12 responder: channel snapshot capture failed — proceeding without telemetry")
        return None


async def _refetch_and_replay(
    db: AsyncSession,
    *,
    api_key_id: UUID,
    invreq_metadata_hex: str,
    ctx: "InboundInvreqContext",
) -> bytes | None:
    """Look up the prior (winning) inbound invreq row and replay its
    minted invoice bytes.

    Called from two places:

    1. **Initial idempotency check** — when the same ``invreq_metadata``
       has been seen and we have a non-expired invoice on file.
    2. **Race-loss recovery** — when two concurrent invreqs raced
       past the initial check and the DB partial unique index
       rejected our INSERT. The other branch already committed; we
       just need its bytes.

    Returns the encoded TLV stream ready for the gateway, or
    ``None`` if the row turns out to be missing / unparseable.

    NOTE: requires the session to be in a *clean* state (no
    PendingRollbackError). Caller is responsible for rolling back
    the failed transaction before calling.
    """
    prior_invreq = (
        await db.execute(
            select(Bolt12InvoiceRequest).where(
                Bolt12InvoiceRequest.api_key_id == api_key_id,
                Bolt12InvoiceRequest.invreq_metadata_hex == invreq_metadata_hex,
                Bolt12InvoiceRequest.direction == Bolt12Direction.INBOUND,
            )
        )
    ).scalar_one_or_none()
    if prior_invreq is None:
        return None
    prior_invoice = (
        await db.execute(select(Bolt12Invoice).where(Bolt12Invoice.invoice_request_id == prior_invreq.id))
    ).scalar_one_or_none()
    if prior_invoice is None or _invoice_expired(prior_invoice):
        return None
    try:
        replay_records = list(decode_bolt12(prior_invoice.invoice_bolt12).records)
    except Bolt12Error:
        logger.exception(
            "bolt12 responder: stored invoice failed to decode during replay for invreq %s (recv_id=%s)",
            prior_invreq.id,
            ctx.recv_id,
        )
        return None
    return tlv_encode_stream(replay_records)


# A "session factory" is anything callable that returns an async
# context manager yielding an ``AsyncSession``. Production uses
# :func:`app.core.database.get_db_context`; tests inject a factory
# backed by the in-memory SQLite engine the rest of the suite
# shares.
SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

# Public type alias for the orchestrator's ``InvoiceResponder`` shape,
# duplicated here so callers can type-annotate without importing the
# orchestrator.
ResponderFn = Callable[[InboundInvreqContext], Awaitable[bytes | None]]


def make_invreq_responder(
    session_factory: SessionFactory | None = None,
) -> ResponderFn:
    """Build the orchestrator's :class:`InvoiceResponder` callback.

    ``session_factory`` defaults to :func:`get_db_context` (the
    process-wide session maker keyed on the running event loop).
    Tests inject a factory backed by the same in-memory SQLite
    engine the rest of the test suite uses.
    """
    factory: SessionFactory = session_factory if session_factory is not None else get_db_context

    async def _responder(ctx: InboundInvreqContext) -> bytes | None:
        return await _respond_to_invreq(ctx, factory)

    return _responder


def _invreq_idempotency_key(invreq: InvoiceRequest) -> str:
    """Stable per-invreq idempotency key for inbound mint dedup.

    Prefers ``invreq_metadata`` — the BOLT 12 field a payer sets so a
    retried fetch yields the same invoice. A payer MAY omit it (CLN
    rotates ``invreq_payer_id`` and may send no metadata), which would
    otherwise skip dedup entirely and let each request mint a fresh LND
    invoice. In that case fall back to the invreq's signature digest
    (the merkle root over its non-signature TLVs — independent of the
    signature nonce, so two byte-identical signed invreqs map to one
    key), namespaced with ``sd:`` so it can never collide with a real
    metadata hex.
    """
    if invreq.metadata:
        return invreq.metadata.hex()
    return "sd:" + invreq.signature_digest().hex()


async def _respond_to_invreq(ctx: InboundInvreqContext, session_factory: SessionFactory) -> bytes | None:
    """Pure logic behind :func:`make_invreq_responder`.

    Returns TLV-encoded ``invoice`` bytes on success, or ``None``
    to silently drop the invreq.
    """
    # T2 (2026-06-12): one short trace_id per invreq flow. Threaded
    # into every audit row this responder emits AND persisted on
    # the ``Bolt12Invoice`` row so downstream observers (settle
    # watchdog, subscribers, reconcile) emit the same id without
    # threading state through their call sites. The contextvar set
    # here is read by ``_audit_inbound`` for the lifetime of this
    # asyncio task.
    from app.services.bolt12.trace import (
        new_trace_id,
        set_current_trace_id,
    )

    trace_id = new_trace_id()
    set_current_trace_id(trace_id)
    # ── Step 1: parse + verify the invreq ────────────────────────
    # Defence-in-depth size cap. Onion-message peers are
    # unauthenticated; without a hard cap, a hostile peer could
    # spray giant payloads to OOM the parser.
    payload_cap = settings.bolt12_max_payload_bytes
    if payload_cap > 0 and len(ctx.invreq_payload) > payload_cap:
        logger.warning(
            "bolt12 responder: oversized invreq recv_id=%s size=%d cap=%d",
            ctx.recv_id,
            len(ctx.invreq_payload),
            payload_cap,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invreq_oversized",
            api_key_id=None,
            amount_msat=None,
            success=False,
            error_message="payload_size_cap_exceeded",
            details={
                "recv_id": ctx.recv_id,
                "size": len(ctx.invreq_payload),
                "cap": payload_cap,
            },
        )
        return None

    try:
        records = tlv_decode_stream(
            ctx.invreq_payload,
            max_records=settings.bolt12_max_tlv_records or None,
            max_value_bytes=settings.bolt12_max_tlv_value_bytes or None,
        )
        invreq_b12 = Bolt12String(hrp="lnr", records=records)
        invreq = InvoiceRequest.parse(invreq_b12)
    except Bolt12Error as exc:
        logger.warning(
            "bolt12 responder: malformed invreq recv_id=%s: %s",
            ctx.recv_id,
            exc,
        )
        return None

    if not verify_invoice_request(invreq):
        logger.warning("bolt12 responder: invreq sig invalid recv_id=%s", ctx.recv_id)
        return None

    # Reject invreqs targeting a different chain than the wallet is
    # configured for. Without this a peer on regtest could send us
    # an invreq while we run on mainnet (or vice-versa) and we'd
    # mint a real invoice on the wrong network.
    if not accepts_chain(
        our_network=settings.bitcoin_network,
        invreq_chain=invreq.chain,
        offer_chains=invreq.offer.chains,
    ):
        logger.warning(
            "bolt12 responder: chain mismatch recv_id=%s our=%s invreq_chain=%s",
            ctx.recv_id,
            settings.bitcoin_network,
            invreq.chain.hex() if invreq.chain else None,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invreq_dropped",
            success=False,
            error_message="chain_mismatch",
            details={
                "recv_id": ctx.recv_id,
                "invreq_chain": invreq.chain.hex() if invreq.chain else None,
            },
        )
        return None

    # Sliding-window rate limit. Without this, any onion-message peer can
    # force the wallet to mint LND invoices in a tight loop. The per-peer key
    # (payer_id, else recv_id) is a courtesy bound only — onion-message
    # senders are anonymous and payer_id is freely rotatable — so the
    # per-offer key (issuer_id) and the global cap are the effective bounds.
    peer_key = invreq.payer_id.hex() if invreq.payer_id is not None else ctx.recv_id
    offer_key = invreq.offer.issuer_id.hex() if invreq.offer.issuer_id is not None else None
    allowed, reason, cap = await check_inbound_invreq_rate(peer_key, offer_key)
    if not allowed:
        # Truncate the counterparty key in durable log/audit output — a full
        # payer pubkey is a who-contacted-us identifier; the prefix is enough
        # to correlate retries during triage without persisting the full key.
        peer_short = peer_key[:16]
        logger.warning(
            "bolt12 responder: rate-limit drop recv_id=%s peer=%s… cap=%s reason=%s",
            ctx.recv_id,
            peer_short,
            cap,
            reason,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invreq_rate_limited",
            success=False,
            error_message=reason,
            details={"recv_id": ctx.recv_id, "peer": peer_short, "cap": cap},
        )
        try:
            from app.services.bolt12.runtime import mark_inbound_error

            mark_inbound_error(f"rate_limit:{cap or 'unknown'}")
        except Exception:  # noqa: BLE001
            pass
        return None

    issuer_id = invreq.offer.issuer_id
    if issuer_id is None:
        # Offer-less invreq: the peer is asking us to mint an invoice
        # without first scanning one of our offers (e.g. merchant-
        # issued refund or direct BOLT 12 payment). Off by default —
        # this widens our attack surface to any onion-message peer.
        if not settings.bolt12_accept_offerless_invreqs:
            logger.info(
                "bolt12 responder: dropping offer-less invreq (disabled) recv_id=%s",
                ctx.recv_id,
            )
            return None
        return await _respond_to_offerless_invreq(ctx, invreq, invreq_b12, session_factory)

    # ── Step 2: look up our offer + load issuer key ──────────────
    async with session_factory() as db:
        offer_row = (
            await db.execute(
                select(Bolt12Offer).where(
                    Bolt12Offer.issuer_id_hex == issuer_id.hex(),
                    Bolt12Offer.status == Bolt12OfferStatus.ACTIVE,
                    Bolt12Offer.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()

        if offer_row is None:
            logger.info(
                "bolt12 responder: no active offer matches issuer_id=%s recv_id=%s",
                issuer_id.hex(),
                ctx.recv_id,
            )
            # Audit-log this drop so post-mortems of "peer timed out
            # paying our offer" can be reconstructed from the DB
            # without scraping container logs. The most common
            # cause is the offer row having been removed (e.g. DB
            # restore, manual delete) while peers still hold the
            # cached offer string and keep sending invreqs for it.
            await _audit_inbound(
                session_factory,
                action="bolt12_invreq_unknown_offer",
                success=False,
                error_message="no_active_offer_matches_issuer_id",
                details={
                    "recv_id": ctx.recv_id,
                    "issuer_id_hex": issuer_id.hex(),
                    "payer_id_hex": (invreq.payer_id.hex() if invreq.payer_id is not None else None),
                    "invreq_amount_msat": invreq.amount,
                    "offer_amount_msat": invreq.offer.amount,
                    "payer_note": invreq.payer_note,
                },
            )
            return None

        if offer_row.encrypted_metadata is None:
            logger.error(
                "bolt12 responder: offer %s has no encrypted issuer key — cannot mint invoice",
                offer_row.id,
            )
            return None

        # Reject expired offers (informational; the spec leaves this
        # to issuer policy). SQLite drops the tzinfo on DateTime
        # round-trips, so coerce both sides to UTC-aware before
        # comparing.
        if offer_row.absolute_expiry is not None:
            expiry = offer_row.absolute_expiry
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                logger.info(
                    "bolt12 responder: offer %s past absolute_expiry; declining",
                    offer_row.id,
                )
                return None

        # ── Step 3: resolve + validate amount / quantity ─────────
        # Bound the quantity against the hard ceiling before resolving the
        # amount, so the ``pinned * quantity`` total is computed from a
        # quantity already known to be in range.
        if not _validate_quantity(invreq, offer_row):
            logger.info(
                "bolt12 responder: invreq quantity invalid for offer %s",
                offer_row.id,
            )
            return None

        amount_msat = _resolve_amount(invreq, offer_row)
        if amount_msat is None or amount_msat <= 0:
            logger.info(
                "bolt12 responder: cannot resolve amount for offer %s recv_id=%s",
                offer_row.id,
                ctx.recv_id,
            )
            return None

        # ── Step 3.5: idempotency on the invreq key ──────────────
        # BOLT 12 mandates that re-sending the same signed invreq
        # bytes yield the same invoice reply. Without dedup, an
        # attacker rotating ``payer_id`` per call (which the
        # rate-limiter keys on) can force unbounded LND invoice
        # mints. We dedupe on (api_key_id, invreq_metadata_hex); for
        # invreqs that omit ``invreq_metadata`` the key falls back to
        # the signature digest so the dedup is never skipped. The
        # partial unique index in migration 013 guarantees at most one
        # inbound row per key per tenant.
        invreq_metadata_hex = _invreq_idempotency_key(invreq)
        replay = await _refetch_and_replay(
            db,
            api_key_id=offer_row.api_key_id,
            invreq_metadata_hex=invreq_metadata_hex,
            ctx=ctx,
        )
        if replay is not None:
            logger.info(
                "bolt12 responder: idempotent replay for offer %s recv_id=%s",
                offer_row.id,
                ctx.recv_id,
            )
            return replay
        # Else: no prior row, or prior invoice expired / missing.
        # Fall through and mint a fresh one. The partial unique
        # index would block a second INSERT when two invreqs race
        # past this check; we catch the resulting IntegrityError
        # below and cancel our orphan LND invoice + replay the
        # winning peer's bytes.

        # Per-invoice amount cap. Even when an offer pinned a price,
        # operators may want a hard upper bound on inbound mints to
        # protect channel-capacity budgeting.
        max_msat = settings.bolt12_inbound_max_amount_msat
        if max_msat > 0 and amount_msat > max_msat:
            logger.warning(
                "bolt12 responder: amount cap exceeded offer=%s requested=%d cap=%d",
                offer_row.id,
                amount_msat,
                max_msat,
            )
            await _audit_inbound(
                session_factory,
                action="bolt12_invreq_amount_cap",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message="amount_cap_exceeded",
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                    "cap_msat": max_msat,
                },
            )
            return None

        # Absolute backstop on the resolved amount regardless of offer
        # type. ``amount_msat`` is the full total (``pinned * quantity`` for
        # fixed-price offers, the peer-supplied amount for open-amount
        # offers); the operator cap above can be disabled, so this ceiling
        # bounds every inbound mint.
        if amount_msat > _HARD_MAX_INBOUND_AMOUNT_MSAT:
            logger.warning(
                "bolt12 responder: hard amount ceiling exceeded offer=%s requested=%d ceiling=%d",
                offer_row.id,
                amount_msat,
                _HARD_MAX_INBOUND_AMOUNT_MSAT,
            )
            await _audit_inbound(
                session_factory,
                action="bolt12_invreq_amount_cap",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message="amount_hard_cap_exceeded",
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                    "ceiling_msat": _HARD_MAX_INBOUND_AMOUNT_MSAT,
                },
            )
            return None

        # ── Step 4: mint a payable LND blinded invoice ───────────
        memo = offer_row.description or invreq.offer.description or ""
        # Ocean (and most senders) wait ~60-90s for an invoice. Each
        # LND call via Tor takes ~5-30s on a healthy circuit, so we
        # have headroom for a couple of retries on transient Tor
        # failures (TTL expired, SOCKS error, etc.) before we burn
        # the sender's deadline. Non-Tor errors (LND auth, 4xx, etc.)
        # are NOT retried — they will not get better.
        #
        # Between Tor-classified failures we:
        #   * SIGNAL NEWNYM   — marks circuits dirty so the retry
        #                       builds a fresh path.
        #   * SIGNAL CLEARDNSCACHE — drop cached resolves that may
        #                       have been bound to the dirty circuit.
        #   * Backoff 1s, 3s  — gives Tor headroom to actually
        #                       finish a NEWNYM build (rate-limited
        #                       at 10s on Tor's side; calls inside
        #                       the rate-limit window are no-ops).
        result = None
        err: str | None = None
        attempts = 0
        _retry_backoffs = (1.0, 3.0)
        # Fix #3 (2026-06-06): per-offer ``min_real_hops_override``
        # supersedes the global setting. Set to ``1`` for non-
        # privacy-sensitive payers (e.g. Ocean) to eliminate the
        # intermediate blinded hop that was the failure point in
        # the 2026-06-05 and 2026-06-06 Ocean payouts.
        offer_override = getattr(offer_row, "min_real_hops_override", None)
        if offer_override is not None and offer_override >= 1:
            primary_num_hops = int(offer_override)
        else:
            primary_num_hops = max(1, settings.bolt12_blinded_path_min_real_hops)
        max_num_paths = max(1, min(8, settings.bolt12_blinded_path_max_paths))
        omit_pubkeys = settings.bolt12_blinded_path_omit_pubkeys
        for attempt in range(3):
            attempts = attempt + 1
            result, err = await lnd_service.add_blinded_invoice(
                amount_msat,
                memo=memo,
                expiry=_DEFAULT_INVOICE_EXPIRY,
                num_hops=primary_num_hops,
                max_num_paths=max_num_paths,
                node_omission_pubkeys=omit_pubkeys,
            )
            if err is None and result is not None:
                break
            if err is None or not _classify_tor_failure(err):
                break
            logger.warning(
                "bolt12 responder: LND add_blinded_invoice transient Tor failure (attempt %d/3): %s",
                attempts,
                err,
            )
            if attempt < len(_retry_backoffs):
                # Best-effort Tor circuit refresh. Failures here are
                # logged at DEBUG and never block the retry loop —
                # Tor will still build a fresh circuit on the next
                # SOCKS connection even if the SIGNAL call failed.
                try:
                    from app.services.anonymize.tor import (
                        signal_cleardnscache,
                        signal_newnym,
                    )

                    ok, sig_err = await signal_newnym(timeout_s=3.0)
                    if not ok:
                        logger.debug(
                            "bolt12 responder: NEWNYM failed (non-fatal): %s",
                            sig_err,
                        )
                    ok, sig_err = await signal_cleardnscache(timeout_s=3.0)
                    if not ok:
                        logger.debug(
                            "bolt12 responder: CLEARDNSCACHE failed (non-fatal): %s",
                            sig_err,
                        )
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "bolt12 responder: tor signal helper unavailable",
                        exc_info=True,
                    )
                await asyncio.sleep(_retry_backoffs[attempt])
        if err is not None or result is None:
            logger.error(
                "bolt12 responder: LND add_blinded_invoice failed after %d attempt(s): %s",
                attempts,
                err,
            )
            await _audit_inbound(
                session_factory,
                action="bolt12_invreq_lnd_mint_failed",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message=(err or "unknown")[:255],
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                    "attempts": attempts,
                    "tor_classified": _classify_tor_failure(err or ""),
                },
            )
            return None
        # Fallback: if LND succeeded at the configured hop count but
        # couldn't actually build any blinded paths (e.g. omission list
        # carved out every viable peer-of-peer, or the local graph
        # genuinely lacks a 2-real-hop option), re-mint at num_hops=1.
        # The first invoice stays OPEN on LND until expiry; that's a
        # small cost compared to silently returning an unpayable
        # invoice to the peer.
        fellback_to_1hop = False
        if primary_num_hops > 1 and not (result.get("blinded_paths") or []):
            logger.warning(
                "bolt12 responder: LND returned 0 blinded paths at num_hops=%d for offer %s — falling back to num_hops=1",
                primary_num_hops,
                offer_row.id,
            )
            result, err = await lnd_service.add_blinded_invoice(
                amount_msat,
                memo=memo,
                expiry=_DEFAULT_INVOICE_EXPIRY,
                num_hops=1,
                max_num_paths=max_num_paths,
                node_omission_pubkeys=omit_pubkeys,
            )
            fellback_to_1hop = True
            if err is not None or result is None:
                logger.error(
                    "bolt12 responder: 1-hop fallback add_blinded_invoice failed: %s",
                    err,
                )
                await _audit_inbound(
                    session_factory,
                    action="bolt12_invreq_lnd_mint_failed",
                    api_key_id=offer_row.api_key_id,
                    amount_msat=amount_msat,
                    success=False,
                    error_message=(err or "unknown")[:255],
                    details={
                        "recv_id": ctx.recv_id,
                        "offer_id": str(offer_row.id),
                        "fallback": True,
                    },
                )
                return None
        try:
            payment_hash = bytes.fromhex(result["r_hash"])
        except (KeyError, ValueError):
            logger.error("bolt12 responder: LND returned invalid r_hash")
            return None
        if len(payment_hash) != 32:
            logger.error(
                "bolt12 responder: payment_hash must be 32 bytes, got %d",
                len(payment_hash),
            )
            return None

        # ── Step 5: build + sign the BOLT 12 invoice ─────────────
        try:
            seed_hex = decrypt_field(offer_row.encrypted_metadata)
            signer = CoincurveSigner(bytes.fromhex(seed_hex))
        except Exception:  # noqa: BLE001
            logger.exception(
                "bolt12 responder: failed to load issuer signer for offer %s",
                offer_row.id,
            )
            # Audit-trail the decrypt failure so DB-tampering or
            # encryption-key rotation issues do not go undetected.
            await _audit_inbound(
                session_factory,
                action="bolt12_issuer_key_decrypt_failed",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message="issuer_key_decrypt_failed",
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                },
            )
            return None

        if signer.public_key != issuer_id:
            logger.error(
                "bolt12 responder: stored issuer key mismatch for offer %s",
                offer_row.id,
            )
            await _audit_inbound(
                session_factory,
                action="bolt12_issuer_key_mismatch",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message="issuer_key_mismatch",
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                },
            )
            return None

        # Encode LND's blinded_paths into BOLT 12 TLV bytes. The
        # spec requires invoice_paths to be present and non-empty
        # AND invoice_blindedpay to have exactly one payinfo per
        # path; if LND returned an empty list we cannot mint a
        # spec-compliant invoice and must drop.
        lnd_paths = result.get("blinded_paths") or []

        # Item 6 + Follow-ups #1-#4: postprocess pipeline.
        # Clamps each path's advertised htlc_max to the live
        # remote_balance (Item 6), drops paths smaller than the
        # request (Follow-up #1), probes liveness (Follow-up #2,
        # off by default), enforces intro diversity (Follow-up
        # #3), and deprioritises intros marked open by the
        # per-intro breaker (Follow-up #4).
        postprocessed_summary: dict | None = None
        if lnd_paths:
            lnd_paths, postprocessed_summary = await _postprocess_paths(
                lnd_paths,
                amount_msat=amount_msat,
            )

        # Option B-adaptive (2026-06-08): if the primary depth's
        # paths are ALL marked open by the breaker, retry at the
        # alternative depth and pick whichever set has at least
        # one healthy intro. Shared with the offer-less branch.
        # Skip when the 1-hop fallback already fired — we already
        # exhausted the depth>1 attempt and a fresh same-depth
        # mint would round-trip LND for nothing.
        if not fellback_to_1hop:
            (
                result,
                lnd_paths,
                payment_hash,
                postprocessed_summary,
            ) = await _maybe_flip_to_alt_depth(
                result=result,
                lnd_paths=lnd_paths,
                payment_hash=payment_hash,
                postprocessed_summary=postprocessed_summary,
                primary_num_hops=primary_num_hops,
                amount_msat=amount_msat,
                memo=memo,
                max_num_paths=max_num_paths,
                omit_pubkeys=omit_pubkeys,
                log_label=f"offer={offer_row.id}",
            )

        _log_blinded_path_policy(
            lnd_paths,
            offer_label=str(offer_row.id),
            recv_id=ctx.recv_id,
        )
        try:
            paths_bytes, blindedpay_bytes = encode_invoice_paths(lnd_paths)
        except (ValueError, TypeError) as exc:
            logger.exception(
                "bolt12 responder: failed to encode LND blinded_paths for offer %s",
                offer_row.id,
            )
            await _audit_inbound(
                session_factory,
                action="bolt12_invreq_encode_paths_failed",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message=str(exc)[:512],
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                    "num_lnd_paths": len(lnd_paths),
                    "exc_type": type(exc).__name__,
                },
            )
            return None

        unsigned_invoice = Invoice(
            invreq=invreq,
            paths=paths_bytes,
            blindedpay=blindedpay_bytes,
            created_at=int(time.time()),
            relative_expiry=_DEFAULT_INVOICE_EXPIRY,
            payment_hash=payment_hash,
            amount=amount_msat,
            node_id=signer.public_key,
        )
        try:
            signed_invoice = sign_invoice(unsigned_invoice, signer)
            invoice_bolt12 = encode_bolt12(signed_invoice.to_bolt12_string())
            invoice_bytes = tlv_encode_stream(signed_invoice.to_records())
        except (Bolt12Error, ValueError):
            logger.exception(
                "bolt12 responder: failed to encode signed invoice for offer %s",
                offer_row.id,
            )
            return None

        # Defensive envelope cap: an encoded invoice larger than the
        # gateway's onion-message reply envelope gets silently dropped
        # at the wire. Drop with an audit row here so the operator can
        # tell the difference between "payer timed out" and "we minted
        # bytes that never went out."
        if len(invoice_bytes) > settings.bolt12_max_outbound_invoice_bytes:
            logger.warning(
                "bolt12 responder: encoded invoice %d bytes exceeds outbound "
                "cap %d for offer %s — dropping (likely too many blinded "
                "paths or oversized description)",
                len(invoice_bytes),
                settings.bolt12_max_outbound_invoice_bytes,
                offer_row.id,
            )
            await _audit_inbound(
                session_factory,
                action="bolt12_invreq_invoice_too_large",
                api_key_id=offer_row.api_key_id,
                amount_msat=amount_msat,
                success=False,
                error_message="invoice_envelope_exceeded",
                details={
                    "recv_id": ctx.recv_id,
                    "offer_id": str(offer_row.id),
                    "invoice_bytes_len": len(invoice_bytes),
                    "cap": settings.bolt12_max_outbound_invoice_bytes,
                },
            )
            return None

        # ── Step 6: persist audit rows ───────────────────────────
        # Capture the offer's primary/foreign-key fields into locals
        # BEFORE the try block. A failed commit + rollback inside the
        # block expires every ORM attribute on ``offer_row``; later
        # attribute access then triggers a lazy reload which raises
        # ``MissingGreenlet`` in the async session. Pinning the
        # values up-front keeps the post-rollback paths greenlet-
        # safe.
        offer_api_key_id = offer_row.api_key_id
        offer_id_value = offer_row.id
        offer_bolt12_value = offer_row.bolt12

        # Telemetry #2: capture channel state at mint time so a
        # post-mortem of "Ocean paid X-sat HTLC and it failed at
        # 10:15 UTC three days ago" has the channel state from
        # *that exact moment*, not "whatever it is now". Disabled
        # via setting; best-effort (None on any failure).
        channel_snapshot = await _maybe_capture_channel_snapshot()

        try:
            invreq_row = Bolt12InvoiceRequest(
                api_key_id=offer_api_key_id,
                offer_id=offer_id_value,
                direction=Bolt12Direction.INBOUND,
                offer_bolt12=offer_bolt12_value,
                amount_msat=amount_msat,
                quantity=invreq.quantity,
                payer_note=invreq.payer_note,
                payer_id_hex=(invreq.payer_id.hex() if invreq.payer_id is not None else None),
                invreq_metadata_hex=invreq_metadata_hex,
                # We do not hold the payer's private key on inbound.
                encrypted_payer_secret=None,
                invreq_bolt12=encode_bolt12(invreq_b12),
                status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
            )
            db.add(invreq_row)
            await db.flush()
            invoice_row = Bolt12Invoice(
                api_key_id=offer_api_key_id,
                invoice_request_id=invreq_row.id,
                direction=Bolt12Direction.INBOUND,
                invoice_bolt12=invoice_bolt12,
                amount_msat=amount_msat,
                payment_hash_hex=payment_hash.hex(),
                node_id_hex=signer.public_key.hex(),
                status=Bolt12InvoiceStatus.OPEN,
                channel_state_snapshot=channel_snapshot,
                # T2 (2026-06-12): persist trace_id alongside the
                # paths summary so downstream observers can grep
                # the chain without re-deriving the link.
                blinded_paths_summary=({**(postprocessed_summary or {}), "trace_id": trace_id}),
            )
            db.add(invoice_row)
            await db.commit()
        except IntegrityError:
            # Two distinct cases collapse onto the same
            # ``(api_key_id, invreq_metadata_hex)`` unique violation:
            #
            #   (a) Race-loss: a concurrent invreq with the same
            #       metadata raced past Step 3.5's dedup check and
            #       won the INSERT first. The prior row is OPEN
            #       and non-expired; we must cancel our orphan
            #       LND mint and replay the winner's bytes.
            #
            #   (b) Intentional re-mint: the prior row exists but
            #       is in FAILED / EXPIRED status (or its OPEN
            #       expiry elapsed). Step 3.5's
            #       ``_refetch_and_replay`` returned ``None``, the
            #       caller fell through to mint fresh, and the
            #       unique index fired on the new INSERT. We need
            #       to keep our new LND mint and let the peer
            #       have the fresh invoice — same wire contract as
            #       the existing "persist failed → return bytes
            #       anyway" branch below.
            #
            # Distinguish by re-inspecting the prior row. Race-loss
            # is the only case where the prior row should pass
            # ``_invoice_expired``'s replay test.
            await db.rollback()
            replay = None
            if invreq_metadata_hex is not None:
                replay = await _refetch_and_replay(
                    db,
                    api_key_id=offer_api_key_id,
                    invreq_metadata_hex=invreq_metadata_hex,
                    ctx=ctx,
                )
            if replay is not None:
                # Case (a): race-loss. Cancel orphan + replay
                # winner.
                logger.info(
                    "bolt12 responder: concurrent-invreq race detected "
                    "(offer=%s recv_id=%s payment_hash=%s) — cancelling "
                    "orphan LND invoice and replaying winner's bytes",
                    offer_id_value,
                    ctx.recv_id,
                    payment_hash.hex(),
                )
                cancel_ok, cancel_err = await lnd_service.cancel_invoice(payment_hash.hex())
                if not cancel_ok:
                    logger.warning(
                        "bolt12 responder: cancel of orphan invoice %s failed: %s (invoice will expire naturally)",
                        payment_hash.hex(),
                        cancel_err,
                    )
                await _audit_inbound(
                    session_factory,
                    action="bolt12_invreq_race_lost",
                    api_key_id=offer_api_key_id,
                    amount_msat=amount_msat,
                    success=False,
                    error_message="concurrent_invreq_race",
                    details={
                        "recv_id": ctx.recv_id,
                        "offer_id": str(offer_id_value),
                        "orphan_payment_hash": payment_hash.hex(),
                        "orphan_cancelled": cancel_ok,
                    },
                )
                return replay
            # Case (b): prior row is non-replayable (FAILED /
            # EXPIRED / OPEN-past-expiry). The new LND mint is
            # the one the peer should pay; we just couldn't
            # update our local index. Log + fall through to the
            # success path so the wire reply isn't dropped. The
            # next reconcile pass will project the LND-side
            # state onto the (stale) row.
            logger.warning(
                "bolt12 responder: persist conflicted with prior "
                "non-replayable row for invreq_metadata %s — "
                "returning fresh invoice bytes, DB index will "
                "remain stale until next reconcile (offer=%s "
                "recv_id=%s payment_hash=%s)",
                invreq_metadata_hex,
                offer_id_value,
                ctx.recv_id,
                payment_hash.hex(),
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "bolt12 responder: persist failed for offer %s — still returning invoice to peer",
                offer_id_value,
            )
            # Don't drop the wire reply just because audit-log
            # writes hit a transient DB error. The peer already
            # has a valid invoice on the way.
            await db.rollback()

        payer_note_truncated = (invreq.payer_note or "")[:200]
        logger.info(
            "bolt12 responder: minted invoice for offer %s amount=%d recv_id=%s payer_note=%r",
            offer_id_value,
            amount_msat,
            ctx.recv_id,
            payer_note_truncated,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invoice_minted",
            api_key_id=offer_api_key_id,
            amount_msat=amount_msat,
            success=True,
            details={
                "recv_id": ctx.recv_id,
                "offer_id": str(offer_id_value),
                "payment_hash": payment_hash.hex(),
                "payer_note": payer_note_truncated,
                "payer_id_hex": (invreq.payer_id.hex() if invreq.payer_id is not None else None),
            },
        )
        try:
            from app.services.bolt12.runtime import mark_inbound_mint_success

            mark_inbound_mint_success()
        except Exception:  # noqa: BLE001 — never block the mint hot path
            pass
        return invoice_bytes


async def _respond_to_offerless_invreq(
    ctx: InboundInvreqContext,
    invreq: InvoiceRequest,
    invreq_b12: Bolt12String,
    session_factory: SessionFactory,
) -> bytes | None:
    """Mint an invoice for an invreq that does **not** reference one
    of our offers.

    The invoice is signed by a fresh ephemeral key (no stable issuer
    identity is exposed) and the resulting rows are attributed to
    the dashboard sentinel API key with ``offer_id=None``.

    Returns ``None`` to silently drop on any policy/LND/encoding
    error — same contract as :func:`_respond_to_invreq`.
    """
    # Offer-less invreqs must carry an explicit amount (BOLT 12
    # §"Requirements for the Sender": "MUST set invreq_amount").
    amount_msat = invreq.amount
    if amount_msat is None or amount_msat <= 0:
        logger.info(
            "bolt12 responder: offer-less invreq missing/invalid amount recv_id=%s",
            ctx.recv_id,
        )
        return None

    # Hard amount cap also applies to offer-less mints — the same
    # tail-risk argument as the offer-bound path, with the added
    # twist that anyone can hit this code path.
    max_msat = settings.bolt12_inbound_max_amount_msat
    if max_msat > 0 and amount_msat > max_msat:
        logger.warning(
            "bolt12 responder: offer-less amount cap exceeded requested=%d cap=%d",
            amount_msat,
            max_msat,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invreq_amount_cap",
            amount_msat=amount_msat,
            success=False,
            error_message="amount_cap_exceeded",
            details={"recv_id": ctx.recv_id, "cap_msat": max_msat, "offerless": True},
        )
        return None

    # Absolute backstop: offer-less mints are fully peer-controlled and
    # the operator cap above may be disabled, so enforce the hard ceiling
    # unconditionally.
    if amount_msat > _HARD_MAX_INBOUND_AMOUNT_MSAT:
        logger.warning(
            "bolt12 responder: offer-less hard amount ceiling exceeded requested=%d ceiling=%d",
            amount_msat,
            _HARD_MAX_INBOUND_AMOUNT_MSAT,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invreq_amount_cap",
            amount_msat=amount_msat,
            success=False,
            error_message="amount_hard_cap_exceeded",
            details={
                "recv_id": ctx.recv_id,
                "ceiling_msat": _HARD_MAX_INBOUND_AMOUNT_MSAT,
                "offerless": True,
            },
        )
        return None

    # Idempotency on ``invreq_metadata``, same contract as the
    # offer-bound path: re-sending the same signed invreq bytes must
    # yield the same invoice. Offer-less mints are attributed to the
    # dashboard sentinel key, so they share the
    # ``(api_key_id, invreq_metadata_hex)`` partial unique index under
    # that tenant. Without this a peer rotating ``payer_id`` per call —
    # which the per-peer rate limiter keys on — could force unbounded
    # LND invoice mints.
    from app.dashboard import DASHBOARD_KEY_ID

    invreq_metadata_hex = _invreq_idempotency_key(invreq)
    async with session_factory() as db:
        replay = await _refetch_and_replay(
            db,
            api_key_id=DASHBOARD_KEY_ID,
            invreq_metadata_hex=invreq_metadata_hex,
            ctx=ctx,
        )
    if replay is not None:
        logger.info(
            "bolt12 responder: idempotent replay for offer-less invreq recv_id=%s",
            ctx.recv_id,
        )
        return replay

    # Mint the LND blinded invoice that will actually receive
    # payment.
    memo = invreq.payer_note or "BOLT 12 direct payment"
    primary_num_hops = max(1, settings.bolt12_blinded_path_min_real_hops)
    max_num_paths = max(1, min(8, settings.bolt12_blinded_path_max_paths))
    omit_pubkeys = settings.bolt12_blinded_path_omit_pubkeys
    result, err = await lnd_service.add_blinded_invoice(
        amount_msat,
        memo=memo,
        expiry=_DEFAULT_INVOICE_EXPIRY,
        num_hops=primary_num_hops,
        max_num_paths=max_num_paths,
        node_omission_pubkeys=omit_pubkeys,
    )
    if err is not None or result is None:
        logger.error(
            "bolt12 responder: LND add_blinded_invoice failed (offer-less): %s",
            err,
        )
        return None
    # See offer-bound path: fall back to num_hops=1 when LND succeeded
    # but couldn't build any path at the configured hop count.
    fellback_to_1hop = False
    if primary_num_hops > 1 and not (result.get("blinded_paths") or []):
        logger.warning(
            "bolt12 responder: LND returned 0 blinded paths at num_hops=%d (offer-less) — falling back to num_hops=1",
            primary_num_hops,
        )
        result, err = await lnd_service.add_blinded_invoice(
            amount_msat,
            memo=memo,
            expiry=_DEFAULT_INVOICE_EXPIRY,
            num_hops=1,
            max_num_paths=max_num_paths,
            node_omission_pubkeys=omit_pubkeys,
        )
        fellback_to_1hop = True
        if err is not None or result is None:
            logger.error(
                "bolt12 responder: 1-hop fallback add_blinded_invoice failed (offer-less): %s",
                err,
            )
            return None
    try:
        payment_hash = bytes.fromhex(result["r_hash"])
    except (KeyError, ValueError):
        logger.error("bolt12 responder: LND returned invalid r_hash (offer-less)")
        return None
    if len(payment_hash) != 32:
        logger.error(
            "bolt12 responder: payment_hash must be 32 bytes (offer-less), got %d",
            len(payment_hash),
        )
        return None

    lnd_paths = result.get("blinded_paths") or []

    # Item 6 + Follow-ups #1-#4: same postprocess pipeline as the
    # offer-bound branch — see the comment there.
    postprocessed_summary_offerless: dict | None = None
    if lnd_paths:
        lnd_paths, postprocessed_summary_offerless = await _postprocess_paths(
            lnd_paths,
            amount_msat=amount_msat,
        )

    # Option B-adaptive (2026-06-08): same breaker-driven depth
    # flip as the offer-bound branch — see ``_maybe_flip_to_alt_depth``.
    # Skip when the 1-hop fallback already fired (same reason).
    if not fellback_to_1hop:
        (
            result,
            lnd_paths,
            payment_hash,
            postprocessed_summary_offerless,
        ) = await _maybe_flip_to_alt_depth(
            result=result,
            lnd_paths=lnd_paths,
            payment_hash=payment_hash,
            postprocessed_summary=postprocessed_summary_offerless,
            primary_num_hops=primary_num_hops,
            amount_msat=amount_msat,
            memo=memo,
            max_num_paths=max_num_paths,
            omit_pubkeys=omit_pubkeys,
            log_label="(offerless)",
        )

    _log_blinded_path_policy(
        lnd_paths,
        offer_label="(offerless)",
        recv_id=ctx.recv_id,
    )
    try:
        paths_bytes, blindedpay_bytes = encode_invoice_paths(lnd_paths)
    except (ValueError, TypeError):
        logger.exception("bolt12 responder: failed to encode LND blinded_paths (offer-less)")
        return None

    # Fresh per-invoice signing key — BOLT 12 lets the recipient
    # pick any key here, and a transient one keeps recurring offer-
    # less payers from being able to link payments to a stable
    # wallet identity.
    signer = CoincurveSigner.generate()

    unsigned_invoice = Invoice(
        invreq=invreq,
        paths=paths_bytes,
        blindedpay=blindedpay_bytes,
        created_at=int(time.time()),
        relative_expiry=_DEFAULT_INVOICE_EXPIRY,
        payment_hash=payment_hash,
        amount=amount_msat,
        node_id=signer.public_key,
    )
    try:
        signed_invoice = sign_invoice(unsigned_invoice, signer)
        invoice_bolt12 = encode_bolt12(signed_invoice.to_bolt12_string())
        invoice_bytes = tlv_encode_stream(signed_invoice.to_records())
    except (Bolt12Error, ValueError):
        logger.exception("bolt12 responder: failed to encode signed offer-less invoice")
        return None

    # Defensive envelope cap (same rationale as the offer-bound path).
    if len(invoice_bytes) > settings.bolt12_max_outbound_invoice_bytes:
        logger.warning(
            "bolt12 responder: encoded offer-less invoice %d bytes exceeds outbound cap %d — dropping",
            len(invoice_bytes),
            settings.bolt12_max_outbound_invoice_bytes,
        )
        await _audit_inbound(
            session_factory,
            action="bolt12_invreq_invoice_too_large",
            amount_msat=amount_msat,
            success=False,
            error_message="invoice_envelope_exceeded",
            details={
                "recv_id": ctx.recv_id,
                "offerless": True,
                "invoice_bytes_len": len(invoice_bytes),
                "cap": settings.bolt12_max_outbound_invoice_bytes,
            },
        )
        return None

    # Attribute the inbound payment to the dashboard sentinel key
    # (offer-less invreqs aren't tied to any user-issued offer).
    # Telemetry #2: same as offer-bound branch.
    channel_snapshot = await _maybe_capture_channel_snapshot()

    async with session_factory() as db:
        try:
            invreq_row = Bolt12InvoiceRequest(
                api_key_id=DASHBOARD_KEY_ID,
                offer_id=None,
                direction=Bolt12Direction.INBOUND,
                offer_bolt12=None,
                amount_msat=amount_msat,
                quantity=invreq.quantity,
                payer_note=invreq.payer_note,
                payer_id_hex=(invreq.payer_id.hex() if invreq.payer_id is not None else None),
                invreq_metadata_hex=invreq_metadata_hex,
                encrypted_payer_secret=None,
                invreq_bolt12=encode_bolt12(invreq_b12),
                status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
            )
            db.add(invreq_row)
            await db.flush()
            invoice_row = Bolt12Invoice(
                api_key_id=DASHBOARD_KEY_ID,
                invoice_request_id=invreq_row.id,
                direction=Bolt12Direction.INBOUND,
                invoice_bolt12=invoice_bolt12,
                amount_msat=amount_msat,
                payment_hash_hex=payment_hash.hex(),
                node_id_hex=signer.public_key.hex(),
                status=Bolt12InvoiceStatus.OPEN,
                channel_state_snapshot=channel_snapshot,
                blinded_paths_summary=postprocessed_summary_offerless,
            )
            db.add(invoice_row)
            await db.commit()
        except IntegrityError:
            # A concurrent invreq with the same metadata won the
            # ``(api_key_id, invreq_metadata_hex)`` unique index. If its
            # invoice is still replayable, cancel our orphan LND mint and
            # return the winner's bytes; otherwise keep our fresh mint and
            # return it (the wire reply must not be dropped).
            await db.rollback()
            replay = None
            if invreq_metadata_hex is not None:
                replay = await _refetch_and_replay(
                    db,
                    api_key_id=DASHBOARD_KEY_ID,
                    invreq_metadata_hex=invreq_metadata_hex,
                    ctx=ctx,
                )
            if replay is not None:
                cancel_ok, cancel_err = await lnd_service.cancel_invoice(payment_hash.hex())
                if not cancel_ok:
                    logger.warning(
                        "bolt12 responder: cancel of orphan offer-less invoice %s failed: %s",
                        payment_hash.hex(),
                        cancel_err,
                    )
                logger.info(
                    "bolt12 responder: concurrent offer-less invreq race (recv_id=%s) — replaying winner's bytes",
                    ctx.recv_id,
                )
                return replay
            logger.warning(
                "bolt12 responder: offer-less persist conflicted with a non-replayable row "
                "(recv_id=%s payment_hash=%s) — returning fresh invoice bytes",
                ctx.recv_id,
                payment_hash.hex(),
            )
        except Exception:  # noqa: BLE001
            logger.exception("bolt12 responder: persist failed for offer-less invreq — still returning invoice to peer")
            await db.rollback()

    payer_note_truncated = (invreq.payer_note or "")[:200]
    logger.info(
        "bolt12 responder: minted offer-less invoice amount=%d recv_id=%s payer_note=%r",
        amount_msat,
        ctx.recv_id,
        payer_note_truncated,
    )
    await _audit_inbound(
        session_factory,
        action="bolt12_invoice_minted",
        amount_msat=amount_msat,
        success=True,
        details={
            "recv_id": ctx.recv_id,
            "offerless": True,
            "payment_hash": payment_hash.hex(),
            "payer_note": payer_note_truncated,
            "payer_id_hex": (invreq.payer_id.hex() if invreq.payer_id is not None else None),
        },
    )
    try:
        from app.services.bolt12.runtime import mark_inbound_mint_success

        mark_inbound_mint_success()
    except Exception:  # noqa: BLE001 — never block the mint hot path
        pass
    return invoice_bytes


def _resolve_amount(invreq: InvoiceRequest, offer_row: Bolt12Offer) -> int | None:
    """Pick the amount (msat) for the invoice we'll mint.

    The pinned price is taken from the TRUSTED DB row
    (``offer_row.amount_msat``), never from the peer-supplied mirrored
    ``invreq.offer.amount`` — the mirrored offer fields are signed only by
    the peer's transient payer key, so trusting them would let a peer
    override the price we set on a fixed-price offer.

      * Fixed-price offer (``offer_row.amount_msat`` set): charge
        ``pinned * quantity``. If the invreq also carries an amount it
        MUST equal that total (the payer doesn't get to underpay).
      * Open-amount offer (no pinned price): the invreq MUST carry a
        positive amount, which is the total to mint.
      * Otherwise the invreq is malformed → ``None``.
    """
    pinned = offer_row.amount_msat
    inv_amt = invreq.amount

    if pinned is not None:
        quantity = invreq.quantity if invreq.quantity is not None else 1
        if quantity < 1:
            return None
        total = pinned * quantity
        if inv_amt is not None and inv_amt != total:
            return None
        return total

    # Open-amount offer — the invreq must supply the total.
    if inv_amt is None or inv_amt <= 0:
        return None
    return inv_amt


def _validate_quantity(invreq: InvoiceRequest, offer_row: Bolt12Offer) -> bool:
    """Enforce ``offer_quantity_max`` if set.

    A quantity of zero is never valid. If the offer didn't set
    ``quantity_max`` then any quantity up to a hard defensive ceiling is
    fine.

    A fixed-price offer with no
    ``quantity_max`` mints ``pinned * quantity``, bounded only by the
    ``bolt12_inbound_max_amount_msat`` cap — which an operator can
    disable by setting it to 0. Apply a hard quantity ceiling here so a
    peer can't drive an unbounded mint via quantity even when the amount
    cap is off.
    """
    q = invreq.quantity
    if q is None:
        return True
    if q < 1:
        return False
    if q > _HARD_QUANTITY_MAX:
        return False
    qmax = offer_row.quantity_max
    if qmax is None:
        return True
    return q <= qmax


async def _audit_inbound(
    session_factory: SessionFactory,
    *,
    action: str,
    success: bool,
    api_key_id: object | None = None,
    api_key_name: str = "__bolt12_inbound__",
    amount_msat: int | None = None,
    error_message: str | None = None,
    details: dict | None = None,
) -> None:
    """Best-effort audit-row emit for inbound BOLT 12 events.

    The receive side has no API-key boundary, so we attribute by
    default to the dashboard sentinel ``APIKey``. Callers may pass
    a different ``api_key_id`` (e.g. the offer-row's owner) when
    the invreq matched a wallet-issued offer.

    Failures are *swallowed* — an audit-log write going wrong must
    never alter the responder's wire behaviour.
    """
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.audit_log import AuditLog
    from app.services.audit_service import _finalize_entry

    # T2 (2026-06-12): auto-merge trace_id from the contextvar so
    # callers don't have to thread it through every audit site.
    from app.services.bolt12.trace import get_current_trace_id

    trace_id = get_current_trace_id()
    if trace_id is not None:
        merged_details = dict(details or {})
        merged_details.setdefault("trace_id", trace_id)
        details = merged_details

    try:
        async with session_factory() as db:
            entry = AuditLog(
                api_key_id=api_key_id or DASHBOARD_KEY_ID,
                api_key_name=api_key_name,
                action=action,
                resource="bolt12_inbound",
                details=details,
                amount_sats=(amount_msat // 1000) if amount_msat is not None else None,
                success=success,
                error_message=error_message,
                ip_address=None,
            )
            await _finalize_entry(db, entry)
    except Exception:  # noqa: BLE001
        logger.exception("bolt12 responder: failed to write audit row")


__all__ = [
    "ResponderFn",
    "SessionFactory",
    "make_invreq_responder",
]
