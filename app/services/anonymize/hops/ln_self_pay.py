# SPDX-License-Identifier: MIT
"""Self-pay across own channel(s) with delay — Lightning self-source.

The ``lightning-self`` source funds the mix by paying an invoice the
wallet mints to itself — a circular self-payment that reshuffles
balance across the wallet's own channels. It leaves through one
pinned channel (``outgoing_chan_id``, MPP off) or fans out across
several (``max_parts`` with an ``ignored_pairs`` blocklist, MPP on);
the two modes are mutually exclusive (see :mod:`..self_pay_routing`).
The reshuffle rewrites the channel-balance fingerprint before the
reverse-swap exit so the on-chain exit output does not map cleanly
onto the pre-mix channel state.

The self-payment settles instantly; the intra-mix delay (LN-side
default ``Uniform(1h, 6h)``) is the session's dwell in ``DELAYING``,
managed by the orchestrator, not a held HTLC.

The body dispatches by status:

* ``FUNDING`` — mint the invoice (reused on retry), resolve the
  routing mode, and fire the self-payment. The gate from ``FUNDING``
  to ``LN_HOLDING`` is the observer reading ``self_pay_status`` =
  ``settled``, so the session only advances once the payment lands.
* ``LN_HOLDING`` — no-op; the payment already settled to reach here.

The self-payment is an LN payment, so LND deduplicates it by payment
hash: re-firing the same invoice is safe, and a transient send
failure simply retries on the next tick (the per-session loop's
bounded-retry budget escalates a persistent failure to
reconciliation). A ``lookup_invoice`` at the top of the fire step
catches the case where a prior tick's payment settled but the process
died before the outcome was recorded.

Production wires the adapters in :class:`LnSelfPayHopDeps` to the
wallet's ``LNDService`` plus the routing resolver; tests inject mocks
so the body runs without a live LND.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..hop_idempotency import (
    HopAttemptKey,
    has_hop_attempt_completed,
    make_hop_idempotency_key,
    record_hop_attempt_completed,
    record_hop_attempt_started,
)
from ..metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


@dataclass
class LnSelfPayHopDeps:
    """Adapters the self-pay hop body calls into.

    Tests inject mocks; production binds them to the wallet's
    ``LNDService`` + routing resolver. Each adapter returns
    ``(result, error)`` so the body records outcomes without raising
    into the per-session loop's bounded-retry budget.
    """

    lnd_add_invoice: Callable[..., Awaitable[tuple[Any, Any]]]
    lnd_send_self_payment: Callable[..., Awaitable[tuple[Any, Any]]]
    lnd_lookup_invoice: Callable[..., Awaitable[tuple[Any, Any]]]
    # Returns (SelfPayRoute, error). The route carries the mode and
    # either outgoing_chan_id (pinned) or max_parts + ignored_pairs
    # (split).
    resolve_self_pay_route: Callable[..., Awaitable[tuple[Any, Any]]]


@dataclass(frozen=True)
class LnSelfPayHopOutcome:
    """Result of one self-pay-hop step."""

    kind: str  # 'noop' | 'fired_self_pay' | 'error'
    detail: str = ""


_NOOP = LnSelfPayHopOutcome(kind="noop")


def _key_for(session: AnonymizeSession, hop_kind: str, attempt: int) -> HopAttemptKey:
    """Build a :class:`HopAttemptKey` for a self-pay hop step."""
    sid_bytes = (
        session.id.bytes
        if hasattr(session.id, "bytes")
        else hashlib.blake2b(str(session.id).encode("utf-8"), digest_size=16).digest()
    )
    stable_nonce = hashlib.blake2b(
        b"%s|%s|%d" % (sid_bytes, hop_kind.encode("utf-8"), attempt),
        digest_size=16,
    ).digest()
    key_str = make_hop_idempotency_key(
        key_bytes=b"\x00" * 32,
        nonce=stable_nonce,
        session_id=sid_bytes,
        hop_index=0,
        hop_kind=hop_kind,
        attempt=attempt,
    )
    return HopAttemptKey(
        session_id=session.id,
        hop_index=0,
        hop_kind=hop_kind,
        attempt=attempt,
        idempotency_key=key_str,
        nonce=stable_nonce,
        key_generation=0,
    )


def _mark_settled(session: AnonymizeSession) -> None:
    pj = dict(session.pipeline_json or {})
    pj["self_pay_status"] = "settled"
    pj.setdefault("self_pay_fired_at_ts", datetime.now(timezone.utc).isoformat())
    session.pipeline_json = pj


def _invoice_settled(info: Any) -> bool:
    if isinstance(info, dict):
        return bool(info.get("settled"))
    return bool(getattr(info, "settled", False))


async def execute_ln_self_pay_hop_step(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LnSelfPayHopDeps,
) -> LnSelfPayHopOutcome:
    """One per-session tick of the self-pay-hop body.

    Owns the ``FUNDING`` and ``LN_HOLDING`` source states; the exit
    (``EXITING`` / ``CONFIRMING``) is the reverse hop's.
    """
    if session.status == AnonymizeStatus.FUNDING.value:
        return await _step_fire_self_pay(db, session, deps)
    if session.status == AnonymizeStatus.LN_HOLDING.value:
        # The self-pay settled to reach LN_HOLDING; nothing to do. The
        # tick advances LN_HOLDING → DELAYING unconditionally.
        return LnSelfPayHopOutcome(kind="noop", detail="ln_holding")
    return _NOOP


async def _step_fire_self_pay(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LnSelfPayHopDeps,
) -> LnSelfPayHopOutcome:
    """Mint the invoice + fire the circular self-payment.

    Idempotent: a settled invoice (recorded outcome, persisted status,
    or a live ``lookup_invoice``) short-circuits to no-op. Re-firing the
    same invoice is safe because LND deduplicates the payment by hash.
    """
    pj = session.pipeline_json or {}
    if not isinstance(pj, dict):
        return LnSelfPayHopOutcome(kind="error", detail="malformed_pipeline_json")
    if pj.get("self_pay_status") == "settled":
        return LnSelfPayHopOutcome(kind="noop", detail="self_pay_already_settled")

    bin_amount = int(session.bin_amount_sat or 0)
    if bin_amount <= 0:
        return LnSelfPayHopOutcome(kind="error", detail="bin_amount_sat must be positive")

    key = _key_for(session, "ln_self_pay_fire", attempt=1)
    if await has_hop_attempt_completed(db, idempotency_key=key.idempotency_key):
        _mark_settled(session)
        return LnSelfPayHopOutcome(kind="noop", detail="self_pay_already_completed")

    invoice = str(pj.get("self_pay_invoice") or "")
    payment_hash = str(pj.get("self_pay_payment_hash_hex") or "")

    # Crash-recovery: a prior tick may have settled the payment but
    # died before recording the outcome. ``lookup_invoice`` is
    # authoritative for our own minted invoice.
    if payment_hash:
        info, lookup_err = await deps.lnd_lookup_invoice(payment_hash)
        if lookup_err is None and info is not None and _invoice_settled(info):
            _mark_settled(session)
            await record_hop_attempt_completed(db, key=key, detail={"resolved": "lookup_settled"})
            return LnSelfPayHopOutcome(kind="fired_self_pay", detail="resolved_settled")

    # Mint the invoice once, then commit its payment hash BEFORE the
    # send. Re-firing the same invoice is safe (LND dedups the payment
    # by hash), but only if the hash survives a crash: a process death
    # in the send window must leave a durable hash the next tick
    # resolves via ``lookup_invoice`` — otherwise the tick rolls back,
    # the next tick mints a fresh hash, and a second self-payment
    # fires. The commit makes the hash durable; an unpaid invoice left
    # behind on a route/send failure is harmless and expires.
    if not invoice or not payment_hash:
        invoice_data, err = await deps.lnd_add_invoice(amount_sat=bin_amount, memo="anonymize self-pay")
        if err is not None or invoice_data is None:
            return LnSelfPayHopOutcome(kind="error", detail=f"add_invoice_failed:{err}")
        invoice = (
            invoice_data.get("payment_request")
            if isinstance(invoice_data, dict)
            else getattr(invoice_data, "payment_request", "")
        ) or ""
        payment_hash = (
            invoice_data.get("r_hash") if isinstance(invoice_data, dict) else getattr(invoice_data, "r_hash", "")
        ) or ""
        if not invoice or not payment_hash:
            return LnSelfPayHopOutcome(kind="error", detail="add_invoice_returned_incomplete")
        pj_writable = dict(session.pipeline_json or {})
        pj_writable["self_pay_invoice"] = invoice
        pj_writable["self_pay_payment_hash_hex"] = payment_hash
        session.pipeline_json = pj_writable
        # Durable hash before the side effect. This releases the tick's
        # row lock; a concurrent driver re-firing would reuse the same
        # committed invoice, which LND dedups — so no double payment.
        await db.commit()

    route, route_err = await deps.resolve_self_pay_route(session=session)
    if route_err is not None or route is None:
        # No viable routing posture (e.g. insufficient local balance, or
        # node info momentarily unavailable). No funds have moved; the
        # loop records this on ``last_error`` and retries next tick. A
        # transient cause clears on its own; a structural one stays
        # visible for operator/user action — the same operational-error
        # contract the sibling hops use.
        return LnSelfPayHopOutcome(kind="error", detail=f"self_pay_route:{route_err or 'unresolved'}")

    mode = getattr(route, "mode", "")
    outgoing_chan_id = getattr(route, "outgoing_chan_id", None)
    max_parts = getattr(route, "max_parts", None)
    ignored_pairs = list(getattr(route, "ignored_pairs", ()) or [])

    pj_writable = dict(session.pipeline_json or {})
    pj_writable["self_pay_mode"] = str(mode)
    if mode == "pinned":
        pj_writable["self_pay_outgoing_chan_id"] = outgoing_chan_id
    else:
        pj_writable["self_pay_max_parts"] = max_parts
    session.pipeline_json = pj_writable

    # Audit marker. Unlike the submarine on-chain funding tx, a self-pay
    # is not a double-spend hazard on re-fire (LND dedups by hash), so
    # the marker is for the audit trail, not a broadcast-window guard.
    await record_hop_attempt_started(db, key=key, detail={"step": "fire_self_pay", "mode": str(mode)})
    await db.flush()

    result, send_err = await deps.lnd_send_self_payment(
        payment_request=invoice,
        outgoing_chan_id=outgoing_chan_id if mode == "pinned" else None,
        max_parts=max_parts if mode == "split" else None,
        ignored_pairs=ignored_pairs if (mode == "split" and ignored_pairs) else None,
    )
    if send_err is not None or result is None:
        # The self-pay did not settle this tick. LND dedups by payment
        # hash, so the next tick safely re-fires the same committed
        # invoice; no funds have moved. The loop surfaces ``last_error``
        # and retries each tick — the hop returns an error outcome
        # rather than raising, so (like the sibling hops' operational
        # errors) it does not trip the loop's exception-counted
        # bounded-retry; a persistent failure stays visible for
        # operator/user action rather than auto-escalating.
        return LnSelfPayHopOutcome(kind="error", detail=f"self_pay_send:{send_err or 'no_result'}")

    _mark_settled(session)
    await record_hop_attempt_completed(db, key=key, detail={"mode": str(mode)})
    return LnSelfPayHopOutcome(kind="fired_self_pay", detail=str(mode))


__all__ = [
    "LnSelfPayHopDeps",
    "LnSelfPayHopOutcome",
    "execute_ln_self_pay_hop_step",
]
