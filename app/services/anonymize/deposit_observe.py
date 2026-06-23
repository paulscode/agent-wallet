# SPDX-License-Identifier: MIT
"""Settlement-observation helpers for ext-lightning deposits.

The anonymize per-session observer needs a way to ask "has the
depositor paid?" without exposing wallet-internal IDs. Two modes:

* **BOLT 11** — the session's ``pipeline_json["source"]["deposit_invoice"]``
  carries the payment-request string. LND's ``lookup_invoice`` flips
  to ``SETTLED`` when paid; the helper below queries by
  ``payment_hash_hex`` decoded from the invoice.
* **BOLT 12** — the session's ``pipeline_json["source"]["deposit_offer_id"]``
  references a row in ``bolt12_offers``. When a depositor pays, the
  inbound responder mints a :class:`Bolt12Invoice` row and the
  existing BOLT 12 reconciliation sweep flips it to ``PAID``. The
  helper joins by ``offer_id`` and returns the most-recent paid
  invoice (or ``None`` if none yet).

Both helpers are pure adapters with no LND-side side-effects beyond
the lookup; they return ``(settled_at_or_None, error)`` so the
observer can record the timestamp into the session row.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def find_paid_inbound_bolt12_invoice_for_session(
    db: AsyncSession,
    *,
    session_pipeline_json: dict[str, Any] | None,
) -> tuple[Optional[datetime], Optional[str]]:
    """Look up the deposit settlement for a BOLT 12 ext-lightning session.

    Returns ``(paid_at, None)`` when a paid inbound invoice for the
    session's bound offer is found. Returns ``(None, None)`` when no
    paid invoice exists yet (the depositor hasn't paid, or LND
    hasn't reflected the settlement yet). Returns ``(None, error)``
    when the lookup fails (e.g., malformed session row).

    The helper is intentionally narrow: it does NOT query LND
    directly. It reads the ``bolt12_invoices`` table, which the
    inbound responder + reconciliation sweep keep up-to-date.
    """
    from app.models.bolt12_invoice import (
        Bolt12Direction,
        Bolt12Invoice,
        Bolt12InvoiceStatus,
    )

    if not isinstance(session_pipeline_json, dict):
        return None, "session has no pipeline_json"
    src = session_pipeline_json.get("source") or {}
    if not isinstance(src, dict):
        return None, "pipeline_json.source is not a dict"
    raw_id = src.get("deposit_offer_id")
    if not isinstance(raw_id, str) or not raw_id.strip():
        # No bound offer ⇒ this session is BOLT 11 or hasn't had its
        # deposit primitive minted yet. Surface a clean ``no offer``
        # signal rather than an error so the observer can fall back
        # to the time-based path.
        return None, None
    try:
        offer_uuid = UUID(raw_id)
    except (TypeError, ValueError):
        return None, f"deposit_offer_id is not a UUID: {raw_id!r}"

    # Join through Bolt12InvoiceRequest → Bolt12Invoice. The
    # reconciliation sweep keeps ``status = PAID`` + ``paid_at`` in
    # sync with LND. Pick the most-recent paid row in case multiple
    # invreqs were minted (rare; would only happen if the depositor
    # ran multiple wallets against the same offer).
    from app.models.bolt12_invoice import Bolt12InvoiceRequest

    stmt = (
        select(Bolt12Invoice)
        .join(
            Bolt12InvoiceRequest,
            Bolt12InvoiceRequest.id == Bolt12Invoice.invoice_request_id,
        )
        .where(Bolt12InvoiceRequest.offer_id == offer_uuid)
        .where(Bolt12Invoice.direction == Bolt12Direction.INBOUND)
        .where(Bolt12Invoice.status == Bolt12InvoiceStatus.PAID)
        .order_by(Bolt12Invoice.paid_at.desc())
        .limit(1)
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        return None, None
    return row.paid_at, None


__all__ = [
    "find_paid_inbound_bolt12_invoice_for_session",
]
