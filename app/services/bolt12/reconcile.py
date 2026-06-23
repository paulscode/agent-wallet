# SPDX-License-Identifier: MIT
"""Settlement reconciliation for BOLT 12 invoices.

Periodic worker that joins ``Bolt12Invoice.payment_hash_hex`` against
LND's ``LookupInvoice`` and flips the BOLT 12 row from ``OPEN`` to
``PAID`` (or ``EXPIRED``) when LND has resolved the underlying HTLC.

The settlement itself is owned by LND — when an HTLC arrives along the
blinded path of a BOLT 12 invoice we minted via
``add_blinded_invoice``, LND auto-settles using its preimage. This
reconciler is purely an *audit-state* projection: it ensures our
``bolt12_invoices`` table reflects on-chain reality so the dashboard,
audit log, and ``GET /v1/bolt12/invoices`` stay accurate.

Design notes:

* **Read-only against LND.** No state mutation on LND.
* **Idempotent.** Processing the same row twice is a no-op.
* **Bounded work.** Each pass processes at most ``DEFAULT_BATCH`` rows
  to keep tail latency predictable on busy nodes.
* **Failure-tolerant.** A per-row LND error is logged and the row is
  skipped — the next pass retries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import PendingRollbackError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import encrypt_field
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceStatus,
)
from app.services.lnd_service import LNDService

logger = logging.getLogger(__name__)

DEFAULT_BATCH: int = 200


def _record_breaker_success_for_paths(row: "Bolt12Invoice") -> None:
    """Feed the per-intro path breaker on an OPEN→PAID transition.

    Mirrors the success-side of what the HTLC event subscriber
    does on its ``bolt12_htlc_settled`` branch — needed because
    that subscriber is disabled in polling mode (no LND REST
    polling equivalent exists for HTLC events).

    Only fires for INBOUND rows: outbound payments don't ride one
    of OUR offered blinded paths, so their breaker state isn't
    ours to update. (In practice ``blinded_paths_summary`` is
    only populated on inbound rows; the direction check is a
    second layer of safety.)

    Best-effort: any error logs and returns. The breaker is
    advisory; a missed success here just means the breaker takes
    one more failure-cycle to learn the path is healthy.
    """
    try:
        if getattr(row, "direction", None) != Bolt12Direction.INBOUND:
            return
        paths_summary = getattr(row, "blinded_paths_summary", None)
        if not isinstance(paths_summary, dict):
            return
        intros = []
        for p in paths_summary.get("paths", []):
            if isinstance(p, dict):
                intro = p.get("intro_pubkey")
                if intro:
                    intros.append(intro)
        if not intros:
            return
        from app.services.bolt12.path_postprocess import get_path_breaker

        breaker = get_path_breaker()
        for intro in intros:
            breaker.record_success(intro)
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12 reconcile: breaker record_success failed for invoice %s",
            getattr(row, "id", "?"),
        )


async def _safe_rollback(db: AsyncSession) -> None:
    """Rollback in best-effort mode.

    A failed commit leaves SQLAlchemy's AsyncSession in a
    "pending rollback" state — subsequent operations raise
    ``PendingRollbackError`` until the session is rolled back.
    We swallow rollback errors themselves because there is
    nowhere useful to surface them: the goal is purely to
    return the session to a usable state for the next iteration.
    """
    try:
        await db.rollback()
    except Exception:  # noqa: BLE001
        logger.exception("bolt12 reconcile: rollback failed (continuing)")


@dataclass(frozen=True, slots=True)
class ReconcileSummary:
    """Counters returned by :func:`reconcile_open_invoices`.

    ``failed`` counts outbound (J2) rows that LND has flagged as a
    terminal payment failure — separate from ``expired`` (a row whose
    own expiry timer fired) and ``errored`` (a per-row exception in
    the reconciler itself, not a payment outcome).
    """

    scanned: int
    paid: int
    expired: int
    failed: int
    errored: int


async def reconcile_open_invoices(
    db: AsyncSession,
    lnd: LNDService,
    *,
    batch: int = DEFAULT_BATCH,
    now: datetime | None = None,
) -> ReconcileSummary:
    """Scan ``OPEN`` BOLT 12 invoices and project LND state.

    Each row is committed individually. If a per-row commit fails
    (e.g. a transient PG hiccup, or a stale-state IntegrityError),
    we rollback the session, count it as ``errored``, and continue
    so a single bad row can't poison the rest of the pass. Rows
    successfully processed earlier in the pass are NOT rolled
    back — they're already durable.

    Returns counts so callers (Celery task, tests) can log a summary.
    """
    current = now or datetime.now(timezone.utc)

    stmt = (
        select(Bolt12Invoice.id)
        .where(Bolt12Invoice.status == Bolt12InvoiceStatus.OPEN)
        .order_by(Bolt12Invoice.created_at.asc())
        .limit(batch)
    )
    row_ids: list[UUID] = list((await db.execute(stmt)).scalars().all())

    paid = 0
    expired = 0
    failed = 0
    errored = 0
    processed_ids: set[UUID] = set()

    for row_id in row_ids:
        if row_id in processed_ids:
            continue
        processed_ids.add(row_id)

        row = await db.get(Bolt12Invoice, row_id)
        if row is None:
            continue
        if row.status != Bolt12InvoiceStatus.OPEN:
            continue

        try:
            updated = await _reconcile_one(row, db, lnd, current)
        except Exception:  # noqa: BLE001 — last-line defense per row
            logger.exception("bolt12 reconcile: unexpected error for invoice %s", row.id)
            errored += 1
            await _safe_rollback(db)
            continue

        if updated is None:
            # No state change → nothing to commit.
            continue

        try:
            await db.commit()
        except (PendingRollbackError, SQLAlchemyError):
            logger.exception(
                "bolt12 reconcile: commit failed for invoice %s; recovering",
                row.id,
            )
            errored += 1
            await _safe_rollback(db)
            continue

        if updated == Bolt12InvoiceStatus.PAID:
            paid += 1
            # 2026-06-11: record breaker success for the path intros
            # we'd advertised. Previously this only fired from the
            # HTLC event subscriber's ``bolt12_htlc_settled`` branch;
            # when the subscriber is disabled or in polling mode the
            # breaker would never learn from settlements. Reconciles
            # OPEN→PAID so we know success here, but we don't know
            # WHICH intro Ocean's payer chose — so we record success
            # against all intros we offered. The breaker registry
            # tolerates this (record_success on a closed intro is a
            # no-op; on an open one it advances toward half-open).
            _record_breaker_success_for_paths(row)
        elif updated == Bolt12InvoiceStatus.EXPIRED:
            expired += 1
        elif updated == Bolt12InvoiceStatus.FAILED:
            failed += 1

    return ReconcileSummary(
        scanned=len(row_ids),
        paid=paid,
        expired=expired,
        failed=failed,
        errored=errored,
    )


async def _reconcile_one(
    row: Bolt12Invoice,
    db: AsyncSession,
    lnd: LNDService,
    now: datetime,
) -> Bolt12InvoiceStatus | None:
    """Reconcile a single row. Returns the new status (or None if unchanged).

    Branches on direction:

    * **Inbound** (LND minted the invoice via ``add_blinded_invoice``)
      → query ``lookup_invoice`` and project ``state``.
    * **Outbound** (we sent a payment via ``send_to_route_v2``) →
      query ``lookup_payment`` and project the HTLC attempt state.
      This is the J2 catch-up path: if the synchronous settlement in
      ``_settle_bolt12_outbound`` returned ``IN_FLIGHT`` (or the
      process crashed mid-settle), the next reconciliation pass
      surfaces the terminal state.
    """
    if row.direction == Bolt12Direction.OUTBOUND:
        return await _reconcile_outbound(row, lnd, now)
    info, err = await lnd.lookup_invoice(row.payment_hash_hex)
    if err is not None:
        # Two cases: invoice not found on LND (could be a peer-side
        # invoice we never minted ourselves), or transient LND error.
        # Either way, leave the row alone and let the next pass retry.
        logger.debug("bolt12 reconcile: LND lookup error for %s: %s", row.payment_hash_hex, err)
        return None
    if info is None:
        return None

    state = (info.get("state") or "").upper()
    settled = bool(info.get("settled"))

    if state == "SETTLED" or settled:
        row.status = Bolt12InvoiceStatus.PAID
        settle_date = info.get("settle_date") or 0
        if settle_date:
            row.paid_at = datetime.fromtimestamp(int(settle_date), tz=timezone.utc)
        else:
            row.paid_at = now
        # Persist preimage if LND surfaces it (REST returns hex on
        # ``/v1/invoice/{r_hash}``). Some LND builds return base64;
        # we store hex so we coerce here.
        preimage = info.get("r_preimage") or info.get("payment_preimage") or ""
        if preimage and not row.encrypted_preimage:
            assert isinstance(preimage, str)  # LND surfaces preimages as hex/base64 strings
            row.encrypted_preimage = encrypt_field(_normalize_preimage(preimage))
        return Bolt12InvoiceStatus.PAID

    if state == "CANCELED":
        row.status = Bolt12InvoiceStatus.EXPIRED
        row.error_message = row.error_message or "LND invoice canceled"
        return Bolt12InvoiceStatus.EXPIRED

    if state == "EXPIRED":
        # LND ≥ 0.18 surfaces EXPIRED as a distinct state once its
        # own expiry timer fires. Project it directly so we don't
        # depend on row.expiry being populated.
        row.status = Bolt12InvoiceStatus.EXPIRED
        row.error_message = row.error_message or "LND invoice expired"
        return Bolt12InvoiceStatus.EXPIRED

    # OPEN/ACCEPTED — check our own expiry mirror.
    if row.expiry is not None:
        expiry = row.expiry
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= now:
            row.status = Bolt12InvoiceStatus.EXPIRED
            row.error_message = row.error_message or "expiry elapsed"
            return Bolt12InvoiceStatus.EXPIRED

    return None


async def _reconcile_outbound(
    row: Bolt12Invoice,
    lnd: LNDService,
    now: datetime,
) -> Bolt12InvoiceStatus | None:
    """Project LND's ``lookup_payment`` state onto an OUTBOUND row.

    LND's ``ListPayments`` records the terminal state of each payment
    keyed by ``payment_hash``. We poll it here so a reconciliation
    pass can finish what an interrupted synchronous settlement left
    open.

    Returns the new status (``PAID`` / ``FAILED``) when the LND state
    is terminal, or ``None`` if the payment is still in flight (or
    LND hasn't seen the payment hash at all yet).
    """
    payment, err = await lnd.lookup_payment(row.payment_hash_hex)
    if err is not None:
        logger.debug(
            "bolt12 reconcile (outbound): LND lookup error for %s: %s",
            row.payment_hash_hex,
            err,
        )
        return None
    if payment is None:
        return None
    status = (payment.get("status") or "").upper()
    if status == "SUCCEEDED":
        row.status = Bolt12InvoiceStatus.PAID
        row.paid_at = now
        preimage = payment.get("payment_preimage") or ""
        if preimage and not row.encrypted_preimage:
            row.encrypted_preimage = encrypt_field(_normalize_preimage(preimage))
        return Bolt12InvoiceStatus.PAID
    if status == "FAILED":
        row.status = Bolt12InvoiceStatus.FAILED
        # Preserve any prior error_message (set by the synchronous
        # path); only overwrite when blank so we don't clobber the
        # richer failure reason.
        if not row.error_message:
            row.error_message = "LND payment failed (terminal)"
        return Bolt12InvoiceStatus.FAILED
    # IN_FLIGHT / INITIATED / UNKNOWN — leave for the next pass.
    return None


def _normalize_preimage(value: str) -> str:
    """Accept hex or base64; return hex."""
    s = value.strip()
    if len(s) == 64:
        try:
            bytes.fromhex(s)
            return s.lower()
        except ValueError:
            pass
    # Try base64 → hex.
    import base64

    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:  # noqa: BLE001
        return s
    return raw.hex()


# ── invreq reconciliation at startup ────────────────────────


async def reconcile_stranded_invreqs(
    db: AsyncSession,
    *,
    request_timeout_seconds: float,
    now: datetime | None = None,
) -> dict[str, int]:
    """Fail any ``Bolt12InvoiceRequest`` rows stranded as PENDING.

    On crash, in-flight outbound ``request_invoice`` futures vanish
    but the corresponding row remains ``PENDING`` forever (no Celery
    retry path owns these — they're per-request HTTP-bound). At
    startup, we walk the table and mark anything older than ``2 *
    request_timeout`` as ``TIMED_OUT`` with reason
    ``reconciliation_timeout``.

    Idempotent. Safe to call on every startup.
    """
    from app.models.bolt12_invoice import (
        Bolt12InvoiceRequest,
        Bolt12InvoiceRequestStatus,
    )

    current = now or datetime.now(timezone.utc)
    cutoff_seconds = max(60.0, 2.0 * float(request_timeout_seconds))
    cutoff = current.timestamp() - cutoff_seconds

    stmt = select(Bolt12InvoiceRequest.id).where(Bolt12InvoiceRequest.status == Bolt12InvoiceRequestStatus.PENDING)
    row_ids: list[UUID] = list((await db.execute(stmt)).scalars().all())

    timed_out = 0
    scanned = 0
    processed_ids: set[UUID] = set()

    for row_id in row_ids:
        if row_id in processed_ids:
            continue
        processed_ids.add(row_id)

        row = await db.get(Bolt12InvoiceRequest, row_id)
        if row is None:
            continue
        if row.status != Bolt12InvoiceRequestStatus.PENDING:
            continue
        scanned += 1

        created_at = row.created_at
        if created_at is None:
            continue
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if created_at.timestamp() > cutoff:
            continue

        row.status = Bolt12InvoiceRequestStatus.TIMED_OUT
        row.error_message = "reconciliation_timeout"
        row.completed_at = current

        try:
            await db.commit()
        except (PendingRollbackError, SQLAlchemyError):
            logger.exception(
                "bolt12 startup reconcile: commit failed for invreq %s; recovering",
                row.id,
            )
            await _safe_rollback(db)
            continue
        timed_out += 1

    if timed_out:
        logger.info(
            "bolt12 startup reconcile: marked %d stranded PENDING invreqs as TIMED_OUT",
            timed_out,
        )

    return {"scanned": scanned, "timed_out": timed_out}


__all__ = [
    "ReconcileSummary",
    "reconcile_open_invoices",
    "reconcile_stranded_invreqs",
    "DEFAULT_BATCH",
]
