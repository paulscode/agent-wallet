# SPDX-License-Identifier: MIT
"""
Celery tasks for Boltz reverse swap processing.

Key design decisions:
  - Each task invocation creates its own async event loop, DB session, HTTP client
  - Resources are cleaned up in finally blocks to prevent leaks in long-running workers
  - Tiered exponential backoff: 15s (first 10), 60s (next 20), 300s (rest)
  - max_retries=200 (cap prevents infinite retries)
  - Crash recovery task scheduled on app startup
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from celery import Celery  # type: ignore[import-untyped]

from app.core.config import settings
from app.tasks.observability import track_task

logger = logging.getLogger(__name__)

celery_app = Celery(
    "agent_wallet",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # ``include`` tells the worker to import these modules at
    # startup so their ``@celery_app.task`` decorators actually
    # register. Without this, only tasks defined directly in
    # ``boltz_tasks`` (the ``-A`` target) are known to the worker
    # — beat tries to enqueue ``advance_braiins_deposit_sessions``
    # every 30 s and the worker rejects it with
    # ``KeyError: 'advance_braiins_deposit_sessions'`` because the
    # decorator in :mod:`app.tasks.braiins_deposit_tasks` never
    # ran. Caught 2026-06-05 alongside the bolt12-telemetry
    # rollout. Add future task modules here.
    include=["app.tasks.braiins_deposit_tasks", "app.tasks.channel_mix_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "cleanup-audit-logs": {
            "task": "cleanup_audit_logs",
            "schedule": 86400.0,  # Run once per day
        },
        "bolt12-reconcile-invoices": {
            "task": "bolt12_reconcile_invoices",
            "schedule": 60.0,  # Every minute — fast feedback for dashboard
        },
        "bolt12-daily-summary": {
            "task": "bolt12_daily_summary",
            "schedule": 86400.0,  # T3: once per day
        },
        # Item 14: prune terminal BOLT 12 rows older than retention.
        # Cheap when there's nothing to prune; bounded to a few
        # thousand rows per pass even when the backlog is large.
        "cleanup-bolt12-old-rows": {
            "task": "cleanup_bolt12_old_rows",
            "schedule": 86400.0,  # Run once per day
        },
        # Diagnostic C: periodic check that LND's gossiped inbound
        # max_htlc isn't grossly over-claiming vs the live
        # remote_balance. Run every 5 minutes — same cadence as the
        # boltz recovery pass, balances signal freshness against
        # the cost of repeated LND graph-edge lookups.
        "check-bolt12-path-drift": {
            "task": "check_bolt12_path_drift",
            "schedule": 300.0,  # Every 5 minutes
        },
        # Telemetry #3: settle-watchdog. Moved to the API
        # process on 2026-06-06 so its breaker
        # ``record_failure`` calls reach the same in-memory
        # registry the responder reads from (the breaker is
        # process-local). The Celery task at
        # :func:`bolt12_settle_watchdog` is retained for manual
        # triggering but NOT scheduled.
        # Periodic recovery picks up swaps that the lifespan
        # synchronous recovery couldn't finish in its 60s budget,
        # plus any swaps abandoned by Celery worker crashes.
        "recover-boltz-swaps": {
            "task": "recover_boltz_swaps",
            "schedule": 300.0,  # Every 5 minutes
        },
        # Same recovery role for channel-mix runs: a worker crash
        # mid-run would otherwise leave the per-channel state machine
        # idle until the next dashboard poll re-triggered the task.
        # Runs every 60 s (not 300 s) because the sequential *bootstrap*
        # executor relies on this beat — not task self-retry — to drive
        # its multi-hour open→drain→recycle loop forward each cycle
        # (see channel_mix_tasks.process_channel_mix_run).
        "recover-channel-mix-runs": {
            "task": "recover_channel_mix_runs",
            "schedule": 60.0,  # Every 60 seconds
        },
        # Sweep the UTXO label store: stamp spent_at on outpoints
        # that disappeared from ListUnspent, seed auto:receive
        # labels from address_purpose hits, soft-purge old non-user
        # rows. Cheap to run; a few hundred ms even on big nodes.
        "reconcile-utxo-labels": {
            "task": "reconcile_utxo_labels",
            "schedule": 300.0,  # Every 5 minutes
        },
        # Braiins Deposit periodic ticker. The dashboard's 5 s
        # poller drives forward progress when the user is watching;
        # this Celery task is the safety net for sessions where
        # the operator closed the browser before COMPLETED.
        "advance-braiins-deposits": {
            "task": "advance_braiins_deposit_sessions",
            "schedule": 30.0,  # Every 30 seconds
        },
        # Preventive Tor age rotation. Issues SIGNAL HUP at
        # ``TOR_ROTATION_INTERVAL_DAYS`` cadence so accumulated guard-
        # state degradation can't wedge us silently. In-flight gated
        # — the task defers when anything is mid-payment. Omitted
        # when the interval is 0 (operator-disabled).
        **(
            {
                "rotate-tor-age": {
                    "task": "rotate_tor_age",
                    "schedule": float(max(1, settings.tor_rotation_interval_days) * 86400),
                },
            }
            if int(settings.tor_rotation_interval_days) > 0
            else {}
        ),
        # LND-side HS descriptor freshness check. Issues
        # HSFETCH against LND's onion every
        # ``TOR_HS_DESCRIPTOR_CHECK_INTERVAL_S`` seconds (default
        # 21600 = 6 h); alarms when the fetch fails across two
        # consecutive ticks (LND-side publish broken). Skips
        # silently when LND_REST_URL is clearnet.
        "check-lnd-hs-descriptor-freshness": {
            "task": "check_lnd_hs_descriptor_freshness",
            "schedule": float(max(60, int(settings.tor_hs_descriptor_check_interval_s))),
        },
    },
)


def _get_backoff(retries: int) -> int:
    """Tiered backoff: 15s → 60s → 300s."""
    if retries < 10:
        return 15
    elif retries < 30:
        return 60
    else:
        return 300


async def _run_process_swap(swap_id: str, routing_fee_limit_percent: float = 3.0) -> dict[str, Any]:
    """Async implementation of the process_boltz_swap task."""
    try:
        uuid.UUID(swap_id)
    except ValueError:
        logger.error("Invalid swap_id format: %s", swap_id)
        return {"status": "error", "detail": "invalid_swap_id"}

    from sqlalchemy import select

    from app.core.bolt11 import payment_hash_from_bolt11
    from app.core.database import get_db_context
    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.boltz_service import BoltzSwapService
    from app.services.lnd_service import LNDService

    lnd = LNDService()
    boltz = BoltzSwapService()

    async with get_db_context() as db:
        try:
            result = await db.execute(select(BoltzSwap).where(BoltzSwap.id == swap_id))
            swap = result.scalar_one_or_none()

            if not swap:
                logger.error("Swap %s not found", swap_id)
                return {"status": "error", "detail": "swap_not_found"}

            if swap.status in (
                SwapStatus.COMPLETED,
                SwapStatus.FAILED,
                SwapStatus.CANCELLED,
                SwapStatus.REFUNDED,
            ):
                logger.info("Swap %s already in terminal state: %s", swap_id, swap.status.value)
                return {"status": swap.status.value}

            # Step 1: Pay the Boltz invoice (if not already paid).
            #
            # Normally only CREATED swaps pay. But an interrupted tick — a
            # worker restart or an app redeploy in the narrow window after
            # PAYING_INVOICE is committed (below) but before/while
            # send_payment_v2 actually registers an HTLC in LND — strands the
            # swap in PAYING_INVOICE with no payment ever sent. The
            # CREATED-gated block would then never re-run, so Boltz never sees
            # an HTLC and advance_swap can't progress: the swap hangs at
            # "Sending over Lightning" until the invoice expires. Re-attempt
            # the payment when (and ONLY when) LND confirms no payment is live
            # for this invoice, so we can never double-pay.
            should_pay = swap.status == SwapStatus.CREATED
            if swap.status == SwapStatus.PAYING_INVOICE:
                reentry_hash = swap.lnd_payment_hash or (
                    payment_hash_from_bolt11(swap.boltz_invoice)
                    if swap.boltz_invoice else None
                )
                if reentry_hash:
                    lookup, lookup_err = await lnd.lookup_payment(reentry_hash)
                    if lookup_err is None and lookup is not None:
                        pay_state = str(lookup.get("status") or "UNKNOWN").upper()
                        if pay_state in ("FAILED", "UNKNOWN"):
                            # No in-flight or succeeded HTLC exists — safe to
                            # (re)send without risk of a duplicate payment.
                            logger.warning(
                                "Swap %s stuck in PAYING_INVOICE with no live "
                                "LND payment (lookup=%s); re-attempting the "
                                "invoice payment",
                                swap_id, pay_state,
                            )
                            should_pay = True
                        elif pay_state == "SUCCEEDED":
                            # A prior tick's payment actually settled but the
                            # status update was lost — reconcile to INVOICE_PAID
                            # and let advance_swap carry on to the claim.
                            swap.lnd_payment_hash = reentry_hash
                            swap.status = SwapStatus.INVOICE_PAID
                            if swap.error_message and swap.error_message.startswith(
                                "Payment attempt encountered a transient"
                            ):
                                swap.error_message = None
                            if swap.status_history is None:
                                swap.status_history = []
                            swap.status_history.append({
                                "status": SwapStatus.INVOICE_PAID.value,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "payment_hash": reentry_hash,
                                "reconciled": True,
                            })
                            await db.commit()
                        # IN_FLIGHT → a payment is live; leave as-is and let
                        # advance_swap reconcile against the Boltz side.
                    # lookup_err → LND flaky; stay conservative (don't re-pay).

            if should_pay:
                logger.info("Paying Boltz invoice for swap %s", swap_id)
                swap.status = SwapStatus.PAYING_INVOICE
                if swap.status_history is None:
                    swap.status_history = []
                swap.status_history.append(
                    {
                        "status": SwapStatus.PAYING_INVOICE.value,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                await db.commit()

                fee_limit_sats = max(
                    10,
                    int(swap.invoice_amount_sats * routing_fee_limit_percent / 100),
                )

                assert swap.boltz_invoice is not None
                # Pay via the router v2 endpoint with MPP enabled
                # (``max_parts``). Single-path ``SendPaymentSync``
                # returns ``no_route`` whenever no ONE channel has
                # enough outbound for the invoice — even when total
                # outbound across several small channels covers it.
                # ``send_payment_v2`` lets LND split the payment across
                # channels and succeed. The error-string contract is
                # the same as ``send_payment_sync`` (relied on below):
                # only a terminal ``status: FAILED`` in the stream
                # returns ``Payment failed: …``; a held HTLC keeps the
                # stream open until the HTTP timeout, surfacing a
                # transient ``Request failed: …`` while LND keeps the
                # in-flight HTLC alive for reconciliation.
                pin_chan_id = getattr(swap, "outgoing_chan_id", None) or None
                # MPP and a first-hop pin are mutually exclusive: LND drops the
                # pin when max_parts>1 (parts may need different first hops), so
                # a pinned drain (bootstrap round / Braiins channel-open) MUST
                # go single-path or it would drain the wrong channels. Only
                # enable MPP when we are NOT pinning.
                max_parts = 1 if pin_chan_id else int(settings.boltz_payment_max_parts)
                pay_result, pay_error = await lnd.send_payment_v2(
                    payment_request=swap.boltz_invoice,
                    # Pin the first hop when set (bootstrap drain / Braiins
                    # channel-open flow drains its freshly-opened channel);
                    # None = LND routes.
                    outgoing_chan_id=pin_chan_id,
                    fee_limit_sats=fee_limit_sats,
                    timeout_seconds=120,
                    max_parts=max_parts,
                )

                if pay_error:
                    # Only ``Payment failed: …`` is a definitive LND-
                    # terminal FAILED — that path returns after seeing
                    # a ``status: FAILED`` line in the SendPaymentV2
                    # stream, which means LND will not retry. Every
                    # other prefix (``Connection failed`` /
                    # ``Request failed`` / ``LND error (5xx)`` /
                    # ``Payment did not reach a terminal state``)
                    # means the HTTP stream ended without LND
                    # confirming the HTLC was rejected — and LND does
                    # NOT cancel an in-flight HTLC when its caller
                    # disconnects. Marking the swap FAILED in that
                    # case strands the user's sats (the HTLC is still
                    # in-flight at Boltz; if/when Boltz settles, the
                    # LN balance has moved but our DB says the swap
                    # failed) and is exactly the bug behind the
                    # 2026-05-21 manual-recovery incident.
                    is_definitive = pay_error.startswith("Payment failed:")
                    if is_definitive:
                        swap.status = SwapStatus.FAILED
                        swap.error_message = f"Invoice payment failed: {pay_error}"
                        if swap.status_history is None:
                            swap.status_history = []
                        swap.status_history.append(
                            {
                                "status": SwapStatus.FAILED.value,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "error": pay_error,
                            }
                        )
                        await db.commit()
                        return {"status": "failed", "detail": pay_error}
                    # Transient error — HTLC may still be in-flight in
                    # LND. Persist the payment_hash (decoded directly
                    # from the BOLT11 invoice — no LND dependency,
                    # since LND is exactly what's flaky right now) so
                    # the next ``advance_swap`` tick can reconcile.
                    # Stay in PAYING_INVOICE so ``recover_pending_swaps``
                    # picks the swap up.
                    payment_hash_hex: Optional[str] = None
                    if swap.boltz_invoice:
                        payment_hash_hex = payment_hash_from_bolt11(swap.boltz_invoice)
                    if payment_hash_hex:
                        swap.lnd_payment_hash = payment_hash_hex
                    # Surface a user-friendly explanation on the swap
                    # row itself so the dashboard shows context
                    # alongside the PAYING_INVOICE status. Cleared
                    # below in the clean-SUCCEEDED branch and by
                    # ``advance_swap`` once the swap moves on.
                    swap.error_message = (
                        "Payment attempt encountered a transient "
                        "network error and is being retried "
                        f"automatically. Payment hash: "
                        f"{payment_hash_hex or '<undecodable>'}. "
                        "No action required — the next reconciliation "
                        "tick will resume. If this persists for more "
                        "than 10 minutes, the swap will surface a "
                        "stuck banner with manual recovery options."
                    )
                    if swap.status_history is None:
                        swap.status_history = []
                    swap.status_history.append(
                        {
                            "status": SwapStatus.PAYING_INVOICE.value,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "transient_error": pay_error,
                            "payment_hash": payment_hash_hex,
                        }
                    )
                    await db.commit()
                    logger.warning(
                        "Swap %s pay_invoice transient error (%s); "
                        "leaving in PAYING_INVOICE for reconciliation, "
                        "payment_hash=%s",
                        swap_id,
                        pay_error,
                        payment_hash_hex or "<undecodable>",
                    )
                    # Fall through to advance_swap — it'll poll Boltz
                    # and pick up wherever the HTLC actually landed
                    # (swap.created → still waiting; transaction.*
                    # → claim; invoice.expired → mark FAILED).
                else:
                    # Clean SUCCEEDED — record INVOICE_PAID with the
                    # preimage / payment_hash LND surfaced.
                    assert pay_result is not None
                    swap.status = SwapStatus.INVOICE_PAID
                    # Clear any transient error message a prior
                    # retry attempt may have left on the row.
                    if swap.error_message and swap.error_message.startswith("Payment attempt encountered a transient"):
                        swap.error_message = None
                    if swap.status_history is None:
                        swap.status_history = []
                    swap.status_history.append(
                        {
                            "status": SwapStatus.INVOICE_PAID.value,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "payment_hash": pay_result.get("payment_hash"),
                        }
                    )
                    if pay_result.get("payment_hash"):
                        swap.lnd_payment_hash = pay_result["payment_hash"]
                    await db.commit()

            # Step 2: Advance the swap state machine. ``advance_swap``
            # returns the (swap, error) tuple — projecting only the
            # error string into the Celery result so the (BoltzSwap)
            # object doesn't trip kombu's JSON serializer (the bug
            # behind the 2026-05-21 incident where advance_swap
            # broadcast the claim but the worker crashed before
            # committing ``claim_txid``).
            _swap, advance_err = await boltz.advance_swap(db, swap)
            return {
                "status": swap.status.value,
                "advance_error": advance_err,
            }

        except Exception as e:
            logger.exception("Error processing swap %s: %s", swap_id, e)
            return {"status": "error", "detail": str(e)}


async def _run_recover_swaps() -> dict[str, Any]:
    """Async implementation of the recover task."""
    from app.core.database import get_db_context
    from app.services.boltz_service import BoltzSwapService

    boltz = BoltzSwapService()

    async with get_db_context() as db:
        try:
            recovered = await boltz.recover_pending_swaps(db)
            logger.info("Recovered %d pending swaps", len(recovered))
            return {"recovered": recovered}
        except Exception as e:
            logger.exception("Error recovering swaps: %s", e)
            return {"error": str(e)}


def _run_async(coro: Any) -> Any:
    """Run an async coroutine in a new event loop (for Celery workers)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        # Close the shared LND client on this loop before tearing it down — the
        # lnd_service singleton caches an httpx.AsyncClient bound to the loop it
        # was created on, and reusing it on the next tick's loop would raise
        # "Event loop is closed" (also avoids leaking the connection pool).
        try:
            from app.services.lnd_service import lnd_service

            loop.run_until_complete(lnd_service.close())
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass
        # Clean up pending tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


@celery_app.task(
    bind=True,
    max_retries=200,
    name="process_boltz_swap",
)
@track_task("process_boltz_swap")
def process_boltz_swap(self: Any, swap_id: str, routing_fee_limit_percent: float = 3.0) -> dict[str, Any]:
    """Process a Boltz reverse swap — pay invoice, monitor, claim.

    Retries with tiered backoff until the swap reaches a terminal state
    or max_retries is exhausted.
    """
    try:
        result: dict[str, Any] = _run_async(_run_process_swap(swap_id, routing_fee_limit_percent))

        status = result.get("status", "")
        if status in ("completed", "failed", "cancelled", "refunded", "error"):
            return result

        # Not yet terminal — retry with backoff
        backoff = _get_backoff(self.request.retries)
        logger.info(
            "Swap %s status=%s, retrying in %ds (attempt %d/%d)",
            swap_id,
            status,
            backoff,
            self.request.retries + 1,
            self.max_retries,
        )
        raise self.retry(countdown=backoff)

    except self.MaxRetriesExceededError:
        logger.error("Swap %s exceeded max retries (%d)", swap_id, self.max_retries)
        # Mark as failed in DB
        try:
            _run_async(_mark_swap_failed(swap_id, "Max retries exceeded"))
        except Exception:
            logger.exception("Failed to mark swap %s as failed after max retries", swap_id)
        return {"status": "failed", "detail": "max_retries_exceeded"}


async def _mark_swap_failed(swap_id: str, error_message: str) -> None:
    """Mark a swap as failed in the database."""
    from sqlalchemy import select

    from app.core.database import get_db_context
    from app.models.boltz_swap import BoltzSwap, SwapStatus

    async with get_db_context() as db:
        result = await db.execute(select(BoltzSwap).where(BoltzSwap.id == swap_id))
        swap = result.scalar_one_or_none()
        if swap and swap.status not in (SwapStatus.COMPLETED, SwapStatus.FAILED):
            swap.status = SwapStatus.FAILED
            swap.error_message = error_message
            if swap.status_history is None:
                swap.status_history = []
            swap.status_history.append(
                {
                    "status": SwapStatus.FAILED.value,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": error_message,
                }
            )
            await db.commit()


@celery_app.task(name="recover_boltz_swaps")
@track_task("recover_boltz_swaps")
def recover_boltz_swaps() -> dict[str, Any]:
    """Recover any swaps left in non-terminal states after a crash/restart."""
    result: dict[str, Any] = _run_async(_run_recover_swaps())
    return result


# ─── Audit Log Retention ──────────────────────────────────────────────


async def _run_cleanup_audit_logs() -> dict[str, Any]:
    """Delete audit log entries older than the configured retention period."""
    from datetime import timedelta

    from app.core.database import get_db_context
    from app.dashboard import DASHBOARD_KEY_ID
    from app.services.audit_service import emit_audit_anchor, prune_audit_log

    retention_days = settings.audit_log_retention_days
    if retention_days <= 0:
        # Retention disabled (keep-forever) — pruning never runs, but the
        # external truncation-detection anchor must still be emitted on the
        # schedule so an off-box observer keeps receiving signed head/count
        # snapshots. Without this, the keep-forever operator (exactly the
        # audience that wants a permanent tamper-evident trail) would get no
        # anchors at all.
        async with get_db_context() as db:
            await emit_audit_anchor(db, deleted=0)
        return {"deleted": 0, "detail": "retention disabled; anchor emitted"}

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    async with get_db_context() as db:
        result = await prune_audit_log(db, cutoff, DASHBOARD_KEY_ID)
        deleted = result["deleted"]
        logger.info(
            "Audit log cleanup: deleted %d entries older than %d days (skipped=%s, anchor_id=%s)",
            deleted,
            retention_days,
            result["skipped"],
            result["anchor_id"],
        )
        return {
            "deleted": deleted,
            "retention_days": retention_days,
            "skipped": result["skipped"],
            "anchor_id": result["anchor_id"],
        }


@celery_app.task(name="cleanup_audit_logs")
@track_task("cleanup_audit_logs")
def cleanup_audit_logs() -> dict[str, Any]:
    """Periodic task: remove audit log entries past the retention window."""
    result: dict[str, Any] = _run_async(_run_cleanup_audit_logs())
    return result


# ─── UTXO Label Reconciliation ────────────────────────────────────────


async def _run_reconcile_utxo_labels() -> dict[str, Any]:
    """Async impl of the UTXO label reconciler.

    See :func:`app.services.utxo_service.reconcile` for the full
    contract. Wraps the call in our standard DB session/cleanup
    pattern and commits the changes once the work is done.
    """
    from app.core.database import get_db_context
    from app.services import utxo_service

    async with get_db_context() as db:
        counters = await utxo_service.reconcile(db)
        await db.commit()
        if counters.get("error"):
            logger.warning("UTXO reconcile: LND list_unspent failed")
        else:
            logger.info(
                "UTXO reconcile: spent=%d auto_labelled=%d purged=%d",
                counters.get("spent_marked", 0),
                counters.get("auto_labelled", 0),
                counters.get("purged", 0),
            )
        return counters


@celery_app.task(name="reconcile_utxo_labels")
@track_task("reconcile_utxo_labels")
def reconcile_utxo_labels() -> dict[str, Any]:
    """Periodic task: keep the utxo_label store in sync with LND."""
    result: dict[str, Any] = _run_async(_run_reconcile_utxo_labels())
    return result


async def _run_bolt12_reconcile() -> dict[str, Any]:
    """Async impl of the BOLT 12 invoice reconciler.

    Joins ``Bolt12Invoice.payment_hash_hex`` against LND's
    ``LookupInvoice`` and projects ``OPEN → PAID/EXPIRED``.
    """
    from app.core.database import get_db_context
    from app.services.bolt12.reconcile import reconcile_open_invoices
    from app.services.lnd_service import LNDService

    lnd = LNDService()
    try:
        async with get_db_context() as db:
            summary = await reconcile_open_invoices(db, lnd)
    finally:
        await lnd.close()

    if summary.scanned:
        logger.info(
            "bolt12 reconcile: scanned=%d paid=%d expired=%d errored=%d",
            summary.scanned,
            summary.paid,
            summary.expired,
            summary.errored,
        )
    return {
        "scanned": summary.scanned,
        "paid": summary.paid,
        "expired": summary.expired,
        "errored": summary.errored,
    }


@celery_app.task(name="bolt12_reconcile_invoices")
@track_task("bolt12_reconcile_invoices")
def bolt12_reconcile_invoices() -> dict[str, Any]:
    """Celery wrapper: project LND-side settlement state onto BOLT 12 rows."""
    result: dict[str, Any] = _run_async(_run_bolt12_reconcile())
    return result


# ── T3 (2026-06-12): daily BOLT 12 activity summary ──────────


async def _run_bolt12_daily_summary() -> dict[str, Any]:
    """Aggregate the past 24 h of BOLT 12 audit events and emit a
    single ``bolt12_daily_summary`` audit row. Lets operators
    track week-over-week trends (mint rate, settle rate, timeout
    rate, transport-error rate) with one query instead of paging
    through the per-event audit stream.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import func, select

    from app.core.database import get_db_context
    from app.models.audit_log import AuditLog
    from app.services.bolt12.responder import _audit_inbound

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=24)

    async with get_db_context() as db:
        stmt = (
            select(AuditLog.action, func.count(AuditLog.id))
            .where(
                AuditLog.created_at >= window_start,
                AuditLog.created_at <= now,
                AuditLog.action.like("bolt12%"),
            )
            .group_by(AuditLog.action)
        )
        rows = (await db.execute(stmt)).all()
    counts: dict[str, int] = {action: int(n) for action, n in rows}

    summary = {
        "window_start_utc": window_start.isoformat(),
        "window_end_utc": now.isoformat(),
        "invreq_received_total": (
            counts.get("bolt12_invoice_minted", 0)
            + counts.get("bolt12_invreq_rate_limited", 0)
            + counts.get("bolt12_invreq_dropped", 0)
            + counts.get("bolt12_invreq_unknown_offer", 0)
        ),
        "invoice_minted_total": counts.get("bolt12_invoice_minted", 0),
        "invoice_sent_to_peer_total": counts.get(
            "bolt12_invoice_sent_to_peer",
            0,
        ),
        "settle_timeout_total": counts.get(
            "bolt12_invoice_settle_timeout",
            0,
        ),
        "htlc_settled_total": counts.get("bolt12_htlc_settled", 0),
        "htlc_link_failed_total": counts.get(
            "bolt12_htlc_link_failed_at_node",
            0,
        ),
        "drift_detected_total": counts.get(
            "bolt12_htlc_max_drift_detected",
            0,
        ),
        "by_action": counts,
    }

    try:
        await _audit_inbound(
            get_db_context,
            action="bolt12_daily_summary",
            success=True,
            details=summary,
        )
    except Exception:  # noqa: BLE001
        logger.exception("bolt12 daily summary: audit emit failed")

    return summary


@celery_app.task(name="bolt12_daily_summary")
@track_task("bolt12_daily_summary")
def bolt12_daily_summary() -> dict[str, Any]:
    """Celery wrapper: emit a daily BOLT 12 activity summary row."""
    result: dict[str, Any] = _run_async(_run_bolt12_daily_summary())
    return result


# ── BOLT 12 retention cleanup (Item 14) ──────────────────────


async def _run_bolt12_cleanup_old_rows() -> dict[str, Any]:
    """Prune terminal BOLT 12 rows older than retention thresholds.

    Two tables:

    * ``bolt12_invoice_requests`` — kept for ``BOLT12_REQUEST_RETENTION_DAYS``
      after ``completed_at`` (or ``created_at`` if completion never
      stamped). Status must be terminal: TIMED_OUT / FAILED / CANCELLED /
      INVOICE_SENT for rows whose invoice has itself been pruned.
    * ``bolt12_invoices`` — kept for ``BOLT12_INVOICE_RETENTION_DAYS``
      after ``paid_at`` (PAID) or ``created_at`` (EXPIRED / FAILED).

    OPEN invoices are never pruned; the reconcile loop owns that
    transition. Foreign-key parents are preserved until the child
    invoice row has been pruned (we prune invoices first, then
    requests).

    Bounded per-pass to avoid long-held write locks in production:
    at most ``default_prune_batch`` rows per table per invocation.
    The next daily run resumes where this one left off.
    """
    from datetime import timedelta

    from sqlalchemy import delete, select

    from app.core.config import settings as _settings
    from app.core.database import get_db_context
    from app.models.bolt12_invoice import (
        Bolt12Invoice,
        Bolt12InvoiceRequest,
        Bolt12InvoiceRequestStatus,
        Bolt12InvoiceStatus,
    )
    from app.models.bolt12_offer import Bolt12Offer

    default_prune_batch = 5_000

    now = datetime.now(timezone.utc)
    invoice_cutoff = now - timedelta(days=int(_settings.bolt12_invoice_retention_days))
    request_cutoff = now - timedelta(days=int(_settings.bolt12_request_retention_days))

    invoices_deleted = 0
    requests_deleted = 0

    async with get_db_context() as db:
        # ── Pass 1: invoices in terminal states ──────────────
        inv_terminal = (
            Bolt12InvoiceStatus.PAID,
            Bolt12InvoiceStatus.EXPIRED,
            Bolt12InvoiceStatus.FAILED,
        )
        # Collect ids in a separate SELECT so the DELETE has a
        # stable, bounded id set (some backends don't accept
        # ORDER BY + LIMIT directly on DELETE).
        #
        # Preservation rule: an invoice linked to a still-alive
        # offer (``Bolt12Offer.deleted_at IS NULL``) survives the
        # cleanup even past retention. That keeps the operator's
        # in-dashboard history readable for offers still in
        # production use; once the operator soft-deletes the
        # offer, its terminal invoices become eligible for prune
        # on the next pass. The invoice→invreq→offer join is via
        # ``invoice_request_id → offer_id``.
        inv_ids = (
            (
                await db.execute(
                    select(Bolt12Invoice.id)
                    .where(
                        Bolt12Invoice.status.in_(inv_terminal),
                        Bolt12Invoice.created_at < invoice_cutoff,
                        ~select(Bolt12Offer.id)
                        .join(
                            Bolt12InvoiceRequest,
                            Bolt12InvoiceRequest.offer_id == Bolt12Offer.id,
                        )
                        .where(
                            Bolt12InvoiceRequest.id == Bolt12Invoice.invoice_request_id,
                            Bolt12Offer.deleted_at.is_(None),
                        )
                        .exists(),
                    )
                    .order_by(Bolt12Invoice.created_at.asc())
                    .limit(default_prune_batch)
                )
            )
            .scalars()
            .all()
        )
        if inv_ids:
            await db.execute(delete(Bolt12Invoice).where(Bolt12Invoice.id.in_(inv_ids)))
            invoices_deleted = len(inv_ids)
            await db.commit()

        # ── Pass 2: requests in terminal states whose child
        # invoices have already been pruned. We delete only when
        # no invoice rows still reference the request.
        req_terminal = (
            Bolt12InvoiceRequestStatus.TIMED_OUT,
            Bolt12InvoiceRequestStatus.FAILED,
            Bolt12InvoiceRequestStatus.CANCELLED,
            Bolt12InvoiceRequestStatus.INVOICE_SENT,
            Bolt12InvoiceRequestStatus.INVOICE_RECEIVED,
        )
        req_ids = (
            (
                await db.execute(
                    select(Bolt12InvoiceRequest.id)
                    .where(
                        Bolt12InvoiceRequest.status.in_(req_terminal),
                        Bolt12InvoiceRequest.created_at < request_cutoff,
                        ~select(Bolt12Invoice.id)
                        .where(Bolt12Invoice.invoice_request_id == Bolt12InvoiceRequest.id)
                        .exists(),
                    )
                    .order_by(Bolt12InvoiceRequest.created_at.asc())
                    .limit(default_prune_batch)
                )
            )
            .scalars()
            .all()
        )
        if req_ids:
            await db.execute(delete(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.id.in_(req_ids)))
            requests_deleted = len(req_ids)
            await db.commit()

    if invoices_deleted or requests_deleted:
        logger.info(
            "bolt12 cleanup: pruned %d invoices, %d invreqs (invoice_retention_days=%d, request_retention_days=%d)",
            invoices_deleted,
            requests_deleted,
            _settings.bolt12_invoice_retention_days,
            _settings.bolt12_request_retention_days,
        )
    return {
        "invoices_deleted": invoices_deleted,
        "requests_deleted": requests_deleted,
        "invoice_retention_days": int(_settings.bolt12_invoice_retention_days),
        "request_retention_days": int(_settings.bolt12_request_retention_days),
    }


@celery_app.task(name="cleanup_bolt12_old_rows")
@track_task("cleanup_bolt12_old_rows")
def cleanup_bolt12_old_rows() -> dict[str, Any]:
    """Celery wrapper: prune terminal BOLT 12 rows older than retention."""
    result: dict[str, Any] = _run_async(_run_bolt12_cleanup_old_rows())
    return result


# ── Diagnostic C: htlc_max-vs-balance drift check ────────────


async def _run_check_bolt12_path_drift() -> dict[str, Any]:
    """Async impl of the BOLT 12 htlc_max-vs-balance drift check.

    Walks every open channel; for each, computes the ratio of the
    gossiped inbound ``max_htlc_msat`` over the live ``remote_balance``.
    When the ratio crosses ``BOLT12_HTLC_MAX_DRIFT_RATIO_ALERT``,
    emits a structured WARN log line + a
    ``bolt12_htlc_max_drift_detected`` audit row so operators can
    correlate against subsequent payment-attempt failures (the
    2026-06-05 Ocean post-mortem signal).
    """
    from app.core.config import settings as _settings
    from app.services.bolt12.path_diagnostics import run_drift_check
    from app.services.lnd_service import LNDService

    lnd = LNDService()
    try:
        summary = await run_drift_check(
            lnd,
            alert_ratio=_settings.bolt12_htlc_max_drift_ratio_alert,
        )
    finally:
        await lnd.close()

    if summary["alerted"]:
        logger.warning(
            "bolt12 path drift: scanned=%d alerted=%d max_ratio=%.2fx (threshold=%.2fx)",
            summary["scanned"],
            summary["alerted"],
            summary["max_ratio"],
            _settings.bolt12_htlc_max_drift_ratio_alert,
        )
    return summary


@celery_app.task(name="check_bolt12_path_drift")
@track_task("check_bolt12_path_drift")
def check_bolt12_path_drift() -> dict[str, Any]:
    """Celery wrapper: log + audit any over-claim drift in our
    open channels' gossiped inbound max_htlc vs live remote_balance."""
    result: dict[str, Any] = _run_async(_run_check_bolt12_path_drift())
    return result


# ── Telemetry #3: settlement watchdog ─────────────────────────
# Real implementation lives in ``app.services.bolt12.settle_watchdog``
# (moved 2026-06-06 so its breaker ``record_failure`` calls land
# in the same in-process registry the responder reads from). The
# Celery task below is a thin delegate retained for backwards
# compat / manual triggering; it is no longer scheduled in
# ``beat_schedule``.


async def _run_bolt12_settle_watchdog() -> dict[str, Any]:
    """Delegate to the shared
    :func:`app.services.bolt12.settle_watchdog.tick_settle_watchdog`
    implementation."""
    from app.services.bolt12.settle_watchdog import tick_settle_watchdog

    return await tick_settle_watchdog()


@celery_app.task(name="bolt12_settle_watchdog")
@track_task("bolt12_settle_watchdog")
def bolt12_settle_watchdog() -> dict[str, Any]:
    """Celery wrapper retained for manual triggering. NOT
    scheduled — the API-process asyncio task is the active path
    (see ``settle_watchdog.run_settle_watchdog``)."""
    result: dict[str, Any] = _run_async(_run_bolt12_settle_watchdog())
    return result


# ── Preventive Tor age rotation ──────────────────────────────


async def _run_rotate_tor_age() -> dict[str, Any]:
    """Preventive Tor age rotation.

    Tor processes that have been up for weeks accumulate guard-state
    degradation. The 2026-05-21 incident's "path restriction" warning
    had been firing for ~3 hours before the wedge — likely a build-up
    of that degradation. A scheduled ``SIGNAL HUP`` rebuilds circuits
    and reloads guard state without dropping the process.

    Behaviour:
      - In-flight gated. If anything looks live (LN HTLCs, Boltz
        swaps, Braiins deposits, anonymize sessions, step-up,
        BOLT 12), defer to next tick. Identical safety guarantee
        to the watchdog's NEWNYM gate.
      - Issues SIGNAL HUP (NOT NEWNYM) — HUP is the gentler reload
        path used here. NEWNYM is reserved for the
        watchdog's recovery escalation.
      - Audit-logs both the fire and the defer via the same helper
        the watchdog uses, so the operator-facing audit feed is
        consistent.
    """
    from app.core.database import get_db_context
    from app.services.anonymize.tor import signal_reload
    from app.services.tor_inflight import check_in_flight
    from app.services.tor_watchdog import _emit_audit

    try:
        inflight = await check_in_flight(get_db_context)
    except Exception as exc:  # noqa: BLE001
        # Fail-closed: a failed in-flight check defers the rotation
        # rather than risking interruption of a real payment.
        logger.warning(
            "tor age rotation: in-flight check raised %s; deferring",
            exc,
        )
        await _emit_audit(
            "tor_age_rotation_deferred",
            details={
                "reason": "in_flight_check_raised",
                "exc": str(exc)[:200],
            },
        )
        return {"status": "deferred", "reason": "in_flight_check_raised"}

    if inflight.in_flight:
        logger.info(
            "tor age rotation: deferred — surfaces=%s",
            inflight.surfaces,
        )
        await _emit_audit(
            "tor_age_rotation_deferred",
            details={"surfaces": inflight.surfaces},
        )
        return {"status": "deferred", "surfaces": inflight.surfaces}

    ok, err = await signal_reload()
    if ok:
        logger.info("tor age rotation: SIGHUP fired successfully")
        await _emit_audit("tor_age_rotation_fired", details={})
        return {"status": "fired"}
    logger.warning("tor age rotation: SIGHUP failed: %s", err)
    await _emit_audit("tor_age_rotation_failed", details={"error": err})
    return {"status": "error", "error": err}


@celery_app.task(name="rotate_tor_age")
@track_task("rotate_tor_age")
def rotate_tor_age() -> dict[str, Any]:
    """Celery wrapper for the preventive rotation. Gated by an
    in-flight check; defers when anything is live."""
    result: dict[str, Any] = _run_async(_run_rotate_tor_age())
    return result


# ── LND-side HS descriptor freshness check ──────────────────


async def _run_lnd_hs_descriptor_check() -> dict[str, Any]:
    """Async impl of the LND HS-descriptor freshness check
    . The check issues ``HSFETCH`` against LND's onion via
    the wallet's Tor control port and reads the resulting
    ``HS_DESC`` async event."""
    from app.services.lnd_hs_descriptor_check import (
        check_lnd_hs_descriptor_freshness,
    )

    return await check_lnd_hs_descriptor_freshness()


@celery_app.task(name="check_lnd_hs_descriptor_freshness")
@track_task("check_lnd_hs_descriptor_freshness")
def check_lnd_hs_descriptor_freshness_task() -> dict[str, Any]:
    """Celery wrapper. Read-only diagnostic — does not touch LND
    or fire any Tor signals. Audit-logs a warning when the
    descriptor has been stale across multiple consecutive ticks
    so the operator notices LND-side republish failures."""
    result: dict[str, Any] = _run_async(_run_lnd_hs_descriptor_check())
    return result
