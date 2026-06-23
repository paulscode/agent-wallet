# SPDX-License-Identifier: MIT
"""BOLT 12 settle watchdog — API-process variant.

Periodically scans ``Bolt12Invoice`` rows that are still OPEN past
``BOLT12_INVOICE_SETTLE_WATCHDOG_MINUTES`` and:

1. Emits a ``bolt12_invoice_settle_timeout`` audit row (idempotent
   via the ``settle_timeout_audited_at`` column flag).
2. Feeds the per-intro circuit breaker
   (:class:`PathBreakerRegistry`) with ``record_failure`` for each
   intro in the invoice's ``blinded_paths_summary``.

**Why this runs in the API process** (not Celery): the breaker is
a Python module-level singleton — its state is per-process.
Failures recorded in the Celery worker's breaker do NOT affect
path selection in the API process. Moving the watchdog into the
API runtime means today's "minted but never settled" failures
*finally* inform the next mint's path choice.

Same logic as the previous Celery-side task (kept for backwards
compat at :func:`app.tasks.boltz_tasks._run_bolt12_settle_watchdog`).
The two implementations should remain in sync.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db_context
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceStatus,
)

logger = logging.getLogger(__name__)

_TICK_INTERVAL_S: float = 60.0


async def run_settle_watchdog(stop_event: asyncio.Event) -> None:
    """Long-running coroutine. Returns when ``stop_event`` is set.

    Sleeps ``_TICK_INTERVAL_S`` between scans; each scan runs the
    watchdog logic + breaker updates. Catches all per-tick errors
    so a transient DB hiccup never kills the loop.
    """
    # In unit tests ``start_bolt12_runtime`` spawns this loop, which
    # ticks immediately and queries the DB. If the test cancels the
    # runtime mid-query the aiosqlite worker thread later signals a
    # closed event loop and pytest fails the run. Tests that exercise
    # the watchdog call ``tick_settle_watchdog`` directly, so the loop
    # wrapper can safely no-op under ``settings.testing``.
    if settings.testing:
        return
    logger.info("bolt12 settle watchdog: starting (API-process variant)")
    while not stop_event.is_set():
        try:
            await tick_settle_watchdog()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("bolt12 settle watchdog: tick failed")
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=_TICK_INTERVAL_S,
            )
        except asyncio.TimeoutError:
            continue
        break
    logger.info("bolt12 settle watchdog: stopped")


async def tick_settle_watchdog() -> dict[str, Any]:
    """Run one watchdog pass. Exposed for unit-testing + for the
    Celery wrapper at :func:`app.tasks.boltz_tasks.bolt12_settle_watchdog`
    to share the same implementation.

    Returns ``{"scanned", "alerted"}`` summary. Disabled when
    ``BOLT12_INVOICE_SETTLE_WATCHDOG_MINUTES <= 0``.
    """
    window_min = int(settings.bolt12_invoice_settle_watchdog_minutes)
    if window_min <= 0:
        return {"scanned": 0, "alerted": 0, "skipped": "disabled"}

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_min)
    alerted = 0
    scanned = 0

    async with get_db_context() as db:
        rows = (
            (
                await db.execute(
                    select(Bolt12Invoice).where(
                        Bolt12Invoice.status == Bolt12InvoiceStatus.OPEN,
                        Bolt12Invoice.direction == Bolt12Direction.INBOUND,
                        Bolt12Invoice.created_at < cutoff,
                        Bolt12Invoice.settle_timeout_audited_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        scanned = len(rows)

        for row in rows:
            # Pin column values into locals so post-commit access
            # doesn't trigger lazy reload (greenlet-safe).
            row_id = row.id
            row_api_key_id = row.api_key_id
            row_amount_msat = row.amount_msat
            row_payment_hash_hex = row.payment_hash_hex
            row_created_at = row.created_at
            row_snapshot_present = row.channel_state_snapshot is not None
            row_paths_summary = row.blinded_paths_summary

            # 2026-06-13: pull two extra diagnostic signals before
            # emitting the audit row so each Ocean-style failure
            # carries enough context to discriminate "Tor blip" from
            # "policy-update race" from "rejected at our LND". Both
            # helpers are best-effort and return None on any error
            # — they MUST NOT block the audit-emit path.
            policy_drift: list[dict] = []
            lnd_htlc_state: dict | None = None
            try:
                from app.services.bolt12.failure_diagnostics import (
                    collect_path_policy_drift,
                    query_invoice_htlc_state,
                )
                from app.services.lnd_service import lnd_service

                policy_drift = await collect_path_policy_drift(
                    lnd_service,
                    row_paths_summary,
                )
                lnd_htlc_state = await query_invoice_htlc_state(
                    lnd_service,
                    payment_hash_hex=row_payment_hash_hex,
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "bolt12 settle watchdog: failure-diagnostics collection raised for %s",
                    row_payment_hash_hex,
                    exc_info=True,
                )

            try:
                from app.services.bolt12.responder import _audit_inbound

                # T2 (2026-06-12): inherit the row's trace_id so the
                # settle-timeout audit row links to the responder's
                # earlier flow.
                from app.services.bolt12.trace import (
                    set_current_trace_id,
                    trace_id_from_row,
                )

                row_trace_id = trace_id_from_row(row)
                set_current_trace_id(row_trace_id)

                await _audit_inbound(
                    get_db_context,
                    action="bolt12_invoice_settle_timeout",
                    api_key_id=row_api_key_id,
                    amount_msat=row_amount_msat,
                    success=False,
                    error_message="settle_window_elapsed",
                    details={
                        "invoice_id": str(row_id),
                        "payment_hash": row_payment_hash_hex,
                        "minted_at": (row_created_at.isoformat() if row_created_at else None),
                        "window_minutes": window_min,
                        "has_channel_state_snapshot": row_snapshot_present,
                        # 2026-06-13 failure-diagnostic enrichment
                        "policy_drift_per_intro": policy_drift,
                        "lnd_invoice_htlc_state": lnd_htlc_state,
                    },
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "bolt12 settle watchdog: audit emit failed for %s",
                    row_payment_hash_hex,
                )
                continue

            row.settle_timeout_audited_at = datetime.now(timezone.utc)
            try:
                await db.commit()
            except Exception:  # noqa: BLE001
                logger.exception(
                    "bolt12 settle watchdog: commit failed for %s",
                    row_payment_hash_hex,
                )
                try:
                    await db.rollback()
                except Exception:  # noqa: BLE001
                    pass
                continue
            alerted += 1
            logger.warning(
                "bolt12 settle watchdog: invoice %s payment_hash=%s "
                "open for >%dm — emitted bolt12_invoice_settle_timeout "
                "audit row (snapshot_present=%s)",
                row_id,
                row_payment_hash_hex,
                window_min,
                row_snapshot_present,
            )
            # 2026-06-13: one-line diagnostic summary so the
            # blip-vs-structural signal is grep-friendly without
            # opening the audit blob.
            #   ``divergent_intros`` — intros whose encoded policy
            #     drifted from gossip between mint and now.
            #   ``divergent_fields`` — union of divergent field
            #     names across all intros, comma-separated. Most
            #     useful single token: a recurring name across
            #     failures pins down the structural cause.
            #   ``min_policy_age_s`` — youngest ``last_update``
            #     across the intros' current policies. Sub-minute
            #     values strongly suggest a policy-update race.
            #   ``htlc_count`` — HTLCs that reached our LND for
            #     this payment_hash (0 → failure was upstream).
            divergent_intros = 0
            divergent_field_set: set[str] = set()
            min_policy_age_s: int | None = None
            for d in policy_drift:
                if not isinstance(d, dict):
                    continue
                div = d.get("divergence") or {}
                if div:
                    divergent_intros += 1
                    divergent_field_set.update(div.keys())
                current = d.get("current") or {}
                policy = current.get("policy") or {} if isinstance(current, dict) else {}
                age = policy.get("last_update_age_s")
                if isinstance(age, int):
                    if min_policy_age_s is None or age < min_policy_age_s:
                        min_policy_age_s = age
            htlc_count = len(lnd_htlc_state.get("htlcs", [])) if isinstance(lnd_htlc_state, dict) else None
            logger.warning(
                "bolt12 settle watchdog diag: invoice=%s intros=%d "
                "divergent_intros=%d divergent_fields=%s "
                "min_policy_age_s=%s lnd_htlc_count=%s "
                "lnd_invoice_state=%s",
                row_id,
                len(policy_drift),
                divergent_intros,
                (",".join(sorted(divergent_field_set)) if divergent_field_set else "none"),
                min_policy_age_s,
                htlc_count,
                (lnd_htlc_state or {}).get("state") if isinstance(lnd_htlc_state, dict) else None,
            )

            # The point of running this in the API process: each
            # path through this failed invoice's intros gets
            # ``record_failure`` on the **same** breaker the
            # responder reads from. Path selection on the next
            # mint will now deprioritise the open intros.
            try:
                from app.services.bolt12.path_postprocess import (
                    get_path_breaker,
                )

                breaker = get_path_breaker()
                if isinstance(row_paths_summary, dict):
                    for p in row_paths_summary.get("paths", []):
                        if isinstance(p, dict):
                            intro = p.get("intro_pubkey")
                            if intro:
                                breaker.record_failure(intro)
            except Exception:  # noqa: BLE001
                logger.exception(
                    "bolt12 settle watchdog: breaker update failed for %s",
                    row_payment_hash_hex,
                )

    return {"scanned": scanned, "alerted": alerted}


__all__ = ["run_settle_watchdog", "tick_settle_watchdog"]
