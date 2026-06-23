# SPDX-License-Identifier: MIT
"""LND invoice-settlement subscriber for BOLT 12.

Replaces the worst-case 60s reconcile latency (the Celery beat
poll for ``Bolt12Invoice.status == OPEN``) with a push stream
from LND. When a blinded-path HTLC settles for one of our minted
invoices, LND emits a server-streamed update on
``/v2/invoices/subscribe`` within milliseconds; we project the
``SETTLED`` state onto the corresponding ``Bolt12Invoice`` row
immediately.

The reconcile loop stays in place as a defence-in-depth catch-up
worker: if the stream is disconnected when LND settles a
payment, the next reconcile pass picks it up. Idempotent — a
SETTLED projection is a no-op on an already-PAID row.

Lifecycle:

* Started from ``app/main.py`` lifespan alongside the BOLT 12
  runtime when ``bolt12_settlement_subscriber_enabled=True``.
* Stopped on shutdown via an ``asyncio.Event``.
* On stream failure (network blip, LND restart, breaker open),
  the supervisor backs off with capped exponential delay and
  re-subscribes from the LND-provided settle index so no
  settlement is lost across the gap.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.exc import PendingRollbackError, SQLAlchemyError

from app.core.config import settings
from app.core.database import get_db_context
from app.core.encryption import encrypt_field
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceStatus,
)
from app.services.lnd_service import lnd_service

logger = logging.getLogger(__name__)

_RECONNECT_BACKOFF_MIN_S: float = 2.0
_RECONNECT_BACKOFF_MAX_S: float = 60.0


async def _polling_mode_active() -> bool:
    """Thin wrapper around :func:`resolve_polling_mode_active` —
    kept for test-patch points and for the docstring summary.

    * ``bolt12_subscriber_polling_mode_enabled=True`` → True (force on).
    * ``bolt12_subscriber_polling_mode_auto_detect=False`` → False
      (operator opted out of auto-detect; honour the explicit setting).
    * Otherwise → wait for LND keepalive's first success (cold-start
      grace), then True iff LND advertises only ``.onion`` addresses.
    """
    from app.services.bolt12.onion_only_detect import (
        resolve_polling_mode_active,
    )

    return await resolve_polling_mode_active()


def _feed_inbound_supervisor(*, transport: bool, lifetime_s: float) -> None:
    """Best-effort feed to the inbound HS supervisor (S1). Lazily
    imported so this module stays usable in test environments that
    don't initialise the supervisor."""
    try:
        from app.services.bolt12.inbound_supervisor import (
            record_subscriber_event,
        )

        record_subscriber_event(transport=transport, lifetime_s=lifetime_s)
    except Exception:  # noqa: BLE001
        # Never block the subscriber's recovery loop on the
        # supervisor — the supervisor is advisory.
        pass


async def run_settlement_subscriber(stop_event: asyncio.Event) -> None:
    """Subscribe to LND invoice updates and project SETTLED onto BOLT 12 rows.

    Long-running coroutine. Returns when ``stop_event`` is set.

    Reconnects with exponential backoff (capped) on any stream
    failure. The ``settle_index`` returned by LND is tracked across
    reconnects so we don't lose settlement notifications that
    arrived during a gap.
    """
    if not settings.bolt12_settlement_subscriber_enabled:
        logger.info("bolt12 settlement subscriber: disabled in settings")
        return

    # 2026-06-11: polling-mode bypass. On Tor-unstable deployments
    # operators may prefer the reconcile loop's poll semantics
    # over the long-lived stream's lower latency. ``reconcile_
    # open_invoices`` already does exactly the projection work
    # this subscriber does — we just run it on a short timer.
    # S2 (2026-06-12): if the env var is at its default, also
    # auto-enable polling when LND advertises only ``.onion``
    # addresses — the shape most likely to suffer Tor stream churn.
    if await _polling_mode_active():
        await _run_polling_mode(stop_event)
        return

    logger.info("bolt12 settlement subscriber: starting")
    backoff = _RECONNECT_BACKOFF_MIN_S
    # ``settle_index`` is LND's monotonic counter of settled invoices.
    # Starting from 0 means "stream all currently-open + future
    # settlements". On reconnect we resume from the highest index
    # observed so the gap is covered without re-processing already-
    # projected rows (the SETTLED branch is idempotent regardless).
    settle_index: int = 0

    from app.services.bolt12 import subscriber_metrics as sm
    from app.services.bolt12 import subscriber_recovery as rec_mod

    while not stop_event.is_set():
        # S4: warmup probe before opening the stream so dead pool
        # connections surface here instead of mid-stream.
        await rec_mod.warmup_probe(subscriber_name="settlement")
        stream_start_ts = sm.record_stream_started("settlement")
        try:
            next_index = await _stream_once(settle_index, stop_event)
            if next_index is not None and next_index > settle_index:
                settle_index = next_index
            # Clean disconnect (stop_event set, or stream EOF) →
            # reset backoff and loop.
            backoff = _RECONNECT_BACKOFF_MIN_S
            sm.record_stream_ended("settlement", stream_start_ts)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            lifetime_s = sm.record_stream_ended("settlement", stream_start_ts)
            # ``str(exc)`` is empty for several httpx long-stream
            # errors (RemoteProtocolError, ReadError, etc. raised
            # from inside ``aiter_lines``). Always include the
            # exception class so operators see what failed, not
            # just "stream failed ()". On the first failure of an
            # episode (backoff still at the floor) emit the
            # traceback once so the underlying cause is captured
            # without spamming the log for every subsequent retry.
            from app.services.bolt12 import subscriber_recovery as rec

            cls = type(exc).__name__
            detail = str(exc) or "no message"
            first_of_episode = backoff == _RECONNECT_BACKOFF_MIN_S
            transport = rec.is_transport_error(exc)
            if transport and rec.newnym_on_transport_error_enabled():
                # 2026-06-11: roll the Tor circuit (best-effort,
                # throttled) and use a short fixed backoff so we
                # reconnect on the fresh circuit. Don't escalate
                # ``backoff`` — transport churn isn't an upstream-
                # down signal.
                fired = await rec.try_newnym_throttled()
                wait_s = rec.transport_error_backoff_s()
                # S1 (2026-06-12): feed the inbound-symptom supervisor.
                _feed_inbound_supervisor(
                    transport=True,
                    lifetime_s=lifetime_s,
                )
                logger.warning(
                    "bolt12 settlement subscriber: stream failed "
                    "(%s: %s) [transport, lifetime=%.1fs, "
                    "newnym_fired=%s]; reconnecting in %.1fs",
                    cls,
                    detail,
                    lifetime_s,
                    fired,
                    wait_s,
                    exc_info=first_of_episode,
                )
            else:
                wait_s = backoff
                logger.warning(
                    "bolt12 settlement subscriber: stream failed (%s: %s) [lifetime=%.1fs]; reconnecting in %.1fs",
                    cls,
                    detail,
                    lifetime_s,
                    backoff,
                    exc_info=first_of_episode,
                )
                backoff = min(_RECONNECT_BACKOFF_MAX_S, backoff * 2.0)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=wait_s)
            except asyncio.TimeoutError:
                pass

    logger.info("bolt12 settlement subscriber: stopped")


async def _run_polling_mode(stop_event: asyncio.Event) -> None:
    """2026-06-11: poll-mode entrypoint. No long-lived stream.

    Calls :func:`reconcile_open_invoices` on a tight timer
    (``bolt12_subscriber_polling_interval_s``). The reconcile
    function already does the LND→DB projection — paid / expired
    / failed state transitions land in the DB the same way the
    streamed projection would, just on a 5-second cadence
    instead of milliseconds.

    Trade-off: settle detection latency goes from ms to
    poll-interval seconds. On Tor-unstable deployments this is a
    strict win — the streamed path was producing zero useful
    settle observations because the stream died before any
    settlement ever traversed it.
    """
    from app.services.bolt12.reconcile import reconcile_open_invoices
    from app.services.lnd_service import lnd_service

    interval = max(1.0, float(settings.bolt12_subscriber_polling_interval_s))
    logger.info(
        "bolt12 settlement subscriber: polling mode (interval=%.1fs; stream bypassed)",
        interval,
    )
    while not stop_event.is_set():
        try:
            async with get_db_context() as db:
                summary = await reconcile_open_invoices(db, lnd_service)
            if summary.paid > 0 or summary.errored > 0:
                logger.info(
                    "bolt12 settlement subscriber (polling): paid=%d expired=%d failed=%d errored=%d",
                    summary.paid,
                    summary.expired,
                    summary.failed,
                    summary.errored,
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("bolt12 settlement subscriber (polling): tick failed; continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("bolt12 settlement subscriber: polling mode stopped")


async def _stream_once(
    settle_index: int,
    stop_event: asyncio.Event,
) -> int | None:
    """Open a single ``/v2/invoices/subscribe`` stream and process
    incoming messages until the stream ends or ``stop_event`` is set.

    Returns the highest ``settle_index`` observed during this stream
    (or ``settle_index`` unchanged if no settlements arrived).
    Raises on transport-level errors so the supervisor backs off.
    """
    client = await lnd_service._get_client()
    # ``settle_index`` is passed as a query parameter on the
    # invoicesrpc subscription. LND will stream the matching
    # invoices in monotonic order starting *after* this index.
    params = {"settle_index": str(settle_index)} if settle_index > 0 else None

    logger.info(
        "bolt12 settlement subscriber: opening stream (settle_index=%d)",
        settle_index,
    )

    last_seen_index = settle_index
    async with client.stream(
        "GET",
        # LND's main ``Lightning.SubscribeInvoices`` REST mapping is
        # ``/v1/invoices/subscribe`` (not /v2 — the /v2/invoices
        # subserver is the hold-invoice subscriber, single-r-hash
        # only). Confirmed empirically against LND 0.18 via probe.
        "/v1/invoices/subscribe",
        params=params,
        timeout=httpx.Timeout(None, connect=20.0),
    ) as response:
        if response.status_code >= 400:
            text = await response.aread()
            msg = text.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"LND subscribe error ({response.status_code}): {msg}")

        async for line in response.aiter_lines():
            if stop_event.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("bolt12 settlement subscriber: ignoring non-JSON line")
                continue
            # gRPC-gateway envelope: ``{"result": {...}}`` or
            # ``{"error": {...}}``.
            if "error" in envelope and envelope["error"]:
                err_msg = envelope["error"].get("message") or str(envelope["error"])
                raise RuntimeError(f"LND stream error: {err_msg}")
            result = envelope.get("result") or envelope
            idx = await _handle_invoice_update(result)
            if idx is not None and idx > last_seen_index:
                last_seen_index = idx

    return last_seen_index


async def _handle_invoice_update(invoice: dict[str, Any]) -> int | None:
    """Project one LND invoice update onto its ``Bolt12Invoice`` row.

    Returns the ``settle_index`` from this update (for resume-point
    tracking) regardless of whether we matched a row, so the
    supervisor advances even on unrelated invoices.
    """
    state = (invoice.get("state") or "").upper()
    settle_index_str = invoice.get("settle_index") or "0"
    try:
        settle_index = int(settle_index_str)
    except (TypeError, ValueError):
        settle_index = 0

    # Only SETTLED is interesting — OPEN/ACCEPTED/CANCELED/EXPIRED
    # are projected by the reconcile loop (which runs on a longer
    # cadence and is the source of truth for non-SETTLED states).
    if state != "SETTLED":
        return settle_index

    r_hash_hex = _extract_r_hash_hex(invoice)
    if not r_hash_hex:
        return settle_index

    try:
        await _project_settled(invoice, r_hash_hex)
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12 settlement subscriber: failed to project SETTLED for %s",
            r_hash_hex,
        )
    return settle_index


def _extract_r_hash_hex(invoice: dict[str, Any]) -> str | None:
    """LND REST returns ``r_hash`` as either hex or base64 depending on
    the endpoint; subscribe returns base64. Normalise to hex."""
    r_hash = invoice.get("r_hash") or ""
    if not r_hash:
        return None
    # Hex path: 64-char string parseable as bytes.
    if len(r_hash) == 64:
        try:
            bytes.fromhex(r_hash)
            return r_hash.lower()
        except ValueError:
            pass
    try:
        raw = base64.b64decode(r_hash, validate=True)
    except Exception:  # noqa: BLE001
        return None
    if len(raw) != 32:
        return None
    return raw.hex()


async def _project_settled(invoice: dict[str, Any], r_hash_hex: str) -> None:
    """Flip the matching BOLT 12 row to PAID, idempotently."""
    async with get_db_context() as db:
        row = (
            await db.execute(
                select(Bolt12Invoice).where(
                    Bolt12Invoice.payment_hash_hex == r_hash_hex,
                    Bolt12Invoice.direction == Bolt12Direction.INBOUND,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            # Not one of ours — could be a regular BOLT 11 invoice
            # under the same LND. The reconcile loop is keyed the
            # same way so it'll skip it too. No-op.
            return
        if row.status == Bolt12InvoiceStatus.PAID:
            return

        row.status = Bolt12InvoiceStatus.PAID
        settle_date = invoice.get("settle_date") or 0
        try:
            settle_ts = int(settle_date)
        except (TypeError, ValueError):
            settle_ts = 0
        if settle_ts > 0:
            row.paid_at = datetime.fromtimestamp(settle_ts, tz=timezone.utc)
        else:
            row.paid_at = datetime.now(timezone.utc)
        preimage = invoice.get("r_preimage") or invoice.get("payment_preimage") or ""
        if preimage and not row.encrypted_preimage:
            row.encrypted_preimage = encrypt_field(_normalize_preimage(preimage))

        # Follow-up #4: feed the per-intro circuit breaker on
        # success. Capture the intros locally before the commit
        # so the post-commit attribute read is greenlet-safe.
        paths_summary = row.blinded_paths_summary

        try:
            await db.commit()
        except (PendingRollbackError, SQLAlchemyError):
            logger.exception(
                "bolt12 settlement subscriber: commit failed for %s",
                r_hash_hex,
            )
            try:
                await db.rollback()
            except Exception:  # noqa: BLE001
                pass
            return
        # Each intro that carried this successful settle gets its
        # breaker closed (and failure history reset). Best-effort.
        try:
            from app.services.bolt12.path_postprocess import get_path_breaker

            breaker = get_path_breaker()
            if isinstance(paths_summary, dict):
                for p in paths_summary.get("paths", []):
                    if isinstance(p, dict):
                        intro = p.get("intro_pubkey")
                        if intro:
                            breaker.record_success(intro)
        except Exception:  # noqa: BLE001
            logger.exception(
                "bolt12 settlement subscriber: breaker update failed for %s",
                r_hash_hex,
            )

        logger.info(
            "bolt12 settlement subscriber: projected SETTLED for %s (row id=%s)",
            r_hash_hex,
            row.id,
        )


def _normalize_preimage(value: str) -> str:
    """Accept hex or base64; return hex. Mirrors reconcile.py."""
    s = value.strip()
    if len(s) == 64:
        try:
            bytes.fromhex(s)
            return s.lower()
        except ValueError:
            pass
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:  # noqa: BLE001
        return s
    return raw.hex()


__all__ = ["run_settlement_subscriber"]
