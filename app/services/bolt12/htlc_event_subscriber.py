# SPDX-License-Identifier: MIT
"""LND HtlcEvent subscriber for BOLT 12 receive-side telemetry.

Streams LND's ``/v2/router/subscribehtlcs`` (HTLC events on every
channel the local node touches) and writes structured audit rows
when an event matches one of our minted BOLT 12 invoices.

The signal this resolves: today a "minted but never paid" BOLT 12
invoice is indistinguishable from "the HTLC reached us and we
silently rejected it" — both look identical from our logs (silent
non-settle). With this subscriber:

* ``bolt12_htlc_received_at_node`` — an HTLC for one of our
  payment_hashes arrived at LND. The reply path WORKED (the
  payer reached us); subsequent settle / fail is the actual
  cause.
* ``bolt12_htlc_link_failed_at_node`` — LND rejected the HTLC
  before forwarding/accepting. Carries LND's ``failure`` reason
  (amount mismatch, expiry-too-soon, fee-mismatch, channel-down).
* ``bolt12_htlc_settled`` — settlement seen on LND's switch
  (mirrors the settlement subscriber's signal at the switch
  layer instead of the invoice layer).

What we DON'T see: HTLCs that died upstream and never reached our
LND at all. The ABSENCE of any of the above for a given payment_hash
within the settle-watchdog window is itself the diagnostic — it
means the HTLC never made it past the intro or an intermediate hop.

Reconnect with capped exponential backoff. Idempotent at the
audit-log layer: the same event delivered twice (e.g. across a
reconnect) writes one audit row per delivery, which is fine —
the audit log is the event journal, not a state store.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db_context
from app.models.bolt12_invoice import Bolt12Direction, Bolt12Invoice
from app.services.lnd_service import lnd_service

logger = logging.getLogger(__name__)

_RECONNECT_BACKOFF_MIN_S: float = 2.0
_RECONNECT_BACKOFF_MAX_S: float = 60.0


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
        pass


async def run_htlc_event_subscriber(stop_event: asyncio.Event) -> None:
    """Subscribe to LND HTLC events; project matches onto audit rows.

    Long-running coroutine. Returns when ``stop_event`` is set.
    Catches all per-event errors so a malformed envelope or a
    transient DB hiccup never tears down the stream.
    """
    if not settings.bolt12_htlc_event_subscriber_enabled:
        logger.info("bolt12 HTLC event subscriber: disabled in settings")
        return

    # 2026-06-11: polling-mode bypass. HTLC events have no LND
    # REST polling equivalent (``forwarding_history`` covers
    # settled forwards only; ``link_fail_event`` and the RECEIVE
    # sub-types are stream-only). In polling mode we accept the
    # loss of HTLC-arrival telemetry as the cost of escaping the
    # long-lived-stream Tor-instability failure mode. Settlement
    # detection is unaffected — the settlement subscriber's
    # polling mode handles that via ``reconcile_open_invoices``.
    # S2 (2026-06-12): also auto-trip polling for onion-only LNDs.
    # Auto-detect can be killed via the dedicated setting so
    # operators explicitly choosing polling-mode=false can
    # actually get polling-mode=false. The shared resolver waits
    # for the LND keepalive's first success before running detect,
    # so a cold-start Tor warmup doesn't cause detect to time out
    # and silently drop us into streaming mode.
    try:
        from app.services.bolt12.onion_only_detect import (
            resolve_polling_mode_active,
        )

        polling_active = await resolve_polling_mode_active()
    except Exception:  # noqa: BLE001
        polling_active = False
    if polling_active:
        logger.info(
            "bolt12 HTLC event subscriber: polling mode active "
            "(no polling equivalent for HTLC events; subscriber "
            "is a no-op). Settle detection runs via the "
            "settlement subscriber's polling reconcile; the "
            "per-intro breaker receives the SUCCESS signal via "
            "reconcile's OPEN→PAID transition. The FAILURE signal "
            "(``bolt12_htlc_link_failed_at_node``) is unavailable "
            "in this mode — the adaptive-depth fallback will not "
            "fire because intros never transition to ``open``."
        )
        await stop_event.wait()
        logger.info("bolt12 HTLC event subscriber: polling mode stopped")
        return

    logger.info("bolt12 HTLC event subscriber: starting")
    backoff = _RECONNECT_BACKOFF_MIN_S

    from app.services.bolt12 import subscriber_metrics as sm
    from app.services.bolt12 import subscriber_recovery as rec_mod

    while not stop_event.is_set():
        # S4: warmup probe before opening the stream so dead pool
        # connections surface here instead of mid-stream.
        await rec_mod.warmup_probe(subscriber_name="htlc_event")
        stream_start_ts = sm.record_stream_started("htlc_event")
        try:
            await _stream_once(stop_event)
            # Clean stream exit (stop_event set or EOF). Reset
            # backoff and re-evaluate the loop guard.
            backoff = _RECONNECT_BACKOFF_MIN_S
            sm.record_stream_ended("htlc_event", stream_start_ts)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            lifetime_s = sm.record_stream_ended("htlc_event", stream_start_ts)
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
                # reconnect on the fresh circuit instead of
                # waiting out the exponential ceiling on a dead
                # one. Don't escalate ``backoff`` — transport
                # churn isn't an upstream-down signal.
                fired = await rec.try_newnym_throttled()
                wait_s = rec.transport_error_backoff_s()
                # S1 (2026-06-12): feed the inbound-symptom supervisor.
                _feed_inbound_supervisor(
                    transport=True,
                    lifetime_s=lifetime_s,
                )
                logger.warning(
                    "bolt12 HTLC event subscriber: stream failed "
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
                    "bolt12 HTLC event subscriber: stream failed (%s: %s) [lifetime=%.1fs]; reconnecting in %.1fs",
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

    logger.info("bolt12 HTLC event subscriber: stopped")


async def _stream_once(stop_event: asyncio.Event) -> None:
    """Open one ``/v2/router/subscribehtlcs`` stream and process
    events until EOF / stop. Raises on transport-level errors so
    the supervisor backs off."""
    client = await lnd_service._get_client()

    logger.info("bolt12 HTLC event subscriber: opening stream")
    async with client.stream(
        "GET",
        # LND's ``Router.SubscribeHtlcEvents`` REST mapping is
        # ``/v2/router/htlcevents`` (not /subscribehtlcs).
        # Confirmed empirically against LND 0.18 via probe.
        "/v2/router/htlcevents",
        timeout=httpx.Timeout(None, connect=20.0),
    ) as response:
        if response.status_code >= 400:
            text = await response.aread()
            msg = text.decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"LND htlc-event stream error ({response.status_code}): {msg}")

        async for line in response.aiter_lines():
            if stop_event.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "error" in envelope and envelope["error"]:
                err = envelope["error"]
                err_msg = err.get("message") if isinstance(err, dict) else str(err)
                raise RuntimeError(f"LND htlc-event stream error: {err_msg}")
            result = envelope.get("result") or envelope
            try:
                await _handle_htlc_event(result)
            except Exception:  # noqa: BLE001
                logger.exception("bolt12 HTLC event subscriber: per-event handler failed")


async def _handle_htlc_event(event: dict[str, Any]) -> None:
    """Project a single LND HTLC event onto a BOLT 12 audit row,
    iff the event matches one of our minted payment_hashes."""
    event_type = event.get("event_type") or ""
    if event_type != "RECEIVE":
        # Forward / send events don't belong to inbound BOLT 12.
        # Could be widened later if we add outbound BOLT 12 use
        # cases that benefit from richer per-hop signal.
        return

    # The relevant payload identifying the HTLC. LND surfaces
    # `payment_hash` (base64) in `forward_event.info`, in
    # `link_fail_event.info`, and in `settle_event.preimage`
    # depending on which sub-type fired.
    payment_hash_hex = _extract_payment_hash(event)
    if not payment_hash_hex:
        return

    matched = await _lookup_bolt12_invoice(payment_hash_hex)
    if matched is None:
        # Not one of ours. Could be a regular BOLT 11 invoice.
        return

    action, error_message, sub_details = _classify(event)
    if action is None:
        return

    base_details = {
        "payment_hash": payment_hash_hex,
        "invoice_id": str(matched["invoice_id"]),
        "api_key_id": str(matched["api_key_id"]),
        "incoming_channel_id": event.get("incoming_channel_id"),
        "outgoing_channel_id": event.get("outgoing_channel_id"),
        "incoming_htlc_id": event.get("incoming_htlc_id"),
        "outgoing_htlc_id": event.get("outgoing_htlc_id"),
        "timestamp_ns": event.get("timestamp_ns"),
    }
    base_details.update(sub_details or {})

    try:
        from app.services.bolt12.responder import _audit_inbound

        # T2 (2026-06-12): inherit the stored trace_id so HTLC-event
        # rows link back to the responder's mint flow. ALWAYS set
        # the contextvar (even if no trace_id is found) so this
        # event doesn't inherit a stale value from a prior event.
        from app.services.bolt12.trace import set_current_trace_id

        paths_summary = matched.get("paths_summary")
        row_trace_id = paths_summary.get("trace_id") if isinstance(paths_summary, dict) else None
        set_current_trace_id(row_trace_id)

        await _audit_inbound(
            get_db_context,
            action=action,
            success=("failed" not in action and "link_fail" not in action),
            api_key_id=matched["api_key_id"],
            error_message=error_message,
            details=base_details,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12 HTLC event subscriber: audit emit failed for %s",
            payment_hash_hex,
        )

    # Follow-up #4: feed the per-intro circuit breaker. This is
    # the ONLY signal the API-process breaker gets for cross-event
    # failures: the watchdog runs in a different process (Celery),
    # so its breaker updates don't reach us. For "HTLC died
    # upstream and we never saw it" failures, no HtlcEvent fires
    # and the breaker doesn't learn — that's a known limitation.
    if action in (
        "bolt12_htlc_link_failed_at_node",
        "bolt12_htlc_forward_failed_inbound",
    ):
        try:
            from app.services.bolt12.path_postprocess import get_path_breaker

            breaker = get_path_breaker()
            paths_summary = matched.get("paths_summary")
            if isinstance(paths_summary, dict):
                for p in paths_summary.get("paths", []):
                    if isinstance(p, dict):
                        intro = p.get("intro_pubkey")
                        if intro:
                            breaker.record_failure(intro)
        except Exception:  # noqa: BLE001
            logger.exception(
                "bolt12 HTLC event subscriber: breaker update failed for %s",
                payment_hash_hex,
            )
    elif action == "bolt12_htlc_settled":
        try:
            from app.services.bolt12.path_postprocess import get_path_breaker

            breaker = get_path_breaker()
            paths_summary = matched.get("paths_summary")
            if isinstance(paths_summary, dict):
                for p in paths_summary.get("paths", []):
                    if isinstance(p, dict):
                        intro = p.get("intro_pubkey")
                        if intro:
                            breaker.record_success(intro)
        except Exception:  # noqa: BLE001
            logger.exception(
                "bolt12 HTLC event subscriber: breaker update failed for %s",
                payment_hash_hex,
            )


def _extract_payment_hash(event: dict[str, Any]) -> str | None:
    """LND surfaces the HTLC payment_hash in different sub-events
    of ``RouterHtlcEvent`` depending on the lifecycle stage. Walk
    the likely keys and return whichever resolves to a 32-byte
    value normalised to hex."""
    candidates = []
    # Top-level fields seen on some LND versions.
    candidates.append(event.get("payment_hash"))
    for key in ("forward_event", "forward_fail_event", "link_fail_event", "settle_event", "final_htlc_event"):
        sub = event.get(key)
        if isinstance(sub, dict):
            candidates.append(sub.get("payment_hash"))
            info = sub.get("info") if isinstance(sub.get("info"), dict) else None
            if info:
                candidates.append(info.get("payment_hash"))
    for c in candidates:
        if not c:
            continue
        h = _normalise_hash(c)
        if h is not None:
            return h
    return None


def _normalise_hash(value: str) -> str | None:
    """Accept hex (64-char) or base64 (28-char); return 64-char hex."""
    if not isinstance(value, str):
        return None
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
        return None
    if len(raw) != 32:
        return None
    return raw.hex()


def _classify(
    event: dict[str, Any],
) -> tuple[str | None, str | None, dict | None]:
    """Map an LND HTLC event to an audit-row ``(action,
    error_message, extra_details)`` triple."""
    if isinstance(event.get("settle_event"), dict):
        return "bolt12_htlc_settled", None, None
    if isinstance(event.get("link_fail_event"), dict):
        lfe = event["link_fail_event"]
        wire = lfe.get("wire_failure")
        detail = lfe.get("failure_detail")
        string = lfe.get("failure_string", "")
        return (
            "bolt12_htlc_link_failed_at_node",
            string or wire or detail or "link_fail",
            {
                "wire_failure": wire,
                "failure_detail": detail,
                "failure_string": string,
            },
        )
    if isinstance(event.get("forward_fail_event"), dict):
        # Forward-fail on a RECEIVE event is unusual but LND has
        # been seen to emit it for HTLCs that arrived but were
        # cancelled before settle. Audit at WARN-equivalent.
        return (
            "bolt12_htlc_forward_failed_inbound",
            "forward_fail_on_inbound",
            None,
        )
    if isinstance(event.get("forward_event"), dict):
        # First sight of the HTLC at our node.
        return "bolt12_htlc_received_at_node", None, None
    # Some LND builds emit a final-htlc event with `settled` /
    # `offchain` flags.
    fhe = event.get("final_htlc_event")
    if isinstance(fhe, dict):
        if fhe.get("settled"):
            return "bolt12_htlc_settled", None, None
        return (
            "bolt12_htlc_link_failed_at_node",
            "final_htlc_not_settled",
            {"final_htlc_event": fhe},
        )
    return None, None, None


async def _lookup_bolt12_invoice(payment_hash_hex: str) -> dict | None:
    """Look up an INBOUND ``Bolt12Invoice`` by payment_hash. Returns
    ``{"invoice_id", "api_key_id", "paths_summary"}`` or ``None`` if
    the hash isn't one of ours. Best-effort: a DB hiccup returns
    None rather than raising into the event loop."""
    try:
        async with get_db_context() as db:
            row = (
                await db.execute(
                    select(
                        Bolt12Invoice.id,
                        Bolt12Invoice.api_key_id,
                        Bolt12Invoice.blinded_paths_summary,
                    ).where(
                        Bolt12Invoice.payment_hash_hex == payment_hash_hex,
                        Bolt12Invoice.direction == Bolt12Direction.INBOUND,
                    )
                )
            ).one_or_none()
            if row is None:
                return None
            return {
                "invoice_id": row[0],
                "api_key_id": row[1],
                "paths_summary": row[2],
            }
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12 HTLC event subscriber: lookup failed for %s",
            payment_hash_hex,
        )
        return None


__all__ = ["run_htlc_event_subscriber"]
