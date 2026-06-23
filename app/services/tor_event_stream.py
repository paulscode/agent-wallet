# SPDX-License-Identifier: MIT
"""Live event subscription on the Tor control port.

The wallet's other Tor probes are pull-based: ``GETINFO`` /
``SIGNAL`` round-trips initiated by the watchdog or the dashboard
panel. Between ticks (30 s by default), a guard collapse or HS-
descriptor failure goes unnoticed. Tor's control protocol supports
``SETEVENTS`` — the wallet subscribes once, then receives Tor's own
events as they happen.

This module holds a long-lived control-port connection, sends
``SETEVENTS WARN ERR CIRC HS_DESC GUARD NETWORK_LIVENESS``, and
dispatches received events into the shared `EventCounters` instance
that the dashboard panel + metrics endpoint read.

The two surfaces (this push stream + the log-pattern scraping)
are complementary — `SETEVENTS` gives semantic events with structure;
log-scraping catches everything else Tor writes to stderr.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


_EVENT_TYPES = "WARN ERR CIRC HS_DESC GUARD NETWORK_LIVENESS"


@dataclass
class EventCounters:
    """In-process counters incremented by the event dispatcher.

    Each label is a Tor event TYPE (the first token after ``650 ``
    in the async-event reply shape). Counters reset on process
    restart.
    """

    circ_failed: int = 0
    hs_desc_failed: int = 0
    guard_down: int = 0
    network_liveness_down_total: int = 0
    warn_total: int = 0
    err_total: int = 0
    # Pattern-matched WARN/ERR sub-counters. We can't get
    # everything from typed events, so we sniff WARN/ERR payloads
    # for the specific log-line patterns that map to recovery actions.
    guard_excluded_total: int = 0
    """``All current guards excluded by path restriction`` — the
    2026-05-21 smoking gun. The watchdog uses this to spot the
    failure mode and accelerate NEWNYM."""
    circuit_stuck_total: int = 0
    """``Tried for N seconds to get a connection to`` — circuit
    build wedged on a specific hop."""
    # Last event timestamp (monotonic seconds) — useful for the
    # "event stream is alive" dashboard signal.
    last_event_ts: float = 0.0
    # Total events received since subscription began.
    events_total: int = 0
    # Stream lifecycle.
    stream_connected: bool = False
    stream_reconnect_total: int = 0
    last_reconnect_error: Optional[str] = None


_COUNTERS = EventCounters()
# Additional per-pool counters used in split mode. The
# default (unified / anonymize-side) counters stay in ``_COUNTERS``
# so single-mode callers and existing tests don't need to change.
# Split-mode lifespan reads ``_COUNTERS_LND`` for the LND pool.
_COUNTERS_LND = EventCounters()


def get_counters() -> EventCounters:
    """Return the live shared counters (read-only — the
    /v1/status/tor endpoint reads this). Backward-compatible
    accessor for the unified / anonymize-side counters."""
    return _COUNTERS


def get_pool_counters(pool: str) -> EventCounters:
    """Return the counters for a named pool.

    Pools: ``"unified"`` / ``"anonymize"`` → the legacy
    ``_COUNTERS``; ``"lnd"`` → ``_COUNTERS_LND``.
    """
    if pool == "lnd":
        return _COUNTERS_LND
    return _COUNTERS


# ── Dispatch logic ─────────────────────────────────────────────────


def _dispatch_event(line: str, counters: Optional[EventCounters] = None) -> None:
    """Update counters based on a single async-event line.

    Tor's async events arrive as ``650 <type> <data>\\r\\n`` (or
    ``650+<type>=…`` multi-line for some events). We only consume
    the first line of each event; the rest of any multi-line is
    skipped at the read level.

    ``counters`` defaults to the unified/anonymize-side
    counters so existing callers and tests don't need to change.
    Split-mode passes the LND-pool counters explicitly.
    """
    import time

    if counters is None:
        counters = _COUNTERS
    counters.events_total += 1
    counters.last_event_ts = time.monotonic()

    # Strip the ``650 `` or ``650-`` / ``650+`` prefix.
    m = re.match(r"^650[\-+ ]\s*(\S+)\s*(.*)$", line)
    if not m:
        return
    event_type = m.group(1).upper()
    payload = m.group(2)

    if event_type == "CIRC":
        # CIRC <id> <status> [<path>] …
        # status FAILED is the one we count.
        if " FAILED" in payload or payload.startswith("FAILED"):
            counters.circ_failed += 1
    elif event_type == "HS_DESC":
        # HS_DESC <action> <addr> <auth> <hsdir> [<descid>]
        if " FAILED" in payload or payload.startswith("FAILED"):
            counters.hs_desc_failed += 1
    elif event_type == "GUARD":
        # GUARD ENTRY $FP STATUS
        if " DOWN" in payload or " DROPPED" in payload:
            counters.guard_down += 1
    elif event_type == "NETWORK_LIVENESS":
        # NETWORK_LIVENESS UP|DOWN
        if "DOWN" in payload:
            counters.network_liveness_down_total += 1
    elif event_type == "WARN":
        counters.warn_total += 1
        _match_log_patterns(payload, counters)
    elif event_type == "ERR":
        counters.err_total += 1
        _match_log_patterns(payload, counters)


# Log-pattern matchers. Tor emits these as WARN/ERR
# payloads through the control protocol; the wallet doesn't need
# to read the container's stderr to spot them.
_PATTERN_GUARD_EXCLUDED = re.compile(
    r"All current guards excluded by path restriction",
    re.IGNORECASE,
)
_PATTERN_CIRCUIT_STUCK = re.compile(
    r"Tried for \d+ seconds to get a connection",
    re.IGNORECASE,
)


def _match_log_patterns(
    payload: str,
    counters: Optional[EventCounters] = None,
) -> None:
    """Increment pattern-specific counters when a WARN/ERR payload
    matches a known recovery-relevant signature.

    Adding a new pattern: bump :class:`EventCounters` with a new
    field, then add an ``if _PATTERN_*.search(payload):`` block
    here. Keep patterns case-insensitive so a future Tor version
    bump can change capitalization without silently breaking
    detection.

    ``counters`` defaults to the unified counters so
    existing call sites + tests don't change."""
    if counters is None:
        counters = _COUNTERS
    if _PATTERN_GUARD_EXCLUDED.search(payload):
        counters.guard_excluded_total += 1
    if _PATTERN_CIRCUIT_STUCK.search(payload):
        counters.circuit_stuck_total += 1


# ── Long-lived connection + reconnect-with-backoff ────────────────


_RECONNECT_BACKOFFS_S = (1.0, 2.0, 4.0, 8.0, 16.0)


async def _run_subscription(
    stop_event: asyncio.Event,
    pool: str = "unified",
) -> None:
    """Open the control port, authenticate, send ``SETEVENTS``, then
    block reading event lines until ``stop_event`` is set or the
    connection drops.

    On disconnect, walk the reconnect backoff schedule. Counter
    state persists across reconnects.

    ``pool`` selects which counters get the events and
    which control port we connect to."""
    counters = get_pool_counters(pool)
    backoff_iter = iter(_RECONNECT_BACKOFFS_S)
    while not stop_event.is_set():
        try:
            await _subscribe_once(stop_event, pool=pool)
            # Clean exit from _subscribe_once → reset backoff.
            backoff_iter = iter(_RECONNECT_BACKOFFS_S)
        except Exception as exc:  # noqa: BLE001
            counters.stream_connected = False
            counters.stream_reconnect_total += 1
            counters.last_reconnect_error = str(exc)[:200]
            logger.info(
                "tor event stream (%s): reconnect: %s",
                pool,
                exc,
            )
            try:
                backoff = next(backoff_iter)
            except StopIteration:
                backoff = _RECONNECT_BACKOFFS_S[-1]
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
    counters.stream_connected = False
    logger.info("tor event stream (%s): stopped", pool)


def _resolve_control_endpoint(pool: str) -> tuple[str, int]:
    """Pick the (host, port) the event-stream connects to
    based on pool. In single mode (or pool="unified"/"anonymize"),
    returns the anonymize control endpoint. In split mode with
    pool="lnd", returns the LND control endpoint."""
    from app.core.config import settings

    if pool == "lnd":
        host = settings.lnd_tor_control_host or "tor-lnd"
        port = int(settings.lnd_tor_control_port) or 9100
        return host, port
    host = settings.anonymize_tor_control_host or "127.0.0.1"
    port = int(settings.anonymize_tor_control_port)
    return host, port


async def _subscribe_once(
    stop_event: asyncio.Event,
    pool: str = "unified",
) -> None:
    """One subscription session. Returns cleanly when ``stop_event``
    is set; raises on connection error so the caller can backoff."""
    from app.core.config import settings

    host, port = _resolve_control_endpoint(pool)
    password = settings.resolved_tor_control_password
    counters = get_pool_counters(pool)
    if not host or port <= 0:
        # No control port configured — sleep until stop_event.
        await stop_event.wait()
        return

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=10.0,
    )

    async def _send(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        # Authenticate.
        if password:
            auth_resp = await _send(f'AUTHENTICATE "{password}"')
        else:
            auth_resp = await _send("AUTHENTICATE")
        if not auth_resp.startswith("250"):
            raise RuntimeError(f"AUTHENTICATE rejected: {auth_resp.strip()[:120]}")

        # Subscribe.
        sub_resp = await _send(f"SETEVENTS {_EVENT_TYPES}")
        if not sub_resp.startswith("250"):
            raise RuntimeError(f"SETEVENTS rejected: {sub_resp.strip()[:120]}")

        counters.stream_connected = True
        logger.info(
            "tor event stream (%s): subscribed to %s",
            pool,
            _EVENT_TYPES,
        )

        # Read events until cancelled / connection drops.
        while not stop_event.is_set():
            try:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=60.0,
                )
            except asyncio.TimeoutError:
                # No event in 60s — that's fine; Tor is quiet. Loop.
                continue
            if not line:
                raise ConnectionError("control port EOF")
            text = line.decode("ascii", errors="replace").strip()
            if text.startswith("650"):
                _dispatch_event(text, counters)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def start_event_stream(
    stop_event: asyncio.Event,
    pool: str = "unified",
) -> None:
    """Public entrypoint — start the long-lived event-subscription
    loop. Failure is bounded by the reconnect schedule; total
    runaway crashes are caught by the supervisor (the lifespan
    treats the task the same way it does the watchdog).

    ``pool`` selects which pool's counters + control port
    this task drives. Single mode runs one task with the default;
    split mode runs two (``"lnd"`` + ``"anonymize"``)."""
    await _run_subscription(stop_event, pool=pool)


__all__ = [
    "EventCounters",
    "get_counters",
    "get_pool_counters",
    "start_event_stream",
]
