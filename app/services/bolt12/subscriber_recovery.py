# SPDX-License-Identifier: MIT
"""Shared transport-error recovery helpers for BOLT 12 subscribers.

The HTLC-event and settlement subscribers both hold long-lived h2
streams to LND over Tor. As of 2026-06-11 we observed three
recurring failure classes against an onion-only LND:

* ``httpx.ReadError`` (no message) — socket closed mid-read.
* ``httpx.RemoteProtocolError`` — LND closed the chunked stream.
* ``httpx.ProxyError: TTL expired`` — Tor circuit literally died
  before the SOCKS5 server could use it.

All three are transport-layer issues on the Tor SOCKS5 path. The
right recovery isn't to sit on a 60 s exponential backoff — by
that point the dropped circuit is long gone and we've just lost
an observation window. The right recovery is:

1. Detect transport-class errors specifically.
2. Fire ``SIGNAL NEWNYM`` to retire dirty circuits (Tor itself
   rate-limits NEWNYM at 10 s; we throttle further to avoid
   bursting under sustained error rates).
3. Use a short fixed backoff (default 2 s) so the next
   reconnect picks up the freshly built circuit.
4. DO NOT escalate the exponential-backoff counter — that's for
   "the upstream is genuinely down", which transport errors
   alone don't indicate.

The two subscribers share these helpers so the policy is
consistent. The NEWNYM throttle is module-level (shared) so a
burst of transport errors across both subscribers fires NEWNYM at
most once per throttle interval — they're hitting the same Tor
proxy, so rolling the circuit once helps both.
"""

from __future__ import annotations

import logging
import time
from typing import Final

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


# Transport-layer error classes. An ``isinstance`` check against
# this tuple identifies "the connection itself failed" vs "the
# server returned a bad payload / our parser threw / etc.".
#
# - ``ConnectError``: SOCKS5 handshake failed or TCP couldn't reach
# - ``ConnectTimeout``: connect phase took longer than the timeout
# - ``ReadError``: stream socket closed by remote mid-read (the
#   most common case observed against onion LND — empty message)
# - ``ReadTimeout``: no bytes from server within the timeout
# - ``WriteError`` / ``WriteTimeout``: outbound side of the stream
# - ``PoolTimeout``: couldn't get a connection from the httpx pool
# - ``RemoteProtocolError``: h2 framing/chunked-encoding broke
# - ``ProxyError``: SOCKS5 server returned an error (TTL expired
#   is the standout — circuit died before we could use it)
_TRANSPORT_ERROR_CLASSES: Final[tuple[type[BaseException], ...]] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadError,
    httpx.ReadTimeout,
    httpx.WriteError,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
    httpx.ProxyError,
)


# Module-level NEWNYM throttle. Shared by both subscribers so a
# burst across both at once fires NEWNYM at most once per window.
_LAST_NEWNYM_AT: float = 0.0


def is_transport_error(exc: BaseException) -> bool:
    """Return True if ``exc`` is a transport-layer httpx error.

    Used by the subscribers to decide between "fast recover via
    NEWNYM" (transport) and "exponential backoff" (everything
    else, including LND-level errors and our own bugs).
    """
    return isinstance(exc, _TRANSPORT_ERROR_CLASSES)


def _newnym_min_interval_s() -> float:
    """Floor on how often we may fire NEWNYM from the subscribers.

    Reuses the wallet's existing ``tor_newnym_min_interval_s``
    knob (default 60 s) so a single setting governs every
    subsystem that may roll circuits. Tor itself rate-limits
    NEWNYM at 10 s as well; we never go tighter than that.
    """
    return max(10.0, float(settings.tor_newnym_min_interval_s))


async def try_newnym_throttled() -> bool:
    """Fire ``SIGNAL NEWNYM`` if not throttled. Best-effort.

    Returns ``True`` iff NEWNYM was actually attempted (and the
    Tor control port accepted it). Returns ``False`` if we
    skipped due to the throttle, or if the signal call raised /
    failed.

    Never raises — callers can use the result purely for log
    enrichment.
    """
    global _LAST_NEWNYM_AT
    now = time.monotonic()
    interval = _newnym_min_interval_s()
    if now - _LAST_NEWNYM_AT < interval:
        return False
    _LAST_NEWNYM_AT = now
    try:
        from app.services.anonymize.tor import signal_newnym

        ok, err = await signal_newnym(timeout_s=3.0)
        if not ok:
            logger.debug(
                "bolt12 subscriber NEWNYM rejected by Tor: %s",
                err,
            )
            return False
        return True
    except Exception:  # noqa: BLE001
        logger.debug(
            "bolt12 subscriber NEWNYM helper raised",
            exc_info=True,
        )
        return False


def transport_error_backoff_s() -> float:
    """Backoff to use after a transport-class error.

    Short and fixed (default 2 s). The point is to reconnect on
    the fresh circuit NEWNYM just created — not to wait out the
    next exponential tier. Configurable via
    ``bolt12_subscriber_transport_error_backoff_s``.
    """
    return float(settings.bolt12_subscriber_transport_error_backoff_s)


def newnym_on_transport_error_enabled() -> bool:
    """Operator kill switch. Default on."""
    return bool(settings.bolt12_subscriber_newnym_on_transport_error)


def _reset_throttle_for_tests() -> None:
    """Test-only: clear the NEWNYM throttle so successive tests
    don't bleed state into each other. NOT part of the public
    API; callers outside ``tests/`` should never use this."""
    global _LAST_NEWNYM_AT
    _LAST_NEWNYM_AT = 0.0


async def warmup_probe(*, subscriber_name: str) -> bool:
    """S4 (2026-06-12): pre-emptive ``GET /v1/getinfo`` over the
    LND httpx pool to confirm the connection is alive *before* we
    open a long-lived stream on top of it.

    Reduces the dead-circuit-in-pool window from "60 s keepalive
    cadence" to "this many seconds since the last warmup probe".
    Bounded by an internal 10 s timeout so a wedged LND can't
    block the subscriber's reconnect loop indefinitely.

    Returns True on a successful probe, False on any error
    (caller's loop decides what to do — typically it can just
    fall through to attempting the stream anyway, since the
    stream itself is the canonical success signal).
    """
    if not settings.bolt12_subscriber_warmup_probe_enabled:
        return True
    import asyncio

    try:
        from app.services.lnd_service import lnd_service

        info, err = await asyncio.wait_for(
            lnd_service.get_info(),
            timeout=10.0,
        )
        if err is not None or info is None:
            logger.info(
                "bolt12 %s subscriber: warmup probe failed (%s)",
                subscriber_name,
                err,
            )
            return False
        return True
    except asyncio.TimeoutError:
        logger.info(
            "bolt12 %s subscriber: warmup probe timed out",
            subscriber_name,
        )
        return False
    except Exception:  # noqa: BLE001
        logger.debug(
            "bolt12 %s subscriber: warmup probe raised",
            subscriber_name,
            exc_info=True,
        )
        return False


__all__ = [
    "is_transport_error",
    "newnym_on_transport_error_enabled",
    "transport_error_backoff_s",
    "try_newnym_throttled",
    "warmup_probe",
]
