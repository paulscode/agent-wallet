# SPDX-License-Identifier: MIT
"""Concurrency, shutdown drain, in-flight gauges.

A single small module owns:

* **Per-API-key concurrency cap** — bounds in-flight requests
  per API key so one runaway agent cannot starve the connection
  pool. Tracked in-process via :class:`asyncio.Semaphore`.
* **Graceful shutdown drain** — module-level flag flips to
  True on SIGTERM / lifespan shutdown; middleware refuses *new*
  requests with 503 while letting in-flight ones finish.
* **In-flight gauges** — module-level counter exposes
  ``in_flight_requests`` for ``/metrics``.

All state is process-local — a multi-worker deployment behind a
load balancer gets *per-worker* caps, which is what we want
(otherwise we'd need a Redis-backed coordination layer with all
the retry/atomicity baggage).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── shutdown drain ─────────────────────────────────────────

_shutdown_started = False
_in_flight_count = 0
_in_flight_lock: Optional[asyncio.Lock] = None


def begin_shutdown() -> None:
    """Flip the drain flag. New requests will be rejected with 503."""
    global _shutdown_started
    _shutdown_started = True


def is_shutting_down() -> bool:
    return _shutdown_started


async def wait_for_drain(timeout_s: float) -> bool:
    """Wait up to ``timeout_s`` for in-flight requests to finish.

    Returns True if the drain completed (count reached 0), False if
    the timeout fired with requests still in flight.
    """
    try:
        timeout_f = float(timeout_s)
    except (TypeError, ValueError):
        timeout_f = 0.0
    deadline = asyncio.get_running_loop().time() + max(0.0, timeout_f)
    while _in_flight_count > 0:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(0.1, remaining))
    return True


def in_flight_count() -> int:
    return _in_flight_count


# ── per-key concurrency cap ────────────────────────────────

# Available slots per API key. asyncio is single-threaded per event
# loop, so a plain integer counter gives a correct non-blocking
# acquire/release without reaching into asyncio.Semaphore internals.
_key_slots: dict[str, int] = {}
_concurrent_per_key_cap = 0  # 0 == disabled

# Backstop against unbounded growth. The concurrency middleware derives the key
# from the inbound Authorization header BEFORE authentication, so an
# unauthenticated attacker could otherwise pin one map entry per distinct
# bearer token. With the pop-on-idle in ``release_for_key`` the map only
# holds keys with an in-flight request, which is naturally bounded; this
# cap is a defensive second line against a flood of slow/never-released
# requests.
_MAX_TRACKED_KEYS = 16384
_dropped_keys_warned = False


def configure_concurrent_cap(cap: int) -> None:
    """Set the per-key cap. 0 disables the limiter."""
    global _concurrent_per_key_cap
    _concurrent_per_key_cap = max(0, int(cap))


def try_acquire_for_key(api_key_id: str) -> bool:
    """Non-blocking acquire. Returns True if the slot was claimed.

    Caller must call :func:`release_for_key` exactly once for every
    successful claim (typically in a try/finally).
    """
    if _concurrent_per_key_cap <= 0:
        return True
    available = _key_slots.get(api_key_id, _concurrent_per_key_cap)
    if available <= 0:
        return False
    # Backstop: if the map is already at its bound and this is a NEW key,
    # refuse the slot rather than grow the map without limit. Existing
    # tracked keys (already mid-flight) are unaffected. This degrades a
    # token-flood into 503s instead of OOM.
    if api_key_id not in _key_slots and len(_key_slots) >= _MAX_TRACKED_KEYS:
        global _dropped_keys_warned
        if not _dropped_keys_warned:
            logger.warning(
                "per-key concurrency map hit the %d-entry backstop; "
                "refusing new keys until in-flight requests drain "
                "(possible unauthenticated token flood)",
                _MAX_TRACKED_KEYS,
            )
            _dropped_keys_warned = True
        return False
    _key_slots[api_key_id] = available - 1
    return True


def release_for_key(api_key_id: str) -> None:
    if _concurrent_per_key_cap <= 0:
        return
    available = _key_slots.get(api_key_id)
    if available is None:
        return
    new_available = min(available + 1, _concurrent_per_key_cap)
    if new_available >= _concurrent_per_key_cap:
        # Fully released (idle) — drop the entry so the map doesn't
        # accumulate one row per distinct (pre-auth, attacker-chosen)
        # key forever.
        _key_slots.pop(api_key_id, None)
    else:
        _key_slots[api_key_id] = new_available


# ── in-flight tracker ──────────────────────────────────────


class TrackInFlight:
    """Async context manager that increments/decrements the counter.

    Used by the middleware to wrap each request.
    """

    async def __aenter__(self) -> "TrackInFlight":
        global _in_flight_count
        _in_flight_count += 1
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        global _in_flight_count
        _in_flight_count = max(0, _in_flight_count - 1)


def tracked_key_count() -> int:
    """Number of API keys currently holding at least one slot. Tests +
    observability."""
    return len(_key_slots)


def _reset_for_tests() -> None:
    """Drop all module-level state. Tests only."""
    global _shutdown_started, _in_flight_count, _dropped_keys_warned
    _shutdown_started = False
    _in_flight_count = 0
    _dropped_keys_warned = False
    _key_slots.clear()
