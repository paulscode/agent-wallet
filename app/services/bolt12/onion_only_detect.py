# SPDX-License-Identifier: MIT
"""S2 (2026-06-12): detect onion-only LND deployments.

When ``/v1/getinfo``'s ``uris`` list contains only ``.onion``
entries, the long-lived gRPC stream pattern is particularly
fragile (the Tor circuit lifecycle dominates everything). For
those deployments we auto-default the subscriber polling mode
on, regardless of the env var, so operators on the most-
vulnerable shape don't need to know about the setting to get
the right behaviour.

Operators who set ``BOLT12_SUBSCRIBER_POLLING_MODE_ENABLED``
explicitly (in either direction) always win — the env var is a
direct override of the auto-detection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Iterable

logger = logging.getLogger(__name__)


# How long to wait at startup for the LND keepalive's first success
# before giving up and running detect anyway. Picked to be a touch
# higher than the keepalive's own probe timeout (20 s) so we don't
# fight the keepalive's first attempt.
_KEEPALIVE_WAIT_TIMEOUT_S: float = 45.0
_KEEPALIVE_POLL_INTERVAL_S: float = 1.0


# Cache the detection result so we don't hit LND every time
# something checks the polling-mode setting. Refreshed at lifespan
# startup; invalidated on explicit ``reset_cache_for_tests``.
_cached_result: bool | None = None
_cache_lock = asyncio.Lock()


def _is_onion_only(uris: Iterable[str]) -> bool:
    """Pure-function classification: True iff every URI's address
    portion ends in ``.onion``. Empty URI list → False (we can't
    classify it as onion-only)."""
    seen_any = False
    for uri in uris:
        seen_any = True
        # URI format: ``pubkey@addr:port``. Strip the pubkey.
        addr = uri.split("@", 1)[-1]
        # Strip the port suffix.
        host = addr.rsplit(":", 1)[0]
        if not host.endswith(".onion"):
            return False
    return seen_any


async def detect_onion_only(*, timeout_s: float = 30.0) -> bool:
    """Query LND ``/v1/getinfo`` once and classify. Best-effort:
    LND unreachable / weird response → returns False (assume
    mixed). Only SUCCESSFUL classifications are cached — transient
    failures don't pin the result, so a subsequent call (next
    subscriber reconnect, typically within seconds) re-queries
    LND once it's reachable again.

    Timeout bumped 10s → 30s on 2026-06-12: on a cold boot the
    Tor circuit to LND-onion can take 10-30 s to build, and the
    prior 10 s timeout fired before that. Log-level demoted too:
    a probe-timeout at startup is expected, not an ``ERROR``.

    Cached across calls in the same process. Use
    :func:`reset_cache_for_tests` to clear in tests.
    """
    global _cached_result
    if _cached_result is not None:
        return _cached_result
    async with _cache_lock:
        if _cached_result is not None:
            return _cached_result
        try:
            from app.services.lnd_service import lnd_service

            info, err = await asyncio.wait_for(
                lnd_service.get_info(),
                timeout=timeout_s,
            )
            if err is not None or info is None:
                # Transient failure — do NOT cache. The next
                # caller re-queries LND when it's reachable.
                logger.info(
                    "bolt12 onion-only detect: get_info failed (%s) — treating as mixed (not cached; will retry)",
                    err,
                )
                return False
            uris = info.get("uris", []) or []
            result = _is_onion_only(uris)
            if result:
                logger.info(
                    "bolt12 onion-only detect: LND advertises only "
                    ".onion addresses — auto-defaulting subscriber "
                    "polling mode to ON (override via "
                    "BOLT12_SUBSCRIBER_POLLING_MODE_ENABLED)",
                )
            # Cache only on a successful classification — the
            # result reflects an authoritative LND response.
            _cached_result = result
            return result
        except asyncio.TimeoutError:
            # Expected on cold start: Tor takes 10-30 s to build
            # the first circuit to LND-onion. Log at INFO without
            # a traceback (the cause is obvious from the message)
            # so operators aren't alarmed by an ``ERROR`` on every
            # first boot.
            logger.info(
                "bolt12 onion-only detect: get_info timed out after "
                "%.0f s (likely cold-start Tor circuit build) — "
                "treating as mixed (not cached; will retry on next call)",
                timeout_s,
            )
            return False
        except Exception:  # noqa: BLE001
            # Unexpected classifier failure — keep the traceback for
            # diagnosis but log at INFO so we don't pollute the
            # ``ERROR`` channel with a transient that auto-recovers.
            logger.info(
                "bolt12 onion-only detect: classifier raised — treating as mixed (not cached; will retry on next call)",
                exc_info=True,
            )
            return False


async def _wait_for_lnd_first_success(
    *,
    timeout_s: float | None = None,
) -> bool:
    """Block until the LND keepalive reports its first successful
    probe, or until ``timeout_s`` elapses. Returns ``True`` if a
    success was observed, ``False`` on timeout.

    Rationale (2026-06-12): on cold start the Tor circuit to the
    LND-onion address takes 10-30 s to build, and historically
    ``detect_onion_only`` fired before the keepalive's first probe
    completed → the detect call timed out → polling-mode auto-
    activation was missed. Gating detect on the keepalive's first
    success removes that race without coupling subscribers to the
    keepalive's internal state directly.

    ``timeout_s`` and the poll interval are resolved from module
    globals at call time (not as default-arg values) so tests can
    monkeypatch them.
    """
    if timeout_s is None:
        timeout_s = _KEEPALIVE_WAIT_TIMEOUT_S
    try:
        from app.services.lnd_keepalive import get_state
    except Exception:  # noqa: BLE001
        # Keepalive module unavailable (test envs) — don't block.
        return False
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if get_state().last_success_at is not None:
                return True
        except Exception:  # noqa: BLE001
            # State not yet initialised — treat as not-ready and
            # keep polling.
            pass
        await asyncio.sleep(_KEEPALIVE_POLL_INTERVAL_S)
    return False


async def resolve_polling_mode_active() -> bool:
    """Shared resolver used by both subscribers.

    Resolution order:

    1. ``bolt12_subscriber_polling_mode_enabled=True`` → True (force on).
    2. ``bolt12_subscriber_polling_mode_auto_detect=False`` → False
       (operator opted out of auto-detect; honour the explicit setting).
    3. Otherwise: wait for the LND keepalive's first success (cold-
       start grace), then run :func:`detect_onion_only`.
    """
    from app.core.config import settings

    if settings.bolt12_subscriber_polling_mode_enabled:
        return True
    if not settings.bolt12_subscriber_polling_mode_auto_detect:
        return False
    # Cache hit short-circuits the wait — no point in stalling a
    # subscriber restart when we've already classified this process.
    if _cached_result is None:
        await _wait_for_lnd_first_success()
    return await detect_onion_only()


def reset_cache_for_tests() -> None:
    """Test-only: clear the cached classification."""
    global _cached_result
    _cached_result = None


__all__ = [
    "detect_onion_only",
    "reset_cache_for_tests",
    "resolve_polling_mode_active",
]
