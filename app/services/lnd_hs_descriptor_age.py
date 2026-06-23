# SPDX-License-Identifier: MIT
"""T4 (2026-06-12): periodic HSFETCH probe of our own LND onion.

Tracks how recently the LND hidden service's descriptor was
fetchable from the Tor HS-directory network. Stale descriptors are
the leading indicator of inbound forwarding failures (peers can't
find us → channel forwards fail → Ocean payouts time out without
HTLCs ever reaching our LND).

What this monitors:
- ``last_fetch_attempt_at``: most recent attempt timestamp
- ``last_fetch_ok_at``: most recent SUCCESSFUL fetch timestamp
- ``last_fetch_error``: last failure reason (truncated)
- ``consecutive_failures``: failed probes in a row

What surfaces on ``/livez``:
- ``hs_descriptor_age_s``: seconds since last successful fetch
- ``hs_descriptor_consecutive_failures``: visible counter

Lifecycle: started from ``app/main.py`` lifespan alongside the LND
keepalive. Honors a stop event. Honors a kill switch
(``LND_HS_DESCRIPTOR_PROBE_INTERVAL_S=0``).

Honest about limits: HSFETCH may return a CACHED descriptor that
Tor already had locally, which is NOT proof a fresh descriptor
exists in the DHT. But for our purposes (operator monitoring), a
sustained HSFETCH failure pattern still signals real trouble — the
local cache eventually expires and the next fetch must reach
HSDirs.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


_DEFAULT_PROBE_INTERVAL_S = 600.0  # 10 minutes
_HSFETCH_TIMEOUT_S = 60.0


@dataclass
class _HsDescriptorState:
    last_fetch_attempt_at: datetime | None = None
    last_fetch_ok_at: datetime | None = None
    last_fetch_ok_monotonic: float = 0.0
    last_fetch_error: str | None = None
    consecutive_failures: int = 0
    attempts_total: int = 0
    successes_total: int = 0


_STATE = _HsDescriptorState()


def get_state() -> _HsDescriptorState:
    """Snapshot of the descriptor-probe state. Cheap; safe from
    any coroutine."""
    return _STATE


def age_seconds() -> float | None:
    """Seconds since the last successful HSFETCH. ``None`` if we
    haven't had a success yet this process."""
    if _STATE.last_fetch_ok_monotonic <= 0.0:
        return None
    return max(0.0, time.monotonic() - _STATE.last_fetch_ok_monotonic)


async def _probe_once() -> tuple[bool, str | None]:
    """One HSFETCH attempt. Best-effort; returns ``(ok, err)``."""
    from app.services.lnd_tor_supervisor import _hsfetch_lnd_onion

    try:
        return await _hsfetch_lnd_onion(timeout_s=_HSFETCH_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


async def _probe_tick() -> None:
    """One iteration of the probe loop: probe + state update +
    inbound-supervisor feed. Extracted so tests can drive a single
    tick without the surrounding ``while not stop_event`` loop."""
    _STATE.attempts_total += 1
    _STATE.last_fetch_attempt_at = datetime.now(timezone.utc)
    ok, err = await _probe_once()
    if ok:
        _STATE.last_fetch_ok_at = _STATE.last_fetch_attempt_at
        _STATE.last_fetch_ok_monotonic = time.monotonic()
        _STATE.last_fetch_error = None
        _STATE.consecutive_failures = 0
        _STATE.successes_total += 1
        logger.debug(
            "lnd hs descriptor probe: OK (successes_total=%d)",
            _STATE.successes_total,
        )
        return
    _STATE.last_fetch_error = (err or "unknown")[:200]
    _STATE.consecutive_failures += 1
    # Log at WARN every Nth failure to signal a sustained issue
    # without spamming.
    if _STATE.consecutive_failures in (1, 3, 10) or (_STATE.consecutive_failures % 10 == 0):
        logger.warning(
            "lnd hs descriptor probe: FAILED %d in a row: %s",
            _STATE.consecutive_failures,
            _STATE.last_fetch_error,
        )
    # 2026-06-12 (idea 2): once we cross the configured threshold
    # of consecutive HSFETCH failures, feed the inbound supervisor
    # so SIGHUP can fire even when the subscribers are healthy
    # (e.g., polling mode). The signal fires on EACH probe past
    # the threshold so the supervisor's per-event ring sees
    # sustained failures, not just a one-shot.
    from app.core.config import settings as _settings

    hs_threshold = int(
        getattr(
            _settings,
            "lnd_hs_descriptor_failure_supervisor_threshold",
            3,
        )
    )
    if hs_threshold > 0 and _STATE.consecutive_failures >= hs_threshold:
        try:
            from app.services.bolt12.inbound_supervisor import (
                record_hs_fetch_failure,
            )

            record_hs_fetch_failure()
        except Exception:  # noqa: BLE001
            pass


async def run_hs_descriptor_age_probe(stop_event: asyncio.Event) -> None:
    """Background loop. Runs ``HSFETCH`` against the LND onion at
    ``LND_HS_DESCRIPTOR_PROBE_INTERVAL_S`` cadence; updates state.
    Returns when ``stop_event`` is set.

    Disabled if the interval setting is ≤ 0.
    """
    from app.core.config import settings

    if settings.testing:
        return

    interval = float(
        getattr(
            settings,
            "lnd_hs_descriptor_probe_interval_s",
            _DEFAULT_PROBE_INTERVAL_S,
        )
    )
    if interval <= 0:
        logger.info("lnd hs descriptor probe: disabled (interval <= 0)")
        return

    # Gate on LND being an onion service — HSFETCH is meaningless
    # for clearnet deployments and would produce a WARN every
    # ~10 min for no operator-actionable reason.
    try:
        from app.services.lnd_tor_supervisor import _lnd_onion_hostname

        if not _lnd_onion_hostname():
            logger.info(
                "lnd hs descriptor probe: disabled (LND_REST_URL is not an onion address — clearnet deployment)"
            )
            return
    except Exception:  # noqa: BLE001
        # If the helper isn't importable for any reason, fall
        # through to attempting the probe; the underlying
        # _hsfetch_lnd_onion will report the same error itself.
        pass

    # Don't fire immediately on startup — give other lifespan
    # tasks (Tor bootstrap, LND keepalive) a chance to warm up.
    initial_delay = min(60.0, interval)
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=initial_delay)
        return
    except asyncio.TimeoutError:
        pass

    logger.info(
        "lnd hs descriptor probe: starting (interval=%.0fs)",
        interval,
    )
    while not stop_event.is_set():
        await _probe_tick()
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass

    logger.info("lnd hs descriptor probe: stopped")


def _reset_for_tests() -> None:
    """Test-only state reset."""
    global _STATE
    _STATE = _HsDescriptorState()


__all__ = [
    "age_seconds",
    "get_state",
    "run_hs_descriptor_age_probe",
]
