# SPDX-License-Identifier: MIT
"""Periodic LND-onion keepalive.

Calling LND over Tor cold takes ~5-15 s for circuit-build +
HS-descriptor lookup. Long-lived processes amortize that cost
because Tor keeps the descriptor cached (~3 h TTL) and reuses
circuits — but if no traffic flows for several minutes, the
circuit dies and the next caller pays the cold-start tax again.

That cold-start tax is exactly what burned Ocean's 60-90 s BOLT-12
deadline on 2026-05-29 (TTL expired → 3 retries from the
responder couldn't recover in time). A lightweight background
ping every minute keeps at least one warm circuit available so
the responder's first call is fast.

Design:
  * One task. Runs ``GET /v1/getinfo`` every
    ``LND_KEEPALIVE_INTERVAL_S`` seconds (default 60).
  * Best-effort: failures are logged at INFO once on transition,
    then DEBUG until recovery — same throttling pattern as
    ``electrum._supervise``.
  * Respects the existing LND circuit breaker — when LND is
    actually down, we shouldn't hammer it (the breaker fast-fails
    after threshold trips, and we wait quietly until it
    half-opens).
  * **Active recovery** (2026-06-02 incident): after
    ``_RECOVERY_TRIGGER_FAILURES`` consecutive failures we drop the
    wedged httpx pool (``lnd_service.close()``) and force-close the
    LND breaker, then probe immediately. This unwedges the
    "cancelled SOCKS handshake left a zombie socket in the pool"
    failure mode, which the breaker's own time-half-open can't
    recover from (the pool reuses the dead socket). After
    ``_RECOVERY_HARD_ALARM_FAILURES`` more failures we stop trying
    and leave the rest to ``/livez`` + Docker healthcheck.
  * Exposes :func:`get_state` so ``/livez`` can read the most
    recent success timestamp + consecutive-failure count.
  * Honors a stop event so lifespan shutdown is clean.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_KEEPALIVE_INTERVAL_S_DEFAULT = 60.0
_KEEPALIVE_TIMEOUT_S = 20.0

# After this many consecutive failures, attempt one active-recovery
# pass (drop the httpx pool + reset the breaker, then probe again).
# Tuned to 5 because:
#   * 5 × 60 s = ~5 min of confirmed unreachability — long enough that
#     a routine Tor blip has already self-cleared, short enough that
#     we recover well before the typical sender deadline (60–90 s)
#     would even apply to a fresh inbound payment.
#   * Aligns with the breaker's own ``failure_threshold=5`` default
#     so the first recovery attempt fires roughly when the breaker
#     finishes its first close→open→half_open cycle. Tighter than
#     that would race; looser would burn operator-visible deadlines.
_RECOVERY_TRIGGER_FAILURES = 5

# Beyond this point we stop attempting active recovery — something
# is structurally wrong (LND down, Tor genuinely unreachable, etc.)
# and continuing to recycle the httpx pool every interval just
# generates noise. ``/livez`` reports unhealthy ≥ here, so the
# Docker healthcheck takes over.
_RECOVERY_HARD_ALARM_FAILURES = 10


@dataclass
class _KeepaliveState:
    """Module-level state read by ``/livez``.

    * ``last_success_at``: most recent successful ``getinfo`` (None
      until the first success post-start).
    * ``consecutive_failures``: how many probes have failed in a row
      since the last success. Resets to 0 on success.
    * ``recoveries_attempted_total``: monotonic counter of
      active-recovery passes (httpx close + breaker reset). Lets ops
      dashboards spot a wallet that keeps wedging.
    * ``last_recovery_at``: most recent active-recovery attempt.
    * ``last_num_inactive_channels``: prior tick's value, used to
      detect 0→positive transitions (peers disconnecting from us).
    * ``inbound_inactivity_events``: timestamps (monotonic) of
      observed 0→positive transitions. Trimmed to the configured
      sliding window every tick.
    * ``inbound_burst_newnyms_total``: monotonic counter of
      NEWNYM signals fired in response to inbound-burst detection
      (see :data:`bolt12 subscriber_recovery`).
    """

    last_success_at: datetime | None = None
    consecutive_failures: int = 0
    recoveries_attempted_total: int = 0
    last_recovery_at: datetime | None = None
    last_error: str | None = None
    started_at: datetime | None = None
    # B-trigger state (2026-06-11)
    last_num_inactive_channels: int = 0
    inbound_inactivity_events: list[float] = field(default_factory=list)
    inbound_burst_newnyms_total: int = 0
    last_inbound_burst_newnym_at: datetime | None = None


_STATE = _KeepaliveState()


def get_state() -> _KeepaliveState:
    """Return the current keepalive state. Cheap; safe to call from
    any context (the dataclass fields are scalars/datetimes that
    can be read without locks)."""
    return _STATE


async def _maybe_fire_inbound_burst_newnym(
    num_inactive_channels: int,
) -> None:
    """B-trigger (2026-06-11): observe inbound peer-disconnect
    bursts and roll the Tor circuit pool when they look like our
    HS descriptor has gone stale.

    Signal: a 0→positive transition in ``num_inactive_channels``
    is a peer just disconnected from our hidden service. A single
    transition is noise (Lightning peers reconnect routinely);
    *bursts* (multiple transitions inside a short window) are the
    pattern we observed on 2026-06-11 — Ocean's payments failed
    because the intro→us forward landed during one such window.

    Implementation: track 0→positive transition timestamps in a
    sliding window. When the count crosses the threshold, fire
    ``signal_newnym`` (throttled by the same shared helper used
    by the BOLT 12 subscribers, so a burst across both subsystems
    rolls circuits at most once per the configured min interval).

    Disabled if ``lnd_inbound_burst_newnym_threshold <= 0``.
    """
    from app.core.config import settings

    threshold = int(settings.lnd_inbound_burst_newnym_threshold)
    if threshold <= 0:
        # B-trigger disabled by operator.
        _STATE.last_num_inactive_channels = num_inactive_channels
        return

    prev = _STATE.last_num_inactive_channels
    _STATE.last_num_inactive_channels = num_inactive_channels

    # Only count 0→positive transitions. positive→larger and
    # positive→smaller aren't "a peer just dropped" signals.
    if not (prev == 0 and num_inactive_channels > 0):
        return

    window_s = max(30.0, float(settings.lnd_inbound_burst_window_s))
    now = time.monotonic()
    _STATE.inbound_inactivity_events.append(now)
    # Trim the sliding window in place.
    cutoff = now - window_s
    _STATE.inbound_inactivity_events = [ts for ts in _STATE.inbound_inactivity_events if ts >= cutoff]

    if len(_STATE.inbound_inactivity_events) < threshold:
        # Not enough yet to call it a burst.
        return

    # Throttled NEWNYM via the shared helper. If the throttle
    # blocked us, that's fine — somebody just rolled circuits
    # within the throttle window already.
    from app.services.bolt12.subscriber_recovery import try_newnym_throttled

    fired = await try_newnym_throttled()
    if not fired:
        logger.info(
            "lnd keepalive: inbound burst detected (events=%d in %.0fs) but NEWNYM was throttled or rejected",
            len(_STATE.inbound_inactivity_events),
            window_s,
        )
        return

    _STATE.inbound_burst_newnyms_total += 1
    _STATE.last_inbound_burst_newnym_at = datetime.now(timezone.utc)
    # Reset the window — we just rolled circuits; future bursts
    # should be measured against the new state.
    _STATE.inbound_inactivity_events.clear()
    logger.warning(
        "lnd keepalive: inbound burst detected (%d disconnects within "
        "%.0fs); fired NEWNYM to roll hidden-service circuits "
        "(total bursts=%d)",
        threshold,
        window_s,
        _STATE.inbound_burst_newnyms_total,
    )


async def _attempt_active_recovery() -> None:
    """Close the wedged httpx pool and force-close the LND breaker.

    This is the canonical unwedge for "cancelled SOCKS handshake
    left a zombie socket in the pool" — which the breaker's
    time-half-open cannot recover from (the pool just reuses the
    dead socket on the half-open probe). See 2026-06-02 wedge
    postmortem.
    """
    from app.services.lnd_service import _LND_BREAKER, lnd_service

    try:
        await lnd_service.close()
    except Exception as exc:  # noqa: BLE001
        # close() should never raise on a half-open pool, but if
        # httpx somehow surfaces an exception we don't want to
        # crash the keepalive task. Log + continue — the breaker
        # reset below still gives the next call a fresh start.
        logger.warning(
            "lnd keepalive: active recovery: lnd_service.close() raised: %s",
            exc,
        )
    _LND_BREAKER.reset()
    _STATE.recoveries_attempted_total += 1
    _STATE.last_recovery_at = datetime.now(timezone.utc)
    logger.warning(
        "lnd keepalive: active recovery: dropped httpx pool + reset breaker "
        "(consecutive_failures=%d, recoveries_total=%d)",
        _STATE.consecutive_failures,
        _STATE.recoveries_attempted_total,
    )


async def run_lnd_keepalive(stop_event: asyncio.Event) -> None:
    """Background loop. Returns when ``stop_event`` is set."""
    from app.core.config import settings
    from app.services.lnd_service import lnd_service

    interval = float(getattr(settings, "lnd_keepalive_interval_s", _KEEPALIVE_INTERVAL_S_DEFAULT))
    if interval <= 0:
        logger.info("lnd keepalive: disabled (interval <= 0)")
        return

    last_sig: str | None = None
    log_every = 20
    _STATE.started_at = datetime.now(timezone.utc)

    logger.info("lnd keepalive: starting, interval=%.1fs", interval)
    while not stop_event.is_set():
        try:
            data, err = await asyncio.wait_for(lnd_service.get_info(), timeout=_KEEPALIVE_TIMEOUT_S)
        except asyncio.TimeoutError:
            data, err = None, f"timeout after {_KEEPALIVE_TIMEOUT_S:.0f}s"
        except Exception as exc:  # noqa: BLE001
            data, err = None, f"{type(exc).__name__}: {exc}"

        if err is None and data is not None:
            if _STATE.consecutive_failures > 0:
                logger.info(
                    "lnd keepalive: recovered after %d failure(s)",
                    _STATE.consecutive_failures,
                )
            _STATE.consecutive_failures = 0
            _STATE.last_success_at = datetime.now(timezone.utc)
            _STATE.last_error = None
            last_sig = None
            # B-trigger (2026-06-11): check inbound-disconnect burst
            # while we have a fresh getinfo snapshot.
            try:
                await _maybe_fire_inbound_burst_newnym(
                    int(data.get("num_inactive_channels") or 0),
                )
            except Exception:  # noqa: BLE001
                # Never let the burst-detector break the keepalive
                # loop. The next tick will try again.
                logger.exception("lnd keepalive: inbound-burst NEWNYM helper raised (non-fatal)")
        else:
            _STATE.consecutive_failures += 1
            _STATE.last_error = err
            sig = (err or "")[:80]
            if sig != last_sig:
                logger.info(
                    "lnd keepalive: probe failed: %s",
                    err,
                )
                last_sig = sig
            elif _STATE.consecutive_failures % log_every == 0:
                logger.info(
                    "lnd keepalive: still failing after %d attempts: %s",
                    _STATE.consecutive_failures,
                    err,
                )
            else:
                logger.debug("lnd keepalive: probe failed: %s", err)

            # Active recovery: fire exactly once at the trigger and
            # then again every ``_RECOVERY_TRIGGER_FAILURES`` rounds
            # up to the hard-alarm ceiling. Past the ceiling we go
            # quiet and let /livez + Docker take over.
            failures = _STATE.consecutive_failures
            if (
                failures >= _RECOVERY_TRIGGER_FAILURES
                and failures <= _RECOVERY_HARD_ALARM_FAILURES
                and failures % _RECOVERY_TRIGGER_FAILURES == 0
            ):
                await _attempt_active_recovery()
            elif failures == _RECOVERY_HARD_ALARM_FAILURES + 1:
                logger.error(
                    "lnd keepalive: HARD ALARM: %d consecutive failures, "
                    "%d active-recovery attempts had no effect — leaving "
                    "to /livez + Docker healthcheck",
                    failures,
                    _STATE.recoveries_attempted_total,
                )

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
        # stop_event fired
        break

    logger.info("lnd keepalive: stopped")


__all__ = ["get_state", "run_lnd_keepalive"]
