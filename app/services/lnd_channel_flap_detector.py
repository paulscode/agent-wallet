# SPDX-License-Identifier: MIT
"""S3 (2026-06-12): channel-flap detector via faster polling.

LND has a ``subscribe_channel_events`` push stream that would give
us instant peer-disconnect signals. But on a Tor-only deployment
that stream is just as fragile as our other long-lived h2 streams
to LND — it'd die for the same reasons B's 60 s tick currently
misses. Polling listchannels on a tighter cadence catches the
flaps without inheriting the long-stream failure mode.

This module's job:
- Poll ``get_channels`` every N seconds (default 15, tighter than
  keepalive's 60 s so we catch sub-minute flaps).
- For each channel, detect ``active → inactive`` transitions
  (peer-side disconnect) and feed those into the same burst-event
  window B's keepalive uses.
- Fires the SAME NEWNYM trigger the keepalive does when the burst
  threshold is reached — they share state via
  ``app.services.lnd_keepalive._STATE.inbound_inactivity_events``.

Disabled if ``LND_CHANNEL_FLAP_DETECT_INTERVAL_S=0``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


_DEFAULT_INTERVAL_S = 5.0


@dataclass
class _FlapState:
    """Per-process state. Reset on restart (same convention as
    other in-memory state in this codebase)."""

    last_active: dict[str, bool] = field(default_factory=dict)
    transitions_total: int = 0
    last_transition_at_monotonic: float = 0.0


_STATE = _FlapState()


def get_state() -> _FlapState:
    return _STATE


async def _poll_and_detect() -> None:
    """One poll tick: compare current ``active`` vs the last
    snapshot per channel; record ``active → inactive`` transitions
    onto the shared burst event window."""
    from app.services.lnd_service import lnd_service

    try:
        channels, err = await lnd_service.get_channels()
    except Exception as exc:  # noqa: BLE001
        logger.debug("lnd channel flap detect: get_channels raised: %s", exc)
        return
    if err is not None or channels is None:
        return

    # Lazy import to avoid pulling in keepalive at module init.
    from app.core.config import settings
    from app.services import lnd_keepalive as ka

    window_s = max(30.0, float(settings.lnd_inbound_burst_window_s))
    now = time.monotonic()
    flap_was_detected = False
    for ch in channels:
        chan_id = str(ch.get("chan_id") or "")
        if not chan_id:
            continue
        active_now = bool(ch.get("active", False))
        prev_active = _STATE.last_active.get(chan_id)
        _STATE.last_active[chan_id] = active_now
        if prev_active is None:
            # First observation — no transition yet.
            continue
        if prev_active and not active_now:
            # active → inactive: this is the burst signal.
            _STATE.transitions_total += 1
            _STATE.last_transition_at_monotonic = now
            ka._STATE.inbound_inactivity_events.append(now)
            flap_was_detected = True
            # 2026-06-12 (idea 1): also feed the inbound supervisor
            # so SIGHUP escalation has a signal source even in
            # polling mode where subscribers never produce transport
            # errors. Best-effort lazy import — the supervisor
            # module might not be initialised in test environments.
            try:
                from app.services.bolt12.inbound_supervisor import (
                    record_channel_flap,
                )

                record_channel_flap()
            except Exception:  # noqa: BLE001
                pass
            logger.info(
                "lnd channel flap detect: %s went INACTIVE (transitions_total=%d)",
                chan_id[:20],
                _STATE.transitions_total,
            )

    if not flap_was_detected:
        return

    # Trim the shared sliding window.
    cutoff = now - window_s
    ka._STATE.inbound_inactivity_events = [ts for ts in ka._STATE.inbound_inactivity_events if ts >= cutoff]
    threshold = int(settings.lnd_inbound_burst_newnym_threshold)
    if threshold <= 0:
        return
    if len(ka._STATE.inbound_inactivity_events) < threshold:
        return

    # Threshold reached — fire NEWNYM via the same shared throttle.
    from app.services.bolt12.subscriber_recovery import try_newnym_throttled

    fired = await try_newnym_throttled()
    if not fired:
        return
    ka._STATE.inbound_burst_newnyms_total += 1
    ka._STATE.inbound_inactivity_events.clear()
    from datetime import datetime, timezone

    ka._STATE.last_inbound_burst_newnym_at = datetime.now(timezone.utc)
    logger.warning(
        "lnd channel flap detect: inbound burst (%d flaps within %.0fs) "
        "— fired NEWNYM to roll HS circuits (total bursts=%d)",
        threshold,
        window_s,
        ka._STATE.inbound_burst_newnyms_total,
    )


async def run_channel_flap_detector(stop_event: asyncio.Event) -> None:
    """Background loop. Returns when ``stop_event`` is set."""
    from app.core.config import settings

    if settings.testing:
        return

    interval = float(
        getattr(
            settings,
            "lnd_channel_flap_detect_interval_s",
            _DEFAULT_INTERVAL_S,
        )
    )
    if interval <= 0:
        logger.info("lnd channel flap detect: disabled (interval <= 0)")
        return

    logger.info(
        "lnd channel flap detector: starting (interval=%.1fs)",
        interval,
    )
    while not stop_event.is_set():
        try:
            await _poll_and_detect()
        except Exception:  # noqa: BLE001
            logger.exception("lnd channel flap detect: poll tick raised; continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("lnd channel flap detector: stopped")


def _reset_for_tests() -> None:
    global _STATE
    _STATE = _FlapState()


__all__ = [
    "get_state",
    "run_channel_flap_detector",
]
