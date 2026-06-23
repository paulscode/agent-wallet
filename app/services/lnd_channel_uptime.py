# SPDX-License-Identifier: MIT
"""T6 (2026-06-12): per-channel active/inactive duration tracker.

Watches LND's channel set via periodic polling and records each
channel's time-active vs time-inactive over rolling windows.
Surfaces per-channel uptime ratio on the dashboard so chronic
flappers (the kind that mask sub-minute peer flaps from B's burst
detector) become visible without manual investigation.

Design:
- Lightweight: polls ``listchannels`` on a configurable interval
  (default 30 s — tighter than keepalive's 60 s so we catch flaps
  that keepalive's coarse cadence misses).
- Per-channel state: tracks the current ``active`` value and a
  monotonic timestamp of the last transition. On each poll we
  integrate the time since the last transition into the
  appropriate (active/inactive) bucket.
- Two rolling windows: 24 h and 7 d. Older samples evicted as
  newer ones land — bounded memory.
- Best-effort: any per-tick error logs and continues; the
  tracker is advisory, never load-bearing.

Lifecycle: started from ``app/main.py`` lifespan; honors a stop
event; disabled if ``LND_CHANNEL_UPTIME_TRACK_INTERVAL_S=0``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


_DEFAULT_TRACK_INTERVAL_S = 30.0
_24H_S = 24 * 3600
_7D_S = 7 * 24 * 3600
_RING_CAPACITY = 2 * 7 * 24 * 60  # one sample per minute × 7 days × headroom


@dataclass
class _ChannelSnapshot:
    """Per-channel uptime/downtime accumulator with a sliding
    sample ring suitable for percentile-style queries."""

    chan_id: str
    peer_pubkey: str = ""
    peer_alias: str = ""
    # Current active state and the monotonic timestamp at which we
    # transitioned to it.
    active: bool = False
    state_started_monotonic: float = 0.0
    # Each sample: (monotonic_ts, was_active_during_interval, dt_s).
    # The ring is bounded to ``_RING_CAPACITY`` to keep memory flat.
    samples: deque[tuple[float, bool, float]] = field(
        default_factory=lambda: deque(maxlen=_RING_CAPACITY),
    )
    # Last time we observed this channel — used to expire entries
    # for channels that disappeared (closed, force-closed).
    last_seen_monotonic: float = 0.0


@dataclass
class _UptimeState:
    channels: dict[str, _ChannelSnapshot] = field(default_factory=dict)
    last_poll_at: datetime | None = None
    last_poll_monotonic: float = 0.0


_STATE = _UptimeState()


def get_state() -> _UptimeState:
    return _STATE


def _ratio_over_window(snap: _ChannelSnapshot, window_s: float) -> float:
    """Fraction of the past ``window_s`` during which the channel
    was active. ``0.0`` if no samples yet."""
    if not snap.samples:
        return 0.0
    now = time.monotonic()
    cutoff = now - window_s
    active_s = 0.0
    total_s = 0.0
    for ts, was_active, dt in snap.samples:
        if ts < cutoff:
            continue
        total_s += dt
        if was_active:
            active_s += dt
    if total_s <= 0.0:
        return 0.0
    return active_s / total_s


def summary() -> dict:
    """Diagnostic snapshot for ``/livez`` / dashboard."""
    out: dict = {"channels": {}}
    for chan_id, snap in _STATE.channels.items():
        out["channels"][chan_id] = {
            "peer_alias": snap.peer_alias,
            "peer_pubkey": snap.peer_pubkey,
            "currently_active": snap.active,
            "uptime_ratio_24h": round(
                _ratio_over_window(snap, _24H_S),
                4,
            ),
            "uptime_ratio_7d": round(
                _ratio_over_window(snap, _7D_S),
                4,
            ),
            "sample_count": len(snap.samples),
        }
    return out


def _record_sample(
    snap: _ChannelSnapshot,
    *,
    now_monotonic: float,
    active_now: bool,
) -> None:
    """Append one sample covering the time since the last
    transition (or the last poll if no transition occurred).

    The sample's ``was_active`` is the state DURING the elapsed
    interval — which is the state we were in at the start of it.
    """
    if snap.state_started_monotonic <= 0.0:
        # First observation for this channel; initialise without
        # recording an interval.
        snap.active = active_now
        snap.state_started_monotonic = now_monotonic
        snap.last_seen_monotonic = now_monotonic
        return
    dt_s = max(0.0, now_monotonic - snap.state_started_monotonic)
    if dt_s > 0:
        snap.samples.append((now_monotonic, snap.active, dt_s))
    if active_now != snap.active:
        # Transitioned. Start a new interval at this timestamp.
        snap.active = active_now
        snap.state_started_monotonic = now_monotonic
    else:
        # Still in the same state; advance the interval-start so
        # the next sample's ``dt`` measures only the new interval.
        snap.state_started_monotonic = now_monotonic
    snap.last_seen_monotonic = now_monotonic


async def _poll_once() -> None:
    """One ``listchannels`` poll + projection onto the tracker."""
    from app.services.lnd_service import lnd_service

    try:
        channels, err = await lnd_service.get_channels()
    except Exception as exc:  # noqa: BLE001
        logger.debug("lnd channel uptime: get_channels raised: %s", exc)
        return
    if err is not None or channels is None:
        return
    now = time.monotonic()
    _STATE.last_poll_at = datetime.now(timezone.utc)
    _STATE.last_poll_monotonic = now
    for ch in channels:
        chan_id = str(ch.get("chan_id") or "")
        if not chan_id:
            continue
        snap = _STATE.channels.setdefault(
            chan_id,
            _ChannelSnapshot(chan_id=chan_id),
        )
        snap.peer_pubkey = ch.get("remote_pubkey", snap.peer_pubkey) or ""
        snap.peer_alias = ch.get("peer_alias", snap.peer_alias) or ""
        active_now = bool(ch.get("active", False))
        _record_sample(snap, now_monotonic=now, active_now=active_now)


async def run_channel_uptime_tracker(stop_event: asyncio.Event) -> None:
    """Background loop. Polls ``listchannels`` on a tight cadence
    and accumulates per-channel uptime samples.

    Disabled when the interval setting is ≤ 0.
    """
    from app.core.config import settings

    if settings.testing:
        return

    interval = float(
        getattr(
            settings,
            "lnd_channel_uptime_track_interval_s",
            _DEFAULT_TRACK_INTERVAL_S,
        )
    )
    if interval <= 0:
        logger.info("lnd channel uptime: disabled (interval <= 0)")
        return

    logger.info(
        "lnd channel uptime tracker: starting (interval=%.1fs)",
        interval,
    )
    while not stop_event.is_set():
        try:
            await _poll_once()
        except Exception:  # noqa: BLE001
            logger.exception("lnd channel uptime: poll tick raised; continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("lnd channel uptime tracker: stopped")


def _reset_for_tests() -> None:
    global _STATE
    _STATE = _UptimeState()


__all__ = [
    "get_state",
    "run_channel_uptime_tracker",
    "summary",
]
