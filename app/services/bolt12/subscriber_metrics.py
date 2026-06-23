# SPDX-License-Identifier: MIT
"""Per-subscriber lifetime + heartbeat telemetry (T1 + T5, 2026-06-12).

Two operator-facing signals consolidated here so the BOLT 12
subscribers (streaming and polling) emit consistent telemetry:

* **Stream-lifetime histogram** (T1): record how long each stream
  stays alive before failing. Operators looking at the median /
  p95 instantly see "streams die in 5 s" vs "streams die in 12
  min" — the strongest leading indicator for inbound HS health
  on a Tor-only deployment.

* **Subscriber heartbeat** (T5): periodic ``bolt12_subscriber_
  heartbeat`` audit row so the absence of events is itself
  diagnostic. A silently-broken subscriber otherwise looks
  identical to "nothing happened today".

State is in-memory and process-local — the same conventions as
:mod:`subscriber_recovery`. ``/livez`` reads :func:`get_state`
to surface the histogram on the existing dashboard surface.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# How many recent stream lifetimes to retain per subscriber. 512
# entries × 2 subscribers = small constant memory; long enough
# that p95 over the recent window is statistically meaningful.
_LIFETIME_RING_CAPACITY = 512


@dataclass
class _SubscriberMetricsState:
    """Module singleton, read by ``/livez``."""

    # Most-recent stream-lifetime samples per subscriber name,
    # in seconds. A bounded ring; oldest evicted on append.
    lifetimes_s: dict[str, list[float]] = field(default_factory=dict)

    # Monotonic counts of stream open events per subscriber. Lets
    # the dashboard tell "subscriber attempted N reconnects" from
    # "subscriber sat idle".
    stream_starts_total: dict[str, int] = field(default_factory=dict)
    stream_ends_total: dict[str, int] = field(default_factory=dict)

    # Last heartbeat timestamps per subscriber (wallclock + monotonic
    # — wallclock for the audit row, monotonic for "is it overdue"
    # comparisons that must survive system clock changes).
    last_heartbeat_at: dict[str, datetime] = field(default_factory=dict)
    last_heartbeat_monotonic: dict[str, float] = field(default_factory=dict)


_STATE = _SubscriberMetricsState()


def get_state() -> _SubscriberMetricsState:
    """Read-only view of the metrics state. Safe to call from any
    coroutine — fields are scalars or lists copied at use-site."""
    return _STATE


def record_stream_started(subscriber_name: str) -> float:
    """Caller convention: hold the returned ``start_ts`` (monotonic
    seconds) and pass it to :func:`record_stream_ended` when the
    stream ends. Returns the timestamp so the caller doesn't need
    its own ``time`` import."""
    _STATE.stream_starts_total[subscriber_name] = _STATE.stream_starts_total.get(subscriber_name, 0) + 1
    return time.monotonic()


def record_stream_ended(subscriber_name: str, start_ts: float) -> float:
    """Compute and record the stream's lifetime. Returns the
    lifetime in seconds so the caller can include it in a log
    line without reaching back into the state.

    Bounded ring: appends to the per-subscriber list and evicts
    the oldest when capacity is reached.
    """
    lifetime_s = max(0.0, time.monotonic() - start_ts)
    samples = _STATE.lifetimes_s.setdefault(subscriber_name, [])
    samples.append(lifetime_s)
    if len(samples) > _LIFETIME_RING_CAPACITY:
        # Trim from the front — drops the oldest sample.
        del samples[: len(samples) - _LIFETIME_RING_CAPACITY]
    _STATE.stream_ends_total[subscriber_name] = _STATE.stream_ends_total.get(subscriber_name, 0) + 1
    return lifetime_s


def _percentile(sorted_samples: list[float], pct: float) -> float:
    """Nearest-rank percentile. Empty list → 0.0."""
    if not sorted_samples:
        return 0.0
    n = len(sorted_samples)
    # Nearest-rank: idx = ceil(pct/100 * n) - 1, clamped to [0, n-1].
    import math

    idx = max(0, min(n - 1, math.ceil(pct / 100.0 * n) - 1))
    return sorted_samples[idx]


def summary(subscriber_name: str | None = None) -> dict:
    """Diagnostic snapshot suitable for ``/livez``.

    Without ``subscriber_name``, returns the aggregate across all
    tracked subscribers. With one, returns just that subscriber.
    """
    names = [subscriber_name] if subscriber_name is not None else sorted(_STATE.lifetimes_s.keys())
    out: dict = {}
    for name in names:
        raw = list(_STATE.lifetimes_s.get(name, []))
        raw.sort()
        out[name] = {
            "sample_count": len(raw),
            "stream_starts_total": _STATE.stream_starts_total.get(name, 0),
            "stream_ends_total": _STATE.stream_ends_total.get(name, 0),
            "lifetime_s_min": raw[0] if raw else 0.0,
            "lifetime_s_p50": _percentile(raw, 50),
            "lifetime_s_p95": _percentile(raw, 95),
            "lifetime_s_max": raw[-1] if raw else 0.0,
            "last_heartbeat_at": (_hb.isoformat() if (_hb := _STATE.last_heartbeat_at.get(name)) else None),
        }
    return out


async def emit_heartbeat(
    subscriber_name: str,
    *,
    extra_details: dict | None = None,
) -> None:
    """Write a ``bolt12_subscriber_heartbeat`` audit row.

    Caller convention: invoke at most once per heartbeat
    interval. We don't throttle here — the caller's loop owns
    the cadence — so a buggy caller could spam. The audit log
    is cheap enough that the cost is bounded by the caller's
    setting.
    """
    now_wall = datetime.now(timezone.utc)
    _STATE.last_heartbeat_at[subscriber_name] = now_wall
    _STATE.last_heartbeat_monotonic[subscriber_name] = time.monotonic()

    details: dict = {
        "subscriber": subscriber_name,
        "stream_starts_total": _STATE.stream_starts_total.get(subscriber_name, 0),
        "stream_ends_total": _STATE.stream_ends_total.get(subscriber_name, 0),
        "lifetime_samples": len(_STATE.lifetimes_s.get(subscriber_name, [])),
    }
    if extra_details:
        details.update(extra_details)

    try:
        from app.core.database import get_db_context
        from app.services.bolt12.responder import _audit_inbound

        await _audit_inbound(
            get_db_context,
            action="bolt12_subscriber_heartbeat",
            amount_msat=None,
            success=True,
            details=details,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12 subscriber heartbeat: audit emit failed (subscriber=%s)",
            subscriber_name,
        )


def _reset_for_tests() -> None:
    """Test-only: clear all state so tests don't leak into each other."""
    _STATE.lifetimes_s.clear()
    _STATE.stream_starts_total.clear()
    _STATE.stream_ends_total.clear()
    _STATE.last_heartbeat_at.clear()
    _STATE.last_heartbeat_monotonic.clear()


async def run_heartbeat_loop(
    stop_event: asyncio.Event,
    *,
    subscriber_name: str,
    interval_s: float,
    extra_provider: Callable[[], dict | None] | None = None,
) -> None:
    """Background coroutine that writes the heartbeat row on a
    timer. Designed to run alongside the subscriber's stream/poll
    loop; the subscriber owns its own lifecycle, this owns the
    heartbeat cadence.

    ``extra_provider``: optional sync callable returning a dict of
    extra details to attach (e.g., current backoff value, mode
    flag). Errors in it are swallowed so a buggy provider doesn't
    take down the heartbeat.
    """
    # T2 hygiene: clear the trace_id contextvar at task entry.
    # Heartbeat events are not flow-scoped and must never
    # inherit a stale id from whatever spawned this task.
    try:
        from app.services.bolt12.trace import set_current_trace_id

        set_current_trace_id(None)
    except Exception:  # noqa: BLE001
        pass

    # Defensive floor on the interval — a 0 or negative value
    # would tight-loop with no sleep. Operators who want the
    # heartbeat off should set the interval setting to 0 (gated
    # at the spawner) rather than relying on this; the floor is
    # belt-and-braces.
    interval_s = max(1.0, float(interval_s))

    while not stop_event.is_set():
        extras: dict = {}
        if extra_provider is not None:
            try:
                extras = dict(extra_provider() or {})
            except Exception:  # noqa: BLE001
                logger.debug(
                    "bolt12 heartbeat extra_provider raised",
                    exc_info=True,
                )
        try:
            await emit_heartbeat(subscriber_name, extra_details=extras)
        except Exception:  # noqa: BLE001
            logger.debug("bolt12 heartbeat emit raised", exc_info=True)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_s)
        except asyncio.TimeoutError:
            pass


__all__ = [
    "emit_heartbeat",
    "get_state",
    "record_stream_ended",
    "record_stream_started",
    "run_heartbeat_loop",
    "summary",
]
