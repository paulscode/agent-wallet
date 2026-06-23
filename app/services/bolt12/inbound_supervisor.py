# SPDX-License-Identifier: MIT
"""S1 (2026-06-12): inbound-symptom HS supervisor with SIGHUP.

The existing :mod:`app.services.lnd_tor_supervisor` runs an
HSFETCH → NEWNYM → SIGHUP ladder, but it's gated on the OUTBOUND
LND breaker tripping. On 2026-06-11 and 2026-06-12 we observed
the wallet's outbound LND calls succeed (briefly) while peer-side
inbound forwards consistently failed, so the outbound breaker
stays closed and the ladder never fires.

This module parallels that supervisor but triggers from INBOUND
symptoms — sustained subscriber transport-error churn with short
median stream lifetimes. The escalation:

  Tier 1: NEWNYM (already handled by ``subscriber_recovery``)
  Tier 2 (THIS module): when subscribers can't keep a stream
          alive for > ``healthy_lifetime_s`` seconds for >
          ``trigger_minutes`` minutes, SIGHUP Tor. SIGHUP drops
          guards, rebuilds the circuit pool, and republishes the
          HS descriptor — the only wallet-side action that
          addresses the peer-side inbound problem.

State is in-memory + process-local. The supervisor reads recent
subscriber events from a bounded ring fed by the two BOLT 12
subscribers via :func:`record_subscriber_event`.

Throttle: ``bolt12_inbound_supervisor_sighup_throttle_s`` (default
1 hour) — SIGHUP is heavyweight (drops every Tor circuit), so we
fire it sparingly.

Kill switch: ``bolt12_inbound_supervisor_enabled=false`` disables
the supervisor entirely. The event collector keeps running so
operators can observe events on ``/livez`` even when the
escalation is off.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


_DEFAULT_RING_CAPACITY = 256
_DEFAULT_TICK_INTERVAL_S = 30.0


@dataclass
class _InboundSignal:
    """One observation that feeds the SIGHUP decision. ``kind``
    discriminates the source so we can apply per-source thresholds
    (transport errors are noisy in streaming mode; channel flaps
    and HSFETCH failures are rarer but stronger signals)."""

    monotonic_ts: float
    # 'transport'        — subscriber stream ended with a transport
    #                      error; counts toward ``failure_threshold``
    # 'transport_clean'  — subscriber stream ended cleanly; doesn't
    #                      count toward threshold but its
    #                      ``lifetime_s`` contributes to the
    #                      recovery gate (currently unused; reserved
    #                      for future subscriber-side wiring)
    # 'channel_flap'     — channel ``active→inactive`` transition
    #                      observed by the flap detector
    # 'hs_fetch_failure' — sustained HSFETCH-probe failure pattern
    kind: str
    # Only meaningful for kind in {'transport', 'transport_clean'}.
    lifetime_s: float = 0.0


@dataclass
class _SupervisorState:
    events: deque[_InboundSignal] = field(
        default_factory=lambda: deque(maxlen=_DEFAULT_RING_CAPACITY),
    )
    last_sighup_at: datetime | None = None
    last_sighup_monotonic: float = 0.0
    sighups_fired_total: int = 0
    last_evaluation_at: datetime | None = None
    last_decision: str = "noop"


_STATE = _SupervisorState()


def get_state() -> _SupervisorState:
    """Snapshot for ``/livez`` / dashboard."""
    return _STATE


def record_subscriber_event(*, transport: bool, lifetime_s: float) -> None:
    """Called by the two BOLT 12 subscribers on each stream
    termination. ``transport=True`` records the failure as a
    "transport-class" event the supervisor counts toward its
    ``failure_threshold`` (default 10 per window). ``transport=
    False`` records the lifetime alone — used to gate the
    "stream recovered recently" check.

    Lazy-imported so a test environment that doesn't initialise
    this module isn't broken. Bounded ring; older events evicted
    automatically.
    """
    # We always record SOMETHING so the "longest healthy lifetime"
    # check sees stream-recovery events even when transport=False.
    _STATE.events.append(
        _InboundSignal(
            monotonic_ts=time.monotonic(),
            kind="transport" if transport else "transport_clean",
            lifetime_s=lifetime_s,
        )
    )


def record_channel_flap() -> None:
    """Called by the S3 channel flap detector on each observed
    ``active → inactive`` transition (2026-06-12). In polling-
    mode deployments (S2 auto-enabled for onion-only LNDs) the
    streaming subscribers don't fail, so the supervisor's only
    signal source for "Tor is degrading" is channel flaps.
    Counted against ``flap_threshold`` (default 3 per window) so
    a small handful of flaps fires SIGHUP without waiting for the
    much-higher transport-error count."""
    _STATE.events.append(
        _InboundSignal(
            monotonic_ts=time.monotonic(),
            kind="channel_flap",
        )
    )


def record_hs_fetch_failure() -> None:
    """Called by the T4 HS-descriptor age probe when its
    consecutive-failure counter crosses the configured threshold
    (2026-06-12). A sustained HSFETCH failure pattern is the
    canonical "HS descriptor going stale" signal — peers can no
    longer find us via the DHT. Counted against
    ``hs_fetch_failure_threshold`` (default 1 per window) so even
    a single consecutive-failure-pattern fire triggers SIGHUP."""
    _STATE.events.append(
        _InboundSignal(
            monotonic_ts=time.monotonic(),
            kind="hs_fetch_failure",
        )
    )


def _events_in_window(window_s: float) -> list[_InboundSignal]:
    cutoff = time.monotonic() - window_s
    return [e for e in _STATE.events if e.monotonic_ts >= cutoff]


def _should_sighup(
    *,
    window_s: float,
    failure_threshold: int,
    healthy_lifetime_s: float,
    sighup_throttle_s: float,
    flap_threshold: int = 10**9,  # effectively disabled when not set
    hs_fetch_failure_threshold: int = 10**9,
) -> tuple[bool, dict]:
    """Decide whether to fire SIGHUP. Returns ``(fire, diag)``.

    Fire when ANY of the per-kind thresholds is met in the window
    AND the throttle window has passed AND (only for non-HSFETCH
    triggers) no healthy stream of ≥ ``healthy_lifetime_s`` has
    recovered.

    Why HSFETCH bypasses the recovery gate: a healthy outbound
    stream proves Tor's transport path works — but it says
    nothing about HS-descriptor publication, which is the
    failure mode SIGHUP specifically refreshes. Transport-error
    and channel-flap triggers, by contrast, ARE about transport
    health; if Tor's transport is intermittently OK, SIGHUP for
    those triggers would just churn.
    """
    diag: dict = {}
    events = _events_in_window(window_s)
    diag["events_in_window"] = len(events)
    transport_count = sum(1 for e in events if e.kind == "transport")
    flap_count = sum(1 for e in events if e.kind == "channel_flap")
    hs_count = sum(1 for e in events if e.kind == "hs_fetch_failure")
    diag["transport_count"] = transport_count
    diag["flap_count"] = flap_count
    diag["hs_fetch_failure_count"] = hs_count
    longest_healthy = max(
        (e.lifetime_s for e in events if e.kind in ("transport", "transport_clean")),
        default=0.0,
    )
    diag["longest_healthy_s"] = round(longest_healthy, 2)

    transport_met = transport_count >= failure_threshold
    flap_met = flap_count >= flap_threshold
    hs_met = hs_count >= hs_fetch_failure_threshold
    if not (transport_met or flap_met or hs_met):
        return False, {**diag, "decision": "below_failure_threshold"}

    # Recovery-gate semantics differ by signal source. ``healthy_
    # lifetime_s`` proves Tor's TRANSPORT path is intermittently
    # working — relevant for transport-error triggers and
    # channel-flap triggers, but NOT for HSFETCH failures. A
    # healthy outbound stream says nothing about HS-descriptor
    # publication, which is exactly what SIGHUP refreshes. So:
    # HSFETCH triggers bypass the gate; everything else respects it.
    if not hs_met and longest_healthy >= healthy_lifetime_s:
        return False, {**diag, "decision": "stream_recovered_recently"}

    # Throttle check.
    now = time.monotonic()
    age = now - _STATE.last_sighup_monotonic
    if _STATE.last_sighup_monotonic > 0 and age < sighup_throttle_s:
        diag["sighup_age_s"] = round(age, 1)
        return False, {**diag, "decision": "throttled"}

    diag["triggered_by"] = [
        kind
        for kind, met in (
            ("transport", transport_met),
            ("channel_flap", flap_met),
            ("hs_fetch_failure", hs_met),
        )
        if met
    ]
    return True, {**diag, "decision": "fire"}


async def _fire_sighup() -> bool:
    """Send ``SIGNAL RELOAD`` (HUP equivalent) to Tor. Returns True
    on success."""
    try:
        from app.services.anonymize.tor import signal_reload

        ok, err = await signal_reload(timeout_s=10.0)
        if not ok:
            logger.warning(
                "bolt12 inbound supervisor: SIGHUP rejected by Tor: %s",
                err,
            )
            return False
        return True
    except Exception:  # noqa: BLE001
        logger.exception("bolt12 inbound supervisor: SIGHUP helper raised")
        return False


async def _emit_supervisor_audit(action: str, details: dict) -> None:
    """Best-effort audit emit. Matches the existing supervisor
    convention (``lnd_tor_supervisor._emit_audit``) where
    ``success=True`` indicates "the supervisor successfully
    observed / decided / acted" — supervisor events are
    informational, not pass/fail outcomes."""
    try:
        from app.core.database import get_db_context
        from app.services.bolt12.responder import _audit_inbound

        await _audit_inbound(
            get_db_context,
            action=action,
            success=True,
            details=details,
        )
    except Exception:  # noqa: BLE001
        logger.exception(
            "bolt12 inbound supervisor: audit emit failed for %s",
            action,
        )


async def run_inbound_supervisor(stop_event: asyncio.Event) -> None:
    """Background loop. Evaluates the supervisor signature each
    tick; fires SIGHUP when conditions are met. Honors a kill
    switch and a settable tick cadence."""
    from app.core.config import settings

    if settings.testing:
        return

    if not getattr(settings, "bolt12_inbound_supervisor_enabled", True):
        logger.info("bolt12 inbound supervisor: disabled in settings")
        return

    interval = float(
        getattr(
            settings,
            "bolt12_inbound_supervisor_tick_interval_s",
            _DEFAULT_TICK_INTERVAL_S,
        )
    )
    if interval <= 0:
        logger.info("bolt12 inbound supervisor: disabled (interval <= 0)")
        return

    # T2 hygiene: clear the trace_id contextvar at task entry so
    # supervisor-emitted audit rows can never inherit a stale id
    # if this task happened to be spawned from a flow context.
    # Supervisor events aren't flow-scoped.
    try:
        from app.services.bolt12.trace import set_current_trace_id

        set_current_trace_id(None)
    except Exception:  # noqa: BLE001
        pass

    logger.info(
        "bolt12 inbound supervisor: starting (tick=%.0fs)",
        interval,
    )
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception:  # noqa: BLE001
            logger.exception("bolt12 inbound supervisor: tick raised; continuing")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("bolt12 inbound supervisor: stopped")


async def _tick() -> None:
    from app.core.config import settings

    window_s = float(
        getattr(
            settings,
            "bolt12_inbound_supervisor_window_s",
            300.0,
        )
    )
    failure_threshold = int(
        getattr(
            settings,
            "bolt12_inbound_supervisor_failure_threshold",
            10,
        )
    )
    flap_threshold = int(
        getattr(
            settings,
            "bolt12_inbound_supervisor_flap_threshold",
            3,
        )
    )
    hs_fetch_failure_threshold = int(
        getattr(
            settings,
            "bolt12_inbound_supervisor_hs_fetch_failure_threshold",
            1,
        )
    )
    healthy_lifetime_s = float(
        getattr(
            settings,
            "bolt12_inbound_supervisor_healthy_lifetime_s",
            30.0,
        )
    )
    sighup_throttle_s = float(
        getattr(
            settings,
            "bolt12_inbound_supervisor_sighup_throttle_s",
            3600.0,
        )
    )

    fire, diag = _should_sighup(
        window_s=window_s,
        failure_threshold=failure_threshold,
        flap_threshold=flap_threshold,
        hs_fetch_failure_threshold=hs_fetch_failure_threshold,
        healthy_lifetime_s=healthy_lifetime_s,
        sighup_throttle_s=sighup_throttle_s,
    )
    _STATE.last_evaluation_at = datetime.now(timezone.utc)
    _STATE.last_decision = diag.get("decision", "unknown")
    if not fire:
        return

    await _emit_supervisor_audit(
        "bolt12_inbound_supervisor_armed",
        {
            "window_s": window_s,
            "failure_threshold": failure_threshold,
            "flap_threshold": flap_threshold,
            "hs_fetch_failure_threshold": hs_fetch_failure_threshold,
            "healthy_lifetime_s": healthy_lifetime_s,
            **diag,
        },
    )
    ok = await _fire_sighup()
    if ok:
        _STATE.last_sighup_at = datetime.now(timezone.utc)
        _STATE.last_sighup_monotonic = time.monotonic()
        _STATE.sighups_fired_total += 1
        await _emit_supervisor_audit(
            "bolt12_inbound_supervisor_sighup_fired",
            {
                **diag,
                "sighups_fired_total": _STATE.sighups_fired_total,
            },
        )
        logger.warning(
            "bolt12 inbound supervisor: SIGHUP fired (events=%d, "
            "transport=%d, flaps=%d, hs_failures=%d, "
            "triggered_by=%s, longest_healthy=%.1fs, total_fires=%d)",
            diag.get("events_in_window", 0),
            diag.get("transport_count", 0),
            diag.get("flap_count", 0),
            diag.get("hs_fetch_failure_count", 0),
            diag.get("triggered_by", []),
            diag.get("longest_healthy_s", 0.0),
            _STATE.sighups_fired_total,
        )


def _reset_for_tests() -> None:
    global _STATE
    _STATE = _SupervisorState()


__all__ = [
    "get_state",
    "record_channel_flap",
    "record_hs_fetch_failure",
    "record_subscriber_event",
    "run_inbound_supervisor",
]
