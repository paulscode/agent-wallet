# SPDX-License-Identifier: MIT
"""Prometheus-style Tor metrics endpoint.

Exposes Tor health + watchdog state in the standard Prometheus text
format. Operators can scrape this via their existing API key (admin
auth) — no new exposure surface, no anonymous endpoint, no
unauthenticated metrics leak.

Metric naming follows Prometheus conventions:
  - ``tor_*`` prefix.
  - ``_total`` for monotonic counters; ``_seconds`` / ``_bytes`` /
    ``_count`` for gauges.

Probes are cached for ``_PROBE_CACHE_TTL_S`` to avoid hammering the
control port on every scrape. The cache is in-process; a worker
restart resets it.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from app.core.security import get_admin_key
from app.models.api_key import APIKey

router = APIRouter()

_PROBE_CACHE_TTL_S = 15.0
_cache: dict[str, Any] = {}


async def _cached_probes() -> dict[str, Any]:
    """Probe Tor for bootstrap / circuits / guards / network-liveness;
    cache the results for ``_PROBE_CACHE_TTL_S`` so repeated scrapes
    don't hammer the control port.

    A probe failure leaves the corresponding metric at -1 (the
    sentinel value the metric description marks as "not available")
    rather than dropping the metric — Prometheus needs consistent
    label sets across scrapes.
    """
    now = time.monotonic()
    if _cache and now - _cache.get("ts", 0) < _PROBE_CACHE_TTL_S:
        return _cache
    from app.services.anonymize.tor import (
        probe_entry_guards,
        probe_network_liveness,
        probe_tor_bootstrap_status,
        probe_tor_circuit_status,
    )

    try:
        boot = await probe_tor_bootstrap_status()
    except Exception:  # noqa: BLE001
        boot = None
    try:
        circuits, _circuit_err = await probe_tor_circuit_status()
    except Exception:  # noqa: BLE001
        circuits = []
    try:
        guards, _guard_err = await probe_entry_guards()
    except Exception:  # noqa: BLE001
        guards = []
    try:
        net_live, _net_err = await probe_network_liveness()
    except Exception:  # noqa: BLE001
        net_live = None

    _cache.clear()
    _cache.update(
        {
            "ts": now,
            "boot": boot,
            "circuits": circuits,
            "guards": guards,
            "net_live": net_live,
        }
    )
    return _cache


def _render(metrics: list[tuple[str, str, str, float]]) -> str:
    """Render a list of ``(name, help, type, value)`` tuples as
    Prometheus text format. Output is sorted for stability."""
    out_parts: list[str] = []
    for name, help_text, mtype, value in metrics:
        out_parts.append(f"# HELP {name} {help_text}")
        out_parts.append(f"# TYPE {name} {mtype}")
        # Format integers without a decimal point; floats compact.
        if value == int(value):
            out_parts.append(f"{name} {int(value)}")
        else:
            out_parts.append(f"{name} {value}")
    return "\n".join(out_parts) + "\n"


def _breaker_state_to_gauge(state: str) -> int:
    """Map breaker state strings to numeric gauge values for
    Prometheus consumption (Prometheus discourages string-valued
    metrics)."""
    return {"closed": 0, "half_open": 1, "open": 2}.get(state, -1)


def _get_lnd_pool_breaker_state_for_metric() -> str:
    """Return the LND-pool Tor breaker state.

    Lazy import so the metrics module doesn't pull in
    ``lnd_service`` at module load (avoids a circular dep with
    config validators that run early in app startup).
    """
    try:
        from app.services.lnd_service import _TOR_LND_BREAKER

        return _TOR_LND_BREAKER.state
    except Exception:  # noqa: BLE001
        return "closed"


def _is_split_mode_enabled_for_metric() -> bool:
    """Surface the split-mode flag as a Prometheus gauge so
    operators' dashboards can branch on it (e.g. only chart the
    LND-pool breaker when the flag is 1)."""
    try:
        from app.core.config import settings

        return bool(getattr(settings, "tor_split_mode", False))
    except Exception:  # noqa: BLE001
        return False


def _newnym_total_across_pools() -> int:
    """Sum NEWNYM count across whatever pools exist in
    this process. Single mode reads the unified state; split
    mode sums lnd + anonymize."""
    try:
        from app.services.tor_watchdog import _STATE, _STATE_LND

        return int(_STATE.newnym_fired_total) + int(_STATE_LND.newnym_fired_total)
    except Exception:  # noqa: BLE001
        return 0


def _sighup_total_across_pools() -> int:
    """Mirror of :func:`_newnym_total_across_pools` for SIGHUP."""
    try:
        from app.services.tor_watchdog import _STATE, _STATE_LND

        return int(_STATE.sighup_fired_total) + int(_STATE_LND.sighup_fired_total)
    except Exception:  # noqa: BLE001
        return 0


@router.get(
    "/v1/status/tor",
    summary="Tor health snapshot as JSON for the dashboard panel",
)
async def tor_status_json(
    admin_key: APIKey = Depends(get_admin_key),
) -> dict[str, Any]:
    """JSON snapshot for the dashboard Tor-health panel.

    Shape is intentionally flat — each key maps to a single number /
    string / list so the Alpine.data getters can read them without
    deeper traversal (the @alpinejs/csp build doesn't reliably
    short-circuit ``a && a.b`` chains).
    """
    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER
    from app.services.tor_event_stream import get_counters
    from app.services.tor_watchdog import _data_dir_used_mb, get_state

    probes = await _cached_probes()
    boot = probes.get("boot")
    circuits = probes.get("circuits") or []
    guards = probes.get("guards") or []
    net_live = probes.get("net_live")
    state = get_state()
    counters = get_counters()
    now = time.monotonic()
    try:
        used_mb = await _data_dir_used_mb()
    except Exception:  # noqa: BLE001
        used_mb = None

    return {
        "bootstrap_progress": (boot.bootstrap_phase_progress if boot else None),
        "circuit_established": (bool(boot.circuit_established) if boot else None),
        "control_port_reachable": (bool(boot.control_port_reachable) if boot else False),
        "active_circuits": len(circuits),
        "guards_total": len(guards),
        "guards_up": sum(1 for g in guards if g.status == "up"),
        "guards": [
            {
                "fingerprint": g.fingerprint,
                "nickname": g.nickname,
                "status": g.status,
            }
            for g in guards
        ],
        "network_liveness": ("up" if net_live is True else "down" if net_live is False else "unknown"),
        "tor_breaker": {
            "state": _TOR_BREAKER.state,
            "consecutive_failures": _TOR_BREAKER.consecutive_failures,
            "last_error": _TOR_BREAKER.last_error,
        },
        "lnd_breaker": {
            "state": _LND_BREAKER.state,
            "consecutive_failures": _LND_BREAKER.consecutive_failures,
        },
        "watchdog": {
            "last_tick_age_s": ((now - state.last_tick_ts) if state.last_tick_ts else None),
            "last_newnym_age_s": ((now - state.last_newnym_ts) if state.last_newnym_ts else None),
            "last_sighup_age_s": ((now - state.last_sighup_ts) if state.last_sighup_ts else None),
            "breaker_open_duration_s": (
                (now - state.tor_breaker_opened_at_ts) if state.tor_breaker_opened_at_ts else 0
            ),
            "alive": (state.last_tick_ts > 0 and (now - state.last_tick_ts) < 90),
        },
        "event_stream": {
            "connected": counters.stream_connected,
            "events_total": counters.events_total,
            "circ_failed": counters.circ_failed,
            "hs_desc_failed": counters.hs_desc_failed,
            "guard_down": counters.guard_down,
            "warn_total": counters.warn_total,
            "err_total": counters.err_total,
            "reconnects": counters.stream_reconnect_total,
            # Pattern-matched WARN/ERR sub-counters.
            "guard_excluded_total": counters.guard_excluded_total,
            "circuit_stuck_total": counters.circuit_stuck_total,
        },
        "data_dir_used_mb": used_mb,
        # Per-listener probe snapshot for operator tooling.
        "listeners": _listener_status_for_json(),
        # LND Tor supervisor — staggered HSFETCH/NEWNYM/SIGHUP
        # recovery for LND-onion stale-descriptor incidents.
        "lnd_tor_supervisor": _lnd_tor_supervisor_for_json(now),
        # Host-identifying / fine-grained Tor timing telemetry is
        # served only here, behind the admin key — never on the
        # unauthenticated ``/livez`` healthcheck.
        "keepalive": _keepalive_for_json(),
        "hs_descriptor": _hs_descriptor_for_json(),
        "channel_uptime": _channel_uptime_for_json(),
        "subscriber_lifetimes": _subscriber_lifetimes_for_json(),
        "inbound_supervisor": _inbound_supervisor_for_json(),
    }


def _keepalive_for_json() -> dict[str, Any]:
    """LND-keepalive counters. Reveal Tor descriptor instability, so
    they ride the admin snapshot rather than the public healthcheck."""
    from app.services.lnd_keepalive import get_state

    s = get_state()
    return {
        "consecutive_failures": s.consecutive_failures,
        "recoveries_attempted_total": s.recoveries_attempted_total,
        "inbound_burst_newnyms_total": s.inbound_burst_newnyms_total,
        "last_success_at": (s.last_success_at.isoformat() if s.last_success_at else None),
    }


def _hs_descriptor_for_json() -> dict[str, Any]:
    """HS-descriptor freshness probe snapshot."""
    from app.services.lnd_hs_descriptor_age import age_seconds, get_state

    s = get_state()
    return {
        "age_s_since_last_ok": age_seconds(),
        "consecutive_failures": s.consecutive_failures,
        "attempts_total": s.attempts_total,
        "successes_total": s.successes_total,
    }


def _channel_uptime_for_json() -> dict[str, Any]:
    """Per-channel uptime — carries peer pubkeys/aliases, so it stays
    behind the admin key."""
    from app.services.lnd_channel_uptime import summary

    return summary()


def _subscriber_lifetimes_for_json() -> dict[str, Any]:
    """BOLT12 subscriber stream-lifetime metrics."""
    from app.services.bolt12.subscriber_metrics import summary

    return summary()


def _inbound_supervisor_for_json() -> dict[str, Any]:
    """Inbound-symptom HS supervisor snapshot."""
    from app.services.bolt12.inbound_supervisor import get_state

    s = get_state()
    return {
        "sighups_fired_total": s.sighups_fired_total,
        "last_decision": s.last_decision,
        "last_sighup_at": (s.last_sighup_at.isoformat() if s.last_sighup_at else None),
    }


def _lnd_tor_supervisor_for_json(now: float) -> dict[str, Any]:
    """Snapshot of supervisor state. Returned as a sub-dict on the
    admin JSON endpoint and consumed by the dashboard panel for
    "auto-recovery history". Keys mirror the supervisor's
    :class:`SupervisorState` fields, but ages are computed at read
    time so the dashboard doesn't have to maintain its own clock."""
    from app.services.lnd_tor_supervisor import get_state as _get_sup_state

    s = _get_sup_state()
    incident_active = s.incident_start_ts > 0
    return {
        "alive": (s.last_tick_ts > 0 and (now - s.last_tick_ts) < 30),
        "last_tick_age_s": ((now - s.last_tick_ts) if s.last_tick_ts else None),
        "last_heartbeat_age_s": ((now - s.last_heartbeat_ts) if s.last_heartbeat_ts else None),
        "incident_active": incident_active,
        "incident_correlation_id": s.incident_correlation_id or None,
        "incident_started_age_s": ((now - s.incident_start_ts) if incident_active else None),
        "current_step": s.current_step if incident_active else None,
        "cycles_started_total": s.cycles_started_total,
        "cycles_cleared_by_step": dict(s.cycles_cleared_by_step),
        "cycles_in_last_24h": len(s.recent_cycle_completions),
        "cycles_disabled_until_age_s": (
            (s.cycles_disabled_until_ts - now) if s.cycles_disabled_until_ts > now else None
        ),
        "inhibits_total": dict(s.inhibits_total),
        "step_outcomes": dict(s.step_outcomes),
        # Last cycle's per-step timeline for the dashboard panel.
        "last_cycle_steps": list(s.last_cycle_steps),
    }


def _listener_status_for_json() -> dict[str, dict]:
    """Map listener name → status dict for the admin JSON endpoint."""
    from app.services.tor_per_listener_probe import get_snapshot

    return get_snapshot()


@router.get(
    "/v1/status/tor/metrics",
    response_class=PlainTextResponse,
    summary="Tor health metrics in Prometheus text format",
)
async def tor_metrics(
    admin_key: APIKey = Depends(get_admin_key),
) -> str:
    """Prometheus scraping endpoint for Tor health."""
    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER
    from app.services.tor_event_stream import get_counters
    from app.services.tor_watchdog import get_state

    probes = await _cached_probes()
    boot = probes.get("boot")
    circuits = probes.get("circuits") or []
    guards = probes.get("guards") or []
    net_live = probes.get("net_live")

    counters = get_counters()
    state = get_state()
    now = time.monotonic()

    metrics: list[tuple[str, str, str, float]] = [
        (
            "tor_bootstrap_progress",
            "Tor bootstrap percentage (0-100); -1 when control port unreachable.",
            "gauge",
            boot.bootstrap_phase_progress if boot else -1,
        ),
        (
            "tor_circuit_established",
            "1 when Tor reports an established circuit, 0 otherwise, -1 when control port unreachable.",
            "gauge",
            (1 if boot and boot.circuit_established else 0) if boot else -1,
        ),
        (
            "tor_control_port_reachable",
            "1 when the control port responded to GETINFO, 0 otherwise.",
            "gauge",
            (1 if boot and boot.control_port_reachable else 0) if boot else 0,
        ),
        (
            "tor_active_circuits",
            "Number of circuits in BUILT/EXTENDED/GUARD_WAIT state at last probe.",
            "gauge",
            len(circuits),
        ),
        (
            "tor_entry_guards_total",
            "Total entry guards Tor is tracking.",
            "gauge",
            len(guards),
        ),
        (
            "tor_entry_guards_up",
            "Entry guards whose status is 'up'.",
            "gauge",
            sum(1 for g in guards if g.status == "up"),
        ),
        (
            "tor_network_liveness_up",
            "Tor's own network-liveness assessment (1=up, 0=down, -1=unknown).",
            "gauge",
            (1 if net_live else 0) if net_live is not None else -1,
        ),
        # True monotonic counters. In split mode we sum
        # across pools so a single ``tor_newnym_total`` figure
        # captures all rotations, regardless of which pool fired
        # each one. Split-mode operators can also consume
        # ``tor_split_mode_enabled`` to know to chart per-pool.
        (
            "tor_newnym_total",
            "Total NEWNYM signals issued by the watchdog (all pools) since process start.",
            "counter",
            _newnym_total_across_pools(),
        ),
        (
            "tor_sighup_total",
            "Total SIGHUP signals issued by the watchdog (all pools) since process start.",
            "counter",
            _sighup_total_across_pools(),
        ),
        (
            "tor_breaker_state",
            "Tor circuit-breaker state (0=closed, 1=half-open, 2=open).",
            "gauge",
            _breaker_state_to_gauge(_TOR_BREAKER.state),
        ),
        (
            "lnd_breaker_state",
            "LND circuit-breaker state (0=closed, 1=half-open, 2=open).",
            "gauge",
            _breaker_state_to_gauge(_LND_BREAKER.state),
        ),
        # LND-pool Tor breaker. In single mode this stays
        # at 0 (closed) since failures route to the shared
        # ``tor_breaker_state``. In split mode this carries the
        # LND-side wedge signal independently of the anonymize one.
        (
            "tor_lnd_breaker_state",
            "LND-pool Tor circuit-breaker state (0=closed, 1=half-open, 2=open). 0 in single mode.",
            "gauge",
            _breaker_state_to_gauge(_get_lnd_pool_breaker_state_for_metric()),
        ),
        (
            "tor_split_mode_enabled",
            "1 when the wallet is running with split tor-lnd / tor-anonymize pools, 0 in unified mode.",
            "gauge",
            1 if _is_split_mode_enabled_for_metric() else 0,
        ),
        (
            "tor_breaker_consecutive_failures",
            "Tor breaker's current consecutive-failure count.",
            "gauge",
            _TOR_BREAKER.consecutive_failures,
        ),
        (
            "tor_watchdog_last_tick_age_seconds",
            "Seconds since the watchdog last completed a tick. >90s suggests the watchdog is stuck.",
            "gauge",
            (now - state.last_tick_ts) if state.last_tick_ts else -1,
        ),
        (
            "tor_breaker_open_duration_seconds",
            "How long the Tor breaker has been open in its current spell (0 when closed).",
            "gauge",
            (now - state.tor_breaker_opened_at_ts) if state.tor_breaker_opened_at_ts else 0,
        ),
        # Log-pattern matched counters from the event stream.
        (
            "tor_guard_excluded_total",
            "Count of 'All current guards excluded by path restriction' warnings since process start.",
            "counter",
            counters.guard_excluded_total,
        ),
        (
            "tor_circuit_stuck_total",
            "Count of 'Tried for N seconds to get a connection' warnings since process start.",
            "counter",
            counters.circuit_stuck_total,
        ),
    ]
    # DataDirectory size (optional; -1 when not measurable).
    try:
        from app.services.tor_watchdog import _data_dir_used_mb

        used = await _data_dir_used_mb()
    except Exception:  # noqa: BLE001
        used = None
    metrics.append(
        (
            "tor_data_dir_used_megabytes",
            "Bytes used by the Tor DataDirectory volume (MB). -1 when not measurable.",
            "gauge",
            used if used is not None else -1,
        )
    )

    # Per-listener probe state. Rendered with name+port
    # labels so a single metric covers all 8 listeners.
    listener_block = _render_per_listener_metrics()

    return _render(metrics) + listener_block


def _render_per_listener_metrics() -> str:
    """Render per-listener probe state as labeled Prometheus
    gauges. Metric names + label keys are stable so
    operator dashboards scrape cleanly:
    ``tor_listener_socks_round_trip_success{listener,port}`` and
    ``tor_listener_last_probe_age_seconds{listener,port}``."""
    from app.services.tor_per_listener_probe import get_snapshot

    snap = get_snapshot()
    if not snap:
        return ""
    lines: list[str] = []
    lines.append(
        "# HELP tor_listener_socks_round_trip_success Last "
        "per-listener SOCKS5 round-trip result (1=ok, 0=fail, "
        "-1=untested)."
    )
    lines.append("# TYPE tor_listener_socks_round_trip_success gauge")
    for name in sorted(snap.keys()):
        entry = snap[name]
        port = entry["port"]
        if entry["ok"] is None:
            value = -1
        else:
            value = 1 if entry["ok"] else 0
        lines.append(f'tor_listener_socks_round_trip_success{{listener="{name}",port="{port}"}} {value}')
    lines.append(
        "# HELP tor_listener_last_probe_age_seconds Age of the most recent probe per listener (-1 when never probed)."
    )
    lines.append("# TYPE tor_listener_last_probe_age_seconds gauge")
    for name in sorted(snap.keys()):
        entry = snap[name]
        port = entry["port"]
        age = entry["last_probe_age_s"]
        v = int(age) if isinstance(age, (int, float)) and age >= 0 else -1
        lines.append(f'tor_listener_last_probe_age_seconds{{listener="{name}",port="{port}"}} {v}')
    return "\n".join(lines) + "\n"
