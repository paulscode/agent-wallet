# SPDX-License-Identifier: MIT
"""Tor recovery watchdog.

# ────────────────────────────────────────────────────────────────────
# Recovery escalation tiers. The watchdog implements tier 2.
#
# Tier 1: in-flight retries (today's per-call patches; not handled
#         here). ``Connection failed:`` keeps swap state recoverable;
#         per-session loops retry one tick later. Mean recovery: <30s.
#
# Tier 2: NEWNYM via watchdog (this module). Fires when the Tor
#         breaker has been open ≥ TOR_NEWNYM_MIN_INTERVAL_S AND
# nothing is in-flight. Mean recovery: 30-90s.
#
# Tier 3: SIGNAL HUP (a.k.a. torrc reload) via watchdog. Fires when
#         the Tor breaker stays open ≥ 3 minutes despite NEWNYM.
#         Reloads torrc + forces a circuit-build retry without
#         dropping the process. Mean recovery: ~90s.
#
# Tier 4: container restart via Docker healthcheck failure.
#         Healthcheck fails 3 × 60s = 3 minutes → Docker restarts
#         tor-proxy. ~60-120s cold-start. In-flight HTLCs may need
#         recovery via today's patches.
#
# Tier 5: operator runbook. Investigation required.
# ────────────────────────────────────────────────────────────────────

NEWNYM is a process-wide signal that marks all existing
circuits dirty. Without (split Tor processes), it affects both
LND and anonymize listeners. We invalidate the anonymize per-session
exit-diversity cache after NEWNYM so the next admission re-evaluates
against the fresh circuit set.

The watchdog writes a last-tick timestamp + emits an
hourly heartbeat audit event so we can verify it's still alive.
Self-supervision: if the loop raises, the supervisor restarts it
up to 3 times in 5 minutes before escalating to a hard alarm.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from app.core.resilience import CircuitBreaker

logger = logging.getLogger(__name__)


# Escalation tier thresholds, in seconds.
_TIER_2_THRESHOLD_S = 60  # breaker open ≥ 60s → try NEWNYM
_TIER_3_THRESHOLD_S = 180  # breaker still open ≥ 3min → SIGHUP
# After tier 3 we yield to the Docker-driven container restart;
# the watchdog stops escalating and surfaces a hard alarm so the
# operator notices.

# Deferral ceiling for the in-flight NEWNYM gate. The NEWNYM action
# is normally gated on the in-flight inventory so we don't rotate
# circuits out from under a live payment. But that inventory probe
# talks to LND *over the very Tor path NEWNYM is meant to heal* — so
# when the path is wedged the probe times out, fail-safes to
# "in-flight", and defers NEWNYM forever, livelocking recovery (and
# blocking Tier-3 SIGHUP, which requires a prior NEWNYM). Once the
# breaker has been open this long with no successful rotation since it
# opened, any "in-flight" surface is itself a casualty of the wedge,
# so we force NEWNYM past the gate. Sits between tier 2 and tier 3 so
# the gated path gets a fair chance first and SIGHUP can still follow.
# Driver: 2026-06-15 tor-recovery livelock incident.
_NEWNYM_FORCE_CEILING_S = 120

# Self-supervision bounds.
_SUPERVISION_MAX_RESTARTS = 3
_SUPERVISION_RESTART_WINDOW_S = 300

# Heartbeat cadence (audit log emit). Hourly is enough to
# verify the watchdog is alive across operator-relevant time scales.
_HEARTBEAT_INTERVAL_S = 3600

# Per-instance state — see WatchdogState below.


@dataclass
class WatchdogState:
    """In-process state the watchdog keeps across ticks.

    Persisted only in-memory — no DB rows; a worker restart resets
    everything, which is the correct behaviour (no need to remember
    that we fired NEWNYM 5 minutes before the crash)."""

    last_tick_ts: float = 0.0
    last_newnym_ts: float = 0.0
    last_sighup_ts: float = 0.0
    last_heartbeat_ts: float = 0.0
    tor_breaker_opened_at_ts: float = 0.0
    consecutive_tier_3_fires: int = 0
    # Monotonic counters for the Prometheus surface. Incremented
    # only on successful signals (so the operator sees "real" rotations,
    # not failed attempts). Reset only on process restart, which is the
    # correct Prometheus-counter semantics.
    newnym_fired_total: int = 0
    sighup_fired_total: int = 0
    # self-supervision: timestamps of recent supervisor restarts.
    supervisor_restarts: list[float] = field(default_factory=list)


_STATE = WatchdogState()


# Additional per-pool state used in split mode. In single
# mode this stays untouched and the existing ``_STATE`` carries
# everything. ``get_pool_state(pool)`` is the canonical accessor.
_STATE_LND = WatchdogState()


def get_state() -> WatchdogState:
    """Return the live watchdog state for the default pool. Kept
    unchanged for backward compatibility with single-mode callers
    + tests; new code on split-mode paths should call
    :func:`get_pool_state` with an explicit pool name."""
    return _STATE


def get_pool_state(pool: str) -> WatchdogState:
    """Return the:class:`WatchdogState` for a named pool.

    Pools: ``"unified"`` / ``"anonymize"`` (both alias to the
    legacy single-pool state) or ``"lnd"`` (split-mode LND pool).
    """
    if pool == "lnd":
        return _STATE_LND
    return _STATE


@dataclass(frozen=True)
class _PoolContext:
    """Per-pool differences a tick consults: which state to mutate,
    which breaker to read, which control port to signal, and which
    pool label to attach to audit emits."""

    pool: str
    state: "WatchdogState"

    @property
    def control_host_override(self) -> Optional[str]:
        """Return the control-port host to pass to ``signal_*``
        helpers, or ``None`` to keep the helpers' default lookup
        (anonymize control host)."""
        from app.core.config import settings

        if self.pool == "lnd":
            return settings.lnd_tor_control_host or None
        return None

    @property
    def control_port_override(self) -> Optional[int]:
        from app.core.config import settings

        if self.pool == "lnd":
            return int(settings.lnd_tor_control_port) or None
        return None

    def breaker(self) -> CircuitBreaker:
        """Return the :class:`CircuitBreaker` whose state this
        watchdog instance reads. Imported here so the lazy import
        avoids a circular ``lnd_service`` <-> ``tor_watchdog``
        dependency at module load."""
        from app.services.lnd_service import _TOR_BREAKER, _TOR_LND_BREAKER

        if self.pool == "lnd":
            return _TOR_LND_BREAKER
        return _TOR_BREAKER


def _pool_ctx(pool: str = "unified") -> _PoolContext:
    """Build the context for ``pool``."""
    return _PoolContext(pool=pool, state=get_pool_state(pool))


async def _emit_audit(action: str, *, details: dict | None = None) -> None:
    """Best-effort audit-log emission. Failure is logged but never
    propagated — the watchdog must not crash on audit issues."""
    try:
        from app.core.database import get_db_context
        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import log_dashboard_action

        async with get_db_context() as db:
            await log_dashboard_action(
                db,
                DASHBOARD_KEY_ID,
                action,
                "tor",
                details=details or {},
                success=True,
            )
    except Exception as exc:  # noqa: BLE001
        logger.info("tor watchdog audit emit (%s) failed: %s", action, exc)


def _now() -> float:
    return time.monotonic()


def _wall_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _invalidate_anonymize_exit_diversity_cache() -> None:
    """After NEWNYM, the per-session exit-diversity cache
    must re-evaluate against the fresh circuit set. The cache lives
    inside the anonymize service; this is the hook the watchdog
    uses to nudge it. If the cache doesn't exist yet (still TBD by
    the anonymize side), the call is a no-op."""
    try:
        from app.services.anonymize.service import get_anonymize_service

        svc = get_anonymize_service()
        # Optional method — present after lands fully.
        invalidate = getattr(svc, "invalidate_exit_diversity_cache", None)
        if callable(invalidate):
            res = invalidate()
            if asyncio.iscoroutine(res):
                await res
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "tor watchdog: anonymize cache invalidation skipped (%s)",
            exc,
        )


async def _watchdog_tick(pool: str = "unified") -> None:
    """One tick of the watchdog loop.

    The escalation logic:
      - If Tor breaker is closed, reset all timers.
      - Else if breaker has been open ≥ tier 2 threshold AND nothing
        is in-flight AND we haven't NEWNYM'd recently, fire NEWNYM.
      - Else if breaker has been open ≥ tier 3 threshold AND we
        already tried NEWNYM, fire SIGHUP.
      - Else if breaker has been open longer than tier 3 threshold
        despite both NEWNYM and SIGHUP, yield to the healthcheck-
        driven container restart (the watchdog goes quiet but
        emits a hard alarm).

    NEWNYM action is gated on the in-flight inventory:
    fail-closed if anything looks live to avoid destabilising a
    mid-flight payment.

    ``pool`` selects which state + breaker + control port
    the tick operates on. Default ``"unified"`` preserves single-
    mode behaviour. Split-mode lifespan starts two tasks, one with
    ``pool="lnd"`` and one with ``pool="anonymize"``.
    """
    from app.core.config import settings

    ctx = _pool_ctx(pool)
    state = ctx.state
    breaker = ctx.breaker()

    now = _now()
    state.last_tick_ts = now

    if breaker.state == "closed":
        # Healthy: reset escalation timers.
        if state.tor_breaker_opened_at_ts:
            await _emit_audit(
                "tor_breaker_recovered",
                details={
                    "duration_s": now - state.tor_breaker_opened_at_ts,
                    "pool": pool,
                },
            )
        state.tor_breaker_opened_at_ts = 0.0
        state.consecutive_tier_3_fires = 0
        await _maybe_emit_heartbeat(ctx)
        # Only the unified/anonymize pool drives per-listener
        # probes — LND has just one listener and lnd_service's own
        # call path covers it.
        if pool != "lnd":
            _spawn_listener_probe_task()
        return

    # Tor breaker is open. Start the clock if this is the first tick
    # we've seen it open.
    if state.tor_breaker_opened_at_ts == 0.0:
        state.tor_breaker_opened_at_ts = now
        await _emit_audit(
            "tor_breaker_opened_observed",
            details={"breaker_state": breaker.state, "pool": pool},
        )

    open_duration_s = now - state.tor_breaker_opened_at_ts

    # Tier 2: NEWNYM.
    if open_duration_s >= _TIER_2_THRESHOLD_S:
        newnym_age = now - state.last_newnym_ts
        cooldown = max(10, int(settings.tor_newnym_min_interval_s))
        if newnym_age >= cooldown:
            # Force past the in-flight gate once the breaker has been
            # open beyond the deferral ceiling with no successful
            # rotation since it opened. This is the only way out of
            # the recovery livelock where the gate's own LND probe
            # times out on the wedged path and defers NEWNYM forever.
            force = (
                open_duration_s >= _NEWNYM_FORCE_CEILING_S and state.last_newnym_ts <= state.tor_breaker_opened_at_ts
            )
            await _maybe_fire_newnym(ctx, force=force)

    # Tier 3: SIGHUP if NEWNYM didn't recover.
    if (
        open_duration_s >= _TIER_3_THRESHOLD_S
        and state.last_newnym_ts > state.tor_breaker_opened_at_ts
        and state.consecutive_tier_3_fires == 0
    ):
        await _maybe_fire_sighup(ctx)

    # Tier 4: yield to Docker healthcheck. Surface a hard alarm so
    # the operator sees this state explicitly.
    if open_duration_s >= _TIER_3_THRESHOLD_S * 2 and state.consecutive_tier_3_fires > 0:
        await _emit_audit(
            "tor_recovery_escalated_to_healthcheck",
            details={
                "open_duration_s": open_duration_s,
                "newnym_fired": state.last_newnym_ts > 0,
                "sighup_fired": state.last_sighup_ts > 0,
                "pool": pool,
            },
        )

    await _maybe_emit_heartbeat(ctx)
    # Fire one per-listener SOCKS5 probe per tick (round-
    # robin). Only the anonymize/unified pool spawns this; the LND
    # pool has just one listener and doesn't need a per-listener
    # rotation.
    if pool != "lnd":
        _spawn_listener_probe_task()


def _spawn_listener_probe_task() -> None:
    """Schedule one per-listener probe in the background. Errors
    are swallowed; results land in the in-process snapshot the
    dashboard / metrics endpoints read."""
    try:
        from app.services.tor_per_listener_probe import probe_next_listener

        asyncio.create_task(probe_next_listener())
    except Exception as exc:  # noqa: BLE001
        logger.info("tor watchdog: could not spawn listener probe: %s", exc)


async def _maybe_fire_newnym(
    ctx: Optional["_PoolContext"] = None,
    *,
    force: bool = False,
) -> None:
    """Tier-2 NEWNYM action. Gated on the in-flight inventory.

    When ``ctx`` is for the LND pool, NEWNYM is sent to
    ``lnd_tor_control_host:lnd_tor_control_port`` instead of the
    default anonymize control endpoint.

    ``force=True`` bypasses the in-flight gate entirely. The caller
    sets this once the breaker has been open past
    ``_NEWNYM_FORCE_CEILING_S`` with no rotation since it opened: at
    that point the in-flight probe itself runs over the wedged path
    and its fail-safe "in-flight" verdict would otherwise defer
    recovery forever. We skip the probe rather than run-but-ignore it
    so a hung LND probe can't add latency to the recovery tick.
    """
    from app.core.database import get_db_context
    from app.services.anonymize.tor import signal_newnym
    from app.services.tor_inflight import check_in_flight

    if ctx is None:
        ctx = _pool_ctx("unified")
    state = ctx.state
    pool = ctx.pool

    if force:
        logger.warning(
            "tor watchdog (%s): forcing NEWNYM past in-flight gate — breaker wedged beyond deferral ceiling (%ds)",
            pool,
            _NEWNYM_FORCE_CEILING_S,
        )
        await _emit_audit(
            "tor_newnym_forced",
            details={
                "reason": "deferral_ceiling_exceeded",
                "ceiling_s": _NEWNYM_FORCE_CEILING_S,
                "pool": pool,
            },
        )
    else:
        # Fail-closed in-flight check. The check is GLOBAL —
        # a payment in flight should defer NEWNYM on EITHER Tor pool,
        # since a NEWNYM on one pool can still rotate circuits used
        # downstream of the other (e.g. the anonymize boltz_submarine
        # round-trip relies on LND staying reachable too).
        try:
            inflight = await check_in_flight(get_db_context)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "tor watchdog (%s): in-flight check raised %s; deferring NEWNYM",
                pool,
                exc,
            )
            await _emit_audit(
                "tor_newnym_deferred",
                details={
                    "reason": "in_flight_check_raised",
                    "exc": str(exc),
                    "pool": pool,
                },
            )
            return
        if inflight.in_flight:
            logger.info(
                "tor watchdog (%s): NEWNYM deferred — in-flight surfaces: %s",
                pool,
                inflight.surfaces,
            )
            await _emit_audit(
                "tor_newnym_deferred",
                details={
                    "in_flight_surfaces": inflight.surfaces,
                    "pool": pool,
                },
            )
            return

    ok, err = await signal_newnym(
        host=ctx.control_host_override,
        port=ctx.control_port_override,
    )
    if ok:
        state.last_newnym_ts = _now()
        state.newnym_fired_total += 1
        logger.info("tor watchdog (%s): NEWNYM fired successfully", pool)
        await _emit_audit("tor_newnym_fired", details={"pool": pool})
        # Invalidate anonymize exit-diversity cache. Only
        # the anonymize/unified pool's NEWNYM affects anonymize
        # circuits; an LND-pool NEWNYM doesn't.
        if pool != "lnd":
            await _invalidate_anonymize_exit_diversity_cache()
    else:
        logger.warning("tor watchdog (%s): NEWNYM failed: %s", pool, err)
        await _emit_audit(
            "tor_newnym_failed",
            details={"error": err, "pool": pool},
        )


async def _maybe_fire_sighup(ctx: Optional["_PoolContext"] = None) -> None:
    """Tier-3 SIGHUP action. No in-flight gating — SIGHUP is gentle
    (no circuit teardown) so it's safe to fire mid-traffic."""
    from app.services.anonymize.tor import signal_reload

    if ctx is None:
        ctx = _pool_ctx("unified")
    state = ctx.state
    pool = ctx.pool

    ok, err = await signal_reload(
        host=ctx.control_host_override,
        port=ctx.control_port_override,
    )
    state.consecutive_tier_3_fires += 1
    if ok:
        state.last_sighup_ts = _now()
        state.sighup_fired_total += 1
        logger.info("tor watchdog (%s): SIGHUP fired successfully", pool)
        await _emit_audit("tor_sighup_fired", details={"pool": pool})
    else:
        logger.warning("tor watchdog (%s): SIGHUP failed: %s", pool, err)
        await _emit_audit(
            "tor_sighup_failed",
            details={"error": err, "pool": pool},
        )


async def _maybe_emit_heartbeat(ctx: Optional["_PoolContext"] = None) -> None:
    """Emit an audit-log heartbeat once per
    ``_HEARTBEAT_INTERVAL_S`` so the operator can verify the watchdog
    is alive across long operational windows. The hourly heartbeat
    is also when growth-check runs (no need to poll disk
    more often than that).

    Heartbeat is per-pool. Both pools emit independently so
    a stalled tor-lnd watchdog can't be hidden by a healthy
    tor-anonymize one (or vice versa)."""
    if ctx is None:
        ctx = _pool_ctx("unified")
    state = ctx.state
    pool = ctx.pool

    now = _now()
    if now - state.last_heartbeat_ts < _HEARTBEAT_INTERVAL_S:
        return
    state.last_heartbeat_ts = now
    data_dir_used_mb = await _data_dir_used_mb()
    await _emit_audit(
        "tor_watchdog_alive",
        details={
            "last_tick_iso": _wall_now_iso(),
            "last_newnym_age_s": (now - state.last_newnym_ts if state.last_newnym_ts else None),
            "data_dir_used_mb": data_dir_used_mb,
            "pool": pool,
        },
    )
    # The growth check is shared infrastructure — run it once
    # from whichever pool's heartbeat fires first. The watchdog
    # state's per-pool ``last_heartbeat_ts`` keeps the same
    # interval guarantee on both pools.
    if pool != "lnd":
        await _maybe_warn_data_dir_growth(data_dir_used_mb)


async def _data_dir_used_mb() -> Optional[int]:
    """Measure the Tor DataDirectory volume's actual content
    size (du-style walk, NOT statvfs). Returns ``None`` when:

    * The path isn't configured (``tor_data_dir_mount_path`` empty).
    * The path doesn't exist (operator running their own Tor; the
      compose volume isn't mounted into this container).
    * The path is NOT a dedicated mountpoint (a plain directory under
      the wallet's filesystem isn't a DataDirectory volume).

    Why a directory walk instead of ``os.statvfs()``: ``statvfs``
    returns the underlying filesystem's used bytes — for a Docker
    named volume that's the WHOLE host filesystem, which is
    misleading (and surfaced as a 2.5 TB false positive in the
    field, hence this rewrite). Walking the directory gives the
    actual Tor cache size, which is what the growth-warn threshold
    was designed against (Tor steady-state ~10-30 MB).

    The walk is bounded by the volume size; for the expected
    workload (a few hundred files in /var/lib/tor) it completes in
    ~10 ms. Runs once per hour from the watchdog heartbeat.
    """
    from app.core.config import settings

    path = (settings.tor_data_dir_mount_path or "").strip()
    if not path:
        return None
    try:
        import os

        if not os.path.exists(path):
            return None
        if not os.path.ismount(path):
            # Path exists but isn't a real mountpoint — the watchdog
            # is running outside the compose stack (dev/test) or the
            # volume isn't actually mounted.
            return None
        total_bytes = 0
        for root, _dirs, files in os.walk(path):
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    total_bytes += os.path.getsize(fp)
                except OSError:
                    # File disappeared between walk and getsize, or
                    # we can't read it. Skip — best-effort sum.
                    continue
        return int(total_bytes / (1024 * 1024))
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001
        logger.info("tor watchdog: data-dir walk(%s) failed: %s", path, exc)
        return None


async def _maybe_warn_data_dir_growth(used_mb: Optional[int]) -> None:
    """Emit an audit warning when DataDirectory usage crosses the
    threshold.. Idempotent — re-emit on each hourly heartbeat
    while still above threshold so the operator notices."""
    if used_mb is None:
        return
    from app.core.config import settings

    threshold_mb = int(settings.tor_data_dir_warn_mb)
    if used_mb < threshold_mb:
        return
    logger.warning(
        "tor DataDirectory growth: %d MB (threshold %d MB)",
        used_mb,
        threshold_mb,
    )
    await _emit_audit(
        "tor_data_dir_growth_warning",
        details={
            "used_mb": used_mb,
            "threshold_mb": threshold_mb,
        },
    )


async def _watchdog_loop(
    stop_event: asyncio.Event,
    pool: str = "unified",
) -> None:
    """The async loop body — runs ticks at the configured cadence
    until ``stop_event`` is set. ``pool`` selects which state /
    breaker / control port the ticks operate on."""
    from app.core.config import settings

    interval = max(5, int(settings.tor_watchdog_interval_s))
    logger.info(
        "tor watchdog (%s) started (interval=%ds)",
        pool,
        interval,
    )
    while not stop_event.is_set():
        try:
            await _watchdog_tick(pool=pool)
        except Exception as exc:  # noqa: BLE001
            # Per-tick exception: log + audit + keep going. The
            # supervisor handles the case where the WHOLE loop
            # dies (e.g. asyncio task gets cancelled abnormally).
            logger.exception(
                "tor watchdog (%s) tick raised: %s",
                pool,
                exc,
            )
            try:
                await _emit_audit(
                    "tor_watchdog_tick_error",
                    details={"error": str(exc)[:300], "pool": pool},
                )
            except Exception:  # noqa: BLE001
                pass
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            break
    logger.info("tor watchdog (%s) stopped", pool)


async def start_watchdog(
    stop_event: asyncio.Event,
    pool: str = "unified",
) -> None:
    """Supervised loop. If ``_watchdog_loop`` ever raises
    or returns unexpectedly, restart it up to
    ``_SUPERVISION_MAX_RESTARTS`` times within
    ``_SUPERVISION_RESTART_WINDOW_S``. Beyond that, escalate to an
    audit alarm + stay stopped (operator action required).

    ``pool`` selects which pool's state + breaker drive
    the watchdog. Lifespan calls this twice in split mode (one
    per pool); single mode calls it once with the default."""
    state = get_pool_state(pool)
    while not stop_event.is_set():
        try:
            await _watchdog_loop(stop_event, pool=pool)
            # Clean exit.
            break
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "tor watchdog (%s) loop crashed: %s",
                pool,
                exc,
            )
            now = _now()
            state.supervisor_restarts = [
                ts for ts in state.supervisor_restarts if now - ts < _SUPERVISION_RESTART_WINDOW_S
            ]
            state.supervisor_restarts.append(now)
            if len(state.supervisor_restarts) > _SUPERVISION_MAX_RESTARTS:
                await _emit_audit(
                    "tor_watchdog_supervision_exhausted",
                    details={
                        "restarts": len(state.supervisor_restarts),
                        "window_s": _SUPERVISION_RESTART_WINDOW_S,
                        "pool": pool,
                    },
                )
                logger.error(
                    "tor watchdog (%s): supervision exhausted, staying stopped",
                    pool,
                )
                return
            await _emit_audit(
                "tor_watchdog_restarting",
                details={"crash": str(exc)[:300], "pool": pool},
            )
            # Brief backoff before retry.
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                continue


__all__ = [
    "WatchdogState",
    "get_state",
    "start_watchdog",
]
