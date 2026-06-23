# SPDX-License-Identifier: MIT
"""LND-onion Tor supervisor.

The driver: the 2026-06-01 stale-HS-descriptor incident.
The wallet's Tor proxy got into a state where it could not reach
LND's hidden service even though general Tor (other onions,
clearnet) worked fine. The existing ``tor_watchdog`` never escalated
because of a separate wiring bug (since fixed — see the breaker-reset
asymmetry in :mod:`app.services.lnd_service`); this module is the
follow-up that adds corroborating signals + an HSFETCH-led
escalation ladder.

# ────────────────────────────────────────────────────────────────────
# Escalation ladder
#
#   T+0    detect — C1..C4 all true (see ``_detect_signature``).
#                   Record incident_start_ts. Emit
#                   ``tor_lnd_recovery_armed`` audit.
#   T+0    step 1 — HSFETCH the LND onion. Surgical refresh of the
#                   one stale descriptor; minimal blast radius.
#   T+60   step 2 — SIGNAL NEWNYM. Drops dirty circuits. Process-
#                   wide blast radius (anonymize circuits rebuild
#                   too; the exit-diversity cache invalidates).
#   T+150  step 3 — SIGNAL HUP. Reload torrc + drop all guards.
#                   ~30 s extra latency on first egress after.
#   T+270  step 4 — Yield to Docker healthcheck. Container restarts
#                   after 3×60s of failed healthchecks.
#   T+450  step 5 — Exhausted. Hard alarm; operator runbook.
#
# Note: the "T+N" times above are LOWER BOUNDS. Each step finishes
# only when its own helper returns AND the LND breaker either closes
# (incident cleared) or stays open past the step's hard-timeout
# (escalate). The ``_LND_BREAKER.state == "closed"`` transition is
# the only positive recovery signal — anything else would race
# against the next probe.
# ────────────────────────────────────────────────────────────────────

# Backoff. Cycles completed in rolling 24 h window:
#   0      can fire immediately
#   1      next cycle after 15 minutes
#   2      next cycle after 45 minutes
#   3      next cycle after 2 hours
#   4+     disabled for the rest of the 24 h window; hard alarm

Concurrency: serialised by a module-level :class:`asyncio.Lock` so
two coroutines can't run cycles simultaneously even if both observe
the signature at the same tick.

State is in-memory only — a process restart resets cycle history.
Matches the convention in :mod:`app.services.tor_watchdog`.

This module DOES NOT close the LND breaker itself. Only LND's own
``record_success()`` from a real call should close it. The
supervisor is read-only with respect to breaker state.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# Step labels. Used in audit event names + log lines; defined as a
# const block so a typo on the call site fails at import.
STEP_DETECT = 0
STEP_HSFETCH = 1
STEP_NEWNYM = 2
STEP_SIGHUP = 3
STEP_YIELDED = 4
STEP_EXHAUSTED = 5

_STEP_NAMES = {
    STEP_DETECT: "detect",
    STEP_HSFETCH: "hsfetch",
    STEP_NEWNYM: "newnym",
    STEP_SIGHUP: "sighup",
    STEP_YIELDED: "yielded",
    STEP_EXHAUSTED: "exhausted",
}

# Inhibit codes. One per false-positive guard.
INHIBIT_COLD_START = "i1_cold_start"
INHIBIT_NO_HSDIRS = "i2_no_hsdirs_reachable"
INHIBIT_COOLDOWN = "i3_cooldown_active"
INHIBIT_BROAD_OUTAGE = "i4_broad_tor_outage"
INHIBIT_RECENT_RESTART = "i5_recent_tor_restart"

# Self-supervision bounds (mirroring tor_watchdog).
_SUPERVISION_MAX_RESTARTS = 3
_SUPERVISION_RESTART_WINDOW_S = 300

# Heartbeat cadence. Hourly is enough to verify the supervisor is
# alive across operator-relevant time scales.
_HEARTBEAT_INTERVAL_S = 3600

# Tick interval between signature evaluations when no cycle is
# active. Tight enough to detect the signature within a few seconds
# of C1's 60 s wait elapsing.
_TICK_INTERVAL_S = 5.0

# After a NEWNYM/SIGHUP we give Tor some time to rebuild circuits
# before declaring the step "didn't clear". Roughly: how long until
# the next keepalive should succeed if the remediation worked.
_STEP_HSFETCH_GRACE_S = 60.0  # HSFETCH itself can take ~60s
_STEP_NEWNYM_GRACE_S = 90.0  # circuit rebuild + next keepalive
_STEP_SIGHUP_GRACE_S = 120.0  # guard selection + next keepalive
_STEP_YIELDED_GRACE_S = 180.0  # 3 healthchecks × 60s
_TRACK_PROCESS_START_TS = time.monotonic()


@dataclass
class SupervisorState:
    """In-process state. Persisted only in-memory (plan Q5).

    A worker restart resets this — same convention as
    :class:`app.services.tor_watchdog.WatchdogState`. The dashboard
    reads ``last_heartbeat_ts`` to verify liveness; recent cycles
    are also written to the audit log (which IS persistent) so the
    operator-visible history survives restarts even if this struct
    doesn't.
    """

    # Liveness
    last_tick_ts: float = 0.0
    last_heartbeat_ts: float = 0.0

    # Current incident (0 = no incident in progress)
    incident_start_ts: float = 0.0
    incident_correlation_id: str = ""
    current_step: int = STEP_DETECT
    current_step_started_ts: float = 0.0

    # Cycle history — list of completion timestamps in the rolling
    # 24 h window. Each entry is a ``time.monotonic()`` value.
    recent_cycle_completions: list[float] = field(default_factory=list)
    last_cycle_end_ts: float = 0.0
    cycles_disabled_until_ts: float = 0.0  # set when 4+ cycles in 24h

    # Monotonic counters (Prometheus surface). Reset only on process
    # restart, which is correct Prometheus-counter semantics.
    cycles_started_total: int = 0
    cycles_cleared_by_step: dict[int, int] = field(default_factory=dict)
    inhibits_total: dict[str, int] = field(default_factory=dict)
    step_outcomes: dict[str, int] = field(default_factory=dict)  # keys like "hsfetch_success", "newnym_failed"

    # Last cycle's step outcomes for the dashboard panel.
    last_cycle_steps: list[dict] = field(default_factory=list)

    # Self-supervision.
    supervisor_restarts: list[float] = field(default_factory=list)


_STATE = SupervisorState()
_CYCLE_LOCK = asyncio.Lock()


def get_state() -> SupervisorState:
    """Return the live supervisor state. Read-only intent — callers
    must not mutate. Used by the dashboard policy endpoint and the
    admin metrics endpoint."""
    return _STATE


def _now() -> float:
    return time.monotonic()


def _wall_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_correlation_id() -> str:
    """Short id usable for audit-event grouping. Not security-
    relevant; just needs to be unique per incident in audit log."""
    return f"lnd-tor-{int(time.time())}-{id(_STATE) & 0xFFFF:04x}"


async def _emit_audit(action: str, *, details: Optional[dict] = None) -> None:
    """Best-effort audit emission. Failure is logged but never
    propagated — the supervisor must never crash on audit issues.
    Mirrors :func:`app.services.tor_watchdog._emit_audit`.
    """
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
        logger.info("lnd tor supervisor: audit emit (%s) failed: %s", action, exc)


def _bump_inhibit(inhibit: str) -> None:
    _STATE.inhibits_total[inhibit] = _STATE.inhibits_total.get(inhibit, 0) + 1


def _bump_step_outcome(step: int, outcome: str) -> None:
    key = f"{_STEP_NAMES[step]}_{outcome}"
    _STATE.step_outcomes[key] = _STATE.step_outcomes.get(key, 0) + 1


def _bump_cleared_by_step(step: int) -> None:
    _STATE.cycles_cleared_by_step[step] = _STATE.cycles_cleared_by_step.get(step, 0) + 1


def _trim_cycle_history(now: Optional[float] = None) -> None:
    """Drop entries older than 24 h from the rolling window."""
    if now is None:
        now = _now()
    cutoff = now - 86400.0
    _STATE.recent_cycle_completions = [ts for ts in _STATE.recent_cycle_completions if ts >= cutoff]


def _cooldown_for_cycle_count(count: int) -> float:
    """Map number of recent cycles → minimum cooldown in seconds.

    Implements the rolling-window backoff schedule. Knobs at the call
    site are pulled from settings; this fn is the policy table.
    """
    from app.core.config import settings

    if count == 0:
        return 0.0
    if count == 1:
        return float(settings.lnd_tor_recovery_cooldown_15m_s)
    if count == 2:
        return float(settings.lnd_tor_recovery_cooldown_45m_s)
    if count == 3:
        return float(settings.lnd_tor_recovery_cooldown_2h_s)
    # 4+ — caller should have checked cycles_disabled_until_ts.
    return 86400.0


def _resolve_c3_probe_targets() -> list[str]:
    """Plan Q2 (recommended option c) — pick up to 2 onion URLs for
    the corroborating "other onion still works" probe.

    Order: explicit operator setting first, then mempool, electrum,
    bolt12-gateway, anonymize operator-registry (if available).
    Filters out empties and non-onion URLs. Returns at most 2 URLs.
    """
    from app.core.config import settings

    candidates: list[str] = []
    explicit = getattr(settings, "lnd_tor_recovery_other_onion_probe_url", None) or ""
    if explicit:
        candidates.append(explicit)
    for url in (
        getattr(settings, "lnd_mempool_url", None) or "",
        getattr(settings, "lnd_electrum_url", None) or "",
    ):
        if url and ".onion" in url:
            candidates.append(url)
    # Dedupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        out.append(c)
        if len(out) == 2:
            break
    return out


async def _probe_one_onion(url: str, timeout_s: float) -> bool:
    """Try to reach a single onion endpoint via the wallet's Tor
    proxy. Returns True on any TCP+TLS success (any HTTP status —
    even 4xx/5xx — counts because we're testing reachability, not
    correctness)."""
    import httpx

    from app.core.config import settings

    proxy = settings.lnd_tor_proxy or "socks5://tor-proxy:9050"
    # Normalize tcp:// (electrum) → use a low-level TCP probe; for
    # http(s):// just do a HEAD.
    try:
        if url.startswith("tcp://"):
            # Skip TCP probes here — they require a SOCKS-aware
            # asyncio socket. Mempool/HTTP onions are easier and
            # sufficient for the C3 corroboration.
            return False
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=timeout_s,
            verify=False,  # operator-supplied onion; not the auth surface
        ) as client:
            # HEAD is cheap; if not supported, GET on a small path.
            try:
                resp = await client.head(url)
            except httpx.HTTPError:
                # Fall back to GET on the same URL.
                resp = await client.get(url)
            # Any response = reachable. Even 404 means the circuit
            # built + the remote answered.
            return resp.status_code is not None
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "lnd tor supervisor: c3 probe to %s failed: %s",
            url,
            exc,
        )
        return False


async def _probe_other_onions() -> tuple[bool, list[str]]:
    """C3 check: probe up to 2 other onions, return (success, tested).

    Success = ≥1 of the tested URLs responded. If we have zero
    targets configured (clearnet-only deployment), we treat that as
    "can't tell" and return success=True so we don't refuse to
    remediate on a misconfigured-knob technicality. Operators who
    want strict behaviour can wire LND_TOR_RECOVERY_OTHER_ONION_PROBE_URL
    explicitly.
    """
    from app.core.config import settings

    targets = _resolve_c3_probe_targets()
    if not targets:
        logger.debug("lnd tor supervisor: c3 has no onion targets — assuming OK")
        return True, []

    timeout_s = float(settings.lnd_tor_recovery_other_onion_timeout_s)
    tested: list[str] = []
    for url in targets:
        ok = await _probe_one_onion(url, timeout_s=timeout_s)
        tested.append(url)
        if ok:
            return True, tested
    return False, tested


def _lnd_onion_hostname() -> Optional[str]:
    """Return the bare ``...onion`` hostname for LND's REST URL, or
    None if LND is on clearnet (in which case the supervisor has
    nothing to do)."""
    from app.core.config import settings
    from app.services.lnd_hs_descriptor_check import _extract_onion_hostname

    return _extract_onion_hostname(settings.lnd_rest_url or "")


async def _hsfetch_lnd_onion(timeout_s: float) -> tuple[bool, Optional[str]]:
    """Issue HSFETCH against LND's onion. Returns (ok, error).

    Wraps :func:`app.services.lnd_hs_descriptor_check.hsfetch_and_wait`
    (the public alias of the formerly underscore-private helper). The
    underscore-private name is still available for backward
    compatibility with existing tests in
    ``test_tor_startup_checks_and_descriptor.py``.
    """
    hostname = _lnd_onion_hostname()
    if not hostname:
        return False, "lnd_rest_url is not an onion address"
    from app.services.lnd_hs_descriptor_check import hsfetch_and_wait

    return await hsfetch_and_wait(hostname, timeout_s=timeout_s)


async def _detect_signature() -> tuple[bool, dict]:
    """Evaluate detection conditions C1–C4. Return (matched, diagnostics)."""
    from app.core.config import settings
    from app.services.lnd_service import _LND_BREAKER, _classify_tor_failure

    diag: dict = {}

    # C1: LND breaker open ≥ detect window.
    if _LND_BREAKER.state != "open" or _LND_BREAKER.opened_at is None:
        return False, {"c1": "breaker_not_open"}
    opened_age_s = (datetime.now(timezone.utc) - _LND_BREAKER.opened_at).total_seconds()
    diag["c1_opened_age_s"] = opened_age_s
    if opened_age_s < float(settings.lnd_tor_recovery_detect_window_s):
        return False, {**diag, "c1": "breaker_open_too_recently"}

    # C2: last_error is Tor-shaped.
    err = _LND_BREAKER.last_error or ""
    diag["c2_last_error"] = err[:200]
    if not _classify_tor_failure(err):
        return False, {**diag, "c2": "error_not_tor_shaped"}

    # C3: at least one other configured onion still responds.
    c3_ok, tested = await _probe_other_onions()
    diag["c3_tested"] = tested
    diag["c3_result"] = "ok" if c3_ok else "all_failed"
    if not c3_ok:
        # I4 is checked separately and emits the inhibit; here we
        # just refuse to detect.
        return False, {**diag, "c3": "broad_outage_suspected"}

    # C4: HSFETCH for the LND onion fails. (A success here means
    # Tor's publishing fine — the issue is downstream of us.)
    hsf_ok, hsf_err = await _hsfetch_lnd_onion(
        timeout_s=float(settings.lnd_tor_recovery_hsfetch_timeout_s),
    )
    diag["c4_hsfetch_ok"] = hsf_ok
    diag["c4_hsfetch_err"] = (hsf_err or "")[:200]
    if hsf_ok:
        return False, {**diag, "c4": "hsfetch_succeeded_downstream_issue"}

    return True, diag


async def _evaluate_inhibits() -> Optional[str]:
    """Return the FIRST matching inhibit name, or None.

    Checks the false-positive guards (inhibit codes) in order.
    """

    now = _now()

    # I1: process uptime < 5 min.
    uptime_s = now - _TRACK_PROCESS_START_TS
    if uptime_s < 300.0:
        return INHIBIT_COLD_START

    # I3: cooldown active from prior cycle.
    if _STATE.cycles_disabled_until_ts > now:
        return INHIBIT_COOLDOWN
    if _STATE.last_cycle_end_ts > 0:
        _trim_cycle_history(now)
        count = len(_STATE.recent_cycle_completions)
        cooldown = _cooldown_for_cycle_count(count)
        if (now - _STATE.last_cycle_end_ts) < cooldown:
            return INHIBIT_COOLDOWN

    # I2: control port not reachable. If we can't even reach the
    # control port, every step of the ladder fails structurally —
    # better to fail loud immediately than to walk all 4 steps
    # only to land at exhausted. Distinct from C4 (HSFETCH) which
    # tests the HS-DHT side; this tests our own control link.
    try:
        from app.services.anonymize.tor import is_tor_control_port_reachable

        reachable = await is_tor_control_port_reachable()
        if not reachable:
            return INHIBIT_NO_HSDIRS
    except Exception:  # noqa: BLE001
        # Helper crashed → don't block the cycle on the inhibit
        # check itself; the cycle's first step will fail loudly
        # via the audit log if the control port really is broken.
        pass

    # I5: recent tor-proxy restart. If Tor itself just started,
    # give it ~30 s to bootstrap circuits / fetch consensus before
    # we step in. The operator may have already done the right
    # fix (manual restart) and the supervisor's HSFETCH/NEWNYM
    # would be noise + risk doubling up the work.
    try:
        from app.services.anonymize.tor import get_tor_process_uptime_s

        tor_uptime, _err = await get_tor_process_uptime_s()
        if tor_uptime is not None and tor_uptime < 30.0:
            return INHIBIT_RECENT_RESTART
    except Exception:  # noqa: BLE001
        # Helper crashed (control-port issue) — let I2 above catch
        # it on the next tick. Don't block this tick on I5.
        pass

    # I4 is evaluated inside _detect_signature's C3 check — if both
    # other onions fail, _detect returns False with that reason and
    # we DON'T start a cycle. Bump the inhibit counter separately
    # in the caller so observability sees it.

    # I2 is best-evaluated in-line when HSFETCH is about to fire,
    # because "HSDirs reachable" is most meaningfully tested by the
    # control-port itself. We treat repeated HSFETCH 550s as I2
    # within _run_cycle.

    return None


# ─── Cycle runner ────────────────────────────────────────────────────


async def _wait_for_clear_or_timeout(grace_s: float) -> bool:
    """Wait up to ``grace_s`` for the LND breaker to close. Returns
    True if it closed, False on timeout. Polls every 2 s — cheaper
    than subscribing to breaker events for a feature that fires
    once per incident.
    """
    from app.services.lnd_service import _LND_BREAKER

    deadline = _now() + grace_s
    while _now() < deadline:
        if _LND_BREAKER.state == "closed":
            return True
        await asyncio.sleep(2.0)
    return _LND_BREAKER.state == "closed"


async def _step_hsfetch(corr_id: str) -> str:
    """Fire HSFETCH. Returns step-outcome string."""
    from app.core.config import settings

    timeout_s = float(settings.lnd_tor_recovery_hsfetch_timeout_s)
    ok, err = await _hsfetch_lnd_onion(timeout_s=timeout_s)
    outcome = "success" if ok else "failed"
    _bump_step_outcome(STEP_HSFETCH, outcome)
    await _emit_audit(
        f"tor_lnd_recovery_step_{STEP_HSFETCH}_outcome",
        details={
            "step": _STEP_NAMES[STEP_HSFETCH],
            "outcome": outcome,
            "error": (err or "")[:200],
            "correlation_id": corr_id,
        },
    )
    return outcome


async def _step_newnym(corr_id: str) -> str:
    """Fire NEWNYM. Returns step-outcome string."""
    from app.core.config import settings
    from app.services.anonymize.tor import signal_newnym

    ok, err = await signal_newnym(
        host=settings.anonymize_tor_control_host or "tor-proxy",
        port=int(settings.anonymize_tor_control_port),
        password=settings.resolved_tor_control_password,
        timeout_s=10.0,
    )
    outcome = "success" if ok else "failed"
    _bump_step_outcome(STEP_NEWNYM, outcome)
    await _emit_audit(
        f"tor_lnd_recovery_step_{STEP_NEWNYM}_outcome",
        details={
            "step": _STEP_NAMES[STEP_NEWNYM],
            "outcome": outcome,
            "error": (err or "")[:200],
            "correlation_id": corr_id,
        },
    )
    # NEWNYM is process-wide — let the anonymize cache invalidate.
    try:
        from app.services.tor_watchdog import (
            _invalidate_anonymize_exit_diversity_cache,
        )

        await _invalidate_anonymize_exit_diversity_cache()
    except Exception as exc:  # noqa: BLE001
        logger.info("lnd tor supervisor: cache invalidate hook failed: %s", exc)
    return outcome


async def _step_sighup(corr_id: str) -> str:
    """Fire SIGHUP. Returns step-outcome string."""
    from app.core.config import settings
    from app.services.anonymize.tor import signal_reload

    ok, err = await signal_reload(
        host=settings.anonymize_tor_control_host or "tor-proxy",
        port=int(settings.anonymize_tor_control_port),
        password=settings.resolved_tor_control_password,
        timeout_s=10.0,
    )
    outcome = "success" if ok else "failed"
    _bump_step_outcome(STEP_SIGHUP, outcome)
    await _emit_audit(
        f"tor_lnd_recovery_step_{STEP_SIGHUP}_outcome",
        details={
            "step": _STEP_NAMES[STEP_SIGHUP],
            "outcome": outcome,
            "error": (err or "")[:200],
            "correlation_id": corr_id,
        },
    )
    return outcome


async def _finish_cycle(cleared_at_step: Optional[int]) -> None:
    """Record cycle completion + reset incident state."""
    now = _now()
    _STATE.recent_cycle_completions.append(now)
    _trim_cycle_history(now)
    _STATE.last_cycle_end_ts = now
    # 4+ cycles in 24h → disable for the rest of the window.
    from app.core.config import settings

    cycle_cap = int(settings.lnd_tor_recovery_max_cycles_per_day)
    cap_hit = len(_STATE.recent_cycle_completions) >= cycle_cap
    if cap_hit:
        # Disable until the OLDEST cycle ages out (so cooldown
        # auto-clears as the rolling window slides).
        oldest = _STATE.recent_cycle_completions[0]
        _STATE.cycles_disabled_until_ts = oldest + 86400.0
        # Distinct audit event for the disabled-by-cap case so
        # operators can tell apart "we're in 15-min cooldown after
        # a successful cycle" from "we hit the rolling-24h cap and
        # auto-recovery is now off until the window slides". The
        # generic cooldown inhibit (i3) would mask the latter.
        # This is a required audit event for the cycle-cap transition.
        await _emit_audit(
            "tor_lnd_recovery_disabled_cycle_cap",
            details={
                "cycles_in_window": len(_STATE.recent_cycle_completions),
                "max_per_day": cycle_cap,
                "disabled_for_s": (_STATE.cycles_disabled_until_ts - now),
            },
        )
    if cleared_at_step is not None:
        _bump_cleared_by_step(cleared_at_step)
    _STATE.incident_start_ts = 0.0
    _STATE.incident_correlation_id = ""
    _STATE.current_step = STEP_DETECT
    _STATE.current_step_started_ts = 0.0


async def _run_cycle(diag: dict) -> None:
    """Execute the escalation ladder.

    Acquires :data:`_CYCLE_LOCK` for the duration. The lock prevents
    a second `_detect_signature` match (in another tick / coroutine)
    from spawning a parallel cycle. Releases on completion or
    exception.
    """
    if _CYCLE_LOCK.locked():
        # Another cycle is in progress; the supervisor's tick loop
        # should not have reached here. Defensive log + skip.
        logger.debug("lnd tor supervisor: cycle already in progress; skipping")
        return

    async with _CYCLE_LOCK:
        corr_id = _gen_correlation_id()
        _STATE.incident_correlation_id = corr_id
        _STATE.incident_start_ts = _now()
        _STATE.cycles_started_total += 1
        _STATE.last_cycle_steps = []
        await _emit_audit(
            "tor_lnd_recovery_armed",
            details={
                "correlation_id": corr_id,
                "diagnostics": diag,
            },
        )
        logger.info("lnd tor supervisor: cycle armed (id=%s)", corr_id)

        # Step 1: HSFETCH
        _STATE.current_step = STEP_HSFETCH
        _STATE.current_step_started_ts = _now()
        await _emit_audit(
            f"tor_lnd_recovery_step_{STEP_HSFETCH}_started",
            details={"correlation_id": corr_id},
        )
        await _step_hsfetch(corr_id)
        cleared = await _wait_for_clear_or_timeout(_STEP_HSFETCH_GRACE_S)
        _STATE.last_cycle_steps.append({"step": _STEP_NAMES[STEP_HSFETCH], "cleared": cleared, "ts": _now()})
        if cleared:
            await _emit_audit(
                "tor_lnd_recovery_cleared",
                details={
                    "correlation_id": corr_id,
                    "cleared_at_step": _STEP_NAMES[STEP_HSFETCH],
                },
            )
            logger.info(
                "lnd tor supervisor: cleared at step %s (id=%s)",
                _STEP_NAMES[STEP_HSFETCH],
                corr_id,
            )
            await _finish_cycle(cleared_at_step=STEP_HSFETCH)
            return

        # Step 2: NEWNYM
        _STATE.current_step = STEP_NEWNYM
        _STATE.current_step_started_ts = _now()
        await _emit_audit(
            f"tor_lnd_recovery_step_{STEP_NEWNYM}_started",
            details={"correlation_id": corr_id},
        )
        await _step_newnym(corr_id)
        cleared = await _wait_for_clear_or_timeout(_STEP_NEWNYM_GRACE_S)
        _STATE.last_cycle_steps.append({"step": _STEP_NAMES[STEP_NEWNYM], "cleared": cleared, "ts": _now()})
        if cleared:
            await _emit_audit(
                "tor_lnd_recovery_cleared",
                details={
                    "correlation_id": corr_id,
                    "cleared_at_step": _STEP_NAMES[STEP_NEWNYM],
                },
            )
            logger.info(
                "lnd tor supervisor: cleared at step %s (id=%s)",
                _STEP_NAMES[STEP_NEWNYM],
                corr_id,
            )
            await _finish_cycle(cleared_at_step=STEP_NEWNYM)
            return

        # Step 3: SIGHUP
        _STATE.current_step = STEP_SIGHUP
        _STATE.current_step_started_ts = _now()
        await _emit_audit(
            f"tor_lnd_recovery_step_{STEP_SIGHUP}_started",
            details={"correlation_id": corr_id},
        )
        await _step_sighup(corr_id)
        cleared = await _wait_for_clear_or_timeout(_STEP_SIGHUP_GRACE_S)
        _STATE.last_cycle_steps.append({"step": _STEP_NAMES[STEP_SIGHUP], "cleared": cleared, "ts": _now()})
        if cleared:
            await _emit_audit(
                "tor_lnd_recovery_cleared",
                details={
                    "correlation_id": corr_id,
                    "cleared_at_step": _STEP_NAMES[STEP_SIGHUP],
                },
            )
            logger.info(
                "lnd tor supervisor: cleared at step %s (id=%s)",
                _STEP_NAMES[STEP_SIGHUP],
                corr_id,
            )
            await _finish_cycle(cleared_at_step=STEP_SIGHUP)
            return

        # Step 4: yield to Docker healthcheck.
        _STATE.current_step = STEP_YIELDED
        _STATE.current_step_started_ts = _now()
        await _emit_audit(
            "tor_lnd_recovery_yielded_to_healthcheck",
            details={"correlation_id": corr_id},
        )
        logger.warning(
            "lnd tor supervisor: yielding to healthcheck (id=%s) — "
            "no fix from HSFETCH/NEWNYM/SIGHUP; container restart "
            "may follow if breaker stays open",
            corr_id,
        )
        cleared = await _wait_for_clear_or_timeout(_STEP_YIELDED_GRACE_S)
        _STATE.last_cycle_steps.append({"step": _STEP_NAMES[STEP_YIELDED], "cleared": cleared, "ts": _now()})
        if cleared:
            await _emit_audit(
                "tor_lnd_recovery_cleared",
                details={
                    "correlation_id": corr_id,
                    "cleared_at_step": _STEP_NAMES[STEP_YIELDED],
                },
            )
            await _finish_cycle(cleared_at_step=STEP_YIELDED)
            return

        # Step 5: exhausted. Operator runbook.
        _STATE.current_step = STEP_EXHAUSTED
        _STATE.current_step_started_ts = _now()
        await _emit_audit(
            "tor_lnd_recovery_exhausted",
            details={"correlation_id": corr_id},
        )
        logger.error(
            "lnd tor supervisor: recovery EXHAUSTED (id=%s) — "
            "operator action required. Auto-recovery yielded to "
            "healthcheck did not clear the breaker. Issue is most "
            "likely outside this wallet (e.g. LND's host-side Tor "
            "controller).",
            corr_id,
        )
        await _finish_cycle(cleared_at_step=None)


# ─── Tick + main loop ────────────────────────────────────────────────


async def _maybe_emit_heartbeat() -> None:
    now = _now()
    if now - _STATE.last_heartbeat_ts < _HEARTBEAT_INTERVAL_S:
        return
    _STATE.last_heartbeat_ts = now
    await _emit_audit(
        "tor_lnd_recovery_heartbeat",
        details={
            "cycles_started_total": _STATE.cycles_started_total,
            "cycles_in_last_24h": len(_STATE.recent_cycle_completions),
        },
    )


async def _supervisor_tick() -> None:
    """One tick of the supervisor loop. Cheap if no incident — most
    of the time this does an O(1) check on the LND breaker and
    returns."""
    from app.core.config import settings

    _STATE.last_tick_ts = _now()
    await _maybe_emit_heartbeat()

    if not settings.lnd_tor_recovery_enabled:
        return

    # Fast path: breaker closed → nothing to do.
    from app.services.lnd_service import _LND_BREAKER

    if _LND_BREAKER.state == "closed":
        return

    # A cycle is already in progress — let it run. Don't interleave
    # detection while inside `_run_cycle`.
    if _CYCLE_LOCK.locked():
        return

    # Cheap inhibit checks before the more expensive signature probes.
    inhibit = await _evaluate_inhibits()
    if inhibit is not None:
        _bump_inhibit(inhibit)
        await _emit_audit(
            f"tor_lnd_recovery_inhibited_{inhibit}",
            details={"breaker_state": _LND_BREAKER.state},
        )
        return

    # Evaluate signature. This may HSFETCH + onion-probe, so it's
    # not free — but we only get here if the breaker is open AND
    # no inhibits matched.
    matched, diag = await _detect_signature()
    if not matched:
        # Distinguish I4 (broad outage) for separate accounting.
        if diag.get("c3") == "broad_outage_suspected":
            _bump_inhibit(INHIBIT_BROAD_OUTAGE)
            await _emit_audit(
                f"tor_lnd_recovery_inhibited_{INHIBIT_BROAD_OUTAGE}",
                details={"tested": diag.get("c3_tested", [])},
            )
        return

    await _run_cycle(diag)


async def _supervisor_loop(stop_event: asyncio.Event) -> None:
    """Tick the supervisor until ``stop_event`` is set."""
    logger.info("lnd tor supervisor: starting")
    while not stop_event.is_set():
        try:
            await _supervisor_tick()
        except Exception as exc:  # noqa: BLE001
            # The tick should never raise on the happy path — its
            # internal helpers swallow audit failures and probe
            # exceptions. If it does raise, the outer supervisor
            # restarts the loop up to 3 times (see start_supervisor).
            logger.exception("lnd tor supervisor: tick crashed: %s", exc)
            raise
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=_TICK_INTERVAL_S,
            )
            break  # stop_event fired
        except asyncio.TimeoutError:
            continue
    logger.info("lnd tor supervisor: stopped")


async def run_lnd_tor_supervisor(stop_event: asyncio.Event) -> None:
    """Supervised entrypoint. Restarts the loop up to
    :data:`_SUPERVISION_MAX_RESTARTS` times within
    :data:`_SUPERVISION_RESTART_WINDOW_S` if it crashes. Beyond
    that, emit a hard alarm and stay stopped — operator action
    required.

    Mirrors :func:`app.services.tor_watchdog.start_watchdog`.
    """
    while not stop_event.is_set():
        try:
            await _supervisor_loop(stop_event)
            # Clean exit (stop_event fired).
            return
        except Exception as exc:  # noqa: BLE001
            logger.exception("lnd tor supervisor: loop crashed: %s", exc)
            now = _now()
            _STATE.supervisor_restarts = [
                ts for ts in _STATE.supervisor_restarts if now - ts < _SUPERVISION_RESTART_WINDOW_S
            ]
            _STATE.supervisor_restarts.append(now)
            if len(_STATE.supervisor_restarts) > _SUPERVISION_MAX_RESTARTS:
                await _emit_audit(
                    "tor_lnd_recovery_supervision_exhausted",
                    details={
                        "restarts": len(_STATE.supervisor_restarts),
                        "window_s": _SUPERVISION_RESTART_WINDOW_S,
                    },
                )
                logger.error("lnd tor supervisor: supervision exhausted, staying stopped")
                return
            await _emit_audit(
                "tor_lnd_recovery_restarting",
                details={"crash": str(exc)[:300]},
            )
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                continue


__all__ = [
    "SupervisorState",
    "get_state",
    "run_lnd_tor_supervisor",
    "STEP_DETECT",
    "STEP_HSFETCH",
    "STEP_NEWNYM",
    "STEP_SIGHUP",
    "STEP_YIELDED",
    "STEP_EXHAUSTED",
    "INHIBIT_COLD_START",
    "INHIBIT_NO_HSDIRS",
    "INHIBIT_COOLDOWN",
    "INHIBIT_BROAD_OUTAGE",
    "INHIBIT_RECENT_RESTART",
]
