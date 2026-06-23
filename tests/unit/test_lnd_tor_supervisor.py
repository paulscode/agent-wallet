# SPDX-License-Identifier: MIT
"""LND Tor supervisor unit tests.

These tests drive the supervisor's signature detection, inhibits,
escalation ladder, and backoff policy with fakes — no real Tor, no
real LND, no real network.

Fakes used:
  - The actual ``_LND_BREAKER`` (a :class:`CircuitBreaker`) is
    manipulated directly via ``record_failure`` / ``record_success``.
    Faster than wrapping a parallel fake — the breaker is the
    source of truth.
  - ``hsfetch_and_wait`` is monkeypatched to return canned outcomes.
  - ``signal_newnym`` / ``signal_reload`` likewise.
  - ``_probe_one_onion`` is monkeypatched so we don't open real
    SOCKS connections.
  - ``_wait_for_clear_or_timeout`` is monkeypatched so we don't
    sleep for the real grace periods (60-180 s).

The fixture below resets supervisor module state + the LND breaker
between tests so a test ordering bug doesn't silently pass.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.services import lnd_tor_supervisor as sup
from app.services.lnd_service import (
    _LND_BREAKER,
    _TOR_BREAKER,
    _TOR_LND_BREAKER,
)

# ── fixture: reset state between tests ────────────────────────────


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch) -> None:
    """Each test starts with a fresh supervisor state + closed
    breakers. Critically also resets ``_TRACK_PROCESS_START_TS`` so
    I1 (cold start inhibit) doesn't false-fire on every test in a
    fast CI run.

    Also auto-mocks the I2 / I5 control-port helpers to return
    "all clear" by default — tests that specifically exercise
    those inhibits override the mocks.
    """
    fresh = sup.SupervisorState()
    for k, v in fresh.__dict__.items():
        setattr(sup._STATE, k, v)

    # Pretend the process has been up a long time so I1 doesn't
    # constantly inhibit. Individual I1 tests override this.
    monkeypatch.setattr(sup, "_TRACK_PROCESS_START_TS", time.monotonic() - 86400)

    for b in (_LND_BREAKER, _TOR_BREAKER, _TOR_LND_BREAKER):
        while b.state != "closed":
            b.record_success()

    # I2 + I5 default: control port reachable + Tor up for a long
    # time. Tests that hit the inhibits explicitly override these.
    monkeypatch.setattr(
        "app.services.anonymize.tor.is_tor_control_port_reachable",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "app.services.anonymize.tor.get_tor_process_uptime_s",
        AsyncMock(return_value=(3600.0, None)),
    )


def _patch_backoff_timeout(monkeypatch) -> None:
    """Make the supervisor's inter-restart backoff
    ``asyncio.wait_for(stop_event.wait(), timeout=...)`` resolve as an
    immediate TimeoutError so the restart loop never sleeps the real
    5 s. Closes the wrapped coroutine first so no
    'coroutine was never awaited' warning fires (filterwarnings=error).
    """

    async def _instant_timeout(coro, timeout=None):
        if asyncio.iscoroutine(coro):
            coro.close()
        raise asyncio.TimeoutError

    monkeypatch.setattr(sup.asyncio, "wait_for", _instant_timeout)


def _force_breaker_open(err: str, opened_seconds_ago: float = 120.0) -> None:
    """Force ``_LND_BREAKER`` open with a specific error and a
    backdated ``opened_at`` so C1's detect_window passes."""
    # Push it open.
    for _ in range(_LND_BREAKER.failure_threshold):
        _LND_BREAKER.record_failure(err)
    assert _LND_BREAKER.state == "open", "test setup: breaker must be open"
    # Backdate so C1 sees a sustained incident.
    _LND_BREAKER.opened_at = datetime.now(timezone.utc) - timedelta(seconds=opened_seconds_ago)
    _LND_BREAKER.last_error = err


# ─── signature detection ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_c1_breaker_closed_no_arm(monkeypatch) -> None:
    """C1 false: breaker closed → signature does not match."""
    matched, diag = await sup._detect_signature()
    assert matched is False
    assert diag.get("c1") == "breaker_not_open"


@pytest.mark.asyncio
async def test_c1_breaker_open_too_recently_no_arm(monkeypatch) -> None:
    """C1 false: breaker open but only 30 s, detect window is 60 s."""
    _force_breaker_open("ProxyError", opened_seconds_ago=30.0)
    matched, diag = await sup._detect_signature()
    assert matched is False
    assert diag.get("c1") == "breaker_open_too_recently"


@pytest.mark.asyncio
async def test_c2_lnd_5xx_not_tor_shaped(monkeypatch) -> None:
    """C2 false: breaker open with LND-side error → signature does
    NOT match (don't run Tor recovery on an LND-side fault)."""
    _force_breaker_open("HTTPStatusError: 502 Bad Gateway")
    matched, diag = await sup._detect_signature()
    assert matched is False
    assert diag.get("c2") == "error_not_tor_shaped"


@pytest.mark.asyncio
async def test_c3_broad_outage_no_arm(monkeypatch) -> None:
    """C3 false: both other onions fail too → broad outage. Signature
    must NOT match — NEWNYM/HSFETCH won't help against a broad
    outage."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    # All probe targets fail.
    monkeypatch.setattr(
        sup,
        "_probe_one_onion",
        AsyncMock(return_value=False),
    )
    monkeypatch.setattr(
        sup,
        "_resolve_c3_probe_targets",
        lambda: ["http://example.onion", "http://other.onion"],
    )
    matched, diag = await sup._detect_signature()
    assert matched is False
    assert diag.get("c3") == "broad_outage_suspected"


@pytest.mark.asyncio
async def test_c4_hsfetch_received_no_arm(monkeypatch) -> None:
    """C4 false: HSFETCH returns RECEIVED → Tor publishing fine.
    The issue is downstream of our cache. Don't try to remediate
    something the supervisor can't fix."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr(sup, "_probe_one_onion", AsyncMock(return_value=True))
    monkeypatch.setattr(
        sup,
        "_resolve_c3_probe_targets",
        lambda: ["http://example.onion"],
    )
    # Force the LND onion hostname so _hsfetch_lnd_onion doesn't
    # short-circuit on "no onion configured" before reaching the
    # monkey-patched hsfetch_and_wait.
    monkeypatch.setattr(
        sup,
        "_lnd_onion_hostname",
        lambda: "examplelndaddress12345.onion",
    )
    # HSFETCH succeeds.
    monkeypatch.setattr(
        "app.services.lnd_hs_descriptor_check.hsfetch_and_wait",
        AsyncMock(return_value=(True, None)),
    )
    matched, diag = await sup._detect_signature()
    assert matched is False
    assert diag.get("c4") == "hsfetch_succeeded_downstream_issue"


@pytest.mark.asyncio
async def test_all_conditions_true_arms(monkeypatch) -> None:
    """Happy path: C1..C4 all true → signature matches."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr(sup, "_probe_one_onion", AsyncMock(return_value=True))
    monkeypatch.setattr(
        sup,
        "_resolve_c3_probe_targets",
        lambda: ["http://example.onion"],
    )
    monkeypatch.setattr(
        "app.services.lnd_hs_descriptor_check.hsfetch_and_wait",
        AsyncMock(return_value=(False, "no HSDir served")),
    )
    # Force the LND onion hostname so the helper finds something.
    monkeypatch.setattr(
        sup,
        "_lnd_onion_hostname",
        lambda: "examplelndaddress12345.onion",
    )
    matched, diag = await sup._detect_signature()
    assert matched is True
    assert "c2_last_error" in diag
    assert diag["c4_hsfetch_ok"] is False


# ─── inhibits ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_i1_cold_start_inhibits(monkeypatch) -> None:
    """I1: process uptime < 5 min → inhibit."""
    # Pretend process just started.
    monkeypatch.setattr(sup, "_TRACK_PROCESS_START_TS", time.monotonic() - 60.0)
    inhibit = await sup._evaluate_inhibits()
    assert inhibit == sup.INHIBIT_COLD_START


@pytest.mark.asyncio
async def test_i3_cooldown_after_recent_cycle(monkeypatch) -> None:
    """I3: cooldown active when a cycle ended within the cycle 1→2
    cooldown window."""
    now = time.monotonic()
    sup._STATE.last_cycle_end_ts = now - 60.0  # 1 min ago
    sup._STATE.recent_cycle_completions = [now - 60.0]
    inhibit = await sup._evaluate_inhibits()
    assert inhibit == sup.INHIBIT_COOLDOWN


@pytest.mark.asyncio
async def test_i3_no_cooldown_after_window_expires(monkeypatch) -> None:
    """I3 clears once enough time passes since the last cycle."""
    now = time.monotonic()
    # Last cycle ended LONGER ago than the 15-min cooldown.
    sup._STATE.last_cycle_end_ts = now - 1100.0  # ~18 min
    sup._STATE.recent_cycle_completions = [now - 1100.0]
    inhibit = await sup._evaluate_inhibits()
    assert inhibit is None


@pytest.mark.asyncio
async def test_i2_control_port_unreachable(monkeypatch) -> None:
    """I2: control-port unreachable → don't try any remediation
    step (they all go through the same control port). Failing
    loud is better than walking the ladder to exhausted."""
    monkeypatch.setattr(
        "app.services.anonymize.tor.is_tor_control_port_reachable",
        AsyncMock(return_value=False),
    )
    # Force the other guards' state into "would normally proceed":
    # uptime past cold-start, no recent tor-proxy restart.
    monkeypatch.setattr(
        "app.services.anonymize.tor.get_tor_process_uptime_s",
        AsyncMock(return_value=(3600.0, None)),
    )
    inhibit = await sup._evaluate_inhibits()
    assert inhibit == sup.INHIBIT_NO_HSDIRS, f"expected I2 inhibit when control port unreachable; got {inhibit!r}"


@pytest.mark.asyncio
async def test_i2_does_not_block_when_helper_crashes(monkeypatch) -> None:
    """If the reachability probe itself throws (transient TCP
    issue, control-port helper crashed), the supervisor must NOT
    block the cycle on the inhibit check itself — let the actual
    cycle's first step fail loudly via the audit log. Permissive
    handling here mirrors I5's same-shape guard."""

    async def _raise(*args, **kwargs):
        raise RuntimeError("synthetic crash in probe")

    monkeypatch.setattr(
        "app.services.anonymize.tor.is_tor_control_port_reachable",
        _raise,
    )
    monkeypatch.setattr(
        "app.services.anonymize.tor.get_tor_process_uptime_s",
        AsyncMock(return_value=(3600.0, None)),
    )
    inhibit = await sup._evaluate_inhibits()
    # Should NOT be I2 (helper crash isn't itself evidence of
    # unreachability); should fall through to None or another guard.
    assert inhibit != sup.INHIBIT_NO_HSDIRS, (
        "I2 must not fire on helper crash; let the cycle's first step fail loudly instead."
    )


@pytest.mark.asyncio
async def test_i5_recent_tor_restart(monkeypatch) -> None:
    """I5: Tor process uptime < 30 s → inhibit. The operator may
    have just restarted tor-proxy as the manual fix; let it
    settle before we add NEWNYM/HSFETCH noise on top."""
    monkeypatch.setattr(
        "app.services.anonymize.tor.is_tor_control_port_reachable",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "app.services.anonymize.tor.get_tor_process_uptime_s",
        AsyncMock(return_value=(15.0, None)),  # Tor restarted 15 s ago
    )
    inhibit = await sup._evaluate_inhibits()
    assert inhibit == sup.INHIBIT_RECENT_RESTART, f"expected I5 inhibit on fresh tor restart; got {inhibit!r}"


@pytest.mark.asyncio
async def test_i5_not_fired_for_established_tor(monkeypatch) -> None:
    """I5 only fires within the 30 s window after Tor (re)starts.
    After that, normal recovery proceeds."""
    monkeypatch.setattr(
        "app.services.anonymize.tor.is_tor_control_port_reachable",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "app.services.anonymize.tor.get_tor_process_uptime_s",
        AsyncMock(return_value=(3600.0, None)),  # 1 hour up
    )
    inhibit = await sup._evaluate_inhibits()
    # Allow None (all guards pass) but explicitly NOT I5.
    assert inhibit != sup.INHIBIT_RECENT_RESTART


@pytest.mark.asyncio
async def test_i3_disabled_after_4_cycles(monkeypatch) -> None:
    """4+ cycles in 24h disables the supervisor for the remainder
    of the window. ``_finish_cycle`` sets ``cycles_disabled_until_ts``
    when the cycle cap is reached."""
    now = time.monotonic()
    # 4 cycles all "just happened".
    sup._STATE.recent_cycle_completions = [now - 100, now - 80, now - 60, now - 40]
    sup._STATE.cycles_disabled_until_ts = now + 3600.0  # 1h from now
    inhibit = await sup._evaluate_inhibits()
    assert inhibit == sup.INHIBIT_COOLDOWN


# ─── escalation ladder ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cycle_clears_at_step_1_hsfetch(monkeypatch) -> None:
    """HSFETCH succeeds → breaker closes → cycle records clear at
    step 1 and stops escalating."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr(
        sup,
        "_step_hsfetch",
        AsyncMock(return_value="success"),
    )
    # The breaker "closes" after HSFETCH.
    monkeypatch.setattr(
        sup,
        "_wait_for_clear_or_timeout",
        AsyncMock(return_value=True),
    )
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)

    await sup._run_cycle({"reason": "test"})

    assert "tor_lnd_recovery_armed" in audits
    assert any(a == "tor_lnd_recovery_cleared" for a in audits), f"missing cleared audit. Got: {audits}"
    assert sup._STATE.cycles_cleared_by_step.get(sup.STEP_HSFETCH) == 1
    assert sup._STATE.incident_start_ts == 0.0  # cycle reset


@pytest.mark.asyncio
async def test_cycle_escalates_through_to_exhausted(monkeypatch) -> None:
    """Nothing clears → cycle walks all the way to step 5 (exhausted)."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr(sup, "_step_hsfetch", AsyncMock(return_value="failed"))
    monkeypatch.setattr(sup, "_step_newnym", AsyncMock(return_value="success"))
    monkeypatch.setattr(sup, "_step_sighup", AsyncMock(return_value="success"))
    # Breaker never closes — all wait calls return False.
    monkeypatch.setattr(
        sup,
        "_wait_for_clear_or_timeout",
        AsyncMock(return_value=False),
    )
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)

    await sup._run_cycle({"reason": "test"})

    # All 4 escalation tiers must have fired.
    assert sup._step_hsfetch.await_count == 1
    assert sup._step_newnym.await_count == 1
    assert sup._step_sighup.await_count == 1
    assert "tor_lnd_recovery_yielded_to_healthcheck" in audits
    assert "tor_lnd_recovery_exhausted" in audits
    # No "cleared" audit when exhausted.
    assert "tor_lnd_recovery_cleared" not in audits


@pytest.mark.asyncio
async def test_cycle_clears_at_step_2_newnym(monkeypatch) -> None:
    """HSFETCH didn't clear, NEWNYM did → step 2 clear."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr(sup, "_step_hsfetch", AsyncMock(return_value="failed"))
    monkeypatch.setattr(sup, "_step_newnym", AsyncMock(return_value="success"))
    # First wait (step 1 grace) returns False; second (step 2 grace) True.
    wait_results = [False, True]

    async def _wait(*args, **kwargs):
        return wait_results.pop(0)

    monkeypatch.setattr(sup, "_wait_for_clear_or_timeout", _wait)
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)

    await sup._run_cycle({"reason": "test"})

    assert sup._STATE.cycles_cleared_by_step.get(sup.STEP_NEWNYM) == 1
    # Step 3 (sighup) must not have been reached.
    assert "tor_lnd_recovery_yielded_to_healthcheck" not in audits


@pytest.mark.asyncio
async def test_cycle_clears_at_step_3_sighup(monkeypatch) -> None:
    """Steps 1 + 2 don't clear; step 3 (SIGHUP) does. SIGHUP is the
    ladder's full guard + circuit flush, for cases where HSFETCH
    didn't refresh the right descriptor AND NEWNYM didn't get fresh
    circuits routed through a working entry guard."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr(sup, "_step_hsfetch", AsyncMock(return_value="failed"))
    monkeypatch.setattr(sup, "_step_newnym", AsyncMock(return_value="success"))
    monkeypatch.setattr(sup, "_step_sighup", AsyncMock(return_value="success"))
    # Step 1, 2 grace returns False (didn't clear); step 3 returns True.
    wait_results = [False, False, True]

    async def _wait(*args, **kwargs):
        return wait_results.pop(0)

    monkeypatch.setattr(sup, "_wait_for_clear_or_timeout", _wait)
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)

    await sup._run_cycle({"reason": "test"})

    assert sup._step_hsfetch.await_count == 1
    assert sup._step_newnym.await_count == 1
    assert sup._step_sighup.await_count == 1, "step 3 SIGHUP should have fired when steps 1 + 2 didn't clear"
    assert sup._STATE.cycles_cleared_by_step.get(sup.STEP_SIGHUP) == 1, (
        "cleared_by_step counter should record SIGHUP as the clearing step"
    )
    # Step 4 (yield) and step 5 (exhausted) must not have been reached.
    assert "tor_lnd_recovery_yielded_to_healthcheck" not in audits
    assert "tor_lnd_recovery_exhausted" not in audits


# ─── backoff + cycle cap ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_first_cycle_no_cooldown(monkeypatch) -> None:
    """First cycle has zero cooldown — next signature match can
    fire immediately."""
    assert sup._cooldown_for_cycle_count(0) == 0.0


@pytest.mark.asyncio
async def test_cooldown_increases_with_cycles(monkeypatch) -> None:
    """Cooldown schedule is monotonic: 15m → 45m → 2h."""
    c1 = sup._cooldown_for_cycle_count(1)
    c2 = sup._cooldown_for_cycle_count(2)
    c3 = sup._cooldown_for_cycle_count(3)
    assert c1 < c2 < c3
    # And the defaults match the documented 15m / 45m / 2h cooldowns.
    assert c1 == 900.0
    assert c2 == 2700.0
    assert c3 == 7200.0


@pytest.mark.asyncio
async def test_finish_cycle_at_cap_disables_window(monkeypatch) -> None:
    """When the cycle cap is hit, ``cycles_disabled_until_ts`` is
    set to the oldest-cycle's age-out time AND a distinct
    ``tor_lnd_recovery_disabled_cycle_cap`` audit fires (the
    dedicated event lets operators tell apart "in
    normal cooldown after a clean cycle" from "hit the rolling-24h
    cap and auto-recovery is now off")."""
    now = time.monotonic()
    # Pre-load history with cap-1 cycles.
    sup._STATE.recent_cycle_completions = [
        now - 100.0,
        now - 50.0,
        now - 25.0,
    ]
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)
    # Finishing one more lands us at the cap (default 4).
    await sup._finish_cycle(cleared_at_step=sup.STEP_HSFETCH)
    assert sup._STATE.cycles_disabled_until_ts > now, "expected cycles_disabled_until_ts to be set when cap hit"
    assert "tor_lnd_recovery_disabled_cycle_cap" in audits, f"expected the distinct disabled-cap audit; got: {audits}"


@pytest.mark.asyncio
async def test_cycle_history_trims_old_entries(monkeypatch) -> None:
    """Cycle completions older than 24 h are dropped from the
    rolling window."""
    now = time.monotonic()
    sup._STATE.recent_cycle_completions = [
        now - 100000.0,  # ~27h ago — should be dropped
        now - 100.0,  # recent — keep
    ]
    sup._trim_cycle_history(now=now)
    assert len(sup._STATE.recent_cycle_completions) == 1
    assert sup._STATE.recent_cycle_completions[0] == now - 100.0


# ─── concurrency ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_signature_match_serialized(monkeypatch) -> None:
    """If two coroutines call ``_run_cycle`` simultaneously, only
    one cycle should actually run. The other should see the lock
    held and return immediately."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    hsfetch_calls = []

    async def _slow_hsfetch(*args, **kwargs):
        hsfetch_calls.append(args)
        await asyncio.sleep(0.05)
        return "success"

    monkeypatch.setattr(sup, "_step_hsfetch", _slow_hsfetch)
    monkeypatch.setattr(
        sup,
        "_wait_for_clear_or_timeout",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())

    # Fire two concurrent cycles.
    await asyncio.gather(
        sup._run_cycle({"first": True}),
        sup._run_cycle({"second": True}),
    )

    # Only ONE cycle should have executed step 1.
    assert len(hsfetch_calls) == 1, f"expected serialized execution; got {len(hsfetch_calls)} hsfetch calls"


# ─── state initialization sanity ────────────────────────────────────


def test_module_state_starts_clean() -> None:
    """Fresh process: counters all zero, no incident in flight."""
    # The fixture has reset state already.
    assert sup._STATE.incident_start_ts == 0.0
    assert sup._STATE.cycles_started_total == 0
    assert sup._STATE.recent_cycle_completions == []
    assert sup._STATE.current_step == sup.STEP_DETECT


def test_step_names_complete() -> None:
    """All step constants have a human-readable name in
    ``_STEP_NAMES``. A missing one would break audit-event names."""
    for step_const in (
        sup.STEP_DETECT,
        sup.STEP_HSFETCH,
        sup.STEP_NEWNYM,
        sup.STEP_SIGHUP,
        sup.STEP_YIELDED,
        sup.STEP_EXHAUSTED,
    ):
        assert step_const in sup._STEP_NAMES, f"missing name for step {step_const}"


# ─── step helpers: outcome + counter bookkeeping ─────────────────────


@pytest.mark.asyncio
async def test_step_hsfetch_records_success_outcome(monkeypatch) -> None:
    """A successful HSFETCH returns 'success' and bumps the
    ``hsfetch_success`` step-outcome counter."""
    monkeypatch.setattr(
        sup,
        "_hsfetch_lnd_onion",
        AsyncMock(return_value=(True, None)),
    )
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())
    outcome = await sup._step_hsfetch("corr-1")
    assert outcome == "success"
    assert sup._STATE.step_outcomes.get("hsfetch_success") == 1


@pytest.mark.asyncio
async def test_step_hsfetch_records_failed_outcome(monkeypatch) -> None:
    """A failed HSFETCH returns 'failed' and bumps the
    ``hsfetch_failed`` counter — the negative branch the escalation
    ladder depends on to keep climbing."""
    monkeypatch.setattr(
        sup,
        "_hsfetch_lnd_onion",
        AsyncMock(return_value=(False, "no HSDir served")),
    )
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())
    outcome = await sup._step_hsfetch("corr-1")
    assert outcome == "failed"
    assert sup._STATE.step_outcomes.get("hsfetch_failed") == 1


@pytest.mark.asyncio
async def test_step_newnym_success_invalidates_cache(monkeypatch) -> None:
    """NEWNYM success records the outcome AND invokes the anonymize
    exit-diversity cache invalidation hook (NEWNYM is process-wide so
    the cached exit set must be dropped)."""
    monkeypatch.setattr(
        "app.services.anonymize.tor.signal_newnym",
        AsyncMock(return_value=(True, None)),
    )
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())
    invalidated = AsyncMock()
    monkeypatch.setattr(
        "app.services.tor_watchdog._invalidate_anonymize_exit_diversity_cache",
        invalidated,
    )
    outcome = await sup._step_newnym("corr-1")
    assert outcome == "success"
    assert sup._STATE.step_outcomes.get("newnym_success") == 1
    invalidated.assert_awaited_once()


@pytest.mark.asyncio
async def test_step_newnym_failed_outcome_when_signal_rejected(monkeypatch) -> None:
    """A rejected NEWNYM returns 'failed' and records the failed
    outcome counter."""
    monkeypatch.setattr(
        "app.services.anonymize.tor.signal_newnym",
        AsyncMock(return_value=(False, "control rejected")),
    )
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())
    monkeypatch.setattr(
        "app.services.tor_watchdog._invalidate_anonymize_exit_diversity_cache",
        AsyncMock(),
    )
    outcome = await sup._step_newnym("corr-1")
    assert outcome == "failed"
    assert sup._STATE.step_outcomes.get("newnym_failed") == 1


@pytest.mark.asyncio
async def test_step_sighup_records_outcome(monkeypatch) -> None:
    """SIGHUP success returns 'success' and records the sighup
    outcome counter."""
    monkeypatch.setattr(
        "app.services.anonymize.tor.signal_reload",
        AsyncMock(return_value=(True, None)),
    )
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())
    outcome = await sup._step_sighup("corr-1")
    assert outcome == "success"
    assert sup._STATE.step_outcomes.get("sighup_success") == 1


# ─── _wait_for_clear_or_timeout ──────────────────────────────────────


@pytest.mark.asyncio
async def test_wait_for_clear_returns_true_when_breaker_already_closed() -> None:
    """If the breaker is already closed when the wait begins, the
    helper returns True immediately without sleeping."""
    # Fixture leaves the breaker closed.
    assert _LND_BREAKER.state == "closed"
    assert await sup._wait_for_clear_or_timeout(grace_s=5.0) is True


@pytest.mark.asyncio
async def test_wait_for_clear_returns_false_on_timeout(monkeypatch) -> None:
    """If the breaker stays open past the grace window, the helper
    returns False — the signal the cycle uses to escalate to the
    next step."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    # grace_s=0 → the while-loop body never runs; the final check
    # observes the still-open breaker and returns False. Deterministic,
    # no real sleep.
    assert await sup._wait_for_clear_or_timeout(grace_s=0.0) is False


# ─── heartbeat ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_heartbeat_emits_when_interval_elapsed(monkeypatch) -> None:
    """When more than the heartbeat interval has elapsed, a heartbeat
    audit fires and ``last_heartbeat_ts`` advances."""
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)
    sup._STATE.last_heartbeat_ts = 0.0  # never beat → due now
    await sup._maybe_emit_heartbeat()
    assert "tor_lnd_recovery_heartbeat" in audits
    assert sup._STATE.last_heartbeat_ts > 0.0


@pytest.mark.asyncio
async def test_heartbeat_suppressed_within_interval(monkeypatch) -> None:
    """A heartbeat that fired recently is not re-emitted before the
    interval elapses — avoids audit-log spam."""
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)
    sup._STATE.last_heartbeat_ts = time.monotonic()  # just beat
    await sup._maybe_emit_heartbeat()
    assert "tor_lnd_recovery_heartbeat" not in audits


# ─── c3 onion probing ────────────────────────────────────────────────


def test_resolve_c3_targets_prefers_explicit_then_onion_urls(monkeypatch) -> None:
    """C3 target resolution puts the explicit operator setting first,
    then adds onion-shaped mempool/electrum URLs, dedupes, and caps
    at 2 targets."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_tor_recovery_other_onion_probe_url",
        "http://explicit.onion",
        raising=False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.lnd_mempool_url",
        "http://mempool.onion",
        raising=False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.lnd_electrum_url",
        "https://clearnet.example.com",  # not onion → excluded
        raising=False,
    )
    targets = sup._resolve_c3_probe_targets()
    assert targets == ["http://explicit.onion", "http://mempool.onion"]


def test_resolve_c3_targets_empty_when_no_onions(monkeypatch) -> None:
    """No explicit URL and no onion-shaped mempool/electrum URLs →
    no targets (the caller then treats C3 as can't-tell)."""
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_other_onion_probe_url", "", raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_mempool_url", "https://mempool.space", raising=False)
    monkeypatch.setattr("app.core.config.settings.lnd_electrum_url", "", raising=False)
    assert sup._resolve_c3_probe_targets() == []


@pytest.mark.asyncio
async def test_probe_other_onions_no_targets_assumes_ok(monkeypatch) -> None:
    """With zero configured targets, C3 returns (True, []) — we don't
    refuse to remediate on a misconfigured-knob technicality."""
    monkeypatch.setattr(sup, "_resolve_c3_probe_targets", lambda: [])
    ok, tested = await sup._probe_other_onions()
    assert ok is True
    assert tested == []


@pytest.mark.asyncio
async def test_probe_other_onions_succeeds_on_first_reachable(monkeypatch) -> None:
    """C3 short-circuits on the first reachable onion — a single
    working onion is enough corroboration that Tor isn't broadly
    down."""
    monkeypatch.setattr(sup, "_resolve_c3_probe_targets", lambda: ["http://a.onion", "http://b.onion"])
    monkeypatch.setattr(sup, "_probe_one_onion", AsyncMock(return_value=True))
    ok, tested = await sup._probe_other_onions()
    assert ok is True
    assert tested == ["http://a.onion"]  # stopped after first success


@pytest.mark.asyncio
async def test_probe_other_onions_all_fail(monkeypatch) -> None:
    """When every configured onion fails, C3 returns
    (False, all_tested) → broad-outage suspicion."""
    monkeypatch.setattr(sup, "_resolve_c3_probe_targets", lambda: ["http://a.onion", "http://b.onion"])
    monkeypatch.setattr(sup, "_probe_one_onion", AsyncMock(return_value=False))
    ok, tested = await sup._probe_other_onions()
    assert ok is False
    assert tested == ["http://a.onion", "http://b.onion"]


@pytest.mark.asyncio
async def test_probe_one_onion_skips_tcp_scheme(monkeypatch) -> None:
    """A ``tcp://`` (electrum) URL is skipped by the HTTP probe — it
    needs a SOCKS-aware socket the C3 check deliberately avoids."""
    assert await sup._probe_one_onion("tcp://electrum.onion:50001", timeout_s=1.0) is False


# ─── _finish_cycle below the cap ─────────────────────────────────────


@pytest.mark.asyncio
async def test_finish_cycle_below_cap_does_not_disable(monkeypatch) -> None:
    """A cycle that completes below the rolling cap records the
    completion + cleared-by-step counter but leaves
    ``cycles_disabled_until_ts`` at 0 and fires no disabled-cap
    audit."""
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)
    sup._STATE.recent_cycle_completions = []  # first cycle of the window
    await sup._finish_cycle(cleared_at_step=sup.STEP_NEWNYM)
    assert sup._STATE.cycles_disabled_until_ts == 0.0
    assert "tor_lnd_recovery_disabled_cycle_cap" not in audits
    assert sup._STATE.cycles_cleared_by_step.get(sup.STEP_NEWNYM) == 1
    assert sup._STATE.incident_start_ts == 0.0


# ─── supervisor tick ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_fast_path_when_breaker_closed(monkeypatch) -> None:
    """With the breaker closed, the tick returns early without
    running inhibit/signature probes — the cheap common case."""
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_enabled", True, raising=False)
    monkeypatch.setattr(sup, "_maybe_emit_heartbeat", AsyncMock())
    monkeypatch.setattr(sup, "_evaluate_inhibits", AsyncMock(side_effect=AssertionError("should not run")))
    # Breaker is closed (fixture). Tick must short-circuit.
    await sup._supervisor_tick()
    assert sup._STATE.last_tick_ts > 0.0


@pytest.mark.asyncio
async def test_tick_disabled_by_setting(monkeypatch) -> None:
    """When recovery is disabled by setting, the tick records its
    liveness timestamp but never touches the breaker or probes."""
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_enabled", False, raising=False)
    monkeypatch.setattr(sup, "_maybe_emit_heartbeat", AsyncMock())
    monkeypatch.setattr(sup, "_evaluate_inhibits", AsyncMock(side_effect=AssertionError("should not run")))
    await sup._supervisor_tick()
    assert sup._STATE.last_tick_ts > 0.0


@pytest.mark.asyncio
async def test_tick_inhibited_emits_audit_and_skips_cycle(monkeypatch) -> None:
    """When an inhibit matches, the tick bumps the inhibit counter,
    emits the inhibit audit, and does NOT run a cycle."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_enabled", True, raising=False)
    monkeypatch.setattr(sup, "_maybe_emit_heartbeat", AsyncMock())
    monkeypatch.setattr(sup, "_evaluate_inhibits", AsyncMock(return_value=sup.INHIBIT_COOLDOWN))
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)
    monkeypatch.setattr(sup, "_run_cycle", AsyncMock(side_effect=AssertionError("no cycle")))
    monkeypatch.setattr(sup, "_detect_signature", AsyncMock(side_effect=AssertionError("no detect")))

    await sup._supervisor_tick()
    assert sup._STATE.inhibits_total.get(sup.INHIBIT_COOLDOWN) == 1
    assert f"tor_lnd_recovery_inhibited_{sup.INHIBIT_COOLDOWN}" in audits


@pytest.mark.asyncio
async def test_tick_broad_outage_bumps_inhibit_no_cycle(monkeypatch) -> None:
    """When the signature fails with C3 broad-outage, the tick
    accounts the I4 broad-outage inhibit separately and does not arm
    a cycle."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_enabled", True, raising=False)
    monkeypatch.setattr(sup, "_maybe_emit_heartbeat", AsyncMock())
    monkeypatch.setattr(sup, "_evaluate_inhibits", AsyncMock(return_value=None))
    monkeypatch.setattr(
        sup,
        "_detect_signature",
        AsyncMock(return_value=(False, {"c3": "broad_outage_suspected", "c3_tested": ["x.onion"]})),
    )
    monkeypatch.setattr(sup, "_run_cycle", AsyncMock(side_effect=AssertionError("no cycle")))
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())

    await sup._supervisor_tick()
    assert sup._STATE.inhibits_total.get(sup.INHIBIT_BROAD_OUTAGE) == 1


@pytest.mark.asyncio
async def test_tick_arms_cycle_on_signature_match(monkeypatch) -> None:
    """Breaker open + no inhibit + signature match → the tick runs a
    cycle with the diagnostics from detection."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_enabled", True, raising=False)
    monkeypatch.setattr(sup, "_maybe_emit_heartbeat", AsyncMock())
    monkeypatch.setattr(sup, "_evaluate_inhibits", AsyncMock(return_value=None))
    monkeypatch.setattr(sup, "_detect_signature", AsyncMock(return_value=(True, {"c1_opened_age_s": 120.0})))
    run = AsyncMock()
    monkeypatch.setattr(sup, "_run_cycle", run)
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())

    await sup._supervisor_tick()
    run.assert_awaited_once()


@pytest.mark.asyncio
async def test_tick_skips_when_cycle_already_running(monkeypatch) -> None:
    """If a cycle is in progress (lock held), the tick must not start
    detection or another cycle — the running cycle owns the
    incident."""
    _force_breaker_open("ProxyError: General SOCKS server failure")
    monkeypatch.setattr("app.core.config.settings.lnd_tor_recovery_enabled", True, raising=False)
    monkeypatch.setattr(sup, "_maybe_emit_heartbeat", AsyncMock())
    monkeypatch.setattr(sup, "_evaluate_inhibits", AsyncMock(side_effect=AssertionError("should not reach inhibits")))

    async with sup._CYCLE_LOCK:
        await sup._supervisor_tick()  # must early-return on locked cycle


# ─── supervised entrypoint: crash/restart/exhaustion ─────────────────


@pytest.mark.asyncio
async def test_run_supervisor_clean_exit_on_stop(monkeypatch) -> None:
    """A clean loop exit (stop_event set) returns without recording a
    supervisor restart."""

    async def _loop(stop_event):
        return  # immediate clean exit

    monkeypatch.setattr(sup, "_supervisor_loop", _loop)
    stop = asyncio.Event()
    await asyncio.wait_for(sup.run_lnd_tor_supervisor(stop), timeout=1.0)
    assert sup._STATE.supervisor_restarts == []


@pytest.mark.asyncio
async def test_run_supervisor_restarts_loop_after_crash(monkeypatch) -> None:
    """A crashing loop is restarted (a restart timestamp is recorded
    and a restarting audit fires) until it exits cleanly."""
    monkeypatch.setattr(sup, "_emit_audit", AsyncMock())
    # Neutralise the inter-restart backoff wait so the test never
    # sleeps the real 5 s: model "stop not set during backoff" as an
    # immediate TimeoutError, which the loop treats as "continue".
    _patch_backoff_timeout(monkeypatch)
    calls = 0

    async def _loop(stop_event):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic loop crash")
        return  # clean on the retry

    monkeypatch.setattr(sup, "_supervisor_loop", _loop)
    stop = asyncio.Event()
    # NOTE: no outer asyncio.wait_for here — the helper patches
    # asyncio.wait_for module-wide, so the internal backoff resolves
    # instantly and the entrypoint returns on its own.
    await sup.run_lnd_tor_supervisor(stop)
    assert calls == 2
    assert len(sup._STATE.supervisor_restarts) == 1


@pytest.mark.asyncio
async def test_run_supervisor_exhausts_after_max_restarts(monkeypatch) -> None:
    """Beyond ``_SUPERVISION_MAX_RESTARTS`` crashes inside the window,
    the supervisor emits a supervision-exhausted alarm and stays
    stopped — operator action required."""
    audits: list[str] = []

    async def _capture(action, details=None):
        audits.append(action)

    monkeypatch.setattr(sup, "_emit_audit", _capture)
    # No real backoff sleep between restarts.
    monkeypatch.setattr(sup, "_SUPERVISION_RESTART_WINDOW_S", 300)
    _patch_backoff_timeout(monkeypatch)

    async def _always_crash(stop_event):
        raise RuntimeError("perma-crash")

    monkeypatch.setattr(sup, "_supervisor_loop", _always_crash)
    stop = asyncio.Event()
    await sup.run_lnd_tor_supervisor(stop)

    assert "tor_lnd_recovery_supervision_exhausted" in audits
    # Restarts capped at MAX+1 attempts before giving up.
    assert len(sup._STATE.supervisor_restarts) == sup._SUPERVISION_MAX_RESTARTS + 1


@pytest.mark.asyncio
async def test_supervisor_loop_exits_cleanly_on_stop(monkeypatch) -> None:
    """``_supervisor_loop`` runs ticks until stop_event is set, then
    returns — the stop path the lifespan relies on for shutdown."""
    ticks = 0

    async def _tick():
        nonlocal ticks
        ticks += 1
        stop.set()  # stop after the first tick

    monkeypatch.setattr(sup, "_supervisor_tick", _tick)
    stop = asyncio.Event()
    await asyncio.wait_for(sup._supervisor_loop(stop), timeout=1.0)
    assert ticks == 1


@pytest.mark.asyncio
async def test_supervisor_loop_propagates_tick_crash(monkeypatch) -> None:
    """A raising tick re-raises out of ``_supervisor_loop`` so the
    supervised entrypoint's restart accounting sees it."""

    async def _tick():
        raise RuntimeError("tick crashed")

    monkeypatch.setattr(sup, "_supervisor_tick", _tick)
    stop = asyncio.Event()
    with pytest.raises(RuntimeError, match="tick crashed"):
        await sup._supervisor_loop(stop)
