# SPDX-License-Identifier: MIT
"""Broadcast deadline + self-broadcast helpers."""

from __future__ import annotations

from app.core.config import settings
from app.services.anonymize.broadcast import (
    BroadcastState,
    compute_boltz_broadcast_deadline,
    decide_self_broadcast_action,
    should_use_boltz_broadcast,
)
from app.services.anonymize.clock import ClockSkewState, update_clock_skew


def test_broadcast_deadline_uses_grace(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_boltz_broadcast_grace_s", 60)
    out = compute_boltz_broadcast_deadline(scheduled_broadcast_at_unix_s=1_000_000)
    assert out == 1_000_060


def test_broadcast_deadline_explicit_grace_overrides_settings() -> None:
    out = compute_boltz_broadcast_deadline(
        scheduled_broadcast_at_unix_s=1_000_000,
        grace_s=120,
    )
    assert out == 1_000_120


def test_decide_returns_wait_when_no_deadline_set() -> None:
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=None,
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
        ),
        clock_state=ClockSkewState.empty(),
        now_unix_s=1_000_000,
    )
    assert decision == "wait"


def test_decide_returns_wait_when_chain_already_observed() -> None:
    state = ClockSkewState.empty()
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_000,  # past
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=True,
            poll_interval_s=30,
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "wait"


def test_decide_returns_wait_when_deadline_not_yet_reached() -> None:
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=1_001_000,  # future
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "wait"


def test_decide_returns_verify_chain_when_self_broadcast_already_attempted() -> None:
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_000,  # past
            self_broadcast_attempted_at_ts=999_500.0,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "verify_chain"


def test_decide_returns_self_broadcast_after_deadline_plus_poll() -> None:
    state = update_clock_skew(ClockSkewState(), skew_ms=10)  # 10 ms drift
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_000,  # 1000 s ago, well past
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "self_broadcast"


def test_decide_returns_hold_for_skew_when_deadline_inside_drift_window() -> None:
    """Broad clock skew means we hold rather than fire prematurely."""
    state = update_clock_skew(ClockSkewState(), skew_ms=2_000)  # 2 s drift
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_999,  # 1 s before now
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    # Deadline+poll has passed (999_999 + 30 = 1_000_029 > now=1_000_000? No,
    # 1_000_029 > 1_000_000 ⇒ not past poll yet — returns wait.
    # Move the deadline back so it IS past.
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_900,  # 100s ago
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
        ),
        clock_state=state,
        now_unix_s=999_901,  # but now is ~deadline → inside skew window
    )
    # Past deadline+poll? 999_900 + 30 = 999_930 > 999_901 → no, returns wait.
    # Our test: deadline well past + still inside skew window:
    state_5s = update_clock_skew(ClockSkewState(), skew_ms=5_000)
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_995,  # 5 s ago
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=2,
        ),
        clock_state=state_5s,
        now_unix_s=1_000_000,
    )
    assert decision == "hold_for_skew"


def test_decide_pause_unhealthy_clock_after_3x_grace(monkeypatch) -> None:
    """/ #69 — skew unhealthy >3×grace pauses deadline checks."""
    monkeypatch.setattr(settings, "anonymize_boltz_broadcast_grace_s", 60)
    # Clock measurement still present, but the watcher has marked the
    # skew as unhealthy for 200s (> 3×60=180s).
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_000,  # well past
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
            skew_unhealthy_since_unix_s=999_800.0,  # 200 s ago
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "pause_unhealthy_clock"


def test_decide_pause_unhealthy_clock_inside_window_still_fires(monkeypatch) -> None:
    """An unhealthy-since marker <3×grace ago does NOT pause."""
    monkeypatch.setattr(settings, "anonymize_boltz_broadcast_grace_s", 60)
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_000,
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=False,
            poll_interval_s=30,
            skew_unhealthy_since_unix_s=999_900.0,  # 100s ago < 180s threshold
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "self_broadcast"


def test_decide_pause_unhealthy_clock_chain_observed_still_wait() -> None:
    """Chain-observed short-circuits before the unhealthy gate."""
    state = update_clock_skew(ClockSkewState(), skew_ms=10)
    decision = decide_self_broadcast_action(
        BroadcastState(
            broadcast_deadline_unix_s=999_000,
            self_broadcast_attempted_at_ts=None,
            claim_tx_observed_on_chain=True,
            poll_interval_s=30,
            skew_unhealthy_since_unix_s=900_000.0,  # ancient
        ),
        clock_state=state,
        now_unix_s=1_000_000,
    )
    assert decision == "wait"


def test_should_use_boltz_broadcast_default_is_boltz(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_broadcast_via", "boltz")
    assert should_use_boltz_broadcast() is True


def test_should_use_boltz_broadcast_self_path(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_broadcast_via", "self")
    assert should_use_boltz_broadcast() is False


# ── Restart-recovery action ─────────────────────────────────────


def test_restart_recovery_post_when_no_prior_attempt() -> None:
    from app.services.anonymize.broadcast import (
        BroadcastState,
        decide_restart_recovery_action,
    )

    state = BroadcastState(
        broadcast_deadline_unix_s=1_000_000,
        self_broadcast_attempted_at_ts=None,
        claim_tx_observed_on_chain=False,
        poll_interval_s=30,
    )
    assert decide_restart_recovery_action(state, now_unix_s=1_001_000) == "post"


def test_restart_recovery_verify_only_when_within_timeout(monkeypatch) -> None:
    from app.services.anonymize.broadcast import (
        BroadcastState,
        decide_restart_recovery_action,
    )

    monkeypatch.setattr(settings, "anonymize_self_broadcast_verify_timeout_s", 300)
    state = BroadcastState(
        broadcast_deadline_unix_s=1_000_000,
        self_broadcast_attempted_at_ts=999_950.0,  # 50s ago
        claim_tx_observed_on_chain=False,
        poll_interval_s=30,
    )
    assert decide_restart_recovery_action(state, now_unix_s=1_000_000) == "verify_only"


def test_restart_recovery_awaits_reconciliation_after_timeout(monkeypatch) -> None:
    from app.services.anonymize.broadcast import (
        BroadcastState,
        decide_restart_recovery_action,
    )

    monkeypatch.setattr(settings, "anonymize_self_broadcast_verify_timeout_s", 300)
    state = BroadcastState(
        broadcast_deadline_unix_s=1_000_000,
        self_broadcast_attempted_at_ts=999_000.0,  # 1000s ago > 300s timeout
        claim_tx_observed_on_chain=False,
        poll_interval_s=30,
    )
    assert decide_restart_recovery_action(state, now_unix_s=1_000_000) == "awaiting_reconciliation"
