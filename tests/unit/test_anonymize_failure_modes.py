# SPDX-License-Identifier: MIT
"""items 9 + 10 + 21 — failure-mode triage helpers.

Boltz error mapping, refund-bound computation, stuck-HTLC alarm.
"""

from __future__ import annotations

from app.services.anonymize.failure_modes import (
    DEFAULT_STUCK_HTLC_THRESHOLD_S,
    StuckHtlcAlarm,
    TriageError,
    build_stuck_htlc_alarm,
    compute_refund_bound_seconds,
    is_htlc_stuck,
    is_session_past_refund_bound,
    map_boltz_error,
)

# ── item 9 ────────────────────────────────────────────────────────


def test_map_boltz_error_known_code() -> None:
    err = map_boltz_error(
        code="INVALID_INVOICE",
        raw_error="Boltz returned 400: invalid bolt11 — peer policy violation",
    )
    assert isinstance(err, TriageError)
    assert "operator rejected the invoice" in err.user_message
    # The raw error must travel separately from the user message.
    assert "Boltz returned 400" in err.raw_error
    assert err.boltz_error_code == "INVALID_INVOICE"


def test_map_boltz_error_unknown_code_falls_back() -> None:
    err = map_boltz_error(
        code="MYSTERY_CODE",
        raw_error="upstream went sideways",
    )
    # Generic fallback message — must not echo the upstream error.
    assert "swap operator" in err.user_message
    assert err.user_message != "upstream went sideways"
    assert err.raw_error == "upstream went sideways"


def test_map_boltz_error_no_code() -> None:
    err = map_boltz_error(code=None, raw_error="generic error string")
    assert err.boltz_error_code is None
    assert "moved to triage" in err.user_message


def test_map_boltz_error_does_not_leak_raw_into_user_message() -> None:
    """The user_message must never include the raw error text verbatim."""
    raw = "Boltz internal: <secret-token-asdf>"
    err = map_boltz_error(code=None, raw_error=raw)
    assert "secret-token-asdf" not in err.user_message
    assert err.raw_error == raw


# ── item 10 ───────────────────────────────────────────────────────


def test_refund_bound_uses_max_of_delay_and_inter_leg() -> None:
    bound = compute_refund_bound_seconds(
        delay_policy_max_s=21_600,  # 6 h
        inter_leg_delay_max_s=172_800,  # 48 h
    )
    # 24h grace beyond the longer of the two.
    assert bound == 172_800 + 24 * 3600


def test_refund_bound_lightning_only_session() -> None:
    """LN-source pipelines have no inter-leg delay."""
    bound = compute_refund_bound_seconds(
        delay_policy_max_s=21_600,
        inter_leg_delay_max_s=None,
    )
    assert bound == 21_600 + 24 * 3600


def test_refund_bound_with_zero_inter_leg() -> None:
    """An explicit zero is treated like a real value, not a missing one."""
    bound = compute_refund_bound_seconds(
        delay_policy_max_s=10_000,
        inter_leg_delay_max_s=0,
    )
    # delay path: 10_000 + 86_400 = 96_400
    # inter_leg path: 0 + 86_400 = 86_400
    assert bound == 96_400


def test_is_session_past_refund_bound_true_above_bound() -> None:
    bound = compute_refund_bound_seconds(
        delay_policy_max_s=3_600,
        inter_leg_delay_max_s=None,
    )
    started = 1_000_000.0
    assert (
        is_session_past_refund_bound(
            session_started_unix_s=started,
            now_unix_s=started + bound + 10,
            delay_policy_max_s=3_600,
            inter_leg_delay_max_s=None,
        )
        is True
    )


def test_is_session_past_refund_bound_false_below_bound() -> None:
    started = 1_000_000.0
    assert (
        is_session_past_refund_bound(
            session_started_unix_s=started,
            now_unix_s=started + 600,
            delay_policy_max_s=3_600,
            inter_leg_delay_max_s=None,
        )
        is False
    )


# ── item 21 ───────────────────────────────────────────────────────


def test_is_htlc_stuck_uses_threshold_default() -> None:
    assert is_htlc_stuck(in_flight_seconds=DEFAULT_STUCK_HTLC_THRESHOLD_S - 1) is False
    assert is_htlc_stuck(in_flight_seconds=DEFAULT_STUCK_HTLC_THRESHOLD_S + 1) is True


def test_is_htlc_stuck_honors_explicit_threshold() -> None:
    assert is_htlc_stuck(in_flight_seconds=300, threshold_s=600) is False
    assert is_htlc_stuck(in_flight_seconds=900, threshold_s=600) is True


def test_build_stuck_htlc_alarm_carries_session_id_and_payment_hash() -> None:
    alarm = build_stuck_htlc_alarm(
        session_id="abc-123",
        payment_hash="ff" * 32,
        in_flight_seconds=4500.0,
        cltv_blocks_remaining=20,
    )
    assert isinstance(alarm, StuckHtlcAlarm)
    assert alarm.session_id == "abc-123"
    assert alarm.payment_hash == "ff" * 32
    assert alarm.stuck_for_seconds == 4500.0
    assert alarm.cltv_blocks_remaining == 20
