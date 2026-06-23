# SPDX-License-Identifier: MIT
"""Reason classifier unit tests.

Validates the Class A/B/C mapping and the ``_CANCELLABLE_REASONS``
gate that the ``AWAITING_RECONCILIATION → CANCELLED`` edge
consumes at the endpoint layer.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.reconciliation_classify import (
    CLASS_SEMI,
    CLASS_TERMINAL,
    CLASS_TRANSIENT,
    MAX_RETRIES_SEMI,
    classify_reason,
    is_cancellable,
)

# ── Class assignment ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason",
    [
        "circuit_rebuild_throttled",
        "wall_clock_budget_exceeded",
        "bounded_retry_exhausted",
        "external_state_unknown",
        "economy_feerate_unavailable",
        "inbound_insufficient_at_lockup",
    ],
)
def test_class_transient_reasons(reason: str) -> None:
    assert classify_reason(reason) == CLASS_TRANSIENT


@pytest.mark.parametrize(
    "reason",
    [
        "mpp_k_floor_exhausted",
        "claim_feerate_outlier",
        "stuck_htlc_alarm",
    ],
)
def test_class_semi_reasons(reason: str) -> None:
    assert classify_reason(reason) == CLASS_SEMI


@pytest.mark.parametrize(
    "reason",
    [
        "operator_signature_mismatch",
        "claim_tx_validation_failed",
        "clock_skew_exceeds_deadline_margin",
        "pipeline_schema_below_min_supported",
    ],
)
def test_class_terminal_reasons(reason: str) -> None:
    assert classify_reason(reason) == CLASS_TERMINAL


# ── Unknown / empty defaults ────────────────────────────────────────


@pytest.mark.parametrize("reason", ["", None, "totally_made_up_reason_xyz"])
def test_unknown_defaults_to_terminal(reason) -> None:
    """Unknown or missing reasons MUST default to Class C so a new
    bug-driven reason can't get silently retried into a tight loop."""
    assert classify_reason(reason) == CLASS_TERMINAL


def test_strips_whitespace() -> None:
    assert classify_reason("  mpp_k_floor_exhausted  ") == CLASS_SEMI
    assert classify_reason("  circuit_rebuild_throttled\n") == CLASS_TRANSIENT


# ── Cancellable gate ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "reason",
    [
        "mpp_k_floor_exhausted",
        "circuit_rebuild_throttled",
        "bounded_retry_exhausted",
        "wall_clock_budget_exceeded",
        "inbound_insufficient_at_lockup",
    ],
)
def test_cancellable_reasons(reason: str) -> None:
    """The no-funds-moved set."""
    assert is_cancellable(reason) is True


@pytest.mark.parametrize(
    "reason",
    [
        # Funds-at-risk Class B reasons must NOT be cancellable.
        "claim_feerate_outlier",
        "stuck_htlc_alarm",
        # Operator-judgement Class C reasons must NOT be cancellable.
        "operator_signature_mismatch",
        "claim_tx_validation_failed",
        "clock_skew_exceeds_deadline_margin",
        "pipeline_schema_below_min_supported",
        # External-state ambiguity → not cancellable (might be in flight).
        "external_state_unknown",
        # Unknown / empty → not cancellable (operator decides).
        "",
        None,
        "made_up",
    ],
)
def test_non_cancellable_reasons(reason) -> None:
    assert is_cancellable(reason) is False


# ── Public constants ────────────────────────────────────────────────


def test_max_retries_semi_is_three() -> None:
    """: Class B budget is a code-level constant pinned at 3.
    Raising this is unsafe per the docstring; this test locks the value
    so a future drive-by change can't quietly raise it."""
    assert MAX_RETRIES_SEMI == 3
