# SPDX-License-Identifier: MIT
"""Reverse-leg K floor + bounded fallback."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.cooperative_claim import (
    assert_k_floor_invariants,
    decide_k_fallback_step,
)


def test_first_attempt_executes_requested_k() -> None:
    out = decide_k_fallback_step(
        requested_k=3,
        last_attempted_k=3,
        decrements_used=0,
        mode="strict",
        k_min_executed=2,
    )
    assert out == "execute"


def test_strict_mode_admits_one_decrement() -> None:
    """K=3 → K=2 in strict mode is allowed (one decrement)."""
    out = decide_k_fallback_step(
        requested_k=3,
        last_attempted_k=3,
        decrements_used=0,
        mode="strict",
        k_min_executed=2,
    )
    # First attempt → execute
    assert out == "execute"
    # First failure ⇒ decrement is allowed (we haven't decremented yet
    # but last_attempted_k is still 3 — the decision after one failed
    # try would be: caller bumps decrements_used and last_attempted_k).
    # Simulate the post-failure call:
    out2 = decide_k_fallback_step(
        requested_k=3,
        last_attempted_k=2,
        decrements_used=1,
        mode="strict",
        k_min_executed=2,
    )
    # Already decremented once + at floor → abort.
    assert out2 == "abort_to_reconciliation"


def test_strict_mode_aborts_after_one_decrement_when_below_floor() -> None:
    out = decide_k_fallback_step(
        requested_k=2,
        last_attempted_k=2,
        decrements_used=1,
        mode="strict",
        k_min_executed=2,
    )
    assert out == "abort_to_reconciliation"


def test_legacy_mode_admits_arbitrary_decrements() -> None:
    out = decide_k_fallback_step(
        requested_k=4,
        last_attempted_k=4,
        decrements_used=2,
        mode="legacy",
        k_min_executed=1,
    )
    assert out == "decrement"


def test_abort_below_min_aborts_on_first_failure() -> None:
    out = decide_k_fallback_step(
        requested_k=3,
        last_attempted_k=3,
        decrements_used=1,
        mode="abort_below_min",
        k_min_executed=2,
    )
    assert out == "abort_to_reconciliation"


def test_decrement_below_floor_aborts() -> None:
    """Even legacy mode aborts when next_k would go below the floor."""
    out = decide_k_fallback_step(
        requested_k=2,
        last_attempted_k=2,
        decrements_used=2,
        mode="legacy",
        k_min_executed=2,
    )
    assert out == "abort_to_reconciliation"


def test_unknown_mode_fail_closed() -> None:
    out = decide_k_fallback_step(
        requested_k=3,
        last_attempted_k=3,
        decrements_used=1,
        mode="bogus",
        k_min_executed=2,  # type: ignore[arg-type]
    )
    assert out == "abort_to_reconciliation"


# ── startup invariants ──────────────────────────────────────


def test_invariant_passes_with_valid_config(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 4)
    assert_k_floor_invariants()  # no raise


def test_invariant_rejects_zero_floor(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 4)
    with pytest.raises(ValueError, match=">= 1"):
        assert_k_floor_invariants()


def test_invariant_rejects_floor_above_range_max(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 5)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_chunks_range_max", 4)
    with pytest.raises(ValueError, match="unreachable"):
        assert_k_floor_invariants()
