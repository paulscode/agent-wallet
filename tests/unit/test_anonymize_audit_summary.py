# SPDX-License-Identifier: MIT
"""Audit-summary scaffold.

Pure-helper tests for bucket time-rounding, count quantization, and
the k-anonymity suppression decision. The actual audit-chain
emission lands alongside the orchestrator's recurring task.
"""

from __future__ import annotations

from app.core.config import settings
from app.services.anonymize.audit_summary import (
    aggregate_window_emission,
    build_bucket_summary,
    quantize_count,
    round_to_bucket_start_unix_s,
)


def test_quantize_count_buckets() -> None:
    assert quantize_count(0) == "0"
    assert quantize_count(1) == "1-3"
    assert quantize_count(3) == "1-3"
    assert quantize_count(4) == "4-10"
    assert quantize_count(10) == "4-10"
    assert quantize_count(11) == "11-30"
    assert quantize_count(30) == "11-30"
    assert quantize_count(31) == "30+"
    assert quantize_count(10_000) == "30+"


def test_round_to_bucket_start_unix_s() -> None:
    """Default bucket size is 3600 s (one hour)."""
    # 10:30 UTC on a fictional day → rounds back to the top of the hour.
    ts = 1715000000  # arbitrary
    rounded = round_to_bucket_start_unix_s(ts, bucket_seconds=3600)
    assert rounded <= ts
    assert (ts - rounded) < 3600
    assert rounded % 3600 == 0


def test_round_to_bucket_uses_settings_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_bucket_s", 1800)
    rounded = round_to_bucket_start_unix_s(1_715_000_001)
    assert rounded % 1800 == 0


def test_build_bucket_summary_suppresses_below_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_min_bucket_count", 5)
    s = build_bucket_summary(
        bucket_start_unix_s=1_715_000_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 1, "failed": 0},
        counts_by_source_kind={"ext-lightning": 1},
    )
    assert s.suppressed is True
    assert s.counts_by_terminal_state == {}
    assert s.counts_by_source_kind == {}
    assert s.raw_total == 1


def test_build_bucket_summary_emits_above_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_audit_min_bucket_count", 5)
    s = build_bucket_summary(
        bucket_start_unix_s=1_715_000_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7, "failed": 1},
        counts_by_source_kind={"ext-lightning": 5, "lightning-self": 3},
    )
    assert s.suppressed is False
    assert s.counts_by_terminal_state == {"completed": "4-10", "failed": "1-3"}
    assert s.counts_by_source_kind == {
        "ext-lightning": "4-10",
        "lightning-self": "1-3",
    }


def test_build_bucket_summary_threshold_zero_disables_suppression(monkeypatch) -> None:
    """ANONYMIZE_AUDIT_MIN_BUCKET_COUNT=0 disables suppression entirely."""
    monkeypatch.setattr(settings, "anonymize_audit_min_bucket_count", 0)
    s = build_bucket_summary(
        bucket_start_unix_s=1_715_000_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 1},
        counts_by_source_kind={"ext-lightning": 1},
    )
    assert s.suppressed is False
    assert s.counts_by_terminal_state == {"completed": "1-3"}


def test_aggregate_window_drops_suppressed_buckets() -> None:
    a = build_bucket_summary(
        bucket_start_unix_s=1_715_000_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7},
        counts_by_source_kind={"ext-lightning": 7},
        min_bucket_count=5,
    )
    b = build_bucket_summary(
        bucket_start_unix_s=1_715_003_600,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 1},
        counts_by_source_kind={"ext-lightning": 1},
        min_bucket_count=5,
    )
    win = aggregate_window_emission(
        [a, b],
        window_start_unix_s=1_715_000_000,
        window_end_unix_s=1_715_086_400,
    )
    assert len(win.summaries) == 1
    assert win.summaries[0] is a
    assert win.had_suppressed_buckets is True


def test_aggregate_window_no_suppression_when_all_above_threshold() -> None:
    a = build_bucket_summary(
        bucket_start_unix_s=1_715_000_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7},
        counts_by_source_kind={"ext-lightning": 7},
        min_bucket_count=5,
    )
    win = aggregate_window_emission(
        [a],
        window_start_unix_s=1_715_000_000,
        window_end_unix_s=1_715_003_600,
    )
    assert win.had_suppressed_buckets is False
    assert len(win.summaries) == 1
