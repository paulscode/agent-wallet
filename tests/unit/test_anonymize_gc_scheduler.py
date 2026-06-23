# SPDX-License-Identifier: MIT
"""Tests for the GC scheduler primitives in ``app.services.anonymize.gc``:

* ``select_next_pass_for_session`` — chooses the next unset pass
  in registry order so the GC walker advances deterministically.
* ``gc_tick_due`` — interval-driven tick gate for the scheduler.

The per-pass logic itself lives in sibling test files
(``test_anonymize_gc_*_passes.py``).
"""

from __future__ import annotations

from app.core.config import settings


def test_select_next_pass_returns_lowest_unset() -> None:
    """Picks the first unset bit in registry order."""
    from app.services.anonymize.gc import (
        GC_PASS_PIPELINE_TRUNCATE,
        select_next_pass_for_session,
    )

    name, bit = select_next_pass_for_session(0)
    assert bit == GC_PASS_PIPELINE_TRUNCATE
    assert name == "pipeline_truncate"


def test_select_next_pass_skips_completed_bits() -> None:
    """A bitfield with pass 1 done returns pass 2."""
    from app.services.anonymize.gc import (
        GC_PASS_EVENT_COLLAPSE,
        GC_PASS_PIPELINE_TRUNCATE,
        select_next_pass_for_session,
    )

    name, bit = select_next_pass_for_session(GC_PASS_PIPELINE_TRUNCATE)
    assert bit == GC_PASS_EVENT_COLLAPSE
    assert name == "event_collapse"


def test_select_next_pass_returns_none_when_all_done() -> None:
    from app.services.anonymize.gc import (
        ALL_PASSES_MASK,
        select_next_pass_for_session,
    )

    assert select_next_pass_for_session(ALL_PASSES_MASK) is None


def test_gc_tick_due_on_fresh_deployment() -> None:
    """A None last-run timestamp fires immediately."""
    from app.services.anonymize.gc import gc_tick_due

    assert gc_tick_due(last_successful_at_unix_s=None) is True


def test_gc_tick_due_after_interval(monkeypatch) -> None:
    from app.services.anonymize.gc import gc_tick_due

    monkeypatch.setattr(settings, "anonymize_gc_tick_interval_s", 300)
    # 400s ago > 300s interval.
    assert (
        gc_tick_due(
            last_successful_at_unix_s=1_000.0,
            now_unix_s=1_400.0,
        )
        is True
    )


def test_gc_tick_not_due_inside_interval(monkeypatch) -> None:
    from app.services.anonymize.gc import gc_tick_due

    monkeypatch.setattr(settings, "anonymize_gc_tick_interval_s", 300)
    # 100s ago < 300s.
    assert (
        gc_tick_due(
            last_successful_at_unix_s=1_000.0,
            now_unix_s=1_100.0,
        )
        is False
    )


def test_gc_tick_due_with_explicit_interval_override() -> None:
    from app.services.anonymize.gc import gc_tick_due

    assert (
        gc_tick_due(
            last_successful_at_unix_s=1_000.0,
            interval_s=60,
            now_unix_s=1_061.0,
        )
        is True
    )


def test_gc_tick_due_zero_interval_always_fires() -> None:
    """A misconfigured zero interval degrades to always-fire."""
    from app.services.anonymize.gc import gc_tick_due

    assert (
        gc_tick_due(
            last_successful_at_unix_s=1_000.0,
            interval_s=0,
            now_unix_s=1_000.5,
        )
        is True
    )
