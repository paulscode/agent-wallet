# SPDX-License-Identifier: MIT
"""Gc bitfield rollover discipline."""

from __future__ import annotations

from app.services.anonymize.gc import (
    ALL_PASSES_MASK,
    GC_PASSES_ORDERED,
    assert_passes_form_contiguous_bit_run,
    assert_passes_registry_covers_documented_set,
)


def test_passes_form_contiguous_bit_run() -> None:
    """The shipped registry passes the contiguous-bit invariant."""
    assert_passes_form_contiguous_bit_run()  # no raise


def test_passes_registry_covers_documented_set() -> None:
    assert_passes_registry_covers_documented_set()  # no raise


def test_all_passes_mask_matches_registry_union() -> None:
    """Belt-and-suspenders: ``ALL_PASSES_MASK`` matches the bit union."""
    union = 0
    for _, bit in GC_PASSES_ORDERED:
        union |= bit
    assert union == ALL_PASSES_MASK


def test_each_pass_label_is_unique() -> None:
    labels = [label for label, _ in GC_PASSES_ORDERED]
    assert len(labels) == len(set(labels))


def test_each_pass_bit_is_unique() -> None:
    bits = [bit for _, bit in GC_PASSES_ORDERED]
    assert len(bits) == len(set(bits))


def test_passes_count_matches_documentation() -> None:
    """10 passes total (the original 7 +)."""
    assert len(GC_PASSES_ORDERED) == 10
