# SPDX-License-Identifier: MIT
"""Sentinel internal-consistency test (/ item 118).

The ``destination_address_blake2b_keyed`` purge sentinel is the literal
``b"\\x00" * 32`` (matching / checklist item 60). The
prior-draft BLAKE2b-keyed construction with undefined
``ANONYMIZE_REUSE_SENTINEL_KEY`` is retracted.

This test pins the sentinel constant in both directions: against the
module-level constant that the application uses, and against the
text of migration 016 which declares the partial-index predicate
``destination_address_blake2b_keyed != E'\\x' || repeat('00', 32)::bytea``.
"""

from __future__ import annotations

from pathlib import Path

from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL
from app.services.anonymize.reuse_detection import is_sentinel


def test_sentinel_is_32_zero_bytes() -> None:
    assert REUSE_DETECTION_SENTINEL == b"\x00" * 32
    assert len(REUSE_DETECTION_SENTINEL) == 32


def test_is_sentinel_helper() -> None:
    assert is_sentinel(REUSE_DETECTION_SENTINEL)
    assert not is_sentinel(b"\x00" * 31 + b"\x01")
    assert not is_sentinel(b"")


def test_migration_016_partial_index_predicate_uses_all_zeros() -> None:
    """Migration 016 must encode the same all-zeros sentinel.

    A drift between the application constant and the migration-time
    partial-index predicate would silently corrupt reuse detection.
    The test reads the migration source directly so a typo in either
    surface is caught at PR time.
    """
    migration_path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "016_anonymize.py"
    text = migration_path.read_text(encoding="utf-8")
    # The predicate is `repeat('00', 32)::bytea` — 32 repetitions of
    # the byte 0x00. Anything else is a regression.
    assert "repeat('00', 32)::bytea" in text, "migration 016 partial index must reference repeat('00', 32)::bytea"
