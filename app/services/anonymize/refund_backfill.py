# SPDX-License-Identifier: MIT
"""Refund-label backfill high-water-mark.

The on-chain startup reconciliation pass walks ``boltz_swaps`` rows
that hit a ``failed`` terminal state and backfills the
``auto:anonymize-refund`` + ``do_not_spend=true`` labels onto any
refund UTXO that the orchestrator missed (e.g., due to a crash mid-
refund). The naive design (per-row ``boltz_swaps.refund_label_backfilled_at_ts``
column) leaks an anonymize-failure fingerprint per row (residual
narrowed by).

 mitigation: replace the per-row marker with a single
``anonymize_runtime_state`` row keyed
``refund_label_backfill_high_water_mark`` whose value records the
ordering position of the most-recently-processed swap row. The
backfill loop reads the high-water mark on each boot and skips rows
whose ordering position is below the mark.

This module ships:

* :func:`read_high_water_mark` — read the persisted HWM (or 0 on
  fresh deployment).
* :func:`update_high_water_mark` — bump the HWM after a successful
  backfill batch.

The actual backfill loop (which iterates ``boltz_swaps`` rows past
the HWM and writes labels) lands with the on-chain reconciliation
pass; this module is the persistence boundary the loop calls into.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings

from .crypto import MultiFernetBundle
from .runtime_state import read_runtime_state, write_runtime_state

# Registry-allowed key (already declared in metadata.py).
_HIGH_WATER_MARK_KEY = "refund_label_backfill_high_water_mark"


@dataclass(frozen=True)
class HighWaterMark:
    """The persisted HWM payload.

     extends the scalar high-water-mark to a two-key ordering
    `(id, created_at_day)` so the anti-orphan sweep can window its
    scan by UTC day without re-reading the full table.
    """

    backfilled_through_boltz_swap_id_ordering: int
    backfilled_at_unix_s: float
    max_processed_created_at_day: int = 0  # YYYYMMDD; 0 = never processed

    @classmethod
    def empty(cls) -> "HighWaterMark":
        return cls(
            backfilled_through_boltz_swap_id_ordering=0,
            backfilled_at_unix_s=0.0,
            max_processed_created_at_day=0,
        )


async def read_high_water_mark(
    db: AsyncSession,
    *,
    bundle: MultiFernetBundle | None = None,
) -> HighWaterMark:
    """Return the persisted HWM, or :meth:`HighWaterMark.empty` on fresh deploy."""
    raw = await read_runtime_state(
        db,
        key=_HIGH_WATER_MARK_KEY,
        bundle=bundle,
    )
    if not isinstance(raw, dict):
        return HighWaterMark.empty()
    return HighWaterMark(
        backfilled_through_boltz_swap_id_ordering=int(raw.get("backfilled_through_boltz_swap_id_ordering", 0)),
        backfilled_at_unix_s=float(raw.get("backfilled_at_unix_s", 0.0)),
        max_processed_created_at_day=int(raw.get("max_processed_created_at_day", 0)),
    )


async def update_high_water_mark(
    db: AsyncSession,
    *,
    new_ordering: int,
    new_created_at_day: int | None = None,
    bundle: MultiFernetBundle | None = None,
    now_unix_s: float | None = None,
) -> HighWaterMark:
    """Bump the HWM monotonically; refuses to regress.

    The backfill loop calls this after each successful batch with
    the highest ordering it processed. The helper refuses to write
    a *lower* ordering than the currently-persisted value so a
    concurrent loop that processed a smaller batch can't roll the
    mark backwards.

    ``new_created_at_day``: UTC-day component of the
    two-key HWM ordering. ``None`` keeps the current day value;
    callers that have a date pass YYYYMMDD-int.
    """
    current = await read_high_water_mark(db, bundle=bundle)
    if new_ordering < current.backfilled_through_boltz_swap_id_ordering:
        return current  # refuse the regression
    n = now_unix_s if now_unix_s is not None else time.time()
    day_component = int(new_created_at_day) if new_created_at_day is not None else current.max_processed_created_at_day
    payload = {
        "backfilled_through_boltz_swap_id_ordering": int(new_ordering),
        "backfilled_at_unix_s": float(n),
        "max_processed_created_at_day": int(day_component),
    }
    await write_runtime_state(
        db,
        key=_HIGH_WATER_MARK_KEY,
        payload=payload,
        bundle=bundle,
    )
    return HighWaterMark(
        backfilled_through_boltz_swap_id_ordering=int(new_ordering),
        backfilled_at_unix_s=float(n),
        max_processed_created_at_day=int(day_component),
    )


class BoltzSwapSequenceRegressionError(RuntimeError):
    """Refused to start under a sequence regression."""


def assert_no_sequence_regression(
    *,
    current_max_boltz_swap_id: int,
    hwm: HighWaterMark,
    override_allowed: bool | None = None,
) -> None:
    """Startup sequence-regression gate.

    A backup-restore that produces ``MAX(boltz_swap.id) < HWM.id`` is
    a strong signal of a database rewind: the backfill loop would
    otherwise skip every row whose ID falls between the rewound
    ``MAX`` and the persisted HWM, leaving refund-labels permanently
    missing for that range.

    The gate refuses to start unless
    ``ALLOW_BOLTZ_SWAP_SEQUENCE_REGRESSION=true`` is set for the
    boot (operator-acknowledged restore). The orchestrator's first
    pass after that one-shot override rewrites the HWM from a full-
    table scan.
    """
    if current_max_boltz_swap_id >= hwm.backfilled_through_boltz_swap_id_ordering:
        return  # no regression
    if override_allowed is None:
        override_allowed = bool(settings.allow_boltz_swap_sequence_regression)
    if override_allowed:
        return  # operator-acknowledged
    raise BoltzSwapSequenceRegressionError(
        f"boltz_swap sequence regression detected: "
        f"MAX(id)={current_max_boltz_swap_id} < HWM.id="
        f"{hwm.backfilled_through_boltz_swap_id_ordering}. "
        "Set ALLOW_BOLTZ_SWAP_SEQUENCE_REGRESSION=true for one boot "
        "to rewrite the HWM from a full-table scan."
    )


@dataclass(frozen=True)
class AntiOrphanScanWindow:
    """The (id, created_at_day) window the anti-orphan sweep scans.

    The sweep targets rows ``id <= max_processed_id AND refund_label
    IS NULL AND status IN failed_terminal_states AND created_at >=
    max_processed_created_at_day - slack_days``. ``slack_days`` is 1
    by default so a swap that committed just before the previous
    boot's HWM-write still gets re-checked.
    """

    max_processed_id: int
    earliest_created_at_day: int  # YYYYMMDD, inclusive lower bound


def build_anti_orphan_scan_window(
    hwm: HighWaterMark,
    *,
    slack_days: int = 1,
) -> AntiOrphanScanWindow:
    """Compute the anti-orphan scan window from a HWM."""
    if hwm.max_processed_created_at_day <= 0:
        # Fresh deployment — no orphan window to scan.
        return AntiOrphanScanWindow(
            max_processed_id=hwm.backfilled_through_boltz_swap_id_ordering,
            earliest_created_at_day=0,
        )
    return AntiOrphanScanWindow(
        max_processed_id=hwm.backfilled_through_boltz_swap_id_ordering,
        # Subtract slack_days. Days are YYYYMMDD ints; the orchestrator
        # converts back to a date for the actual query. Simple
        # subtraction is fine for slack=1 day intra-month; the loop
        # uses a real date-arithmetic when slack spans a month boundary.
        earliest_created_at_day=hwm.max_processed_created_at_day - slack_days,
    )


__all__ = [
    "HighWaterMark",
    "AntiOrphanScanWindow",
    "BoltzSwapSequenceRegressionError",
    "read_high_water_mark",
    "update_high_water_mark",
    "assert_no_sequence_regression",
    "build_anti_orphan_scan_window",
]
