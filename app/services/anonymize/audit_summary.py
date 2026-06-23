# SPDX-License-Identifier: MIT
"""Audit-summary scaffold.

The wallet forbids synchronous tamper-evident-audit rows for sensitive
state transitions (``delaying``, ``hopping``, ``exiting``,
``confirming``, ``completed``). Instead a periodic summarizer emits
delayed coarse bucket rows of the form
``anonymize.bucket_summary { bucket_start_rounded, bucket_seconds,
counts_by_terminal_state, counts_by_source_kind }``.

For low-volume operators a single completed session in a
bucket would re-leak per-session existence. Mitigation:

* Suppress any bucket whose total count is below
  ``ANONYMIZE_AUDIT_MIN_BUCKET_COUNT`` (default 5).
* Quantize counts to a public bucket set:
  ``{"0", "1-3", "4-10", "11-30", "30+"}`` so a bucket of exactly 1
  reports as ``"1-3"``.
* When buckets are suppressed, emit a single
  per-window ``had_suppressed_buckets`` boolean rather than a
  per-bucket marker (the latter re-introduces the longitudinal
  channel the suppression is meant to defeat).

This module ships the pure-helper layer (bucket-time rounding,
count quantization, suppression decision); the actual emission to
the audit chain lands alongside the orchestrator's recurring task.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Mapping

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# public bucket set. Bins are intentionally coarse — anything
# less than ``MIN_BUCKET_COUNT`` is suppressed wholesale, so the
# smallest reported value is ``1-3``.
QUANTIZED_BUCKET_LABELS: tuple[tuple[int, str], ...] = (
    (3, "1-3"),
    (10, "4-10"),
    (30, "11-30"),
    (10**18, "30+"),
)


def quantize_count(count: int) -> str:
    """Map a session count to its public bucket label."""
    if count <= 0:
        return "0"
    for upper, label in QUANTIZED_BUCKET_LABELS:
        if count <= upper:
            return label
    return "30+"


def round_to_bucket_start_unix_s(
    ts_unix_s: int | float,
    *,
    bucket_seconds: int | None = None,
) -> int:
    """Round ``ts_unix_s`` down to the start of its bucket window."""
    bucket = bucket_seconds if bucket_seconds is not None else int(settings.anonymize_audit_bucket_s)
    if bucket <= 0:
        bucket = 3600
    return (int(ts_unix_s) // bucket) * bucket


@dataclass(frozen=True)
class BucketSummary:
    """Output shape of a single audit-bucket emission."""

    bucket_start_unix_s: int
    bucket_seconds: int
    suppressed: bool
    counts_by_terminal_state: dict[str, str]  # quantized labels
    counts_by_source_kind: dict[str, str]  # quantized labels
    raw_total: int  # not emitted; debug-only


@dataclass
class WindowEmission:
    """Aggregated emission for an audit window across all buckets.

    When ``ANONYMIZE_AUDIT_PER_BUCKET_SUPPRESSION_MARKERS``
    is False (default) the window emits a single
    ``had_suppressed_buckets`` boolean instead of a per-bucket
    suppression marker.
    """

    window_start_unix_s: int
    window_end_unix_s: int
    summaries: list[BucketSummary] = field(default_factory=list)
    had_suppressed_buckets: bool = False


def build_bucket_summary(
    *,
    bucket_start_unix_s: int,
    bucket_seconds: int,
    counts_by_terminal_state: Mapping[str, int],
    counts_by_source_kind: Mapping[str, int],
    min_bucket_count: int | None = None,
) -> BucketSummary:
    """Apply k-anonymity suppression + quantization to a raw bucket.

    Returns a :class:`BucketSummary` with ``suppressed=True`` and
    empty count dicts when the bucket falls below the threshold.
    """
    threshold = min_bucket_count if min_bucket_count is not None else int(settings.anonymize_audit_min_bucket_count)
    raw_total = sum(counts_by_terminal_state.values())
    if threshold > 0 and raw_total < threshold:
        return BucketSummary(
            bucket_start_unix_s=bucket_start_unix_s,
            bucket_seconds=bucket_seconds,
            suppressed=True,
            counts_by_terminal_state={},
            counts_by_source_kind={},
            raw_total=raw_total,
        )
    return BucketSummary(
        bucket_start_unix_s=bucket_start_unix_s,
        bucket_seconds=bucket_seconds,
        suppressed=False,
        counts_by_terminal_state={k: quantize_count(v) for k, v in counts_by_terminal_state.items()},
        counts_by_source_kind={k: quantize_count(v) for k, v in counts_by_source_kind.items()},
        raw_total=raw_total,
    )


def aggregate_window_emission(
    summaries: list[BucketSummary],
    *,
    window_start_unix_s: int,
    window_end_unix_s: int,
) -> WindowEmission:
    """Roll up a list of bucket summaries for a single audit window."""
    return WindowEmission(
        window_start_unix_s=window_start_unix_s,
        window_end_unix_s=window_end_unix_s,
        summaries=[s for s in summaries if not s.suppressed],
        had_suppressed_buckets=any(s.suppressed for s in summaries),
    )


# --------------------------------------------------------------------
# Audit-bucket k-anonymity emitter.
# --------------------------------------------------------------------


async def collect_session_counts_for_bucket(
    db: AsyncSession,
    *,
    bucket_start_unix_s: int,
    bucket_seconds: int,
) -> tuple[Mapping[str, int], Mapping[str, int]]:
    """Read the raw counts for one audit bucket from the DB.

    Returns ``(counts_by_terminal_state, counts_by_source_kind)``
    over sessions whose ``completed_at`` falls inside the bucket
    window. Pure read; the caller passes the result to
    :func:`build_bucket_summary` which applies the k-anonymity
    suppression and quantization.
    """
    from datetime import datetime, timezone

    from sqlalchemy import func, select

    from app.models.anonymize_session import (
        ANONYMIZE_TERMINAL_STATUSES,
        AnonymizeSession,
    )

    bucket_start = datetime.fromtimestamp(bucket_start_unix_s, tz=timezone.utc)
    bucket_end = datetime.fromtimestamp(bucket_start_unix_s + bucket_seconds, tz=timezone.utc)

    by_status: dict[str, int] = {}
    by_source: dict[str, int] = {}

    base = (
        select(AnonymizeSession.status, func.count())
        .where(AnonymizeSession.completed_at.is_not(None))
        .where(AnonymizeSession.completed_at >= bucket_start)
        .where(AnonymizeSession.completed_at < bucket_end)
        .where(AnonymizeSession.status.in_(list(ANONYMIZE_TERMINAL_STATUSES)))
        .group_by(AnonymizeSession.status)
    )
    result = await db.execute(base)
    for status, count in result.all():
        by_status[str(status)] = int(count)

    src_stmt = (
        select(AnonymizeSession.source_kind, func.count())
        .where(AnonymizeSession.completed_at.is_not(None))
        .where(AnonymizeSession.completed_at >= bucket_start)
        .where(AnonymizeSession.completed_at < bucket_end)
        .where(AnonymizeSession.status.in_(list(ANONYMIZE_TERMINAL_STATUSES)))
        .group_by(AnonymizeSession.source_kind)
    )
    src_result = await db.execute(src_stmt)
    for source_kind, count in src_result.all():
        by_source[str(source_kind)] = int(count)

    return by_status, by_source


def build_audit_payload(emission: WindowEmission) -> dict:
    """Build the ``anonymize.bucket_summary`` audit payload from a window."""
    return {
        "window_start_unix_s": emission.window_start_unix_s,
        "window_end_unix_s": emission.window_end_unix_s,
        "had_suppressed_buckets": emission.had_suppressed_buckets,
        "buckets": [
            {
                "bucket_start_unix_s": s.bucket_start_unix_s,
                "bucket_seconds": s.bucket_seconds,
                "counts_by_terminal_state": s.counts_by_terminal_state,
                "counts_by_source_kind": s.counts_by_source_kind,
            }
            for s in emission.summaries
        ],
    }


__all__ = [
    "QUANTIZED_BUCKET_LABELS",
    "BucketSummary",
    "WindowEmission",
    "quantize_count",
    "round_to_bucket_start_unix_s",
    "build_bucket_summary",
    "aggregate_window_emission",
    "collect_session_counts_for_bucket",
    "build_audit_payload",
]
