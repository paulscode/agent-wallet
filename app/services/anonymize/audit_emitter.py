# SPDX-License-Identifier: MIT
"""Recurring audit-chain summary emitter.

Anonymize sessions deliberately avoid synchronous per-transition audit
rows (those would leak exact timing + state). Instead, a recurring
task aggregates terminal-state counts over bucketed windows and
emits a single ``anonymize.bucket_summary`` audit row per window with
k-anonymity suppression and per-bucket count quantization
.

This module ships:

* :func:`audit_emit_tick_due` — pure cadence decision.
* :func:`enumerate_pending_buckets` — pure enumeration of bucket
  starts the emitter needs to walk on this tick.
* :func:`build_emission_window_for_buckets` — pure aggregation across
  a list of buckets into a single :class:`WindowEmission`.

The orchestrator-facing wrapper that issues the actual
``log_dashboard_action`` call against the global tamper-evident
audit chain lives alongside the recurring-task scheduler; it
consumes these pure helpers.
"""

from __future__ import annotations

import time as _time
from dataclasses import dataclass
from typing import Iterable

from app.core.config import settings

from .audit_summary import (
    BucketSummary,
    WindowEmission,
    aggregate_window_emission,
)


def audit_emit_tick_due(
    *,
    last_emit_at_unix_s: float | None,
    interval_s: int | None = None,
    now_unix_s: float | None = None,
) -> bool:
    """Pure decision: should the audit-emit task fire now?

    Defaults to one tick per ``ANONYMIZE_AUDIT_BUCKET_S``.  A fresh
    deployment (``last_emit_at_unix_s is None``) fires immediately so
    the first interval doesn't go unaudited.
    """
    if last_emit_at_unix_s is None:
        return True
    cadence = int(interval_s) if interval_s is not None else int(settings.anonymize_audit_bucket_s)
    if cadence <= 0:
        return True
    now = now_unix_s if now_unix_s is not None else _time.time()
    return (now - float(last_emit_at_unix_s)) >= float(cadence)


def enumerate_pending_buckets(
    *,
    last_emitted_bucket_start_unix_s: int | None,
    now_unix_s: float | None = None,
    bucket_seconds: int | None = None,
    emit_jitter_s: int | None = None,
) -> list[int]:
    """Return bucket starts the emitter must walk.

    Algorithm:

    * The *cutoff* — the latest bucket eligible for emission — is the
      one ending strictly before
      ``now - ANONYMIZE_AUDIT_BUCKET_EMIT_JITTER_S``. The jitter
      buffer guarantees the bucket has settled and removes the
      timing-side-channel between bucket-end-of-life and audit-emit.
    * Walk from ``last_emitted + bucket_seconds`` up to the cutoff,
      stepping by ``bucket_seconds``. Fresh deployment starts one
      bucket back.

    Returns the list in ascending order. Empty list ⇒ nothing to do
    this tick.
    """
    bucket_s = int(bucket_seconds) if bucket_seconds is not None else int(settings.anonymize_audit_bucket_s)
    if bucket_s <= 0:
        return []
    jitter = int(emit_jitter_s) if emit_jitter_s is not None else int(settings.anonymize_audit_bucket_emit_jitter_s)
    now = now_unix_s if now_unix_s is not None else _time.time()

    # The latest bucket whose end is past the jitter cutoff.
    cutoff = int(now - max(0, jitter))
    # Find the largest bucket_start such that bucket_start + bucket_s <= cutoff.
    latest_bucket_start = (cutoff // bucket_s) * bucket_s - bucket_s
    if latest_bucket_start < 0:
        return []

    if last_emitted_bucket_start_unix_s is None:
        first = latest_bucket_start  # emit just the latest on fresh deploy
    else:
        first = int(last_emitted_bucket_start_unix_s) + bucket_s

    if first > latest_bucket_start:
        return []
    return list(range(first, latest_bucket_start + 1, bucket_s))


def build_emission_window_for_buckets(
    summaries: Iterable[BucketSummary],
    *,
    window_start_unix_s: int,
    window_end_unix_s: int,
) -> WindowEmission:
    """Aggregate a list of per-bucket summaries into one window emission.

    Thin wrapper around :func:`aggregate_window_emission` so callers
    can keep their orchestrator-side imports narrow.
    """
    return aggregate_window_emission(
        list(summaries),
        window_start_unix_s=window_start_unix_s,
        window_end_unix_s=window_end_unix_s,
    )


@dataclass(frozen=True)
class AuditEmitOutcome:
    """One per-tick result the orchestrator records.

    ``emitted_window`` is ``None`` when the tick decided there were
    no buckets ready (cadence not yet elapsed or jitter buffer not
    cleared). When non-None, the orchestrator passes it to the audit
    chain writer and bumps the runtime_state high-water mark.
    """

    pending_bucket_starts: list[int]
    emitted_window: WindowEmission | None


__all__ = [
    "AuditEmitOutcome",
    "audit_emit_tick_due",
    "enumerate_pending_buckets",
    "build_emission_window_for_buckets",
]
