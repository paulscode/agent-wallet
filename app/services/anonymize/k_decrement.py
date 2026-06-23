# SPDX-License-Identifier: MIT
"""Persisted strict-K decrement counter.

 brittleness A: the strict-mode K-fallback decision
needs to know how many decrements the *current session* has already
spent. Without persistence, an orchestrator restart mid-fallback
would forget the prior decrement and let the session decrement again
— defeating the single-decrement bound.

The session schema includes ``anonymize_session.k_decrements_used``
(migration 016 + 019). This module exposes the increment + read
helpers so the orchestrator's reverse-leg routing path persists each
decrement inside the row-locked transaction.

 brittleness B: the fallback mode is frozen at session-create
into ``pipeline_json.reverse_payment_mpp_fallback_mode``. A mid-flight
config flip MUST NOT change a session's behavior; the helper reads the
frozen value via :func:`get_frozen_fallback_mode`.
"""

from __future__ import annotations

from typing import Literal, cast

from app.models.anonymize_session import AnonymizeSession

FallbackMode = Literal["strict", "abort_below_min", "legacy"]


def increment_k_decrements_used(session: AnonymizeSession) -> int:
    """Increment ``session.k_decrements_used`` and return the new value.

    The orchestrator wraps this in its row-locked transaction so a
    concurrent reverse-leg attempt cannot double-decrement.
    """
    if session.k_decrements_used is None:
        session.k_decrements_used = 0
    session.k_decrements_used += 1
    return int(session.k_decrements_used)


def get_k_decrements_used(session: AnonymizeSession) -> int:
    """Return ``session.k_decrements_used`` (defaulting to 0)."""
    return int(session.k_decrements_used or 0)


def get_frozen_fallback_mode(session: AnonymizeSession) -> FallbackMode:
    """Read the frozen fallback mode from the pipeline_json.

    Falls back to the configured default when the row was created
    before the fallback-mode field existed (forward-compat for
    pre sessions).
    """
    pipeline = session.pipeline_json or {}
    if isinstance(pipeline, dict):
        mode = pipeline.get("reverse_payment_mpp_fallback_mode")
        if mode in ("strict", "abort_below_min", "legacy"):
            return cast(FallbackMode, mode)
    from app.core.config import settings as _settings

    cfg = _settings.anonymize_reverse_mpp_fallback_mode
    if cfg in ("strict", "abort_below_min", "legacy"):
        return cfg  # type: ignore[return-value]
    return "strict"


__all__ = [
    "FallbackMode",
    "increment_k_decrements_used",
    "get_k_decrements_used",
    "get_frozen_fallback_mode",
]
