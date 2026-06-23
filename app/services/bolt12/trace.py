# SPDX-License-Identifier: MIT
"""T2 (2026-06-12): per-payment trace_id for audit-log correlation.

A short random ID generated at the start of each invreq flow and
threaded through every subsequent audit row for that payment.
Replaces the prior manual "grep payment_hash → find mint → get
recv_id → grep recv_id" workflow with a single short identifier
operators can copy from one row and grep across the entire flow.

Persistence: stored at mint time in ``Bolt12Invoice.blinded_paths_
summary["trace_id"]``. Subsequent observers (settle watchdog,
subscribers, reconcile) read the row's stored trace_id and emit
it in their audit details so the chain stays connected without
threading state through call sites.

Format: 8 hex chars (4 random bytes). Short enough to copy/paste
visually, large enough to avoid collisions in any reasonable
operator query window (~4.3B distinct IDs).
"""

from __future__ import annotations

import contextvars
import secrets
from typing import Any

# Context-local trace ID. Set at the start of a responder /
# subscriber / reconcile flow and read by ``_audit_inbound`` so
# every audit row in the flow gets the same trace_id without
# threading state through every call site.
_TRACE_ID_VAR: contextvars.ContextVar[str | None] = contextvars.ContextVar("bolt12_trace_id", default=None)


def set_current_trace_id(trace_id: str | None) -> None:
    """Set the trace_id for the current asyncio context. Subsequent
    ``get_current_trace_id`` calls in the same task return this
    value. Pass ``None`` to clear."""
    _TRACE_ID_VAR.set(trace_id)


def get_current_trace_id() -> str | None:
    """Read the trace_id from the current asyncio context. Returns
    ``None`` if not set."""
    return _TRACE_ID_VAR.get()


def new_trace_id() -> str:
    """Fresh 8-char hex trace ID. Suitable for one BOLT 12 flow."""
    return secrets.token_hex(4)


def trace_id_from_row(row: Any) -> str | None:
    """Read trace_id from a ``Bolt12Invoice`` row, or ``None`` if
    the row predates T2 / has no stored trace_id."""
    summary = getattr(row, "blinded_paths_summary", None)
    if isinstance(summary, dict):
        tid = summary.get("trace_id")
        if isinstance(tid, str) and tid:
            return tid
    return None


def with_trace(
    details: dict | None,
    trace_id: str | None,
) -> dict:
    """Return ``details`` with ``trace_id`` added (if both
    non-None). Safe to call with either argument None — the
    resulting dict may be empty."""
    out = dict(details or {})
    if trace_id:
        out.setdefault("trace_id", trace_id)
    return out


__all__ = [
    "get_current_trace_id",
    "new_trace_id",
    "set_current_trace_id",
    "trace_id_from_row",
    "with_trace",
]
