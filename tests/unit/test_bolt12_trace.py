# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.trace`` (T2).

Short per-payment trace_id threaded through every BOLT 12 audit
row via a ``contextvars.ContextVar``. Also exercises the
"always-set" pattern downstream consumers (HTLC subscriber,
settle watchdog) use so events can't inherit a stale id from a
prior loop iteration.
"""

from __future__ import annotations

# ── Contextvar API ──────────────────────────────────────────────


def test_trace_id_contextvar_round_trip():
    """set + get returns the same id within the same context."""
    from app.services.bolt12 import trace

    trace.set_current_trace_id("abcd1234")
    assert trace.get_current_trace_id() == "abcd1234"
    trace.set_current_trace_id(None)
    assert trace.get_current_trace_id() is None


def test_new_trace_id_is_unique():
    """Successive calls return different ids."""
    from app.services.bolt12 import trace

    ids = {trace.new_trace_id() for _ in range(50)}
    assert len(ids) == 50


# ── Row-stored trace_id reader ──────────────────────────────────


def test_trace_id_from_row_handles_missing():
    """Row without a stored trace_id returns None."""
    from app.services.bolt12 import trace

    class _StubRow:
        blinded_paths_summary = None

    assert trace.trace_id_from_row(_StubRow()) is None

    class _Row2:
        blinded_paths_summary = {"paths": []}

    assert trace.trace_id_from_row(_Row2()) is None


def test_trace_id_from_row_returns_stored():
    """Row with stored trace_id returns it."""
    from app.services.bolt12 import trace

    class _Row:
        blinded_paths_summary = {"paths": [], "trace_id": "deadbeef"}

    assert trace.trace_id_from_row(_Row()) == "deadbeef"


# ── HTLC subscriber "always-set" pattern ────────────────────────


def test_htlc_subscriber_trace_id_pattern_always_sets(monkeypatch):
    """Regression: the HTLC event handler used to set the trace_id
    contextvar ONLY when the row had a paths_summary dict — leaving
    the previous event's trace_id in place when the current event's
    row had no trace_id. Verifies the always-set pattern by
    exercising the relevant snippet directly."""
    from app.services.bolt12 import trace

    # Seed a stale trace_id from a "prior event".
    trace.set_current_trace_id("STALE123")
    assert trace.get_current_trace_id() == "STALE123"

    # Mirror the production snippet from htlc_event_subscriber.py
    matched = {
        "invoice_id": "x",
        "api_key_id": "y",
        "paths_summary": None,
    }
    paths_summary = matched.get("paths_summary")
    row_trace_id = paths_summary.get("trace_id") if isinstance(paths_summary, dict) else None
    trace.set_current_trace_id(row_trace_id)

    # The stale trace_id MUST have been cleared.
    assert trace.get_current_trace_id() is None

    trace.set_current_trace_id(None)


def test_htlc_subscriber_trace_id_pattern_uses_row_trace_id():
    """Same snippet, but when the row HAS a stored trace_id we
    pick it up instead of clearing."""
    from app.services.bolt12 import trace

    trace.set_current_trace_id("PRIOR")

    matched = {
        "invoice_id": "x",
        "api_key_id": "y",
        "paths_summary": {"trace_id": "FRESHID1", "paths": []},
    }
    paths_summary = matched.get("paths_summary")
    row_trace_id = paths_summary.get("trace_id") if isinstance(paths_summary, dict) else None
    trace.set_current_trace_id(row_trace_id)

    assert trace.get_current_trace_id() == "FRESHID1"
    trace.set_current_trace_id(None)
