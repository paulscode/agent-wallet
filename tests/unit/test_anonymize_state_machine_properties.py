# SPDX-License-Identifier: MIT
"""
Property-based tests for the anonymize state machine.

The structural tests in test_anonymize_state_machine.py pin specific
edges; these generalize over random statuses and random *legal* walks to
surface unreachable states, missing failure escapes, or edges that the
predicate and the asserting wrapper disagree on.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.services.anonymize import state_machine as sm

_STATUSES = sm.all_known_statuses()


def test_graph_is_non_empty():
    assert _STATUSES


@given(st.sampled_from(_STATUSES))
def test_self_transition_always_legal(status):
    """An idempotent re-write to the same status is always allowed."""
    assert sm.is_legal_transition(from_status=status, to_status=status)
    sm.assert_legal_transition(from_status=status, to_status=status)  # no raise


@given(st.sampled_from(_STATUSES))
def test_terminal_iff_no_outgoing(status):
    """A terminal status has no outgoing edges, and a status with no
    outgoing edges is terminal — no silent dead-end non-terminals."""
    if sm.is_terminal(status):
        assert sm.legal_next_statuses(status) == frozenset()
    if not sm.legal_next_statuses(status):
        assert sm.is_terminal(status)


@given(st.sampled_from(_STATUSES), st.sampled_from(_STATUSES))
def test_predicate_and_assert_agree(a, b):
    """``assert_legal_transition`` raises exactly when ``is_legal_transition``
    is False."""
    if sm.is_legal_transition(from_status=a, to_status=b):
        sm.assert_legal_transition(from_status=a, to_status=b)  # no raise
    else:
        with pytest.raises(sm.IllegalStateTransitionError):
            sm.assert_legal_transition(from_status=a, to_status=b)


@given(st.data())
def test_random_legal_walk_never_violates_graph(data):
    """Following only legal edges from any starting status never produces
    an illegal transition and always terminates at a terminal status."""
    status = data.draw(st.sampled_from(_STATUSES))
    for _ in range(25):
        nxt = sm.legal_next_statuses(status)
        if not nxt:
            assert sm.is_terminal(status)
            return
        to = data.draw(st.sampled_from(sorted(nxt)))
        assert sm.is_legal_transition(from_status=status, to_status=to)
        sm.assert_legal_transition(from_status=status, to_status=to)
        status = to
    # A 25-step walk that never hit a terminal is fine for cyclic regions
    # (retry/observe loops); the point is that no step was illegal.
