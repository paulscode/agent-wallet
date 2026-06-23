# SPDX-License-Identifier: MIT
"""State-machine graph invariants + transition validator."""

from __future__ import annotations

import pytest

from app.models.anonymize_session import AnonymizeStatus
from app.services.anonymize.state_machine import (
    IllegalStateTransitionError,
    TransitionAttempt,
    all_known_statuses,
    assert_graph_covers_every_enum_value,
    assert_legal_transition,
    is_legal_transition,
    is_terminal,
    legal_next_statuses,
    validate_attempts,
)


def test_graph_covers_every_status_value() -> None:
    """Every enum value has a row in the transition graph."""
    # No-raise.
    assert_graph_covers_every_enum_value()


def test_all_known_statuses_matches_enum() -> None:
    known = set(all_known_statuses())
    assert known == {s.value for s in AnonymizeStatus}


def test_terminals_have_no_outgoing_edges() -> None:
    for s in (
        AnonymizeStatus.COMPLETED,
        AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY,
        AnonymizeStatus.CANCELLED,
        AnonymizeStatus.FAILED,
    ):
        assert legal_next_statuses(s.value) == frozenset()
        assert is_terminal(s.value)


def test_created_to_funding_is_legal() -> None:
    """LN-self path: ``created → funding`` skips ``sourcing``."""
    assert is_legal_transition(
        from_status=AnonymizeStatus.CREATED.value,
        to_status=AnonymizeStatus.FUNDING.value,
    )


def test_created_to_completed_is_illegal() -> None:
    """A skip-the-pipeline transition is rejected."""
    assert not is_legal_transition(
        from_status=AnonymizeStatus.CREATED.value,
        to_status=AnonymizeStatus.COMPLETED.value,
    )


def test_assert_legal_transition_raises_on_illegal_edge() -> None:
    with pytest.raises(IllegalStateTransitionError, match="not in the transition graph"):
        assert_legal_transition(
            from_status=AnonymizeStatus.CREATED.value,
            to_status=AnonymizeStatus.EXITING.value,
        )


def test_idempotent_self_transition_is_legal() -> None:
    """A no-op write to the same status never raises."""
    for s in all_known_statuses():
        assert is_legal_transition(from_status=s, to_status=s)


def test_terminal_has_no_outgoing_transition() -> None:
    """``failed`` is a sink — even ``failed → cancelled`` is illegal."""
    with pytest.raises(IllegalStateTransitionError):
        assert_legal_transition(
            from_status=AnonymizeStatus.FAILED.value,
            to_status=AnonymizeStatus.CANCELLED.value,
        )


def test_awaiting_reconciliation_can_re_enter_live_path() -> None:
    """Reconciliation routes a stuck session back into the live state machine."""
    assert is_legal_transition(
        from_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        to_status=AnonymizeStatus.HOPPING.value,
    )
    assert is_legal_transition(
        from_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        to_status=AnonymizeStatus.COMPLETED.value,
    )


def test_validate_attempts_all_or_nothing() -> None:
    """A batch with one illegal entry rejects the whole batch."""
    legal = TransitionAttempt(
        session_id="a",
        from_status=AnonymizeStatus.CREATED.value,
        to_status=AnonymizeStatus.FUNDING.value,
        reason="self_pay_dispatch",
    )
    illegal = TransitionAttempt(
        session_id="b",
        from_status=AnonymizeStatus.CREATED.value,
        to_status=AnonymizeStatus.EXITING.value,  # skip-the-pipeline
        reason="bug",
    )
    with pytest.raises(IllegalStateTransitionError):
        validate_attempts([legal, illegal])


def test_every_non_terminal_has_a_failure_escape() -> None:
    """Every non-terminal state can transition to ``failed`` or
    ``awaiting_reconciliation`` so a stuck session is recoverable."""
    for s in all_known_statuses():
        if is_terminal(s):
            continue
        escapes = legal_next_statuses(s)
        assert (
            AnonymizeStatus.FAILED.value in escapes
            or AnonymizeStatus.COMPLETED.value in escapes
            or AnonymizeStatus.AWAITING_RECONCILIATION.value in escapes
        ), f"{s} has no failure-side escape"
