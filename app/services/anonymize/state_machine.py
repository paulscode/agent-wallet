# SPDX-License-Identifier: MIT
"""Anonymize session state machine.

A pure-data encoding of the allowed transitions plus a small set of
predicate helpers the orchestrator (and tests) use to decide whether
a given mutation is a legal state-machine step.

The full per-state execution lives in :mod:`app.services.anonymize.service`
which calls into the hop-specific modules under
:mod:`app.services.anonymize.hops`. This module is intentionally
free of side-effects so the transition graph can be exercised by
unit tests without standing up the full orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable

from app.models.anonymize_session import (
    ANONYMIZE_TERMINAL_STATUSES,
    AnonymizeStatus,
)

# The canonical transition graph.
#
# Read as: ``from_status → {legal next_status}``. The orchestrator
# never bypasses this graph; every state-mutating write goes through
# :func:`assert_legal_transition` so a regression that adds a new
# transition without updating the table is caught immediately.
_TRANSITIONS: dict[str, frozenset[str]] = {
    AnonymizeStatus.CREATED.value: frozenset(
        {
            AnonymizeStatus.SOURCING.value,
            AnonymizeStatus.FUNDING.value,  # ln-self path skips sourcing
            AnonymizeStatus.CANCELLED.value,
            AnonymizeStatus.FAILED.value,
        }
    ),
    AnonymizeStatus.SOURCING.value: frozenset(
        {
            AnonymizeStatus.FUNDING.value,
            AnonymizeStatus.LN_HOLDING.value,  # ext-lightning short-circuit
            AnonymizeStatus.CANCELLED.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.FUNDING.value: frozenset(
        {
            AnonymizeStatus.LN_HOLDING.value,
            AnonymizeStatus.DELAYING.value,
            AnonymizeStatus.CANCELLED.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.LN_HOLDING.value: frozenset(
        {
            AnonymizeStatus.DELAYING.value,
            AnonymizeStatus.HOPPING.value,
            AnonymizeStatus.REFUNDING.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.DELAYING.value: frozenset(
        {
            AnonymizeStatus.HOPPING.value,
            AnonymizeStatus.EXITING.value,
            AnonymizeStatus.REFUNDING.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.HOPPING.value: frozenset(
        {
            AnonymizeStatus.DELAYING.value,  # next inter-leg delay
            AnonymizeStatus.EXITING.value,
            AnonymizeStatus.REFUNDING.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
            AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        }
    ),
    AnonymizeStatus.EXITING.value: frozenset(
        {
            AnonymizeStatus.CONFIRMING.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.CONFIRMING.value: frozenset(
        {
            AnonymizeStatus.COMPLETED.value,
            AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.AWAITING_RECONCILIATION.value: frozenset(
        {
            # Reconciliation can re-enter the live path or escalate to failed.
            AnonymizeStatus.HOPPING.value,
            AnonymizeStatus.EXITING.value,
            AnonymizeStatus.CONFIRMING.value,
            AnonymizeStatus.COMPLETED.value,
            AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value,
            AnonymizeStatus.REFUNDING.value,
            AnonymizeStatus.FAILED.value,
            # User-initiated Cancel for no-funds-moved reasons.
            # The reason classifier (reconciliation_classify.is_cancellable)
            # gates which reasons can take this edge; the state machine
            # itself only checks legality, so the gating happens at the
            # endpoint layer.
            AnonymizeStatus.CANCELLED.value,
        }
    ),
    AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value: frozenset(
        {
            AnonymizeStatus.COMPLETED.value,
            AnonymizeStatus.FAILED.value,
        }
    ),
    AnonymizeStatus.AWAITING_LIQUID_DWELL.value: frozenset(
        {
            AnonymizeStatus.HOPPING.value,
            AnonymizeStatus.DELAYING.value,
            AnonymizeStatus.EXITING.value,
            AnonymizeStatus.REFUNDING.value,
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    AnonymizeStatus.REFUNDING.value: frozenset(
        {
            AnonymizeStatus.FAILED.value,
            AnonymizeStatus.AWAITING_RECONCILIATION.value,
        }
    ),
    # Terminal statuses — no outgoing edges.
    AnonymizeStatus.COMPLETED.value: frozenset(),
    AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value: frozenset(),
    AnonymizeStatus.CANCELLED.value: frozenset(),
    AnonymizeStatus.FAILED.value: frozenset(),
}


class IllegalStateTransitionError(ValueError):
    """Raised when the orchestrator attempts a transition not in the graph."""


def is_terminal(status: str) -> bool:
    """True iff ``status`` admits no outgoing transitions."""
    return status in ANONYMIZE_TERMINAL_STATUSES


def legal_next_statuses(from_status: str) -> FrozenSet[str]:
    """Return the set of statuses ``from_status`` may transition to."""
    return _TRANSITIONS.get(from_status, frozenset())


def is_legal_transition(*, from_status: str, to_status: str) -> bool:
    """Pure predicate — does the graph allow this edge?"""
    if from_status == to_status:
        # Idempotent re-write is always allowed (e.g., a retry that
        # observes the persisted state already matches the target).
        return True
    return to_status in legal_next_statuses(from_status)


def assert_legal_transition(*, from_status: str, to_status: str) -> None:
    """Raise :class:`IllegalStateTransitionError` on a graph violation."""
    if not is_legal_transition(from_status=from_status, to_status=to_status):
        raise IllegalStateTransitionError(
            f"{from_status!r} → {to_status!r} is not in the transition graph; "
            f"legal next statuses are: {sorted(legal_next_statuses(from_status))}"
        )


def all_known_statuses() -> tuple[str, ...]:
    """Every status known to the graph (including terminals)."""
    return tuple(sorted(_TRANSITIONS.keys()))


def assert_graph_covers_every_enum_value() -> None:
    """Startup invariant: every ``AnonymizeStatus`` enum value has a row."""
    known = set(_TRANSITIONS.keys())
    enum_values = {s.value for s in AnonymizeStatus}
    missing = enum_values - known
    if missing:
        raise RuntimeError(
            f"state machine missing rows for: {sorted(missing)}. Update _TRANSITIONS in state_machine.py."
        )
    spurious = known - enum_values
    if spurious:
        raise RuntimeError(
            f"state machine has rows for unknown statuses: {sorted(spurious)}. "
            "Drop them from _TRANSITIONS in state_machine.py."
        )


@dataclass(frozen=True)
class TransitionAttempt:
    """A proposed state-machine step the orchestrator records before applying."""

    session_id: str
    from_status: str
    to_status: str
    reason: str  # short tag for the audit event; never the full payload


def validate_attempts(attempts: Iterable[TransitionAttempt]) -> None:
    """Validate a batch of transitions in one call (e.g., on reconciliation).

    All-or-nothing: if any attempt is illegal, the entire batch is
    rejected and the orchestrator does not begin applying any of them.
    """
    for a in attempts:
        assert_legal_transition(from_status=a.from_status, to_status=a.to_status)


__all__ = [
    "IllegalStateTransitionError",
    "TransitionAttempt",
    "all_known_statuses",
    "assert_graph_covers_every_enum_value",
    "assert_legal_transition",
    "is_legal_transition",
    "is_terminal",
    "legal_next_statuses",
    "validate_attempts",
]
