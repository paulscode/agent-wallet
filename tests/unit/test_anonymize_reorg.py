# SPDX-License-Identifier: MIT
"""/ items 27 + 55 — reorg-aware completion decision.

The pure-helper layer maps a confirmation observation to a state-
machine decision. The schema fields and orchestrator wiring will
read this helper exclusively so the decision contract stays in one
place.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeStatus
from app.services.anonymize.reorg import (
    ConfirmationObservation,
    decide_terminal_state,
    map_decision_to_status,
)


def test_decision_is_completed_when_depth_at_min(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_min_confirmations", 2)
    obs = ConfirmationObservation(current_depth=2, max_depth_seen=2, reorg_count=0)
    assert decide_terminal_state(obs) == "completed"


def test_decision_stays_confirming_below_min(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_min_confirmations", 2)
    obs = ConfirmationObservation(current_depth=1, max_depth_seen=1, reorg_count=0)
    assert decide_terminal_state(obs) == "stay_confirming"


def test_decision_uncertain_after_giveup(monkeypatch) -> None:
    """Completed_with_reorg_uncertainty when churn ≥ giveup AND we have seen depth ≥ 1."""
    monkeypatch.setattr(settings, "anonymize_claim_min_confirmations", 2)
    monkeypatch.setattr(settings, "anonymize_claim_reorg_giveup_blocks", 12)
    obs = ConfirmationObservation(current_depth=0, max_depth_seen=1, reorg_count=12)
    assert decide_terminal_state(obs) == "completed_with_reorg_uncertainty"


def test_decision_failed_when_never_mined(monkeypatch) -> None:
    """No max_depth_seen + giveup churn means we never saw the tx mine."""
    monkeypatch.setattr(settings, "anonymize_claim_min_confirmations", 2)
    monkeypatch.setattr(settings, "anonymize_claim_reorg_giveup_blocks", 12)
    obs = ConfirmationObservation(current_depth=-1, max_depth_seen=0, reorg_count=12)
    assert decide_terminal_state(obs) == "failed_no_chain_record"


def test_map_decision_to_status() -> None:
    assert map_decision_to_status("stay_confirming") is None
    assert map_decision_to_status("completed") == AnonymizeStatus.COMPLETED.value
    assert (
        map_decision_to_status("completed_with_reorg_uncertainty")
        == AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value
    )
    assert map_decision_to_status("failed_no_chain_record") == AnonymizeStatus.FAILED.value


def test_map_decision_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown ReorgDecision"):
        map_decision_to_status("not-a-decision")  # type: ignore[arg-type]
