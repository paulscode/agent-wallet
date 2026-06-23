# SPDX-License-Identifier: MIT
"""Unit tests for the ``BraiinsDepositSession`` model itself.

Pins behavior on the model that the service relies on:
  * ``record_transition`` appends to ``status_history`` and sets
    ``completed_at`` on the COMPLETED transition.
  * The enum has the 9 documented states.
  * ``NON_TERMINAL_STATUSES`` / ``TERMINAL_STATUSES`` frozensets have
    the cardinalities the orchestrator + recovery scan rely on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.models.braiins_deposit_session import (
    NON_TERMINAL_STATUSES,
    TERMINAL_STATUSES,
    BraiinsDepositSession,
    BraiinsDepositStatus,
)


class TestStatusEnum:
    def test_fourteen_states(self):
        """The full lifecycle spans 14 states: the Lightning
        self-source baseline; SUBMARINE_SWAPPING for the on-chain
        source path; AWAITING_LN_FUNDS and AWAITING_ONCHAIN_FUNDS for
        the external-source flows; AWAITING_FEE_REDUCTION for the
        dust-prevention stuck-at-send recovery path; and
        OPENING_CHANNEL for the channel-open alternative. 14 total.
        """
        names = {s.value for s in BraiinsDepositStatus}
        assert names == {
            "created",
            "awaiting_ln_funds",
            "awaiting_onchain_funds",
            "submarine_swapping",
            "opening_channel",
            "swapping",
            "funded",
            "sending",
            "awaiting_fee_reduction",
            "broadcast",
            "completed",
            "refunded",
            "failed",
            "cancelled",
        }

    def test_non_terminal_set(self):
        assert {s.value for s in NON_TERMINAL_STATUSES} == {
            "created",
            "awaiting_ln_funds",
            "awaiting_onchain_funds",
            "submarine_swapping",
            "opening_channel",
            "swapping",
            "funded",
            "sending",
            "awaiting_fee_reduction",
            "broadcast",
        }

    def test_terminal_set(self):
        assert {s.value for s in TERMINAL_STATUSES} == {
            "completed",
            "refunded",
            "failed",
            "cancelled",
        }

    def test_terminal_and_non_terminal_partition_the_enum(self):
        """No state should be in both sets; together they should
        cover every status value."""
        overlap = NON_TERMINAL_STATUSES & TERMINAL_STATUSES
        assert overlap == frozenset()
        all_states = set(BraiinsDepositStatus)
        assert (NON_TERMINAL_STATUSES | TERMINAL_STATUSES) == all_states


class TestRecordTransition:
    def _new_session(self, **overrides):
        defaults = dict(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            status=BraiinsDepositStatus.CREATED,
            status_history=[],
        )
        defaults.update(overrides)
        return BraiinsDepositSession(**defaults)

    def test_records_status_history_entry(self):
        s = self._new_session()
        s.record_transition(BraiinsDepositStatus.SWAPPING)
        assert s.status == BraiinsDepositStatus.SWAPPING
        assert len(s.status_history) == 1
        entry = s.status_history[0]
        assert entry["status"] == "swapping"
        assert "timestamp" in entry

    def test_appends_to_existing_history(self):
        existing = [{"status": "created", "timestamp": "2026-05-18T00:00:00+00:00"}]
        s = self._new_session(status_history=list(existing))
        s.record_transition(BraiinsDepositStatus.SWAPPING)
        assert len(s.status_history) == 2
        assert s.status_history[0] == existing[0]
        assert s.status_history[1]["status"] == "swapping"

    def test_includes_detail_when_supplied(self):
        s = self._new_session()
        s.record_transition(BraiinsDepositStatus.SWAPPING, detail="boltz=xyz")
        assert s.status_history[0]["detail"] == "boltz=xyz"

    def test_skips_detail_when_none(self):
        s = self._new_session()
        s.record_transition(BraiinsDepositStatus.SWAPPING, detail=None)
        assert "detail" not in s.status_history[0]

    def test_completed_sets_completed_at(self):
        s = self._new_session(status=BraiinsDepositStatus.BROADCAST)
        assert s.completed_at is None
        s.record_transition(BraiinsDepositStatus.COMPLETED, detail="confs=3")
        assert s.completed_at is not None
        # The timestamp should be a recent UTC datetime.
        delta = (datetime.now(timezone.utc) - s.completed_at).total_seconds()
        assert 0 <= delta < 5

    def test_non_completed_transitions_dont_set_completed_at(self):
        s = self._new_session()
        s.record_transition(BraiinsDepositStatus.SWAPPING)
        s.record_transition(BraiinsDepositStatus.FAILED, detail="boltz error")
        assert s.completed_at is None

    def test_status_history_none_is_initialised(self):
        """A row with no status_history (e.g. fresh insert) still
        records correctly."""
        s = self._new_session(status_history=None)
        s.record_transition(BraiinsDepositStatus.SWAPPING)
        assert s.status_history is not None
        assert len(s.status_history) == 1


class TestListViewFieldPin:
    """Pin the field set the Braiins Deposit *tab* (the deposits list)
    depends on.

    The tab renders each row using these columns. A future schema
    refactor that renames or drops one would silently break the tab;
    this test fails fast instead.
    """

    REQUIRED_FIELDS = (
        # Identity + state
        "id",
        "status",
        "source_kind",
        "deposit_amount_sats",
        "destination_address",
        # Timestamps
        "created_at",
        "updated_at",
        "completed_at",
        # Pipeline txids surfaced in the row + mempool links
        "submarine_funding_txid",
        "fresh_utxo_txid",
        "send_txid",
        "send_confirmations",
        "refund_txid",
        # Error surface
        "error_message",
        "status_history",
    )

    def test_model_has_fields_list_view_needs(self):
        for field in self.REQUIRED_FIELDS:
            assert hasattr(BraiinsDepositSession, field), (
                f"BraiinsDepositSession is missing field {field!r} that the deposits-list tab template depends on."
            )
