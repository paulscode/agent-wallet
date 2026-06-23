# SPDX-License-Identifier: MIT
"""Tests for the recovery classifier (``app.services.boltz_recovery``).

The classifier is a pure function — all inputs are passed by argument
and no DB/network access happens — so these tests construct
``BoltzSwap`` instances in-memory and assert on the returned
``RecoveryHint``.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
from app.services.boltz_recovery import (
    ACTION_COOPERATIVE_CLAIM,
    ACTION_LIQUID_COOPERATIVE_REFUND,
    ACTION_LIQUID_REVERSE_UNILATERAL_CLAIM,
    ACTION_LIQUID_UNILATERAL_REFUND,
    ACTION_UNILATERAL_CLAIM,
    LIQUID_DWELL_STUCK_THRESHOLD_SECONDS,
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_OK,
    SEVERITY_WARNING,
    STATE_AWAITING_CLAIM,
    STATE_AWAITING_CONFIRMATIONS,
    STATE_AWAITING_LOCKUP_CONFIRMATION,
    STATE_CANCELLED,
    STATE_CLAIM_RETRY_AVAILABLE,
    STATE_COMPLETED,
    STATE_FAILED,
    STATE_IN_PROGRESS,
    STATE_REFUNDED,
    STATE_STUCK_CREATED,
    STATE_STUCK_INVOICE_PAID,
    STATE_STUCK_PAYING_INVOICE,
    STATE_TIMEOUT_IMMINENT,
    STATE_TIMEOUT_PASSED,
    STATE_TIMEOUT_WARNING,
    STATE_TRANSIENT_PAYMENT_ERROR,
    RecoveryHint,
    aggregate_recovery_hints,
    classify_recovery_state,
    classify_session_recovery_state,
)


def _now() -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_swap(
    *,
    status: SwapStatus = SwapStatus.CREATED,
    error_message: str | None = None,
    timeout_block_height: int | None = 850_000,
    claim_txid: str | None = None,
    recovery_count: int = 0,
    age_seconds: int = 1,
) -> BoltzSwap:
    now = _now()
    created_at = now - timedelta(seconds=age_seconds)
    return BoltzSwap(
        id=uuid4(),
        api_key_id=uuid4(),
        boltz_swap_id="test-rec",
        direction=BoltzSwapDirection.REVERSE,
        status=status,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        timeout_block_height=timeout_block_height,
        error_message=error_message,
        claim_txid=claim_txid,
        recovery_count=recovery_count,
        created_at=created_at,
        updated_at=created_at,
    )


class TestTerminalStates:
    def test_completed(self):
        hint = classify_recovery_state(_make_swap(status=SwapStatus.COMPLETED), now=_now())
        assert hint.state == STATE_COMPLETED
        assert hint.severity == SEVERITY_OK
        assert hint.actions == ()

    def test_failed_includes_error_message(self):
        hint = classify_recovery_state(
            _make_swap(status=SwapStatus.FAILED, error_message="Lockup expired"),
            now=_now(),
        )
        assert hint.state == STATE_FAILED
        assert hint.severity == SEVERITY_WARNING
        assert "Lockup expired" in hint.detail
        assert hint.metadata.get("error_message") == "Lockup expired"

    def test_refunded(self):
        hint = classify_recovery_state(_make_swap(status=SwapStatus.REFUNDED), now=_now())
        assert hint.state == STATE_REFUNDED
        assert hint.severity == SEVERITY_INFO

    def test_cancelled(self):
        hint = classify_recovery_state(_make_swap(status=SwapStatus.CANCELLED), now=_now())
        assert hint.state == STATE_CANCELLED
        assert hint.severity == SEVERITY_INFO


class TestClaimedPhase:
    def test_claimed_no_confs(self):
        hint = classify_recovery_state(
            _make_swap(status=SwapStatus.CLAIMED, claim_txid="abc" * 21 + "x"),
            now=_now(),
        )
        assert hint.state == STATE_AWAITING_CONFIRMATIONS
        assert hint.severity == SEVERITY_INFO

    def test_claimed_with_confs_includes_count(self):
        hint = classify_recovery_state(
            _make_swap(status=SwapStatus.CLAIMED, claim_txid="a" * 64),
            claim_confirmations=2,
            now=_now(),
        )
        assert hint.state == STATE_AWAITING_CONFIRMATIONS
        assert "2 confirmation" in hint.headline or "(2)" in hint.headline
        assert hint.metadata.get("claim_confirmations") == 2


class TestClaimingPhase:
    def test_timeout_passed_offers_unilateral(self):
        swap = _make_swap(status=SwapStatus.CLAIMING, timeout_block_height=800_000)
        hint = classify_recovery_state(swap, btc_tip_height=800_001, now=_now())
        assert hint.state == STATE_TIMEOUT_PASSED
        assert hint.severity == SEVERITY_CRITICAL
        assert ACTION_UNILATERAL_CLAIM in hint.actions

    def test_timeout_imminent_critical(self):
        swap = _make_swap(status=SwapStatus.CLAIMING, timeout_block_height=800_005)
        hint = classify_recovery_state(swap, btc_tip_height=800_000, now=_now())
        assert hint.state == STATE_TIMEOUT_IMMINENT
        assert hint.severity == SEVERITY_CRITICAL
        assert ACTION_COOPERATIVE_CLAIM in hint.actions
        assert ACTION_UNILATERAL_CLAIM not in hint.actions  # timeout not yet passed

    def test_timeout_warning_yellow(self):
        swap = _make_swap(status=SwapStatus.CLAIMING, timeout_block_height=800_020)
        hint = classify_recovery_state(swap, btc_tip_height=800_000, now=_now())
        assert hint.state == STATE_TIMEOUT_WARNING
        assert hint.severity == SEVERITY_WARNING

    def test_claim_retry_available_after_prior_failure(self):
        swap = _make_swap(
            status=SwapStatus.CLAIMING,
            recovery_count=1,
            error_message="Claim script failed: timeout",
            timeout_block_height=900_000,
        )
        hint = classify_recovery_state(swap, btc_tip_height=800_000, now=_now())
        assert hint.state == STATE_CLAIM_RETRY_AVAILABLE
        assert ACTION_COOPERATIVE_CLAIM in hint.actions
        assert hint.metadata.get("recovery_count") == 1

    def test_claiming_fresh(self):
        swap = _make_swap(status=SwapStatus.CLAIMING, timeout_block_height=900_000)
        hint = classify_recovery_state(swap, btc_tip_height=800_000, now=_now())
        assert hint.state == STATE_AWAITING_CLAIM


class TestInvoicePaidPhase:
    def test_invoice_paid_fresh(self):
        swap = _make_swap(status=SwapStatus.INVOICE_PAID, age_seconds=10)
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_AWAITING_LOCKUP_CONFIRMATION

    def test_invoice_paid_stuck(self):
        swap = _make_swap(status=SwapStatus.INVOICE_PAID, age_seconds=60 * 60)
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_STUCK_INVOICE_PAID
        assert hint.severity == SEVERITY_WARNING


class TestPayingInvoicePhase:
    def test_paying_fresh(self):
        swap = _make_swap(status=SwapStatus.PAYING_INVOICE, age_seconds=10)
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_IN_PROGRESS

    def test_paying_with_transient_error(self):
        swap = _make_swap(
            status=SwapStatus.PAYING_INVOICE,
            error_message="Payment attempt encountered a transient routing failure; retrying…",
        )
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_TRANSIENT_PAYMENT_ERROR
        assert hint.severity == SEVERITY_INFO

    def test_paying_stuck(self):
        swap = _make_swap(status=SwapStatus.PAYING_INVOICE, age_seconds=60 * 60)
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_STUCK_PAYING_INVOICE
        assert hint.severity == SEVERITY_WARNING


class TestCreatedPhase:
    def test_created_fresh(self):
        swap = _make_swap(status=SwapStatus.CREATED, age_seconds=10)
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_IN_PROGRESS

    def test_created_stuck(self):
        swap = _make_swap(status=SwapStatus.CREATED, age_seconds=60 * 60)
        hint = classify_recovery_state(swap, now=_now())
        assert hint.state == STATE_STUCK_CREATED


class TestHintSerialisation:
    def test_to_dict_shape(self):
        hint = RecoveryHint(
            state="x",
            severity="ok",
            headline="h",
            detail="d",
            actions=("a",),
            metadata={"k": 1},
        )
        d = hint.to_dict()
        assert d == {
            "state": "x",
            "severity": "ok",
            "headline": "h",
            "detail": "d",
            "actions": ["a"],
            "metadata": {"k": 1},
        }


class TestAggregateRecoveryHints:
    def _hint(self, severity: str, state: str = "s") -> RecoveryHint:
        return RecoveryHint(state=state, severity=severity, headline="h", detail="d")

    def test_empty_returns_none(self):
        assert aggregate_recovery_hints([]) is None

    def test_single_hint_returned(self):
        h = self._hint(SEVERITY_INFO, "only")
        assert aggregate_recovery_hints([h]) is h

    def test_worst_severity_wins(self):
        a = self._hint(SEVERITY_INFO, "a")
        b = self._hint(SEVERITY_CRITICAL, "b")
        c = self._hint(SEVERITY_WARNING, "c")
        result = aggregate_recovery_hints([a, b, c])
        assert result is b

    def test_tie_favors_first_caller_order(self):
        a = self._hint(SEVERITY_WARNING, "reverse")
        b = self._hint(SEVERITY_WARNING, "submarine")
        result = aggregate_recovery_hints([a, b])
        assert result is a

    def test_tie_prefers_actionable_hint(self):
        # An equally-severe informational hint must not hide an actionable
        # one — a surfaced recovery button (e.g. the session-level Liquid
        # refund/claim) wins the tie even when appended later.
        info = self._hint(SEVERITY_WARNING, "status_note")
        actionable = RecoveryHint(
            state="liquid_swap_stuck",
            severity=SEVERITY_WARNING,
            headline="h",
            detail="d",
            actions=("liquid_cooperative_refund",),
        )
        assert aggregate_recovery_hints([info, actionable]) is actionable
        # Among two actionable ties, the first still wins.
        actionable2 = RecoveryHint(
            state="other",
            severity=SEVERITY_WARNING,
            headline="h",
            detail="d",
            actions=("bump_fee",),
        )
        assert aggregate_recovery_hints([actionable, actionable2]) is actionable

    def test_ok_severity_treated_as_lowest(self):
        a = self._hint(SEVERITY_OK, "ok")
        b = self._hint(SEVERITY_INFO, "info")
        result = aggregate_recovery_hints([a, b])
        assert result is b


class TestClassifySessionRecoveryState:
    def _now(self) -> datetime:
        return datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    def test_non_dwell_status_returns_none(self):
        result = classify_session_recovery_state(
            status="funding",
            updated_at=self._now() - timedelta(days=2),
            now=self._now(),
        )
        assert result is None

    def test_dwell_fresh_returns_none(self):
        # Just-entered the dwell — well under threshold.
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=1),
            now=self._now(),
        )
        assert result is None

    def test_dwell_stuck_indexer_reachable_generic_copy(self):
        # 26h since update; default threshold is 25h.
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=26),
            liquid_indexer_reachable=True,
            now=self._now(),
        )
        assert result is not None
        assert result.state == "awaiting_liquid_dwell_stuck"
        assert result.severity == SEVERITY_WARNING
        assert "unreachable" not in result.detail
        assert result.metadata["liquid_indexer_reachable"] is True

    def test_dwell_stuck_indexer_unreachable_distinct_copy(self):
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=26),
            liquid_indexer_reachable=False,
            now=self._now(),
        )
        assert result is not None
        assert result.severity == SEVERITY_WARNING
        assert "unreachable" in result.detail
        assert result.metadata["liquid_indexer_reachable"] is False

    def test_dwell_threshold_honors_pipeline_override(self):
        # Pipeline says max dwell 2h, so threshold becomes 3h. Age 4h
        # should fire.
        pipeline = {"liquid": {"dwell_max_seconds": 2 * 3600}}
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=4),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is not None
        assert result.metadata["dwell_threshold_seconds"] == 3 * 3600

    def test_dwell_below_pipeline_override_returns_none(self):
        # Override extends the threshold to 49h (48h + 1h grace).
        # Age 26h is well under that even though it would exceed the
        # 25h fallback.
        pipeline = {"liquid": {"dwell_max_seconds": 48 * 3600}}
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=26),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is None

    def test_fallback_threshold_constant(self):
        # Sanity-check the constant matches docs (24h max + 1h
        # grace).
        assert LIQUID_DWELL_STUCK_THRESHOLD_SECONDS == 25 * 3600

    def test_lockup_stuck_offers_refund_actions(self):
        # A present leg-2 submarine lockup that hasn't settled is
        # refundable: short (1h) threshold + cooperative/unilateral
        # refund actions surfaced so the operator can recover from the UI.
        pipeline = {"liquid_submarine_lock_txid": "abcd" * 16}
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=2),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is not None
        assert result.state == "awaiting_liquid_dwell_stuck"
        assert list(result.actions) == [
            ACTION_LIQUID_COOPERATIVE_REFUND,
            ACTION_LIQUID_UNILATERAL_REFUND,
        ]
        assert "refund" in result.detail.lower()
        assert result.metadata["liquid_submarine_lockup_present"] is True

    def test_lockup_below_short_threshold_returns_none(self):
        # The lockup short threshold is 1h; 30 min in is not yet stuck.
        pipeline = {"liquid_submarine_lock_txid": "abcd" * 16}
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(minutes=30),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is None

    def test_dwell_without_lockup_has_no_refund_actions(self):
        # Plain dwell-stuck (no leg-2 lockup) keeps the auto-resume copy
        # and offers no refund buttons.
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=26),
            liquid_indexer_reachable=True,
            now=self._now(),
        )
        assert result is not None
        assert result.actions == ()
        assert result.metadata["liquid_submarine_lockup_present"] is False

    def test_hopping_leg1_claim_stuck_offers_unilateral_claim(self):
        # Leg-1 reverse claim broadcast (preimage revealed) but unconfirmed
        # for >1h → surface the post-timeout unilateral claim.
        pipeline = {"liquid_lbtc_claim_txid": "abcd" * 16}
        result = classify_session_recovery_state(
            status="hopping",
            updated_at=self._now() - timedelta(hours=2),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is not None
        assert result.state == "liquid_reverse_claim_stuck"
        assert list(result.actions) == [ACTION_LIQUID_REVERSE_UNILATERAL_CLAIM]

    def test_hopping_claim_confirmed_no_hint(self):
        pipeline = {
            "liquid_lbtc_claim_txid": "abcd" * 16,
            "liquid_lbtc_claim_confirmed": True,
        }
        result = classify_session_recovery_state(
            status="hopping",
            updated_at=self._now() - timedelta(hours=2),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is None

    def test_hopping_claim_already_unilateral_no_hint(self):
        # Once a unilateral claim was broadcast, stop re-offering it.
        pipeline = {
            "liquid_lbtc_claim_txid": "abcd" * 16,
            "liquid_reverse_unilateral_claim_txid": "ef01" * 16,
        }
        result = classify_session_recovery_state(
            status="hopping",
            updated_at=self._now() - timedelta(hours=2),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is None

    def test_hopping_claim_below_threshold_no_hint(self):
        pipeline = {"liquid_lbtc_claim_txid": "abcd" * 16}
        result = classify_session_recovery_state(
            status="hopping",
            updated_at=self._now() - timedelta(minutes=30),
            pipeline_json=pipeline,
            now=self._now(),
        )
        assert result is None

    def test_hopping_no_claim_broadcast_no_hint(self):
        # Plain hopping with no leg-1 claim yet → no session-level hint.
        result = classify_session_recovery_state(
            status="hopping",
            updated_at=self._now() - timedelta(hours=2),
            pipeline_json={},
            now=self._now(),
        )
        assert result is None

    def test_lockup_already_refunded_offers_no_actions(self):
        # Once a refund tx has been broadcast the lockup is spent — the
        # classifier must stop offering the refund levers (the session is
        # also terminalized, but this guards the edge where it isn't).
        pipeline = {
            "liquid_submarine_lock_txid": "abcd" * 16,
            "liquid_submarine_refund_txid": "ef01" * 16,
        }
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=self._now() - timedelta(hours=2),
            pipeline_json=pipeline,
            now=self._now(),
        )
        # Not refundable anymore; the short (1h) lockup threshold no
        # longer applies, so a 2h age is below the normal-dwell threshold
        # and no hint fires.
        assert result is None

    def test_missing_updated_at_returns_none(self):
        result = classify_session_recovery_state(
            status="awaiting_liquid_dwell",
            updated_at=None,
            now=self._now(),
        )
        assert result is None
