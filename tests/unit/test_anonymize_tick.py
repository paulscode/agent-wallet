# SPDX-License-Identifier: MIT
"""Per-session tick dispatcher."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.service import (
    AnonymizeService,
    reset_anonymize_service,
)
from app.services.anonymize.tick import (
    TickObservations,
    decide_tick_action,
    filter_to_legal_target,
)


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _session(*, status: str, source_kind: str = "ext-lightning") -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind=source_kind,
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


# ── Terminal / wait base cases ───────────────────────────────────────


def test_terminal_session_returns_noop() -> None:
    s = _session(status=AnonymizeStatus.COMPLETED.value)
    out = decide_tick_action(s, TickObservations())
    assert out.kind == "noop_terminal"


def test_failed_session_returns_noop() -> None:
    s = _session(status=AnonymizeStatus.FAILED.value)
    out = decide_tick_action(s, TickObservations())
    assert out.kind == "noop_terminal"


def test_funding_with_no_observations_waits() -> None:
    s = _session(status=AnonymizeStatus.FUNDING.value)
    out = decide_tick_action(s, TickObservations())
    assert out.kind == "wait"


# ── CREATED forward-dispatch (per source kind) ───────────────────────


def test_created_onchain_self_dispatches_to_sourcing() -> None:
    # On-chain sources have no inbound invoice to settle at CREATED, so
    # they advance to SOURCING (where the submarine hop issues the swap
    # and broadcasts the wallet's funding). Without this they wedge at
    # CREATED forever — the on-chain observer emits nothing pre-SOURCING.
    s = _session(status=AnonymizeStatus.CREATED.value, source_kind="onchain-self")
    out = decide_tick_action(s, TickObservations())
    assert out.kind == "transition"
    assert out.to_status == AnonymizeStatus.SOURCING.value


def test_created_ext_onchain_dispatches_to_sourcing() -> None:
    s = _session(status=AnonymizeStatus.CREATED.value, source_kind="ext-onchain")
    out = decide_tick_action(s, TickObservations())
    assert out.kind == "transition"
    assert out.to_status == AnonymizeStatus.SOURCING.value


def test_created_ln_self_advances_to_funding_on_settle() -> None:
    # Invoice-funded sources skip SOURCING and jump to FUNDING the
    # moment the funding invoice settles.
    s = _session(status=AnonymizeStatus.CREATED.value, source_kind="lightning-self")
    out = decide_tick_action(s, TickObservations(funding_invoice_settled=True))
    assert out.kind == "transition"
    assert out.to_status == AnonymizeStatus.FUNDING.value


def test_created_ext_lightning_waits_until_deposit_settles() -> None:
    # ext-lightning waits at CREATED for the depositor to pay; it must
    # NOT be pushed to SOURCING (only on-chain sources go there).
    s = _session(status=AnonymizeStatus.CREATED.value, source_kind="ext-lightning")
    out = decide_tick_action(s, TickObservations())
    assert out.kind == "wait"

    settled = decide_tick_action(s, TickObservations(funding_invoice_settled=True))
    assert settled.kind == "transition"
    assert settled.to_status == AnonymizeStatus.FUNDING.value


# ── Early-exit branches ──────────────────────────────────────────────


def test_fatal_error_routes_to_failed_from_funding() -> None:
    s = _session(status=AnonymizeStatus.FUNDING.value)
    out = decide_tick_action(s, TickObservations(fatal_error_kind="boltz_oom"))
    assert out.kind == "fail"
    assert out.to_status == AnonymizeStatus.FAILED.value
    assert "boltz_oom" in out.reason


def test_reconcile_signal_routes_to_awaiting_reconciliation() -> None:
    s = _session(status=AnonymizeStatus.HOPPING.value)
    out = decide_tick_action(
        s,
        TickObservations(reconcile_reason="probe_timeout"),
    )
    assert out.kind == "reconcile"
    assert out.to_status == AnonymizeStatus.AWAITING_RECONCILIATION.value


def test_user_cancel_routes_to_cancelled_only_when_legal() -> None:
    """Cancel is legal from CREATED but not from HOPPING."""
    creatable = _session(status=AnonymizeStatus.CREATED.value)
    out = decide_tick_action(
        creatable,
        TickObservations(user_cancel_requested=True),
    )
    assert out.kind == "transition"
    assert out.to_status == AnonymizeStatus.CANCELLED.value

    # From HOPPING the dispatcher ignores the cancel request — the
    # session is past the point of no return; ``refund`` is the
    # operator's path.
    hopping = _session(status=AnonymizeStatus.HOPPING.value)
    out = decide_tick_action(
        hopping,
        TickObservations(user_cancel_requested=True),
    )
    assert out.kind == "wait"


def test_user_refund_routes_to_refunding_when_legal() -> None:
    s = _session(status=AnonymizeStatus.DELAYING.value)
    out = decide_tick_action(s, TickObservations(user_refund_requested=True))
    assert out.kind == "transition"
    assert out.to_status == AnonymizeStatus.REFUNDING.value


# ── Forward-progress branches ────────────────────────────────────────


def test_funding_advances_when_invoice_settles() -> None:
    s = _session(status=AnonymizeStatus.FUNDING.value)
    out = decide_tick_action(
        s,
        TickObservations(funding_invoice_settled=True),
    )
    assert out.to_status == AnonymizeStatus.LN_HOLDING.value


def test_ln_holding_advances_to_delaying() -> None:
    s = _session(status=AnonymizeStatus.LN_HOLDING.value)
    out = decide_tick_action(s, TickObservations())
    assert out.to_status == AnonymizeStatus.DELAYING.value


def test_delaying_advances_to_hopping_when_not_last() -> None:
    s = _session(status=AnonymizeStatus.DELAYING.value)
    out = decide_tick_action(
        s,
        TickObservations(delay_window_elapsed=True, is_last_hop=False),
    )
    assert out.to_status == AnonymizeStatus.HOPPING.value


def test_delaying_advances_to_exiting_when_last() -> None:
    s = _session(status=AnonymizeStatus.DELAYING.value)
    out = decide_tick_action(
        s,
        TickObservations(delay_window_elapsed=True, is_last_hop=True),
    )
    assert out.to_status == AnonymizeStatus.EXITING.value


def test_hopping_advances_to_delaying_when_not_last() -> None:
    s = _session(status=AnonymizeStatus.HOPPING.value)
    out = decide_tick_action(
        s,
        TickObservations(hop_completed=True, is_last_hop=False),
    )
    assert out.to_status == AnonymizeStatus.DELAYING.value


def test_hopping_advances_to_exiting_when_last() -> None:
    s = _session(status=AnonymizeStatus.HOPPING.value)
    out = decide_tick_action(
        s,
        TickObservations(hop_completed=True, is_last_hop=True),
    )
    assert out.to_status == AnonymizeStatus.EXITING.value


def test_exiting_advances_to_confirming_when_tx_observed() -> None:
    s = _session(status=AnonymizeStatus.EXITING.value)
    out = decide_tick_action(
        s,
        TickObservations(claim_tx_observed_on_chain=True),
    )
    assert out.to_status == AnonymizeStatus.CONFIRMING.value


def test_confirming_completes_at_min_confs() -> None:
    s = _session(status=AnonymizeStatus.CONFIRMING.value)
    out = decide_tick_action(
        s,
        TickObservations(claim_tx_min_confirmations_reached=True),
    )
    assert out.to_status == AnonymizeStatus.COMPLETED.value


def test_confirming_with_reorg_uncertainty() -> None:
    s = _session(status=AnonymizeStatus.CONFIRMING.value)
    out = decide_tick_action(
        s,
        TickObservations(claim_tx_reorg_uncertainty=True),
    )
    assert out.to_status == AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value


# ── Service integration ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tick_session_applies_transition(db_session) -> None:
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()

    action = await svc.tick_session(
        db_session,
        sess,
        TickObservations(funding_invoice_settled=True),
    )
    assert action.kind == "transition"
    assert sess.status == AnonymizeStatus.LN_HOLDING.value
    await svc.stop()


@pytest.mark.asyncio
async def test_tick_session_wait_does_not_mutate(db_session) -> None:
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    action = await svc.tick_session(db_session, sess, TickObservations())
    assert action.kind == "wait"
    assert sess.status == AnonymizeStatus.FUNDING.value
    await svc.stop()


@pytest.mark.asyncio
async def test_tick_session_terminal_is_noop(db_session) -> None:
    svc = AnonymizeService()
    await svc.start()
    sess = _session(status=AnonymizeStatus.COMPLETED.value)
    db_session.add(sess)
    await db_session.flush()
    action = await svc.tick_session(db_session, sess, TickObservations())
    assert action.kind == "noop_terminal"
    assert sess.status == AnonymizeStatus.COMPLETED.value
    await svc.stop()


# ── Race guard ───────────────────────────────────────────────────────


def test_filter_to_legal_target_returns_none_for_illegal() -> None:
    assert (
        filter_to_legal_target(
            from_status=AnonymizeStatus.CREATED.value,
            candidate=AnonymizeStatus.EXITING.value,
        )
        is None
    )


def test_filter_to_legal_target_passes_legal() -> None:
    assert (
        filter_to_legal_target(
            from_status=AnonymizeStatus.CREATED.value,
            candidate=AnonymizeStatus.FUNDING.value,
        )
        == AnonymizeStatus.FUNDING.value
    )
