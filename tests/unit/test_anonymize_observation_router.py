# SPDX-License-Identifier: MIT
"""Per-source-kind observation collector dispatch."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.ln_self_pay_observe import (
    observe_ln_self_pay,
)
from app.services.anonymize.observation_router import default_observation_fn
from app.services.anonymize.tick import TickObservations


def _session(
    *,
    status: str,
    source_kind: str = "lightning-self",
    delay_min_seconds: int = 0,
    updated_offset_s: float = 0,
) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind=source_kind,
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={
            "delay_policy": {"min_seconds": delay_min_seconds},
        },
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        created_at=now - timedelta(seconds=updated_offset_s),
        updated_at=now - timedelta(seconds=updated_offset_s),
    )


# ── LN-self-pay observer ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_observe_ln_self_pay_created_signals_settlement(db_session) -> None:
    s = _session(status=AnonymizeStatus.CREATED.value)
    obs = await observe_ln_self_pay(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_observe_ln_self_pay_funding_gated_on_self_pay_status(db_session) -> None:
    """FUNDING holds until the hop body records the self-payment as
    settled; only then does it signal the LN_HOLDING advance."""
    s = _session(status=AnonymizeStatus.FUNDING.value)
    # Before the self-pay settles: "wait" (None, not False).
    obs = await observe_ln_self_pay(db_session, s)
    assert obs.funding_invoice_settled is None
    # After the hop body persists settlement: advance.
    s.pipeline_json = {**s.pipeline_json, "self_pay_status": "settled"}
    obs = await observe_ln_self_pay(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_observe_ln_self_pay_delaying_zero_window_advances(db_session) -> None:
    """A delay_min_seconds=0 immediately advances."""
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        delay_min_seconds=0,
    )
    obs = await observe_ln_self_pay(db_session, s)
    assert obs.delay_window_elapsed is True
    assert obs.is_last_hop is True


@pytest.mark.asyncio
async def test_observe_ln_self_pay_delaying_inside_window_waits(db_session) -> None:
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        delay_min_seconds=3600,
        updated_offset_s=60,  # 60s elapsed of 3600s window
    )
    obs = await observe_ln_self_pay(db_session, s)
    assert obs.delay_window_elapsed is False


@pytest.mark.asyncio
async def test_observe_ln_self_pay_delaying_past_window_advances(db_session) -> None:
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        delay_min_seconds=60,
        updated_offset_s=120,  # past
    )
    obs = await observe_ln_self_pay(db_session, s)
    assert obs.delay_window_elapsed is True


@pytest.mark.asyncio
async def test_observe_ln_self_pay_other_statuses_empty(db_session) -> None:
    """LN_HOLDING / HOPPING / EXITING / CONFIRMING all return empty obs."""
    for status in (
        AnonymizeStatus.LN_HOLDING.value,
        AnonymizeStatus.HOPPING.value,
        AnonymizeStatus.EXITING.value,
        AnonymizeStatus.CONFIRMING.value,
    ):
        s = _session(status=status)
        obs = await observe_ln_self_pay(db_session, s)
        assert obs == TickObservations()


# ── Default router ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_router_dispatches_to_ln_self_pay(db_session) -> None:
    s = _session(
        status=AnonymizeStatus.CREATED.value,
        source_kind="lightning-self",
    )
    obs = await default_observation_fn(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_router_dispatches_ext_lightning(db_session) -> None:
    """ext-lightning is wired via the ext_lightning observer."""
    s = _session(
        status=AnonymizeStatus.CREATED.value,
        source_kind="ext-lightning",
    )
    obs = await default_observation_fn(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_router_returns_empty_for_onchain_source_kinds(db_session) -> None:
    """on-chain source kinds — router returns empty obs."""
    for kind in ("onchain-self", "ext-onchain"):
        s = _session(
            status=AnonymizeStatus.CREATED.value,
            source_kind=kind,
        )
        obs = await default_observation_fn(db_session, s)
        assert obs == TickObservations()


# ── End-to-end: tick the LN-self-pay session through the state machine ──


@pytest.mark.asyncio
async def test_ln_self_pay_session_advances_through_state_machine(
    db_session,
) -> None:
    """Five ticks drive a CREATED session to EXITING via LN-self-pay obs.

    CREATED → FUNDING → LN_HOLDING → DELAYING → EXITING.
    """
    from app.services.anonymize.service import (
        AnonymizeService,
        reset_anonymize_service,
    )

    reset_anonymize_service()
    svc = AnonymizeService()
    await svc.start()

    s = _session(
        status=AnonymizeStatus.CREATED.value,
        source_kind="lightning-self",
        delay_min_seconds=0,
    )
    db_session.add(s)
    await db_session.flush()

    # Tick 1: CREATED + obs(funding_invoice_settled=True) → FUNDING
    obs = await default_observation_fn(db_session, s)
    await svc.tick_session(db_session, s, obs)
    assert s.status == AnonymizeStatus.FUNDING.value

    # Tick 2: FUNDING holds until the self-pay settles. The hop body
    # fires the self-payment and persists ``self_pay_status``; this
    # test exercises only the observation + tick path, so stand in for
    # the hop body by marking it settled.
    obs = await default_observation_fn(db_session, s)
    await svc.tick_session(db_session, s, obs)
    assert s.status == AnonymizeStatus.FUNDING.value  # no settlement yet → waits

    s.pipeline_json = {**s.pipeline_json, "self_pay_status": "settled"}
    obs = await default_observation_fn(db_session, s)
    await svc.tick_session(db_session, s, obs)
    assert s.status == AnonymizeStatus.LN_HOLDING.value

    # Tick 3: LN_HOLDING → DELAYING (automatic, no obs needed)
    obs = await default_observation_fn(db_session, s)
    await svc.tick_session(db_session, s, obs)
    assert s.status == AnonymizeStatus.DELAYING.value

    # Tick 4: DELAYING + obs(elapsed=True, is_last_hop=True) → EXITING
    obs = await default_observation_fn(db_session, s)
    await svc.tick_session(db_session, s, obs)
    assert s.status == AnonymizeStatus.EXITING.value

    await svc.stop()
    reset_anonymize_service()


# ── Persisted-reason promotion (gap fix) ────────────────────────────


@pytest.mark.asyncio
async def test_router_promotes_persisted_reconcile_reason(db_session) -> None:
    """Regression: a hop body that sets
    ``session.awaiting_reconciliation_reason`` (e.g. reverse-hop
    K-fallback exhaustion) must surface as ``reconcile_reason`` so
    the tick decider can transition out of EXITING into
    AWAITING_RECONCILIATION. Without this the session wedges in
    EXITING forever and never shows up in the dashboard.
    """
    s = _session(status=AnonymizeStatus.EXITING.value)
    s.awaiting_reconciliation_reason = "mpp_k_floor_exhausted"
    obs = await default_observation_fn(db_session, s)
    assert obs.reconcile_reason == "mpp_k_floor_exhausted"


@pytest.mark.asyncio
async def test_router_does_not_loop_when_already_routed(db_session) -> None:
    """Once the session is in AWAITING_RECONCILIATION, the persisted
    reason must NOT be re-surfaced — otherwise the reconciliation
    handler can't itself transition the session back to the live
    path without immediately being re-routed back.
    """
    s = _session(status=AnonymizeStatus.AWAITING_RECONCILIATION.value)
    s.awaiting_reconciliation_reason = "mpp_k_floor_exhausted"
    obs = await default_observation_fn(db_session, s)
    assert obs.reconcile_reason is None


@pytest.mark.asyncio
async def test_router_ignores_persisted_reason_when_terminal(
    db_session,
) -> None:
    """Terminal statuses have no outgoing transitions — there's no
    point surfacing the reason."""
    for status in (
        AnonymizeStatus.FAILED.value,
        AnonymizeStatus.CANCELLED.value,
        AnonymizeStatus.COMPLETED.value,
    ):
        s = _session(status=status)
        s.awaiting_reconciliation_reason = "mpp_k_floor_exhausted"
        obs = await default_observation_fn(db_session, s)
        assert obs.reconcile_reason is None
