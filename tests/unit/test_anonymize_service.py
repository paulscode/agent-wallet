# SPDX-License-Identifier: MIT
"""AnonymizeService orchestrator scaffolding tests."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.service import (
    AnonymizeService,
    get_anonymize_service,
    reset_anonymize_service,
)
from app.services.anonymize.state_machine import IllegalStateTransitionError


@pytest.fixture(autouse=True)
def _clean_singleton():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.CREATED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=None,
    )


@pytest.mark.asyncio
async def test_start_is_idempotent() -> None:
    svc = AnonymizeService()
    await svc.start()
    await svc.start()  # no-raise
    await svc.stop()


@pytest.mark.asyncio
async def test_stop_cancels_per_session_tasks() -> None:
    svc = AnonymizeService()
    await svc.start()

    async def _long_task() -> None:
        await asyncio.sleep(60)

    t = asyncio.create_task(_long_task())
    svc.register_task("sess-1", t)
    assert svc.is_session_task_running("sess-1") is True

    await svc.stop()
    # After stop, the task is cancelled.
    assert t.cancelled() or t.done()


@pytest.mark.asyncio
async def test_register_task_replaces_existing() -> None:
    svc = AnonymizeService()
    await svc.start()

    async def _task() -> None:
        await asyncio.sleep(60)

    t1 = asyncio.create_task(_task())
    t2 = asyncio.create_task(_task())
    svc.register_task("sid", t1)
    svc.register_task("sid", t2)
    # t1 was cancelled.
    await asyncio.sleep(0)  # let cancel propagate
    assert t1.cancelled() or t1.done()
    assert svc.is_session_task_running("sid") is True
    await svc.stop()


@pytest.mark.asyncio
async def test_in_flight_count_counts_only_active() -> None:
    svc = AnonymizeService()
    await svc.start()

    async def _quick() -> None:
        return None

    t = asyncio.create_task(_quick())
    svc.register_task("s1", t)
    await t  # finish
    # Done tasks don't count.
    assert svc.in_flight_count() == 0
    await svc.stop()


@pytest.mark.asyncio
async def test_transition_session_advances_legal_edge(db_session) -> None:
    svc = AnonymizeService()
    await svc.start()
    sess = _session()
    db_session.add(sess)
    await db_session.flush()

    await svc.transition_session(
        db_session,
        sess,
        to_status=AnonymizeStatus.FUNDING,
        reason="self_pay_dispatch",
    )
    assert sess.status == AnonymizeStatus.FUNDING.value
    await svc.stop()


@pytest.mark.asyncio
async def test_transition_session_refuses_illegal_edge(db_session) -> None:
    svc = AnonymizeService()
    await svc.start()
    sess = _session()
    db_session.add(sess)
    await db_session.flush()

    with pytest.raises(IllegalStateTransitionError):
        await svc.transition_session(
            db_session,
            sess,
            to_status=AnonymizeStatus.EXITING,  # skip-the-pipeline
            reason="bug",
        )
    # Status not mutated on the illegal attempt.
    assert sess.status == AnonymizeStatus.CREATED.value
    await svc.stop()


@pytest.mark.asyncio
async def test_transition_session_is_idempotent(db_session) -> None:
    """Writing the same status twice is a no-op."""
    svc = AnonymizeService()
    await svc.start()
    sess = _session()
    db_session.add(sess)
    await db_session.flush()

    await svc.transition_session(
        db_session,
        sess,
        to_status=AnonymizeStatus.CREATED,
        reason="resync",
    )
    assert sess.status == AnonymizeStatus.CREATED.value
    await svc.stop()


def test_get_singleton_constructs_lazily() -> None:
    a = get_anonymize_service()
    b = get_anonymize_service()
    assert a is b
    reset_anonymize_service()
    c = get_anonymize_service()
    assert c is not a


def test_is_session_terminal() -> None:
    sess = _session()
    assert AnonymizeService.is_session_terminal(sess) is False
    sess.status = AnonymizeStatus.COMPLETED.value
    sess.completed_at = datetime.now(timezone.utc)
    assert AnonymizeService.is_session_terminal(sess) is True


# ── transition_to_awaiting_reconciliation ────────────────────────────


@pytest.mark.asyncio
async def test_transition_to_ar_populates_all_columns(db_session) -> None:
    """The helper atomically writes pre_status / reason / counters."""
    svc = AnonymizeService()
    await svc.start()

    # Walk a session through CREATED → FUNDING so pre_status is
    # meaningfully different from the starting status.
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await svc.transition_session(
        db_session,
        sess,
        to_status=AnonymizeStatus.FUNDING,
        reason="setup",
    )
    assert sess.status == AnonymizeStatus.FUNDING.value

    await svc.transition_to_awaiting_reconciliation(
        db_session,
        sess,
        reason="mpp_k_floor_exhausted",
    )

    assert sess.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert sess.pre_reconciliation_status == AnonymizeStatus.FUNDING.value
    assert sess.awaiting_reconciliation_reason == "mpp_k_floor_exhausted"
    assert sess.reconciliation_attempts == 0
    assert sess.last_reconciliation_attempt_ts is None
    await svc.stop()


@pytest.mark.asyncio
async def test_transition_to_ar_idempotent_does_not_clobber_pre_status(
    db_session,
) -> None:
    """A second call must NOT overwrite pre_reconciliation_status — that
    field captures the original live status the recovery path will
    resume to."""
    svc = AnonymizeService()
    await svc.start()

    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await svc.transition_session(
        db_session,
        sess,
        to_status=AnonymizeStatus.FUNDING,
        reason="setup",
    )

    await svc.transition_to_awaiting_reconciliation(
        db_session,
        sess,
        reason="first_reason",
    )
    # Simulate a recovery attempt incrementing the counter, then a
    # repeat reconcile.
    sess.reconciliation_attempts = 3
    from datetime import datetime as _dt

    sess.last_reconciliation_attempt_ts = _dt.now(timezone.utc)

    await svc.transition_to_awaiting_reconciliation(
        db_session,
        sess,
        reason="second_reason",
    )

    # Pre-status untouched.
    assert sess.pre_reconciliation_status == AnonymizeStatus.FUNDING.value
    # Most-recent reason wins.
    assert sess.awaiting_reconciliation_reason == "second_reason"
    # Attempt counters / timestamps not reset on the idempotent path.
    assert sess.reconciliation_attempts == 3
    assert sess.last_reconciliation_attempt_ts is not None
    await svc.stop()


@pytest.mark.asyncio
async def test_transition_to_ar_preserves_attempts_across_cycles(
    db_session,
) -> None:
    """Per recovery, reconciliation_attempts accumulates
    across the session's lifetime. When a session bounces AR → live
    → AR (after a failed auto-retry resume), the count must be
    preserved so the auto-retry budget bounds total retries, not
    just per-cycle retries."""
    from datetime import datetime as _dt
    from datetime import timezone

    svc = AnonymizeService()
    await svc.start()

    # Walk session up through the legal pipeline so we land in
    # EXITING (which IS a legal AR → live resume target).
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    for step in (
        AnonymizeStatus.FUNDING,
        AnonymizeStatus.LN_HOLDING,
        AnonymizeStatus.DELAYING,
        AnonymizeStatus.EXITING,
    ):
        await svc.transition_session(
            db_session,
            sess,
            to_status=step,
            reason="setup",
        )
    assert sess.status == AnonymizeStatus.EXITING.value

    # First AR entry.
    await svc.transition_to_awaiting_reconciliation(
        db_session,
        sess,
        reason="mpp_k_floor_exhausted",
    )
    assert sess.reconciliation_attempts == 0  # fresh row, DB default

    # Simulate a probe tick: bump counter + resume to EXITING.
    sess.reconciliation_attempts = 1
    sess.last_reconciliation_attempt_ts = _dt.now(timezone.utc)
    await svc.transition_session(
        db_session,
        sess,
        to_status=AnonymizeStatus.EXITING,
        reason="reconciliation_retry",
    )
    assert sess.status == AnonymizeStatus.EXITING.value

    # Session fails again → second fresh AR entry. The helper must
    # NOT reset attempts; the count from the previous cycle survives.
    await svc.transition_to_awaiting_reconciliation(
        db_session,
        sess,
        reason="mpp_k_floor_exhausted",
    )
    assert sess.reconciliation_attempts == 1
    assert sess.last_reconciliation_attempt_ts is not None
    assert sess.pre_reconciliation_status == AnonymizeStatus.EXITING.value
    await svc.stop()


@pytest.mark.asyncio
async def test_tick_session_routes_reconcile_through_helper(db_session) -> None:
    """tick_session must apply the four-column write when the action
    targets AWAITING_RECONCILIATION."""
    from app.services.anonymize.tick import TickObservations

    svc = AnonymizeService()
    await svc.start()
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await svc.transition_session(
        db_session,
        sess,
        to_status=AnonymizeStatus.FUNDING,
        reason="setup",
    )

    # Simulate a hop emitting a reconcile signal. The decider produces
    # an action with the wrapped "reconcile:foo" reason; the helper
    # must strip the prefix for the persisted column.
    obs = TickObservations(reconcile_reason="mpp_k_floor_exhausted")
    await svc.tick_session(db_session, sess, obs)

    assert sess.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert sess.awaiting_reconciliation_reason == "mpp_k_floor_exhausted"
    assert sess.pre_reconciliation_status == AnonymizeStatus.FUNDING.value
    await svc.stop()
