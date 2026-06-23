# SPDX-License-Identifier: MIT
"""Multi-output orchestration helpers.

Covers:

* ``select_ready_outputs`` filters by ``completed_at IS NULL`` AND
  ``scheduled_at_unix_s <= now`` AND sorts by ``output_index``.
* ``mark_output_completed`` updates the row idempotently.
* ``is_session_fully_complete`` returns True iff all outputs done.
* ``count_pending_outputs`` matches the actual pending count.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionOutput,
    AnonymizeStatus,
)
from app.services.anonymize.multi_output_orchestrator import (
    count_pending_outputs,
    is_session_fully_complete,
    mark_output_completed,
    select_ready_outputs,
)


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.CREATED.value,
        source_kind="lightning-self",
        requested_amount_sat=850_000,
        bin_amount_sat=100_000,
        pipeline_json={"multi_output": True, "output_count": 3},
        quote_hmac=b"\x00" * 32,
        destination_address_enc=b"enc-0",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\x00" * 32,
        destination_reuse_key_generation=0,
    )


def _output(
    *,
    session_id,
    output_index: int,
    scheduled_at_unix_s: float | None,
    amount: int = 100_000,
    completed_at: datetime | None = None,
) -> AnonymizeSessionOutput:
    return AnonymizeSessionOutput(
        session_id=session_id,
        output_index=output_index,
        destination_address_enc=f"enc-{output_index}".encode(),
        destination_script_type="p2tr",
        bin_amount_sat=amount,
        scheduled_at_unix_s=scheduled_at_unix_s,
        destination_address_blake2b_keyed=(f"hash-{output_index}".encode().ljust(32, b"\x00")),
        destination_reuse_key_generation=0,
        completed_at=completed_at,
    )


# ── select_ready_outputs ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_select_ready_returns_only_outputs_past_schedule(
    db_session,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    now = datetime.now(timezone.utc).timestamp()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=now - 100,
        )
    )
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=1,
            scheduled_at_unix_s=now + 3600,  # not yet
        )
    )
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=2,
            scheduled_at_unix_s=now - 50,
        )
    )
    await db_session.flush()
    ready = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=now,
    )
    assert [r.output_index for r in ready] == [0, 2]


@pytest.mark.asyncio
async def test_select_ready_excludes_completed(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    now = datetime.now(timezone.utc).timestamp()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=now - 100,
            completed_at=datetime.now(timezone.utc),
        )
    )
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=1,
            scheduled_at_unix_s=now - 100,
        )
    )
    await db_session.flush()
    ready = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=now,
    )
    assert [r.output_index for r in ready] == [1]


@pytest.mark.asyncio
async def test_select_ready_admits_null_schedule_immediately(
    db_session,
) -> None:
    """A row with NULL schedule is admitted as soon as the orchestrator
    looks at it — safety fallback for operator-injected rows."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=None,
        )
    )
    await db_session.flush()
    ready = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=0.0,
    )
    assert len(ready) == 1


@pytest.mark.asyncio
async def test_select_ready_sorts_by_output_index(db_session) -> None:
    """The orchestrator iterates outputs in insertion-order so its
    fan-out is deterministic. The DB-level ORDER BY enforces this
    even when rows were inserted out of order."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    now = datetime.now(timezone.utc).timestamp()
    # Insert with output_index 2 first, then 0, then 1.
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=2,
            scheduled_at_unix_s=now - 10,
        )
    )
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=now - 100,
        )
    )
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=1,
            scheduled_at_unix_s=now - 50,
        )
    )
    await db_session.flush()
    ready = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=now,
    )
    assert [r.output_index for r in ready] == [0, 1, 2]


@pytest.mark.asyncio
async def test_select_ready_carries_destination_data(db_session) -> None:
    """The ReadyOutput value object carries enough data for the
    orchestrator to dispatch the egress without re-reading the row."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=0.0,
            amount=350_000,
        )
    )
    await db_session.flush()
    ready = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=1.0,
    )
    assert len(ready) == 1
    r = ready[0]
    assert r.session_id == sess.id
    assert r.output_index == 0
    assert r.destination_address_enc == b"enc-0"
    assert r.destination_script_type == "p2tr"
    assert r.bin_amount_sat == 350_000


# ── mark_output_completed ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_mark_completed_updates_the_row(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=0.0,
        )
    )
    await db_session.flush()
    ok = await mark_output_completed(
        db_session,
        session_id=sess.id,
        output_index=0,
        output_txid="ab" * 32,
        output_vout=3,
    )
    assert ok is True
    await db_session.commit()
    row = (
        await db_session.execute(select(AnonymizeSessionOutput).where(AnonymizeSessionOutput.session_id == sess.id))
    ).scalar_one()
    assert row.output_txid == "ab" * 32
    assert row.output_vout == 3
    assert row.completed_at is not None


@pytest.mark.asyncio
async def test_mark_completed_returns_false_when_no_row(db_session) -> None:
    ok = await mark_output_completed(
        db_session,
        session_id=uuid4(),
        output_index=0,
        output_txid="ab" * 32,
        output_vout=0,
    )
    assert ok is False


@pytest.mark.asyncio
async def test_mark_completed_refuses_empty_txid(db_session) -> None:
    with pytest.raises(ValueError):
        await mark_output_completed(
            db_session,
            session_id=uuid4(),
            output_index=0,
            output_txid="",
            output_vout=0,
        )


@pytest.mark.asyncio
async def test_mark_completed_refuses_negative_vout(db_session) -> None:
    with pytest.raises(ValueError):
        await mark_output_completed(
            db_session,
            session_id=uuid4(),
            output_index=0,
            output_txid="ab" * 32,
            output_vout=-1,
        )


@pytest.mark.asyncio
async def test_mark_completed_is_idempotent(db_session) -> None:
    """Re-marking an already-completed output is a no-op update of
    output_txid / output_vout."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=0.0,
        )
    )
    await db_session.flush()
    assert await mark_output_completed(
        db_session,
        session_id=sess.id,
        output_index=0,
        output_txid="ab" * 32,
        output_vout=0,
    )
    # Re-mark with different vout — should succeed.
    assert await mark_output_completed(
        db_session,
        session_id=sess.id,
        output_index=0,
        output_txid="ab" * 32,
        output_vout=5,
    )
    await db_session.commit()
    row = (
        await db_session.execute(select(AnonymizeSessionOutput).where(AnonymizeSessionOutput.session_id == sess.id))
    ).scalar_one()
    assert row.output_vout == 5


# ── is_session_fully_complete + count_pending_outputs ───────────────


@pytest.mark.asyncio
async def test_session_fully_complete_false_when_some_pending(
    db_session,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=0,
            scheduled_at_unix_s=0.0,
            completed_at=datetime.now(timezone.utc),
        )
    )
    db_session.add(
        _output(
            session_id=sess.id,
            output_index=1,
            scheduled_at_unix_s=0.0,
        )
    )
    await db_session.flush()
    assert (
        await is_session_fully_complete(
            db_session,
            session_id=sess.id,
        )
        is False
    )
    assert (
        await count_pending_outputs(
            db_session,
            session_id=sess.id,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_session_fully_complete_true_when_all_done(
    db_session,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    when = datetime.now(timezone.utc)
    for i in range(3):
        db_session.add(
            _output(
                session_id=sess.id,
                output_index=i,
                scheduled_at_unix_s=0.0,
                completed_at=when,
            )
        )
    await db_session.flush()
    assert (
        await is_session_fully_complete(
            db_session,
            session_id=sess.id,
        )
        is True
    )
    assert (
        await count_pending_outputs(
            db_session,
            session_id=sess.id,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_session_fully_complete_false_when_no_output_rows(
    db_session,
) -> None:
    """A session with zero rows is a single-output session, not a
    completed multi-output session — the gate must return False so
    the existing single-output completion path stays authoritative."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    assert (
        await is_session_fully_complete(
            db_session,
            session_id=sess.id,
        )
        is False
    )


# ── select + mark integration ───────────────────────────────────────


@pytest.mark.asyncio
async def test_select_then_mark_removes_from_ready_set(db_session) -> None:
    """After marking output 0 complete, the next select_ready call
    must not return it."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    now = datetime.now(timezone.utc).timestamp()
    for i in range(3):
        db_session.add(
            _output(
                session_id=sess.id,
                output_index=i,
                scheduled_at_unix_s=now - 100,
            )
        )
    await db_session.flush()
    ready_before = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=now,
    )
    assert [r.output_index for r in ready_before] == [0, 1, 2]
    await mark_output_completed(
        db_session,
        session_id=sess.id,
        output_index=1,
        output_txid="cd" * 32,
        output_vout=0,
    )
    await db_session.commit()
    ready_after = await select_ready_outputs(
        db_session,
        session_id=sess.id,
        now_unix_s=now,
    )
    assert [r.output_index for r in ready_after] == [0, 2]
