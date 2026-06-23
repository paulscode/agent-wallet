# SPDX-License-Identifier: MIT
"""Hop_attempt_started/completed event persistence."""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeStatus,
)
from app.services.anonymize.hop_idempotency import (
    HopAttemptKey,
    fetch_existing_hop_attempt,
    has_hop_attempt_completed,
    record_hop_attempt_completed,
    record_hop_attempt_started,
)


def _session() -> AnonymizeSession:
    from datetime import datetime, timezone

    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.HOPPING.value,
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
        completed_at=datetime.now(timezone.utc),
    )


def _key(*, sid, idem_key: str = "deadbeef" * 8) -> HopAttemptKey:
    return HopAttemptKey(
        session_id=sid,
        hop_index=0,
        hop_kind="reverse",
        attempt=0,
        idempotency_key=idem_key,
        nonce=b"\x10" * 16,
        key_generation=0,
    )


@pytest.mark.asyncio
async def test_record_started_writes_event_row(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    key = _key(sid=sess.id)
    row = await record_hop_attempt_started(
        db_session,
        key=key,
        detail={"sat": 250_000},
    )
    assert row.kind == "hop_attempt_started"
    assert row.hop_idempotency_key == key.idempotency_key
    assert row.hop_idempotency_key_generation == 0
    assert row.hop_idempotency_nonce_enc == key.nonce
    assert row.detail_json == {"sat": 250_000}


@pytest.mark.asyncio
async def test_record_started_is_idempotent(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    key = _key(sid=sess.id)
    first = await record_hop_attempt_started(db_session, key=key)
    await db_session.flush()
    second = await record_hop_attempt_started(db_session, key=key)
    assert first is second  # same row returned


@pytest.mark.asyncio
async def test_fetch_existing_returns_none_for_unknown_key(db_session) -> None:
    out = await fetch_existing_hop_attempt(db_session, idempotency_key="missing")
    assert out is None


@pytest.mark.asyncio
async def test_record_completed_writes_separate_row(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    key = _key(sid=sess.id)
    started = await record_hop_attempt_started(db_session, key=key)
    completed = await record_hop_attempt_completed(
        db_session,
        key=key,
        detail={"result": "ok"},
    )
    assert completed is not started
    assert completed.kind == "hop_attempt_completed"
    assert completed.detail_json == {"result": "ok"}


@pytest.mark.asyncio
async def test_has_completed_returns_true_after_completed(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    key = _key(sid=sess.id)
    await record_hop_attempt_started(db_session, key=key)
    assert (await has_hop_attempt_completed(db_session, idempotency_key=key.idempotency_key)) is False
    await record_hop_attempt_completed(db_session, key=key)
    assert (await has_hop_attempt_completed(db_session, idempotency_key=key.idempotency_key)) is True


def test_dispatcher_decision_issue_when_no_prior_attempt() -> None:
    """No prior attempt → caller may issue the side effect."""
    from app.services.anonymize.hop_idempotency import dispatcher_decision

    assert (
        dispatcher_decision(
            started_event=None,
            completed_event=None,
        )
        == "issue_side_effect"
    )


def test_dispatcher_decision_verify_when_started_without_completed() -> None:
    """'timeouts are reconciliation triggers, not retries'."""
    from unittest.mock import MagicMock

    from app.services.anonymize.hop_idempotency import dispatcher_decision

    assert (
        dispatcher_decision(
            started_event=MagicMock(),
            completed_event=None,
        )
        == "verify_remote_state"
    )


def test_dispatcher_decision_noop_when_both_events_present() -> None:
    """Once both events landed the dispatcher must short-circuit."""
    from unittest.mock import MagicMock

    from app.services.anonymize.hop_idempotency import dispatcher_decision

    assert (
        dispatcher_decision(
            started_event=MagicMock(),
            completed_event=MagicMock(),
        )
        == "completed_idempotent_no_op"
    )


@pytest.mark.asyncio
async def test_fetch_completed_returns_completed_row_only(db_session) -> None:
    """``fetch_completed_hop_attempt`` ignores started rows."""
    from app.services.anonymize.hop_idempotency import (
        fetch_completed_hop_attempt,
    )

    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    key = _key(sid=sess.id)
    await record_hop_attempt_started(db_session, key=key)
    # Only the started row exists — fetch_completed must return None.
    out = await fetch_completed_hop_attempt(
        db_session,
        idempotency_key=key.idempotency_key,
    )
    assert out is None
    await record_hop_attempt_completed(db_session, key=key)
    out = await fetch_completed_hop_attempt(
        db_session,
        idempotency_key=key.idempotency_key,
    )
    assert out is not None
    assert out.kind == "hop_attempt_completed"


@pytest.mark.asyncio
async def test_hop_idempotency_key_uniqueness_across_sessions(db_session) -> None:
    """Two distinct sessions must never collide on the same
    idempotency key (the key includes session_id in its derivation).

    Verifies derivation invariant: distinct session UUIDs → distinct keys.
    """
    from app.services.anonymize.hop_idempotency import (
        make_hop_idempotency_key,
    )

    sid_a = uuid4().bytes
    sid_b = uuid4().bytes
    nonce = b"\x10" * 16
    key_bytes = b"\xff" * 32
    out_a = make_hop_idempotency_key(
        key_bytes=key_bytes,
        nonce=nonce,
        session_id=sid_a,
        hop_index=0,
        hop_kind="reverse_create",
        attempt=1,
    )
    out_b = make_hop_idempotency_key(
        key_bytes=key_bytes,
        nonce=nonce,
        session_id=sid_b,
        hop_index=0,
        hop_kind="reverse_create",
        attempt=1,
    )
    assert out_a != out_b


@pytest.mark.asyncio
async def test_recovery_pattern_using_started_row(db_session) -> None:
    """Simulate recovery: a 'started' row exists but no 'completed'.
    The orchestrator should detect this and query the external system."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    key = _key(sid=sess.id)
    await record_hop_attempt_started(db_session, key=key)
    # Crash + restart …
    existing = await fetch_existing_hop_attempt(
        db_session,
        idempotency_key=key.idempotency_key,
    )
    assert existing is not None
    assert existing.kind == "hop_attempt_started"
    completed = await has_hop_attempt_completed(
        db_session,
        idempotency_key=key.idempotency_key,
    )
    assert completed is False
