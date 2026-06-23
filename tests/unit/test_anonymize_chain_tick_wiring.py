# SPDX-License-Identifier: MIT
"""Chain-poll + self-broadcast tick wiring.

The recurring ticks must:

* read confirmation depth via the anonymize chain client and write
  it onto the session row (— reorg-aware completion);
* broadcast the cached ``claim_tx_hex`` through the anonymize chain
  client and record the returned txid (— self-broadcast
  fallback).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize import chain_egress
from app.services.anonymize import service as anon_service
from app.services.anonymize.clock import ClockSkewState, store_clock_skew_state


def _session_row(
    *,
    status: str,
    claim_txid: str | None = None,
    claim_tx_hex: str | None = None,
    claim_tx_confirmations: int = 0,
    broadcast_deadline_unix_s: int | None = None,
    claim_broadcast_at_ts: datetime | None = None,
) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={"exit": {"destination_address": "bcrt1ptest"}},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        claim_tx_hex=claim_tx_hex,
        claim_txid=claim_txid,
        claim_tx_confirmations=claim_tx_confirmations,
        claim_tx_reorg_observed_count=0,
        broadcast_deadline_unix_s=broadcast_deadline_unix_s,
        claim_broadcast_at_ts=claim_broadcast_at_ts,
    )


# ── chain_poll_tick ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_chain_poll_writes_confirmation_count(
    db_engine,
    monkeypatch,
) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    async with factory() as db:
        row = _session_row(
            status=AnonymizeStatus.CONFIRMING.value,
            claim_txid="ab" * 32,
            claim_tx_confirmations=0,
        )
        db.add(row)
        await db.commit()
        sid = row.id

    async def _stub_confs(txid, **_):
        return {
            "txid": txid,
            "confirmed": True,
            "confirmations": 3,
            "block_height": 100,
        }, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_tx_confirmations",
        _stub_confs,
    )

    await anon_service._chain_poll_tick_run()

    async with factory() as db:
        row = (await db.execute(select(AnonymizeSession).where(AnonymizeSession.id == sid))).scalar_one()
        assert row.claim_tx_confirmations == 3


@pytest.mark.asyncio
async def test_chain_poll_records_reorg_on_confirmation_drop(
    db_engine,
    monkeypatch,
) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    async with factory() as db:
        row = _session_row(
            status=AnonymizeStatus.CONFIRMING.value,
            claim_txid="ab" * 32,
            claim_tx_confirmations=5,
        )
        db.add(row)
        await db.commit()
        sid = row.id

    async def _stub_drop(txid, **_):
        return {
            "txid": txid,
            "confirmed": True,
            "confirmations": 2,
            "block_height": 100,
        }, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_tx_confirmations",
        _stub_drop,
    )

    await anon_service._chain_poll_tick_run()

    async with factory() as db:
        row = (await db.execute(select(AnonymizeSession).where(AnonymizeSession.id == sid))).scalar_one()
        assert row.claim_tx_confirmations == 2
        assert row.claim_tx_reorg_observed_count == 1


@pytest.mark.asyncio
async def test_chain_poll_skips_sessions_without_txid(
    db_engine,
    monkeypatch,
) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    async with factory() as db:
        row = _session_row(
            status=AnonymizeStatus.CONFIRMING.value,
            claim_txid=None,
            claim_tx_confirmations=0,
        )
        db.add(row)
        await db.commit()

    calls: list[str] = []

    async def _spy(txid, **_):
        calls.append(txid)
        return None, "should not be called"

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_tx_confirmations",
        _spy,
    )

    await anon_service._chain_poll_tick_run()
    assert calls == []


# ── self_broadcast_tick ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_self_broadcast_writes_txid_and_attempt_ts(
    db_engine,
    monkeypatch,
) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    expected_txid = "cd" * 32
    past_deadline = datetime.now(timezone.utc) - timedelta(hours=1)

    async with factory() as db:
        row = _session_row(
            status=AnonymizeStatus.EXITING.value,
            claim_tx_hex="deadbeef",
            broadcast_deadline_unix_s=int(past_deadline.timestamp()),
            claim_broadcast_at_ts=past_deadline,
        )
        db.add(row)
        # Persist a measured-zero clock skew so the skew
        # gate permits firing.
        await store_clock_skew_state(
            db,
            ClockSkewState(skew_ms=0, measured_at_unix_s=0.0),
        )
        await db.commit()
        sid = row.id

    calls: list[str] = []

    async def _stub_broadcast(tx_hex, **_):
        calls.append(tx_hex)
        return expected_txid, None

    monkeypatch.setattr(
        chain_egress,
        "anonymize_broadcast_tx",
        _stub_broadcast,
    )

    await anon_service._self_broadcast_tick_run()

    assert calls == ["deadbeef"]
    async with factory() as db:
        row = (await db.execute(select(AnonymizeSession).where(AnonymizeSession.id == sid))).scalar_one()
        assert row.claim_txid == expected_txid
        assert row.self_broadcast_attempted_at_ts is not None


@pytest.mark.asyncio
async def test_self_broadcast_records_attempt_even_on_failure(
    db_engine,
    monkeypatch,
) -> None:
    """Attempt timestamp persists *before* the broadcast,
    so an egress failure still leaves the marker on the row (to
    drive next-tick decision)."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    past_deadline = datetime.now(timezone.utc) - timedelta(hours=1)

    async with factory() as db:
        row = _session_row(
            status=AnonymizeStatus.EXITING.value,
            claim_tx_hex="deadbeef",
            broadcast_deadline_unix_s=int(past_deadline.timestamp()),
            claim_broadcast_at_ts=past_deadline,
        )
        db.add(row)
        await store_clock_skew_state(
            db,
            ClockSkewState(skew_ms=0, measured_at_unix_s=0.0),
        )
        await db.commit()
        sid = row.id

    async def _stub_fail(tx_hex, **_):
        return None, "backend unreachable"

    monkeypatch.setattr(
        chain_egress,
        "anonymize_broadcast_tx",
        _stub_fail,
    )

    await anon_service._self_broadcast_tick_run()

    async with factory() as db:
        row = (await db.execute(select(AnonymizeSession).where(AnonymizeSession.id == sid))).scalar_one()
        assert row.self_broadcast_attempted_at_ts is not None
        assert row.claim_txid is None  # broadcast failed → no txid


@pytest.mark.asyncio
async def test_self_broadcast_skips_when_deadline_not_passed(
    db_engine,
    monkeypatch,
) -> None:
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    future_deadline = datetime.now(timezone.utc) + timedelta(hours=1)

    async with factory() as db:
        row = _session_row(
            status=AnonymizeStatus.EXITING.value,
            claim_tx_hex="deadbeef",
            broadcast_deadline_unix_s=int(future_deadline.timestamp()),
            claim_broadcast_at_ts=datetime.now(timezone.utc),
        )
        db.add(row)
        await db.commit()

    calls: list[str] = []

    async def _spy(tx_hex, **_):
        calls.append(tx_hex)
        return None, "should not be called"

    monkeypatch.setattr(
        chain_egress,
        "anonymize_broadcast_tx",
        _spy,
    )

    await anon_service._self_broadcast_tick_run()
    assert calls == []
