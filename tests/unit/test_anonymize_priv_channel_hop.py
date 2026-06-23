# SPDX-License-Identifier: MIT
"""Priv_channel hop body + throwaway-channel lifecycle."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.priv_channel import (
    PrivChannelHopDeps,
    execute_priv_channel_hop_step,
    sample_close_delay_s,
)


def _session(*, status: str, pj: dict | None = None) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="lightning-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pj or {},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


def _mock_deps(
    *,
    peer_returns=None,
    open_returns=None,
    active_returns=None,
    push_returns=None,
    close_returns=None,
) -> PrivChannelHopDeps:
    return PrivChannelHopDeps(
        select_auto_peer=AsyncMock(
            return_value=peer_returns or ({"pubkey": "02deadbeef" * 7}, None),
        ),
        lnd_open_private_channel=AsyncMock(
            return_value=open_returns or ("ab" * 32 + ":0", None),
        ),
        lnd_channel_is_active=AsyncMock(
            return_value=active_returns or (True, None),
        ),
        lnd_send_payment_through_channel=AsyncMock(
            return_value=push_returns or ({"status": "succeeded"}, None),
        ),
        lnd_close_channel_cooperative=AsyncMock(
            return_value=close_returns or ({"closing_txid": "deadbeef"}, None),
        ),
    )


# ── sample_close_delay_s ────────────────────────────────────────────


def test_sample_close_delay_within_band(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_throwaway_channel_close_delay_min_s",
        7200,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_throwaway_channel_close_delay_max_s",
        86400,
    )
    for _ in range(50):
        d = sample_close_delay_s()
        assert 7200 <= d <= 86400


def test_sample_close_delay_handles_inverted_range(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_throwaway_channel_close_delay_min_s",
        7200,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_throwaway_channel_close_delay_max_s",
        1000,
    )
    out = sample_close_delay_s()
    assert out == 7200


# ── HOPPING — open channel ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_hopping_picks_peer_and_opens_channel(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "opened_channel"
    assert sess.pipeline_json["priv_channel_id"] == "ab" * 32 + ":0"


@pytest.mark.asyncio
async def test_open_returns_error_when_no_eligible_peer(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(peer_returns=(None, "no_peers"))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "no_eligible_peer" in out.detail


@pytest.mark.asyncio
async def test_open_returns_error_on_lnd_open_failure(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(open_returns=(None, "insufficient_funds"))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "open_channel_failed" in out.detail


# ── HOPPING — push payment ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_push_awaits_active_channel(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={"priv_channel_id": "ab" * 32 + ":0"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(active_returns=(False, None))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "awaiting_channel_active" in out.detail


@pytest.mark.asyncio
async def test_push_records_close_delay(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={"priv_channel_id": "ab" * 32 + ":0"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "pushed_payment"
    assert "priv_channel_close_at_unix_s" in sess.pipeline_json
    # Close-at is in the future.
    assert sess.pipeline_json["priv_channel_close_at_unix_s"] > (datetime.now(timezone.utc).timestamp())


# ── AWAITING_CHANNEL_CLOSE — cooperative close ──────────────────────


@pytest.mark.asyncio
async def test_close_awaits_sampled_delay(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value,
        pj={
            "priv_channel_id": "ab" * 32 + ":0",
            "priv_channel_close_at_unix_s": (datetime.now(timezone.utc).timestamp() + 3600),
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "awaiting_close_delay" in out.detail


@pytest.mark.asyncio
async def test_close_fires_when_delay_elapsed(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value,
        pj={
            "priv_channel_id": "ab" * 32 + ":0",
            "priv_channel_close_at_unix_s": 0,  # in the past
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "close_broadcast"


@pytest.mark.asyncio
async def test_close_returns_error_on_lnd_close_failure(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value,
        pj={
            "priv_channel_id": "ab" * 32 + ":0",
            "priv_channel_close_at_unix_s": 0,
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(close_returns=(None, "peer_offline"))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "close_failed" in out.detail


@pytest.mark.asyncio
async def test_close_failure_does_not_persist_completion(
    db_session,
) -> None:
    """When the cooperative close fails, the hop returns
    an error WITHOUT marking the close as completed; the next tick
    can retry (operator decides whether to intervene)."""
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSessionEvent

    sess = _session(
        status=AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value,
        pj={
            "priv_channel_id": "cd" * 32 + ":0",
            "priv_channel_close_at_unix_s": 0,
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(close_returns=(None, "peer_unresponsive"))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    # No completion event — next tick can retry.
    completed = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                    AnonymizeSessionEvent.kind == "hop_attempt_completed",
                )
            )
        )
        .scalars()
        .all()
    )
    # Open + push completed events may exist; we only care that
    # the close step did NOT mark completion.
    assert all((c.detail_json or {}).get("close_result") is None for c in completed)


@pytest.mark.asyncio
async def test_open_channel_rejects_peer_with_empty_pubkey(
    db_session,
) -> None:
    """When the auto-peer selector returns a peer with no
    pubkey, the open step fails closed."""
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(peer_returns=({"pubkey": ""}, None))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "peer_returned_no_pubkey" in out.detail


@pytest.mark.asyncio
async def test_push_payment_failure_routes_to_error(db_session) -> None:
    """Push-payment failure surfaces as an error so the per-session
    loop's bounded-retry handles the LN-route issue."""
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={"priv_channel_id": "ef" * 32 + ":0"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(push_returns=(None, "no_route"))
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "push_payment_failed" in out.detail


@pytest.mark.asyncio
async def test_unhandled_status_returns_noop(db_session) -> None:
    sess = _session(status=AnonymizeStatus.EXITING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_priv_channel_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
