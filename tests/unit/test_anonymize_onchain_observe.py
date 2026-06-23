# SPDX-License-Identifier: MIT
"""/ — on-chain source observation collector.

Drives the dispatcher's LN_HOLDING / HOPPING / DELAYING transitions
for ``onchain-self`` / ``ext-onchain`` sessions and enforces the
 inter-leg delay window between submarine completion and
reverse-leg start.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.onchain_observe import (
    _inter_leg_delay_window_s,
    _sample_delay_target_s,
    observe_onchain_source,
)


def _session(
    *,
    status: str,
    pj: dict | None = None,
    source_kind: str = "onchain-self",
) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind=source_kind,
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


# ── window helpers ──────────────────────────────────────────────────


def test_inter_leg_window_reads_pipeline_json() -> None:
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        pj={
            "inter_leg_delay": {
                "min_seconds": 7200,
                "max_seconds": 14400,
            },
        },
    )
    mn, mx = _inter_leg_delay_window_s(s)
    assert (mn, mx) == (7200, 14400)


def test_inter_leg_window_falls_back_to_documented_floor() -> None:
    s = _session(status=AnonymizeStatus.DELAYING.value, pj={})
    mn, _mx = _inter_leg_delay_window_s(s)
    assert mn >= 6 * 3600  # 6 h floor


def test_sample_target_returns_value_inside_window() -> None:
    for _ in range(50):
        t = _sample_delay_target_s(7200, 14400)
        assert 7200 <= t <= 14400


# ── observation collector — happy paths ─────────────────────────────


@pytest.mark.asyncio
async def test_sourcing_returns_empty_observations(db_session) -> None:
    s = _session(status=AnonymizeStatus.SOURCING.value)
    out = await observe_onchain_source(db_session, s)
    assert out.funding_invoice_settled is None
    assert out.delay_window_elapsed is None


@pytest.mark.asyncio
async def test_funding_signals_settlement_when_broadcast_recorded(
    db_session,
) -> None:
    s = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_funding_broadcast_at_ts": "2026-05-11T00:00:00+00:00"},
    )
    out = await observe_onchain_source(db_session, s)
    assert out.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_funding_waits_when_no_broadcast_record(db_session) -> None:
    s = _session(status=AnonymizeStatus.FUNDING.value, pj={})
    out = await observe_onchain_source(db_session, s)
    assert out.funding_invoice_settled is None


@pytest.mark.asyncio
async def test_ln_holding_advances_when_settlement_claimed(db_session) -> None:
    s = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_status": "transaction.claimed"},
    )
    out = await observe_onchain_source(db_session, s)
    assert out.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_ln_holding_waits_during_in_flight_status(db_session) -> None:
    s = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_status": "transaction.mempool"},
    )
    out = await observe_onchain_source(db_session, s)
    assert out.funding_invoice_settled is None


@pytest.mark.asyncio
async def test_hopping_marks_completion_at_settlement(db_session) -> None:
    """Submarine settled → HOPPING → DELAYING via hop_completed."""
    s = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={"submarine_swap_status": "invoice.settled"},
    )
    out = await observe_onchain_source(db_session, s)
    assert out.hop_completed is True
    assert out.is_last_hop is True


# ── inter-leg delay enforcement ──────────────────────────────


@pytest.mark.asyncio
async def test_delaying_holds_when_inter_leg_window_not_elapsed(
    db_session,
) -> None:
    """DELAYING refuses to advance until the persisted
    inter_leg_delay window has elapsed since funding broadcast."""
    now = datetime.now(timezone.utc)
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        pj={
            "submarine_funding_broadcast_at_ts": now.isoformat(),
            "inter_leg_delay": {
                "min_seconds": 21_600,
                "max_seconds": 21_600,
            },
            "inter_leg_delay_target_s": 21_600,
        },
    )
    out = await observe_onchain_source(db_session, s)
    assert out.delay_window_elapsed is False


@pytest.mark.asyncio
async def test_delaying_advances_when_inter_leg_window_elapsed(
    db_session,
) -> None:
    """Once the elapsed delta exceeds the persisted
    target, the gate opens and the dispatcher moves to EXITING."""
    old = datetime.now(timezone.utc) - timedelta(hours=7)
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        pj={
            "submarine_funding_broadcast_at_ts": old.isoformat(),
            "inter_leg_delay": {
                "min_seconds": 21_600,  # 6 h
                "max_seconds": 21_600,
            },
            "inter_leg_delay_target_s": 21_600,
        },
    )
    out = await observe_onchain_source(db_session, s)
    assert out.delay_window_elapsed is True
    assert out.is_last_hop is True


@pytest.mark.asyncio
async def test_delaying_fails_open_when_funding_timestamp_missing(
    db_session,
) -> None:
    """If the submarine leg never recorded a broadcast (e.g., the
    session was injected without going through the hop body), the
    delay gate fails open rather than wedging the state machine."""
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        pj={},
    )
    out = await observe_onchain_source(db_session, s)
    assert out.delay_window_elapsed is True
    assert out.is_last_hop is True


@pytest.mark.asyncio
async def test_other_status_returns_empty(db_session) -> None:
    s = _session(status=AnonymizeStatus.EXITING.value)
    out = await observe_onchain_source(db_session, s)
    assert out.funding_invoice_settled is None
    assert out.delay_window_elapsed is None
