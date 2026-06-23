# SPDX-License-Identifier: MIT
"""Reverse-exit observation collector."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.reverse_observe import observe_reverse_exit
from app.services.anonymize.observation_router import default_observation_fn
from app.services.anonymize.tick import TickObservations


def _session(*, status: str, **extras) -> AnonymizeSession:
    s = AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="lightning-self",
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
    for k, v in extras.items():
        setattr(s, k, v)
    return s


# ── EXITING ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_exiting_no_broadcast_yet_waits(db_session) -> None:
    s = _session(status=AnonymizeStatus.EXITING.value)
    obs = await observe_reverse_exit(db_session, s)
    assert obs.claim_tx_observed_on_chain is False


@pytest.mark.asyncio
async def test_exiting_with_broadcast_observed(db_session) -> None:
    s = _session(
        status=AnonymizeStatus.EXITING.value,
        claim_broadcast_at_ts=datetime.now(timezone.utc),
    )
    obs = await observe_reverse_exit(db_session, s)
    assert obs.claim_tx_observed_on_chain is True


# ── CONFIRMING ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_confirming_waits_for_min_confirmations(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_min_confirmations", 2)
    s = _session(status=AnonymizeStatus.CONFIRMING.value)
    s.__dict__["claim_tx_confirmations"] = 1
    obs = await observe_reverse_exit(db_session, s)
    assert obs.claim_tx_min_confirmations_reached is False


@pytest.mark.asyncio
async def test_confirming_advances_at_min_confirmations(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_min_confirmations", 2)
    s = _session(status=AnonymizeStatus.CONFIRMING.value)
    s.__dict__["claim_tx_confirmations"] = 2
    obs = await observe_reverse_exit(db_session, s)
    assert obs.claim_tx_min_confirmations_reached is True


@pytest.mark.asyncio
async def test_confirming_signals_reorg_uncertainty(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_reorg_giveup_blocks", 12)
    s = _session(status=AnonymizeStatus.CONFIRMING.value)
    s.__dict__["claim_tx_reorg_observed_count"] = 15
    obs = await observe_reverse_exit(db_session, s)
    assert obs.claim_tx_reorg_uncertainty is True


# ── Other statuses ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reverse_observer_silent_for_other_statuses(db_session) -> None:
    for status in (
        AnonymizeStatus.CREATED.value,
        AnonymizeStatus.FUNDING.value,
        AnonymizeStatus.LN_HOLDING.value,
        AnonymizeStatus.DELAYING.value,
        AnonymizeStatus.HOPPING.value,
    ):
        s = _session(status=status)
        obs = await observe_reverse_exit(db_session, s)
        assert obs == TickObservations()


# ── Router merge: source + exit observers compose ────────────────────


@pytest.mark.asyncio
async def test_router_merges_source_and_exit_for_exiting_session(
    db_session,
) -> None:
    """An EXITING session with claim broadcast: source observer is
    silent, exit observer signals claim_tx_observed_on_chain."""
    s = _session(
        status=AnonymizeStatus.EXITING.value,
        claim_broadcast_at_ts=datetime.now(timezone.utc),
    )
    obs = await default_observation_fn(db_session, s)
    assert obs.claim_tx_observed_on_chain is True


@pytest.mark.asyncio
async def test_router_source_observer_still_fires_in_funding(db_session) -> None:
    """LN-self-pay in FUNDING: source observer wins, exit silent."""
    s = _session(
        source_kind="lightning-self",
        status=AnonymizeStatus.FUNDING.value,
    )
    s.source_kind = "lightning-self"
    # The source observer gates FUNDING on the hop body's persisted
    # self-pay settlement; mark it settled so the source-side signal
    # fires (and the exit observer stays silent at FUNDING).
    s.pipeline_json = {**(s.pipeline_json or {}), "self_pay_status": "settled"}
    obs = await default_observation_fn(db_session, s)
    assert obs.funding_invoice_settled is True
