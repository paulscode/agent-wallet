# SPDX-License-Identifier: MIT
"""LN self-pay observation collector unit tests.

The collector is a pure read of the session row + the system clock.
It gates ``FUNDING`` → ``LN_HOLDING`` on the hop body's persisted
``self_pay_status`` so the session only advances once the
self-payment has settled.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.ln_self_pay_observe import observe_ln_self_pay


def _session(*, status: str, pj: dict | None = None, updated_at: datetime | None = None) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="lightning-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pj or {},
        updated_at=updated_at,
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


@pytest.mark.asyncio
async def test_created_signals_settled_to_reach_funding(db_session) -> None:
    sess = _session(status=AnonymizeStatus.CREATED.value)
    obs = await observe_ln_self_pay(db_session, sess)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_funding_waits_until_self_pay_settled(db_session) -> None:
    """At FUNDING the observer must NOT signal settled until the hop
    body records ``self_pay_status == settled`` — otherwise the session
    would advance before the self-payment lands."""
    sess = _session(status=AnonymizeStatus.FUNDING.value, pj={})
    obs = await observe_ln_self_pay(db_session, sess)
    # None means "wait" — the dispatcher refuses to advance.
    assert obs.funding_invoice_settled is None


@pytest.mark.asyncio
async def test_funding_signals_settled_once_status_set(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value, pj={"self_pay_status": "settled"})
    obs = await observe_ln_self_pay(db_session, sess)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_delaying_signals_elapsed_after_window(db_session) -> None:
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    sess = _session(
        status=AnonymizeStatus.DELAYING.value,
        pj={"delay_policy": {"min_seconds": 3600}},
        updated_at=past,
    )
    obs = await observe_ln_self_pay(db_session, sess)
    assert obs.delay_window_elapsed is True
    assert obs.is_last_hop is True


@pytest.mark.asyncio
async def test_delaying_waits_within_window(db_session) -> None:
    now = datetime.now(timezone.utc)
    sess = _session(
        status=AnonymizeStatus.DELAYING.value,
        pj={"delay_policy": {"min_seconds": 3600}},
        updated_at=now,
    )
    obs = await observe_ln_self_pay(db_session, sess)
    assert obs.delay_window_elapsed is False


@pytest.mark.asyncio
async def test_ln_holding_returns_empty_snapshot(db_session) -> None:
    sess = _session(status=AnonymizeStatus.LN_HOLDING.value, pj={"self_pay_status": "settled"})
    obs = await observe_ln_self_pay(db_session, sess)
    assert obs.funding_invoice_settled is None
    assert obs.delay_window_elapsed is None
