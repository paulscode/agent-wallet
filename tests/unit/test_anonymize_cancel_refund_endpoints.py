# SPDX-License-Identifier: MIT
"""POST /anonymize/sessions/{id}/cancel + /refund endpoints.

Covers:

* Cancel transitions a CREATED / SOURCING / FUNDING session to CANCELLED.
* Refund transitions LN_HOLDING / DELAYING / HOPPING to REFUNDING.
* Both endpoints return 404 for malformed / unknown id.
* Both endpoints return 409 with the legal next-status set when the
  current status doesn't admit the requested transition.
* Disabled deployment ⇒ 404.
* Successful transitions surface the safe projected summary.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_cancel_session,
    dash_anonymize_refund_session,
)
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.service import reset_anonymize_service


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _session(*, status: str) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct" * 16,
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


# ── Cancel ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancel_transitions_created_to_cancelled(db_session) -> None:
    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.CREATED.value)
    db_session.add(s)
    await db_session.commit()

    out = await dash_anonymize_cancel_session(str(s.id), db=db_session)
    assert out["id"] == str(s.id)
    assert out["status"] == AnonymizeStatus.CANCELLED.value

    # Verify the row in DB also moved.
    await db_session.refresh(s)
    assert s.status == AnonymizeStatus.CANCELLED.value


@pytest.mark.asyncio
async def test_cancel_returns_409_from_completed(db_session) -> None:
    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.COMPLETED.value)
    db_session.add(s)
    await db_session.commit()

    resp = await dash_anonymize_cancel_session(str(s.id), db=db_session)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_cancel_returns_404_for_unknown_id(db_session) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_cancel_session(str(uuid4()), db=db_session)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cancel_returns_404_for_malformed_id(db_session) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_cancel_session("not-a-uuid", db=db_session)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cancel_returns_404_when_disabled(db_session) -> None:
    settings.anonymize_enabled = False
    try:
        resp = await dash_anonymize_cancel_session(str(uuid4()), db=db_session)
        assert resp.status_code == 404
    finally:
        settings.anonymize_enabled = True


# ── Refund ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refund_transitions_delaying_to_refunding(db_session) -> None:
    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.DELAYING.value)
    db_session.add(s)
    await db_session.commit()

    out = await dash_anonymize_refund_session(str(s.id), db=db_session)
    assert out["status"] == AnonymizeStatus.REFUNDING.value


@pytest.mark.asyncio
async def test_refund_transitions_ln_holding_to_refunding(db_session) -> None:
    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.LN_HOLDING.value)
    db_session.add(s)
    await db_session.commit()

    out = await dash_anonymize_refund_session(str(s.id), db=db_session)
    assert out["status"] == AnonymizeStatus.REFUNDING.value


@pytest.mark.asyncio
async def test_refund_returns_409_from_created(db_session) -> None:
    """``created`` is not in the legal refund predecessors."""
    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.CREATED.value)
    db_session.add(s)
    await db_session.commit()
    resp = await dash_anonymize_refund_session(str(s.id), db=db_session)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_refund_returns_409_from_completed(db_session) -> None:
    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.COMPLETED.value)
    db_session.add(s)
    await db_session.commit()
    resp = await dash_anonymize_refund_session(str(s.id), db=db_session)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_refund_returns_404_for_unknown_id(db_session) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_refund_session(str(uuid4()), db=db_session)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_refund_returns_404_when_disabled(db_session) -> None:
    settings.anonymize_enabled = False
    try:
        resp = await dash_anonymize_refund_session(str(uuid4()), db=db_session)
        assert resp.status_code == 404
    finally:
        settings.anonymize_enabled = True


# ── Response shape ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancel_409_body_includes_legal_next_statuses(db_session) -> None:
    """The 409 payload tells the SPA which transitions ARE legal."""
    import json

    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.FAILED.value)
    db_session.add(s)
    await db_session.commit()
    resp = await dash_anonymize_cancel_session(str(s.id), db=db_session)
    assert resp.status_code == 409
    body = json.loads(resp.body)
    assert body["code"] == "illegal_state_transition"
    assert body["from_status"] == AnonymizeStatus.FAILED.value
    assert body["to_status"] == AnonymizeStatus.CANCELLED.value
    # ``failed`` is terminal so legal_next_statuses is empty.
    assert body["legal_next_statuses"] == []


@pytest.mark.asyncio
async def test_cancel_response_does_not_leak_destination(db_session) -> None:
    """Successful cancel returns the safe projected shape only."""
    import json

    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.CREATED.value)
    db_session.add(s)
    await db_session.commit()
    out = await dash_anonymize_cancel_session(str(s.id), db=db_session)
    blob = json.dumps(out, default=str)
    assert "destination_address_enc" not in blob
    assert "quote_hmac" not in blob
