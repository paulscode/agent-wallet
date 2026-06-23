# SPDX-License-Identifier: MIT
"""Reconciliation-action endpoint tests.

Covers the four endpoints in
``app/dashboard/api.py`` for operator-actionable session recovery:

* ``POST /anonymize/sessions/{id}/reconciliation/retry``
* ``POST /anonymize/sessions/{id}/reconciliation/fail``
* ``POST /anonymize/sessions/{id}/reconciliation/cancel`` (edge)
* ``POST /anonymize/sessions/{id}/reconciliation/refund`` (step-up)
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_reconciliation_cancel,
    dash_anonymize_reconciliation_fail,
    dash_anonymize_reconciliation_refund,
    dash_anonymize_reconciliation_retry,
    dash_anonymize_stepup_issue,
)
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.service import (
    get_anonymize_service,
    reset_anonymize_service,
)


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


@pytest.fixture
def _stepup_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_stepup_cookie_hmac_key_fernet",
        "a" * 44,
    )
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_ttl_s", 300)
    monkeypatch.setattr(settings, "anonymize_enabled", True)


def _mock_request(*, body: dict | None = None, cookie_subject: str = "cookie-abc") -> MagicMock:
    req = MagicMock()
    req.cookies = {"dashboard_session": cookie_subject}

    async def _json() -> dict:
        return body or {}

    req.json = _json
    return req


async def _make_awaiting_reconciliation_session(
    db_session,
    *,
    reason: str = "mpp_k_floor_exhausted",
    pre_status: str = AnonymizeStatus.EXITING.value,
):
    """Build a session row that's been parked in AWAITING_RECONCILIATION
    via the production helper, so all four reconciliation columns are
    populated the way the production wiring expects."""
    s = AnonymizeSession(
        id=uuid4(),
        status=pre_status,
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
    db_session.add(s)
    await db_session.flush()
    svc = get_anonymize_service()
    await svc.start()
    await svc.transition_to_awaiting_reconciliation(
        db_session,
        s,
        reason=reason,
    )
    await db_session.commit()
    return s


# ── Retry endpoint ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_retry_resumes_to_pre_status_and_clears_counters(
    db_session,
) -> None:
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(db_session)
    s.reconciliation_attempts = 5
    await db_session.commit()

    out = await dash_anonymize_reconciliation_retry(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert out["status"] == AnonymizeStatus.EXITING.value
    # Audit event emitted with the detail_json schema.
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    retry_events = [e for e in events if e.kind == "reconciliation_manual_retry"]
    assert len(retry_events) == 1
    # schema: {"previous_attempts": N, "reason": "...", "target_status": "..."}
    detail = retry_events[0].detail_json
    assert detail["previous_attempts"] == 5
    assert detail["reason"] == "mpp_k_floor_exhausted"
    assert detail["target_status"] == AnonymizeStatus.EXITING.value
    # Counters reset.
    await db_session.refresh(s)
    assert s.reconciliation_attempts == 0
    assert s.last_reconciliation_attempt_ts is None


@pytest.mark.asyncio
async def test_retry_409_when_not_in_awaiting_reconciliation(
    db_session,
) -> None:
    settings.anonymize_enabled = True
    s = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.EXITING.value,
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
    db_session.add(s)
    await db_session.commit()
    resp = await dash_anonymize_reconciliation_retry(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_retry_409_when_pre_reconciliation_status_is_null(
    db_session,
) -> None:
    """Legacy rows from before the reconciliation columns existed may have pre_status NULL."""
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(db_session)
    s.pre_reconciliation_status = None
    await db_session.commit()
    resp = await dash_anonymize_reconciliation_retry(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_retry_404_for_unknown_id(db_session) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_reconciliation_retry(
        str(uuid4()),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_retry_404_when_disabled(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    resp = await dash_anonymize_reconciliation_retry(
        str(uuid4()),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 404


# ── Cancel endpoint ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancel_succeeds_for_cancellable_reason(db_session) -> None:
    """``mpp_k_floor_exhausted`` is in the no-funds-moved set."""
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="mpp_k_floor_exhausted",
    )
    out = await dash_anonymize_reconciliation_cancel(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert out["status"] == AnonymizeStatus.CANCELLED.value
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    cancel_events = [e for e in events if e.kind == "reconciliation_manual_cancel"]
    assert len(cancel_events) == 1
    # schema: {"reason": "...", "to_status": "..."}
    detail = cancel_events[0].detail_json
    assert detail["reason"] == "mpp_k_floor_exhausted"
    assert detail["to_status"] == AnonymizeStatus.CANCELLED.value


@pytest.mark.asyncio
async def test_cancel_409_for_non_cancellable_reason(db_session) -> None:
    """``claim_feerate_outlier`` is funds-at-risk → not cancellable."""
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="claim_feerate_outlier",
    )
    resp = await dash_anonymize_reconciliation_cancel(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_cancel_409_when_not_in_awaiting_reconciliation(
    db_session,
) -> None:
    settings.anonymize_enabled = True
    s = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.EXITING.value,
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
    db_session.add(s)
    await db_session.commit()
    resp = await dash_anonymize_reconciliation_cancel(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 409


# ── Fail endpoint ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fail_terminates_with_audit_event(db_session) -> None:
    """Fail endpoint works on any reason — no cancellable gate."""
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="pipeline_schema_below_min_supported",
    )
    out = await dash_anonymize_reconciliation_fail(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert out["status"] == AnonymizeStatus.FAILED.value
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    fail_events = [e for e in events if e.kind == "reconciliation_manual_fail"]
    assert len(fail_events) == 1
    # schema: {"reason": "...", "to_status": "..."}
    detail = fail_events[0].detail_json
    assert detail["reason"] == "pipeline_schema_below_min_supported"
    assert detail["to_status"] == AnonymizeStatus.FAILED.value


@pytest.mark.asyncio
async def test_fail_409_when_not_in_awaiting_reconciliation(
    db_session,
) -> None:
    settings.anonymize_enabled = True
    s = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
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
    db_session.add(s)
    await db_session.commit()
    resp = await dash_anonymize_reconciliation_fail(
        str(s.id),
        request=_mock_request(),
        db=db_session,
    )
    assert resp.status_code == 409


# ── Refund endpoint (step-up) ──────────────────────────────────


@pytest.mark.asyncio
async def test_refund_requires_stepup_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="claim_feerate_outlier",
    )
    # No nonce in body → 400.
    resp = await dash_anonymize_reconciliation_refund(
        str(s.id),
        request=_mock_request(body={}),
        db=db_session,
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_refund_rejects_invalid_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="claim_feerate_outlier",
    )
    resp = await dash_anonymize_reconciliation_refund(
        str(s.id),
        request=_mock_request(body={"stepup_nonce": "not-a-valid-nonce"}),
        db=db_session,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_refund_succeeds_with_valid_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    """End-to-end: issue a nonce via /stepup/issue with the correct
    scope, then use it to refund."""
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="claim_feerate_outlier",
    )
    # Issue a nonce bound to the reconciliation-refund scope AND this
    # session (security H3 — the nonce is session-bound).
    issue_req = _mock_request(
        body={"scope": "anonymize_reconciliation_refund", "session_id": str(s.id)},
        cookie_subject="test-session",
    )
    issued = await dash_anonymize_stepup_issue(issue_req, db=db_session)
    nonce = issued["nonce"]

    refund_req = _mock_request(
        body={"stepup_nonce": nonce},
        cookie_subject="test-session",
    )
    out = await dash_anonymize_reconciliation_refund(
        str(s.id),
        request=refund_req,
        db=db_session,
    )
    assert out["status"] == AnonymizeStatus.REFUNDING.value
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    refund_events = [e for e in events if e.kind == "reconciliation_manual_refund"]
    assert len(refund_events) == 1
    assert refund_events[0].detail_json.get("stepup_nonce_present") is True


@pytest.mark.asyncio
async def test_refund_rejects_nonce_for_different_scope(
    db_session,
    _stepup_keyset,
) -> None:
    """A nonce minted for ``anonymize_decoy_spend_override`` MUST NOT
    authorise a reconciliation-refund call. Defense against
    scope-confusion."""
    settings.anonymize_enabled = True
    s = await _make_awaiting_reconciliation_session(
        db_session,
        reason="claim_feerate_outlier",
    )
    wrong_scope_req = _mock_request(
        body={"scope": "anonymize_decoy_spend_override"},
        cookie_subject="test-session",
    )
    issued = await dash_anonymize_stepup_issue(
        wrong_scope_req,
        db=db_session,
    )
    refund_req = _mock_request(
        body={"stepup_nonce": issued["nonce"]},
        cookie_subject="test-session",
    )
    resp = await dash_anonymize_reconciliation_refund(
        str(s.id),
        request=refund_req,
        db=db_session,
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_refund_404_when_disabled(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    resp = await dash_anonymize_reconciliation_refund(
        str(uuid4()),
        request=_mock_request(body={"stepup_nonce": "x"}),
        db=db_session,
    )
    assert resp.status_code == 404


# ── State-machine edge added by ──────────────────────────────


def test_state_machine_permits_ar_to_cancelled() -> None:
    """The state machine permits ``AWAITING_RECONCILIATION → CANCELLED``."""
    from app.services.anonymize.state_machine import is_legal_transition

    assert is_legal_transition(
        from_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        to_status=AnonymizeStatus.CANCELLED.value,
    )
