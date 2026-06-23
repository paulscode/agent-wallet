# SPDX-License-Identifier: MIT
"""Dashboard step-up + spend-override endpoints.

These endpoints sit at:

* ``POST /anonymize/stepup/issue`` — issues a transport nonce bound
  to the cookie + scope.
* ``POST /anonymize/sessions/{id}/spend-override`` — verifies the
  nonce + emits the override audit event.
"""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_spend_override,
    dash_anonymize_stepup_issue,
)
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
    AnonymizeStepupState,
)


@pytest.fixture
def _stepup_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_stepup_cookie_hmac_key_fernet",
        "a" * 44,
    )
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_ttl_s", 300)
    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        False,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_refund_override_spends",
        False,
    )


def _mock_request(*, body: dict, cookie_subject: str = "cookie-abc") -> MagicMock:
    req = MagicMock()
    req.cookies = {"dashboard_session": cookie_subject}

    async def _json() -> dict:
        return body

    req.json = _json
    return req


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="onchain-self",
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


# ── /anonymize/stepup/issue ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_stepup_issue_returns_nonce_and_ttl(
    db_session,
    _stepup_keyset,
) -> None:
    req = _mock_request(body={"scope": "anonymize_decoy_spend_override"})
    out = await dash_anonymize_stepup_issue(req, db=db_session)
    assert "nonce" in out
    assert isinstance(out["nonce"], str)
    assert len(out["nonce"]) > 0
    assert out["ttl_s"] == 300


@pytest.mark.asyncio
async def test_stepup_issue_persists_row_under_blinded_cookie(
    db_session,
    _stepup_keyset,
) -> None:
    req = _mock_request(body={"scope": "anonymize_refund_spend_override"})
    await dash_anonymize_stepup_issue(req, db=db_session)
    rows = (
        (
            await db_session.execute(
                select(AnonymizeStepupState).where(
                    AnonymizeStepupState.scope == "anonymize_refund_spend_override",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    # cookie_id_hmac is keyed-derivative, not the cookie string.
    assert rows[0].cookie_id_hmac != b"cookie-abc"
    assert len(rows[0].cookie_id_hmac) == 32


@pytest.mark.asyncio
async def test_stepup_issue_rejects_unknown_scope(
    db_session,
    _stepup_keyset,
) -> None:
    req = _mock_request(body={"scope": "arbitrary_attacker_scope"})
    out = await dash_anonymize_stepup_issue(req, db=db_session)
    assert out.status_code == 400


@pytest.mark.asyncio
async def test_stepup_issue_returns_404_when_disabled(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    req = _mock_request(body={"scope": "anonymize_decoy_spend_override"})
    out = await dash_anonymize_stepup_issue(req, db=db_session)
    assert out.status_code == 404


# ── /anonymize/sessions/{id}/spend-override ─────────────────────────


@pytest.mark.asyncio
async def test_spend_override_emits_event_on_valid_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    issue = await dash_anonymize_stepup_issue(
        # Bind the nonce to this session (security H3).
        _mock_request(body={"scope": "anonymize_decoy_spend_override", "session_id": str(sess.id)}),
        db=db_session,
    )
    nonce = issue["nonce"]
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:anonymize-decoy",
            "stepup_nonce": nonce,
        }
    )
    out = await dash_anonymize_spend_override(
        str(sess.id),
        req,
        db=db_session,
    )
    assert out == {"ok": True}
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                    AnonymizeSessionEvent.kind == "anonymize_decoy_spend_override",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].detail_json["label"] == "auto:anonymize-decoy"


@pytest.mark.asyncio
async def test_spend_override_rejects_wrong_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:anonymize-decoy",
            "stepup_nonce": "not-a-real-nonce",
        }
    )
    out = await dash_anonymize_spend_override(
        str(sess.id),
        req,
        db=db_session,
    )
    assert out.status_code == 403


@pytest.mark.asyncio
async def test_spend_override_rejects_nonce_from_wrong_scope(
    db_session,
    _stepup_keyset,
) -> None:
    """A nonce issued for the decoy scope must not satisfy a refund-label
    spend-override (and vice versa)."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    issue = await dash_anonymize_stepup_issue(
        _mock_request(body={"scope": "anonymize_decoy_spend_override"}),
        db=db_session,
    )
    nonce = issue["nonce"]
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:anonymize-refund",  # refund-family label
            "stepup_nonce": nonce,
        }
    )
    out = await dash_anonymize_spend_override(
        str(sess.id),
        req,
        db=db_session,
    )
    assert out.status_code == 403


@pytest.mark.asyncio
async def test_spend_override_refuses_when_external_flag_on(
    db_session,
    _stepup_keyset,
    monkeypatch,
) -> None:
    """Hard-refusal default: even a valid nonce cannot unlock the spend."""
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        True,
    )
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:anonymize-decoy",
            "stepup_nonce": "anything",
        }
    )
    out = await dash_anonymize_spend_override(
        str(sess.id),
        req,
        db=db_session,
    )
    assert out.status_code == 403


@pytest.mark.asyncio
async def test_spend_override_rejects_admit_label(
    db_session,
    _stepup_keyset,
) -> None:
    """A label that doesn't require step-up must not flow through this
    endpoint — the caller can spend it directly."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:receive",
            "stepup_nonce": "anything",
        }
    )
    out = await dash_anonymize_spend_override(
        str(sess.id),
        req,
        db=db_session,
    )
    assert out.status_code == 400


@pytest.mark.asyncio
async def test_spend_override_missing_fields_400(
    db_session,
    _stepup_keyset,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    req = _mock_request(body={"outpoint": "", "label": "", "stepup_nonce": ""})
    out = await dash_anonymize_spend_override(
        str(sess.id),
        req,
        db=db_session,
    )
    assert out.status_code == 400


@pytest.mark.asyncio
async def test_spend_override_unknown_session_returns_404(
    db_session,
    _stepup_keyset,
) -> None:
    issue = await dash_anonymize_stepup_issue(
        _mock_request(body={"scope": "anonymize_decoy_spend_override"}),
        db=db_session,
    )
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:anonymize-decoy",
            "stepup_nonce": issue["nonce"],
        }
    )
    out = await dash_anonymize_spend_override(
        str(uuid4()),
        req,
        db=db_session,
    )
    assert out.status_code == 404


@pytest.mark.asyncio
async def test_spend_override_returns_404_when_disabled(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    req = _mock_request(
        body={
            "outpoint": "ab" * 32 + ":0",
            "label": "auto:anonymize-decoy",
            "stepup_nonce": "any",
        }
    )
    out = await dash_anonymize_spend_override(
        str(uuid4()),
        req,
        db=db_session,
    )
    assert out.status_code == 404
