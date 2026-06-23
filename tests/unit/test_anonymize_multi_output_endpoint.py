# SPDX-License-Identifier: MIT
"""Quote-token-bound `POST /anonymize/sessions/multi` flow.

The dashboard surface is two endpoints:

* ``POST /anonymize/quote/multi`` — issues a signed quote token over
  the canonical multi-output pipeline JSON.
* ``POST /anonymize/sessions/multi`` — redeems the token, validates
  the plan object, persists the session + N output rows.

Together they mirror the single-output ``/anonymize/quote`` +
``/anonymize/sessions`` shape.
"""

from __future__ import annotations

import json as _json
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_create_multi_output_session,
    dash_anonymize_quote_multi,
)
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionOutput,
    AnonymizeStatus,
)

_REGTEST_P2TR_A = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
_REGTEST_P2WPKH = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"
_REGTEST_P2WSH = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqezzy8c"


@pytest.fixture(autouse=True)
def _enable_anonymize_and_keyset(monkeypatch):
    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(settings, "anonymize_min_sat", 50_000)
    monkeypatch.setattr(settings, "anonymize_max_sat", 10_000_000)
    monkeypatch.setattr(
        settings,
        "anonymize_amount_bins_sat",
        "50000,100000,250000,500000,1000000",
    )
    monkeypatch.setattr(settings, "anonymize_multi_output_max_count", 5)
    # Fresh quote-token keyset so issue + decode use the same key.
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


def _mock_request(
    *,
    body: dict,
    cookie_subject: str = "cookie-abc",
    health: dict | None = None,
) -> MagicMock:
    """Request stub mirroring the FastAPI shape the endpoint uses."""
    req = MagicMock()
    req.cookies = {"dashboard_session": cookie_subject}
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.app = MagicMock()
    req.app.state = MagicMock()
    req.app.state.anonymize_health = health if health is not None else {"tor_bootstrap_ready": True}
    payload = _json.dumps(body).encode("utf-8")

    async def _body() -> bytes:
        return payload

    req.body = _body
    return req


async def _issue_token(
    *,
    destinations: list[tuple[str, int]],
    cookie_subject: str = "cookie-abc",
    source_kind: str = "lightning-self",
) -> str:
    body = {
        "source_kind": source_kind,
        "destinations": [{"address": a, "amount_sat": amt} for a, amt in destinations],
    }
    out = await dash_anonymize_quote_multi(
        _mock_request(body=body, cookie_subject=cookie_subject),
    )
    return out["quote_token"]


# ── quote endpoint ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_quote_returns_token_and_bin_amounts() -> None:
    body = {
        "source_kind": "lightning-self",
        "destinations": [
            {"address": _REGTEST_P2TR_A, "amount_sat": 100_000},
            {"address": _REGTEST_P2WPKH, "amount_sat": 250_000},
        ],
    }
    out = await dash_anonymize_quote_multi(_mock_request(body=body))
    assert isinstance(out["quote_token"], str)
    assert out["quote_token"].count(".") == 2  # gen.body.mac
    assert out["bin_amounts_sat"] == [100_000, 250_000]
    assert out["ttl_s"] == int(settings.anonymize_quote_token_ttl_s)


@pytest.mark.asyncio
async def test_quote_404_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    out = await dash_anonymize_quote_multi(
        _mock_request(
            body={
                "source_kind": "lightning-self",
                "destinations": [{"address": _REGTEST_P2TR_A, "amount_sat": 100_000}],
            }
        )
    )
    assert out.status_code == 404


@pytest.mark.asyncio
async def test_quote_rejects_malformed_destinations() -> None:
    out = await dash_anonymize_quote_multi(
        _mock_request(
            body={
                "source_kind": "lightning-self",
                "destinations": [],
            }
        )
    )
    assert out.status_code == 422


@pytest.mark.asyncio
async def test_quote_rejects_invalid_destination() -> None:
    out = await dash_anonymize_quote_multi(
        _mock_request(
            body={
                "source_kind": "lightning-self",
                "destinations": [
                    {"address": "not-a-real-address", "amount_sat": 100_000},
                ],
            }
        )
    )
    assert out.status_code == 422


# ── session-create endpoint, token-bound ───────────────────────────


@pytest.mark.asyncio
async def test_session_create_consumes_quote_token(db_session) -> None:
    token = await _issue_token(
        destinations=[
            (_REGTEST_P2TR_A, 100_000),
            (_REGTEST_P2WPKH, 250_000),
            (_REGTEST_P2WSH, 500_000),
        ]
    )
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(body={"quote_token": token}),
        db=db_session,
    )
    assert "id" in out
    assert out["status"] == AnonymizeStatus.CREATED.value
    assert out["source_kind"] == "lightning-self"
    assert out["output_count"] == 3

    sessions = (await db_session.execute(select(AnonymizeSession))).scalars().all()
    assert len(sessions) == 1
    outputs = (
        (
            await db_session.execute(
                select(AnonymizeSessionOutput)
                .where(AnonymizeSessionOutput.session_id == sessions[0].id)
                .order_by(AnonymizeSessionOutput.output_index)
            )
        )
        .scalars()
        .all()
    )
    assert [o.output_index for o in outputs] == [0, 1, 2]
    assert [o.bin_amount_sat for o in outputs] == [100_000, 250_000, 500_000]


@pytest.mark.asyncio
async def test_session_create_rejects_missing_token(db_session) -> None:
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(body={}),
        db=db_session,
    )
    assert out.status_code == 422


@pytest.mark.asyncio
async def test_session_create_rejects_garbage_token(db_session) -> None:
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(body={"quote_token": "not-a-valid-token"}),
        db=db_session,
    )
    assert out.status_code == 422


@pytest.mark.asyncio
async def test_session_create_rejects_token_under_different_cookie(
    db_session,
) -> None:
    """Token bound to one cookie must not work under another — the
    cookie_subject_hmac mismatch is what defeats cookie-rotation
    replay."""
    token = await _issue_token(
        destinations=[(_REGTEST_P2TR_A, 100_000)],
        cookie_subject="cookie-original",
    )
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(
            body={"quote_token": token},
            cookie_subject="cookie-attacker",
        ),
        db=db_session,
    )
    # Distinct cookies → cookie_subject_hmac mismatch → 422 destination_rejected.
    assert out.status_code == 422


@pytest.mark.asyncio
async def test_session_create_404_when_disabled(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(body={"quote_token": "x"}),
        db=db_session,
    )
    assert out.status_code == 404


@pytest.mark.asyncio
async def test_session_create_503_on_clock_skew(db_session) -> None:
    token = await _issue_token(destinations=[(_REGTEST_P2TR_A, 100_000)])
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(
            body={"quote_token": token},
            health={"clock_skew_within_threshold": False},
        ),
        db=db_session,
    )
    assert out.status_code == 503


@pytest.mark.asyncio
async def test_session_create_503_on_tor_not_bootstrapped(db_session) -> None:
    token = await _issue_token(destinations=[(_REGTEST_P2TR_A, 100_000)])
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(
            body={"quote_token": token},
            health={"tor_bootstrap_ready": False},
        ),
        db=db_session,
    )
    assert out.status_code == 503


@pytest.mark.asyncio
async def test_session_create_503_when_keyset_unconfigured(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        "",
    )
    out = await dash_anonymize_create_multi_output_session(
        _mock_request(body={"quote_token": "x"}),
        db=db_session,
    )
    assert out.status_code == 503


@pytest.mark.asyncio
async def test_mirror_index_zero_in_singular_columns(db_session) -> None:
    """The parent session row carries output 0's amount + script_type
    + quote_hmac in the singular columns."""
    token = await _issue_token(
        destinations=[
            (_REGTEST_P2TR_A, 250_000),
            (_REGTEST_P2WPKH, 100_000),
        ]
    )
    await dash_anonymize_create_multi_output_session(
        _mock_request(body={"quote_token": token}),
        db=db_session,
    )
    sess = (await db_session.execute(select(AnonymizeSession))).scalar_one()
    assert sess.bin_amount_sat == 250_000
    assert sess.destination_script_type == "p2tr"
    assert sess.pipeline_json["multi_output"] is True
    assert sess.pipeline_json["output_count"] == 2
    assert sess.requested_amount_sat == 350_000
    # quote_hmac mirrors the cookie HMAC the token was bound to.
    assert len(sess.quote_hmac) == 32
    assert sess.quote_hmac != b"\x00" * 32
