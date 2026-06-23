# SPDX-License-Identifier: MIT
"""Create endpoint reuse hard-block + triple-validation."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_create_session,
    dash_anonymize_quote,
)
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.reuse_detection import (
    ReuseDetectionKeySet,
    load_reuse_detection_keyset,
)
from app.services.anonymize.service import reset_anonymize_service

_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"


@pytest.fixture
def _quote_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture
def _reuse_keyset(monkeypatch):
    """Seed a reuse-detection key so the hard-block path engages."""
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_detection_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _mock_request(*, body, cookie="abc", source_ip="127.0.0.1"):
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    req = MagicMock()
    req.body = AsyncMock(return_value=raw)
    req.cookies = {"dashboard_session": cookie} if cookie else {}
    req.app.state.anonymize_health = {
        "egress_endpoints_onion_only": True,
        "operator_registry_size": 1,
        "tor_bootstrap_ready": True,
    }
    if source_ip is None:
        req.client = None
    else:
        req.client = MagicMock()
        req.client.host = source_ip
    return req


async def _get_quote_token(cookie="abc"):
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            },
            cookie=cookie,
        )
    )
    assert isinstance(out, dict), f"quote returned {out}"
    return out["quote_token"]


# ── Reuse-detection keyset loader ────────────────────────────────────


def test_load_reuse_keyset_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_fernet", "")
    assert load_reuse_detection_keyset() is None


def test_load_reuse_keyset_returns_keyset_when_configured(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_detection_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    ks = load_reuse_detection_keyset()
    assert isinstance(ks, ReuseDetectionKeySet)


# ── Create endpoint reuse hard-block ─────────────────────────────────


@pytest.mark.asyncio
async def test_create_rejects_reused_destination(
    db_engine,
    db_session,
    _quote_keyset,
    _reuse_keyset,
    monkeypatch,
) -> None:
    """A destination that matches a prior session is 422."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    # Seed a prior session whose destination hash matches our reuse key.
    ks = load_reuse_detection_keyset()
    assert ks is not None
    prior_hash = ks.hash_active(_REGTEST_P2TR)
    prior = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=prior_hash,
        destination_reuse_key_generation=0,
    )
    db_session.add(prior)
    await db_session.commit()

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="reuse-tester")

    # The reuse hard-block must pay the same key-derivation cost the
    # accept path incurs (PBKDF2 in ``encrypt_destination_address``) so a
    # rejected destination is not separable from an accepted one by
    # response timing.
    import app.services.anonymize.crypto as _crypto

    real_encrypt = _crypto.encrypt_destination_address
    calls: list[str] = []

    def _spy(addr: str):  # noqa: ANN202
        calls.append(addr)
        return real_encrypt(addr)

    monkeypatch.setattr(_crypto, "encrypt_destination_address", _spy)

    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="reuse-tester"),
        db=db_session,
    )
    assert resp.status_code == 422
    assert _REGTEST_P2TR in calls, "reuse hard-block must run the encrypt ballast"


@pytest.mark.asyncio
async def test_create_admits_first_use_of_destination(
    db_engine,
    db_session,
    _quote_keyset,
    _reuse_keyset,
    monkeypatch,
) -> None:
    """A destination never seen before is admitted; the new row's hash
    uses the active reuse key."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="firstuse")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="firstuse"),
        db=db_session,
    )
    assert isinstance(out, dict)
    # The persisted row's keyed hash matches the active key's hash.
    ks = load_reuse_detection_keyset()
    expected = ks.hash_active(_REGTEST_P2TR)
    async with factory() as fresh:
        from uuid import UUID

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == UUID(out["id"])))).scalar_one()
        assert row.destination_address_blake2b_keyed == expected
        assert row.destination_reuse_key_generation == 0

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_admits_when_reuse_keyset_unset(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """Lightning-only deployments without a reuse key still admit creates;
    the row is written with the sentinel hash."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_fernet", "")

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="nokeysess")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="nokeysess"),
        db=db_session,
    )
    assert isinstance(out, dict)

    from app.services.anonymize.metadata import REUSE_DETECTION_SENTINEL

    async with factory() as fresh:
        from uuid import UUID

        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == UUID(out["id"])))).scalar_one()
        assert row.destination_address_blake2b_keyed == REUSE_DETECTION_SENTINEL

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()
