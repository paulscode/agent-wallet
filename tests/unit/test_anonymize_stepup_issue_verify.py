# SPDX-License-Identifier: MIT
"""Async step-up nonce issue + verify.

The dashboard's step-up flow:
1. Operator selects a non-anonymize spend that touches an
   ``auto:anonymize-*`` UTXO.
2. ``check_anonymize_spend_eligibility`` returns ``"require_stepup"``.
3. Dashboard calls :func:`issue_stepup_nonce` with the session
   cookie subject + a scope discriminator + receives the transport
   nonce.
4. UI presents a re-auth confirmation; on submit, dashboard calls
   :func:`verify_stepup_nonce` with the same scope.
5. On success, the override proceeds + the audit event lands.
6. On failure, the cookie's lockout counter increments (handled by
   the existing ``record_failed_verify`` helper).
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeStepupState
from app.services.anonymize.stepup import (
    issue_stepup_nonce,
    verify_stepup_nonce,
)


@pytest.fixture
def _stepup_keyset(monkeypatch):
    """Configure the cookie HMAC key so the blinding is deterministic
    inside this test session."""
    monkeypatch.setattr(
        settings,
        "anonymize_stepup_cookie_hmac_key_fernet",
        "a" * 44,
    )
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_ttl_s", 300)


@pytest.mark.asyncio
async def test_issue_returns_transport_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    assert isinstance(nonce, str)
    assert len(nonce) > 0


@pytest.mark.asyncio
async def test_stored_nonce_is_not_the_transport_value(
    db_session,
    _stepup_keyset,
) -> None:
    """The row stores an HMAC of the nonce, never the replayable value."""
    from sqlalchemy import select

    from app.services.anonymize.stepup import decode_nonce_from_transport

    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    row = (
        await db_session.execute(
            select(AnonymizeStepupState).where(
                AnonymizeStepupState.scope == "anonymize_decoy_spend_override",
            )
        )
    ).scalar_one()
    assert row.nonce_enc != decode_nonce_from_transport(nonce)


@pytest.mark.asyncio
async def test_raw_stored_value_does_not_verify(
    db_session,
    _stepup_keyset,
) -> None:
    """A value lifted straight from the DB cannot satisfy a challenge."""
    import base64

    from sqlalchemy import select

    await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    row = (
        await db_session.execute(
            select(AnonymizeStepupState).where(
                AnonymizeStepupState.scope == "anonymize_decoy_spend_override",
            )
        )
    ).scalar_one()
    lifted = base64.urlsafe_b64encode(row.nonce_enc).rstrip(b"=").decode("ascii")
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
        transport_nonce=lifted,
    )
    assert ok is False


@pytest.mark.asyncio
async def test_issue_persists_row_with_scope(
    db_session,
    _stepup_keyset,
) -> None:
    from sqlalchemy import select

    await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_refund_spend_override",
    )
    await db_session.commit()
    row = (
        await db_session.execute(
            select(AnonymizeStepupState).where(
                AnonymizeStepupState.scope == "anonymize_refund_spend_override",
            )
        )
    ).scalar_one()
    assert row.kind == "nonce"
    assert row.nonce_enc is not None
    assert len(row.nonce_enc) > 0


@pytest.mark.asyncio
async def test_verify_consumes_the_nonce_on_success(
    db_session,
    _stepup_keyset,
) -> None:
    from sqlalchemy import select

    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
        transport_nonce=nonce,
    )
    await db_session.commit()
    assert ok is True
    # The row was deleted (single-use).
    rows = (await db_session.execute(select(AnonymizeStepupState))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_verify_refuses_wrong_cookie(
    db_session,
    _stepup_keyset,
) -> None:
    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookie-DIFFERENT",
        scope="anonymize_decoy_spend_override",
        transport_nonce=nonce,
    )
    await db_session.commit()
    assert ok is False


@pytest.mark.asyncio
async def test_verify_refuses_wrong_scope(
    db_session,
    _stepup_keyset,
) -> None:
    """A nonce issued for the decoy-spend scope must NOT verify under
    the refund-spend scope."""
    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_refund_spend_override",  # different scope
        transport_nonce=nonce,
    )
    await db_session.commit()
    assert ok is False


@pytest.mark.asyncio
async def test_verify_refuses_tampered_nonce(
    db_session,
    _stepup_keyset,
) -> None:
    await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
        transport_nonce="not-a-real-nonce",
    )
    assert ok is False


@pytest.mark.asyncio
async def test_verify_refuses_after_expiry(
    db_session,
    _stepup_keyset,
) -> None:
    """A nonce past its expiry doesn't verify even with correct
    cookie + scope."""
    from datetime import datetime, timezone

    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
        ttl_s=60,
    )
    await db_session.commit()
    # 10 minutes later → past the 60s TTL.
    future = datetime.now(timezone.utc).timestamp() + 600
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
        transport_nonce=nonce,
        now_unix_s=future,
    )
    assert ok is False


@pytest.mark.asyncio
async def test_verify_is_single_use(
    db_session,
    _stepup_keyset,
) -> None:
    """A second verify with the same nonce fails — the row was
    deleted on the first successful verify."""
    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    assert (
        await verify_stepup_nonce(
            db_session,
            cookie_subject="cookie-abc",
            scope="anonymize_decoy_spend_override",
            transport_nonce=nonce,
        )
        is True
    )
    await db_session.commit()
    # Replay → False.
    assert (
        await verify_stepup_nonce(
            db_session,
            cookie_subject="cookie-abc",
            scope="anonymize_decoy_spend_override",
            transport_nonce=nonce,
        )
        is False
    )


@pytest.mark.asyncio
async def test_independent_nonces_for_independent_scopes(
    db_session,
    _stepup_keyset,
) -> None:
    """The same cookie can hold two in-flight nonces for two
    different override flows simultaneously."""
    n_decoy = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_decoy_spend_override",
    )
    n_refund = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookie-abc",
        scope="anonymize_refund_spend_override",
    )
    await db_session.commit()
    assert (
        await verify_stepup_nonce(
            db_session,
            cookie_subject="cookie-abc",
            scope="anonymize_decoy_spend_override",
            transport_nonce=n_decoy,
        )
        is True
    )
    await db_session.commit()
    assert (
        await verify_stepup_nonce(
            db_session,
            cookie_subject="cookie-abc",
            scope="anonymize_refund_spend_override",
            transport_nonce=n_refund,
        )
        is True
    )
