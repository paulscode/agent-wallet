# SPDX-License-Identifier: MIT
"""Step-up hardening regression tests.

Covers:
* action binding — a nonce issued for one session cannot satisfy a
  verify for a different session in the same scope;
* DB-backed lockout — repeated failed verifies lock the cookie out;
* SECRET_KEY-derived blinding — an unset dedicated HMAC key falls back
  to a SECRET_KEY-derived key, never an empty key.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import AnonymizeStepupState
from app.services.anonymize.stepup import (
    _stepup_blinding_key,
    issue_stepup_nonce,
    verify_stepup_nonce,
)


@pytest.fixture
def _keyset(monkeypatch):
    monkeypatch.setattr(settings, "anonymize_stepup_cookie_hmac_key_fernet", "a" * 44)
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_ttl_s", 300)
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_verify_rate_limit_per_min", 3)
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_verify_lockout_s", 300)


@pytest.mark.asyncio
async def test_nonce_bound_to_session_rejected_for_other_session(db_session, _keyset):
    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookieA",
        scope="anonymize_reconciliation_refund",
        binding="11111111-1111-1111-1111-111111111111",
    )
    await db_session.commit()

    # Wrong session binding → reject.
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookieA",
        scope="anonymize_reconciliation_refund",
        transport_nonce=nonce,
        binding="22222222-2222-2222-2222-222222222222",
    )
    assert ok is False
    await db_session.commit()

    # Correct session binding → accept (nonce still present).
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookieA",
        scope="anonymize_reconciliation_refund",
        transport_nonce=nonce,
        binding="11111111-1111-1111-1111-111111111111",
    )
    assert ok is True


@pytest.mark.asyncio
async def test_repeated_failures_lock_cookie_out(db_session, _keyset):
    # Threshold is 3 (fixture). Three bad verifies trip the lockout.
    for _ in range(3):
        ok = await verify_stepup_nonce(
            db_session,
            cookie_subject="cookieB",
            scope="anonymize_decoy_spend_override",
            transport_nonce="AAAA",  # never matches
        )
        assert ok is False
        await db_session.commit()

    # A lockout row now exists and is active.
    lock = (
        await db_session.execute(
            select(AnonymizeStepupState).where(
                AnonymizeStepupState.kind == "lockout",
            )
        )
    ).scalar_one()
    assert lock.failed_verifies >= 3

    # Even a *valid* nonce is refused while locked out.
    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookieB",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookieB",
        scope="anonymize_decoy_spend_override",
        transport_nonce=nonce,
    )
    assert ok is False


@pytest.mark.asyncio
async def test_successful_verify_clears_lockout_counter(db_session, _keyset):
    # Two failures (below threshold of 3), then a success clears the row.
    for _ in range(2):
        await verify_stepup_nonce(
            db_session,
            cookie_subject="cookieC",
            scope="anonymize_decoy_spend_override",
            transport_nonce="AAAA",
        )
        await db_session.commit()

    nonce = await issue_stepup_nonce(
        db_session,
        cookie_subject="cookieC",
        scope="anonymize_decoy_spend_override",
    )
    await db_session.commit()
    ok = await verify_stepup_nonce(
        db_session,
        cookie_subject="cookieC",
        scope="anonymize_decoy_spend_override",
        transport_nonce=nonce,
    )
    assert ok is True
    await db_session.commit()

    locks = (
        await db_session.execute(
            select(AnonymizeStepupState).where(AnonymizeStepupState.kind == "lockout")
        )
    ).scalars().all()
    assert locks == []


def test_blinding_key_falls_back_to_secret_key_not_empty(monkeypatch):
    monkeypatch.setattr(settings, "anonymize_stepup_cookie_hmac_key_fernet", "")
    monkeypatch.setattr(settings, "secret_key", "s" * 48)
    key = _stepup_blinding_key()
    assert key != b""
    assert len(key) == 32  # HMAC-SHA256 digest
    # Distinct from a naive empty-key HMAC of the same context.
    import hashlib
    import hmac as _hmac

    naive_empty = _hmac.new(b"", b"agent-wallet/anonymize-stepup-cookie/v1", hashlib.sha256).digest()
    assert key != naive_empty


def test_blinding_key_prefers_configured_key(monkeypatch):
    monkeypatch.setattr(settings, "anonymize_stepup_cookie_hmac_key_fernet", "z" * 44)
    assert _stepup_blinding_key() == ("z" * 44).encode("ascii")
