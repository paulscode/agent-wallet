# SPDX-License-Identifier: MIT
"""Production write path for ``anonymize_decoy_output`` rows.

The consolidation flow's decoy-output emitter calls
:func:`record_decoy_output` once per decoy output it appends. The
on-chain self-source path ships the row write (receive-only); the
external user-funded path adds spending.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeDecoyOutput,
    AnonymizeSession,
    AnonymizeStatus,
)
from app.services.anonymize.decoy_seed import (
    DecoySeedError,
    derive_session_account,
    record_decoy_output,
)


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.HOPPING.value,
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


@pytest.fixture
def _account_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_decoy_seed_account_key",
        "x" * 32,
    )


@pytest.mark.asyncio
async def test_record_decoy_output_writes_row(
    db_session,
    _account_key,
) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()

    await record_decoy_output(
        db_session,
        session_id=sess.id,
        derivation_index=7,
        address="bcrt1p" + "a" * 56,
        value_sat=123_456,
    )
    await db_session.commit()

    row = (
        await db_session.execute(select(AnonymizeDecoyOutput).where(AnonymizeDecoyOutput.session_id == sess.id))
    ).scalar_one()
    assert row.derivation_index == 7
    assert row.value_sat == 123_456
    assert row.address == "bcrt1p" + "a" * 56
    assert row.outpoint is None
    assert row.seed_orphaned is False
    # Session account is the HMAC derivative — deterministic per session.
    expected = derive_session_account(
        sess.id,
        account_key=b"x" * 32,
    )
    assert row.session_account == expected


@pytest.mark.asyncio
async def test_record_decoy_output_persists_outpoint_when_supplied(
    db_session,
    _account_key,
) -> None:
    """Post-broadcast the consolidation tx's outpoint is captured."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await record_decoy_output(
        db_session,
        session_id=sess.id,
        derivation_index=3,
        address="bcrt1p" + "b" * 56,
        value_sat=500_000,
        outpoint="ab" * 32 + ":1",
    )
    await db_session.commit()
    row = (
        await db_session.execute(select(AnonymizeDecoyOutput).where(AnonymizeDecoyOutput.session_id == sess.id))
    ).scalar_one()
    assert row.outpoint == "ab" * 32 + ":1"


@pytest.mark.asyncio
async def test_record_decoy_output_rejects_zero_value(
    db_session,
    _account_key,
) -> None:
    with pytest.raises(ValueError, match="value_sat must be positive"):
        await record_decoy_output(
            db_session,
            session_id=uuid4(),
            derivation_index=0,
            address="bcrt1ptest",
            value_sat=0,
        )


@pytest.mark.asyncio
async def test_record_decoy_output_rejects_empty_address(
    db_session,
    _account_key,
) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        await record_decoy_output(
            db_session,
            session_id=uuid4(),
            derivation_index=0,
            address="",
            value_sat=500_000,
        )


@pytest.mark.asyncio
async def test_record_decoy_output_refuses_when_account_key_unset(
    db_session,
    monkeypatch,
) -> None:
    """A deployment without ``ANONYMIZE_DECOY_SEED_ACCOUNT_KEY`` can
    not derive a session_account; the write refuses."""
    monkeypatch.setattr(settings, "anonymize_decoy_seed_account_key", "")
    with pytest.raises(DecoySeedError, match="ACCOUNT_KEY"):
        await record_decoy_output(
            db_session,
            session_id=uuid4(),
            derivation_index=0,
            address="bcrt1ptest",
            value_sat=500_000,
        )


@pytest.mark.asyncio
async def test_record_decoy_output_distinct_session_accounts(
    db_session,
    _account_key,
) -> None:
    """Two distinct sessions produce distinct session_accounts."""
    s1 = _session()
    s2 = _session()
    db_session.add(s1)
    db_session.add(s2)
    await db_session.flush()
    for s in (s1, s2):
        await record_decoy_output(
            db_session,
            session_id=s.id,
            derivation_index=0,
            address="bcrt1p" + "c" * 56,
            value_sat=100_000,
        )
    await db_session.commit()
    rows = (
        await db_session.execute(select(AnonymizeDecoyOutput.session_account).order_by(AnonymizeDecoyOutput.id))
    ).all()
    sa1, sa2 = rows[0][0], rows[1][0]
    assert sa1 != sa2
