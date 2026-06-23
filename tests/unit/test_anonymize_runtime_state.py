# SPDX-License-Identifier: MIT
"""Anonymize_runtime_state read/write."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.services.anonymize.crypto import MultiFernetBundle
from app.services.anonymize.metadata import ANONYMIZE_RUNTIME_STATE_KEYS
from app.services.anonymize.runtime_state import (
    RuntimeStateKeyRejectedError,
    delete_runtime_state,
    read_runtime_state,
    write_runtime_state,
)

_REGISTRY_KEY = next(iter(ANONYMIZE_RUNTIME_STATE_KEYS))


@pytest.mark.asyncio
async def test_write_then_read_roundtrips_cleartext(db_session) -> None:
    payload = {"level": 3.14, "burst": True}
    await write_runtime_state(db_session, key=_REGISTRY_KEY, payload=payload)
    await db_session.commit()
    out = await read_runtime_state(db_session, key=_REGISTRY_KEY)
    assert out == payload


@pytest.mark.asyncio
async def test_read_returns_none_for_missing_key(db_session) -> None:
    out = await read_runtime_state(db_session, key=_REGISTRY_KEY)
    assert out is None


@pytest.mark.asyncio
async def test_write_then_read_with_encryption_bundle(db_session) -> None:
    """The Fernet bundle wraps the value column on the persistence path."""
    bundle = MultiFernetBundle(keys=(Fernet.generate_key(),))
    payload = {"sensitive": "circuit-rebuild bucket"}
    await write_runtime_state(
        db_session,
        key=_REGISTRY_KEY,
        payload=payload,
        bundle=bundle,
    )
    await db_session.commit()

    # Direct DB read shows ciphertext, not cleartext.
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeRuntimeState

    row = (
        await db_session.execute(select(AnonymizeRuntimeState).where(AnonymizeRuntimeState.key == _REGISTRY_KEY))
    ).scalar_one()
    assert b"sensitive" not in row.value  # encrypted

    out = await read_runtime_state(db_session, key=_REGISTRY_KEY, bundle=bundle)
    assert out == payload


@pytest.mark.asyncio
async def test_read_with_bundle_falls_back_to_cleartext(db_session) -> None:
    """Pre-020a row (cleartext) still readable after the migration when
    the application passes a bundle. Tests the transition discipline."""
    bundle = MultiFernetBundle(keys=(Fernet.generate_key(),))
    # Write cleartext (no bundle).
    payload = {"legacy": "row"}
    await write_runtime_state(db_session, key=_REGISTRY_KEY, payload=payload)
    await db_session.commit()
    # Read with bundle should still decode the cleartext.
    out = await read_runtime_state(db_session, key=_REGISTRY_KEY, bundle=bundle)
    assert out == payload


@pytest.mark.asyncio
async def test_write_rejects_unregistered_key(db_session) -> None:
    with pytest.raises(RuntimeStateKeyRejectedError, match="not in"):
        await write_runtime_state(
            db_session,
            key="ad_hoc_key_not_in_registry",
            payload={},
        )


@pytest.mark.asyncio
async def test_read_rejects_unregistered_key(db_session) -> None:
    with pytest.raises(RuntimeStateKeyRejectedError):
        await read_runtime_state(db_session, key="some_unregistered_key")


@pytest.mark.asyncio
async def test_write_is_idempotent_against_repeated_calls(db_session) -> None:
    await write_runtime_state(db_session, key=_REGISTRY_KEY, payload={"v": 1})
    await write_runtime_state(db_session, key=_REGISTRY_KEY, payload={"v": 2})
    await db_session.commit()
    out = await read_runtime_state(db_session, key=_REGISTRY_KEY)
    assert out == {"v": 2}


@pytest.mark.asyncio
async def test_delete_removes_row(db_session) -> None:
    await write_runtime_state(db_session, key=_REGISTRY_KEY, payload={"v": 1})
    await db_session.commit()
    deleted = await delete_runtime_state(db_session, key=_REGISTRY_KEY)
    assert deleted is True
    await db_session.commit()
    assert await read_runtime_state(db_session, key=_REGISTRY_KEY) is None
