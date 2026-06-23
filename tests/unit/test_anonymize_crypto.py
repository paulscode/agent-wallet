# SPDX-License-Identifier: MIT
"""Destination encryption + canary.

Round-trip an address through encrypt/decrypt, verify the redaction
sentinel, and assert the canary gate writes-then-reads correctly
across sessions.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.crypto import (
    DESTINATION_REDACTED_SENTINEL,
    CryptoCanaryError,
    decrypt_destination_address,
    encrypt_destination_address,
    is_redacted_destination,
    redact_destination_address,
    run_canary_decrypt,
)

_SAMPLE_ADDR = "bcrt1qexampleaddressxxxxxxxxxxxxxxxxxxxxxxxxxx"


def test_encrypt_decrypt_roundtrips() -> None:
    ct = encrypt_destination_address(_SAMPLE_ADDR)
    assert isinstance(ct, bytes)
    assert _SAMPLE_ADDR.encode() not in ct  # plaintext not present
    pt = decrypt_destination_address(ct)
    assert pt == _SAMPLE_ADDR


def test_encrypt_rejects_empty_or_non_string() -> None:
    with pytest.raises(ValueError):
        encrypt_destination_address("")
    with pytest.raises(ValueError):
        encrypt_destination_address(b"bytes")  # type: ignore[arg-type]


def test_redaction_sentinel_helpers() -> None:
    assert redact_destination_address() == DESTINATION_REDACTED_SENTINEL
    assert is_redacted_destination(DESTINATION_REDACTED_SENTINEL)
    ct = encrypt_destination_address(_SAMPLE_ADDR)
    assert not is_redacted_destination(ct)


def test_decrypt_rejects_redacted_sentinel() -> None:
    with pytest.raises(ValueError, match="retention-redacted"):
        decrypt_destination_address(DESTINATION_REDACTED_SENTINEL)


@pytest.mark.asyncio
async def test_canary_writes_then_reads(db_session) -> None:
    """First call writes the canary row; second call decrypts."""
    await run_canary_decrypt(db_session)  # write
    await run_canary_decrypt(db_session)  # read + verify


@pytest.mark.asyncio
async def test_canary_detects_corruption(db_session) -> None:
    """Corrupting the stored canary row causes the gate to refuse."""
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSettings

    await run_canary_decrypt(db_session)  # write a valid row

    result = await db_session.execute(select(AnonymizeSettings).where(AnonymizeSettings.key == "crypto_canary"))
    row = result.scalar_one()
    row.value = {"ciphertext_b64": "not-a-real-ciphertext"}
    await db_session.commit()

    with pytest.raises(CryptoCanaryError):
        await run_canary_decrypt(db_session)


@pytest.mark.asyncio
async def test_destination_ciphertext_roundtrips_via_session_column(
    db_session,
) -> None:
    """End-to-end: encrypt destination, persist on a real session row,
    re-read from DB, and decrypt — proves the column flow and the
    encryption together survive the SQLAlchemy/SQLite path the unit
    tests rely on."""
    from uuid import uuid4

    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

    ct = encrypt_destination_address(_SAMPLE_ADDR)
    sid = uuid4()
    row = AnonymizeSession(
        id=sid,
        status=AnonymizeStatus.CREATED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=ct,
        destination_script_type="p2wkh",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )
    db_session.add(row)
    await db_session.commit()

    loaded = (await db_session.execute(select(AnonymizeSession).where(AnonymizeSession.id == sid))).scalar_one()
    assert bytes(loaded.destination_address_enc) == ct
    assert decrypt_destination_address(bytes(loaded.destination_address_enc)) == _SAMPLE_ADDR


def test_decrypt_succeeds_after_rotation_via_previous_key(monkeypatch) -> None:
    """Rotation contract: old ciphertext still decrypts when
    the rotated-out key is held as ``SECRET_KEY_PREVIOUS``.

    Verifies that the destination-address column survives a SECRET_KEY
    rotation without re-encrypting every row.
    """
    import importlib

    from app.core import encryption as enc_mod
    from app.core.config import settings

    original_secret = settings.secret_key
    # Encrypt under the original key.
    ct = encrypt_destination_address(_SAMPLE_ADDR)

    # Rotate the active SECRET_KEY; old becomes SECRET_KEY_PREVIOUS.
    new_secret = "n" * len(original_secret)
    monkeypatch.setattr(settings, "secret_key", new_secret)
    monkeypatch.setattr(settings, "secret_key_previous", original_secret)
    # Clear the cached derived Fernet so encrypt/decrypt re-derives.
    importlib.reload(enc_mod)
    from app.services.anonymize import crypto as crypto_mod  # noqa: F401

    importlib.reload(crypto_mod)

    # Old ciphertext still decrypts via the previous-key fallback.
    assert crypto_mod.decrypt_destination_address(ct) == _SAMPLE_ADDR
