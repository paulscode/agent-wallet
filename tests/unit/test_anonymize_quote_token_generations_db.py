# SPDX-License-Identifier: MIT
"""Cross-replica quote-token key-generation DB index.

When the quote-token HMAC key rotates, the rotating replica writes
a row into ``anonymize_quote_token_key_generations`` so replicas
whose in-memory keyset is still on the old generation can resolve
the new generation synchronously via
:func:`lookup_key_generation_via_db`.

The DB-fallback verify path uses :func:`decide_quote_token_verify_action`
to step through ``wait_for_propagation`` → ``fallback_db_read`` →
``unavailable_503``; this test file exercises the table + register
+ lookup primitives that the fallback consumes.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.quote_token import (
    _fingerprint_key_material,
    lookup_key_generation_via_db,
    register_quote_token_generation,
)


@pytest.mark.asyncio
async def test_register_then_lookup_round_trip(db_session) -> None:
    key_bytes = b"\x01" * 32
    await register_quote_token_generation(
        db_session,
        generation=5,
        key_bytes=key_bytes,
    )
    await db_session.commit()

    fingerprint = await lookup_key_generation_via_db(
        db_session,
        generation=5,
    )
    assert fingerprint == _fingerprint_key_material(key_bytes)


@pytest.mark.asyncio
async def test_lookup_returns_none_for_unknown_generation(db_session) -> None:
    fingerprint = await lookup_key_generation_via_db(
        db_session,
        generation=999,
    )
    assert fingerprint is None


@pytest.mark.asyncio
async def test_register_is_idempotent_against_replays(db_session) -> None:
    key_bytes = b"\x02" * 32
    await register_quote_token_generation(
        db_session,
        generation=7,
        key_bytes=key_bytes,
    )
    await db_session.commit()
    # Second call with the same generation + same key must not raise
    # nor duplicate the row.
    await register_quote_token_generation(
        db_session,
        generation=7,
        key_bytes=key_bytes,
    )
    await db_session.commit()
    fingerprint = await lookup_key_generation_via_db(
        db_session,
        generation=7,
    )
    assert fingerprint == _fingerprint_key_material(key_bytes)


@pytest.mark.asyncio
async def test_register_overwrites_fingerprint_for_same_generation(
    db_session,
) -> None:
    """A re-registration with new key material (e.g., the rotation
    re-issued the same generation number after a rollback) updates
    the fingerprint in place."""
    await register_quote_token_generation(
        db_session,
        generation=11,
        key_bytes=b"\x03" * 32,
    )
    await db_session.commit()
    await register_quote_token_generation(
        db_session,
        generation=11,
        key_bytes=b"\x04" * 32,
    )
    await db_session.commit()
    fingerprint = await lookup_key_generation_via_db(
        db_session,
        generation=11,
    )
    assert fingerprint == _fingerprint_key_material(b"\x04" * 32)


@pytest.mark.asyncio
async def test_register_skips_when_fingerprint_already_registered(
    db_session,
) -> None:
    """Regression: the recurring rotation tick re-fires every cadence
    interval even when the operator hasn't actually rotated their
    Fernet bundle. Each fire calls ``register_quote_token_generation``
    with a fresh ``generation=int(time.time())`` but the SAME key
    material. Without idempotency on the fingerprint, the second
    fire would trip the schema's ``UNIQUE(key_fingerprint_hex)``
    constraint and the rotation tick would crash.

    Correct behaviour: the second call is a no-op (the prior
    generation row already maps to this key material).
    """
    key_bytes = b"\x05" * 32
    await register_quote_token_generation(
        db_session,
        generation=100,
        key_bytes=key_bytes,
    )
    await db_session.commit()

    # Re-register the SAME key material at a NEW generation. Must
    # NOT raise IntegrityError and must NOT create a second row.
    await register_quote_token_generation(
        db_session,
        generation=200,
        key_bytes=key_bytes,
    )
    await db_session.commit()

    # The original generation still resolves; the new generation
    # number isn't registered (no genuine rotation happened).
    assert await lookup_key_generation_via_db(db_session, generation=100) == _fingerprint_key_material(key_bytes)
    assert await lookup_key_generation_via_db(db_session, generation=200) is None


def test_fingerprint_is_64_hex_chars() -> None:
    fp = _fingerprint_key_material(b"\x00" * 32)
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_changes_with_input() -> None:
    fp_a = _fingerprint_key_material(b"\x00" * 32)
    fp_b = _fingerprint_key_material(b"\x01" * 32)
    assert fp_a != fp_b
