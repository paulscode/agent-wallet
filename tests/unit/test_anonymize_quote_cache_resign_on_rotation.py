# SPDX-License-Identifier: MIT
"""Quote-cache pre-warm resign pass on rotation.

When the quote-cache signing key rotates, every entry signed under
the rotated-out key is re-signed in place by the rotation tick.
The read path then accepts the entry without falling into the
 soft-stale blocking flow.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.services.anonymize import service as anon_service
from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    get_quote_cache,
    reset_quote_cache,
    sign_cache_entry,
    verify_cache_entry,
)


@pytest.fixture(autouse=True)
def reset_cache_between_tests():
    reset_quote_cache()
    yield
    reset_quote_cache()


@pytest.fixture
def signing_key(monkeypatch):
    """Configure a Fernet-formatted signing key for the test."""
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_signing_key_fernet",
        key,
    )
    return key


@pytest.mark.asyncio
async def test_rotation_tick_resigns_existing_entries(
    db_engine,
    monkeypatch,
    signing_key,
) -> None:
    """When the rotation tick fires the quote_cache_signing policy,
    every cache entry's signing_key_generation must advance and
    the new signature must still verify under the active key."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)
    # Force the rotation policy to fire immediately by setting
    # cadence > 0 days (default may already be) and no prior last-at.
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_rotation_days",
        1,
    )
    # floor must be zero or the "elapsed ≥ floor" branch
    # would never fire on a never-rotated key.
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_detection_key_rotation_min_interval_s",
        0,
    )

    cache = get_quote_cache()
    key = CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC")
    payload = {"fee": 1}
    # Seed an entry under generation=0 (pre-rotation).
    sig = sign_cache_entry(
        key=key,
        payload=payload,
        fetched_at_unix_s=500.0,
        signing_key_generation=0,
    )
    cache.put(
        CacheEntry(
            key=key,
            payload=payload,
            fetched_at_unix_s=500.0,
            operator_signature=sig,
            signing_key_generation=0,
        )
    )
    assert cache.get(key).signing_key_generation == 0

    await anon_service._rotation_tick_run()

    rebuilt = cache.get(key)
    assert rebuilt is not None
    # Generation advanced (the rotation tick uses unix_s of "now" as
    # the new generation; any value > 0 proves the resign happened).
    assert rebuilt.signing_key_generation > 0
    assert rebuilt.payload == payload
    # The new signature verifies — proves the resign used the
    # currently-configured key.
    assert verify_cache_entry(rebuilt) is True


@pytest.mark.asyncio
async def test_rotation_tick_resign_pass_noop_on_empty_cache(
    db_engine,
    monkeypatch,
    signing_key,
) -> None:
    """An empty cache + rotation due must not raise."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_rotation_days",
        1,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_detection_key_rotation_min_interval_s",
        0,
    )

    # No entries — the tick should walk policies + record timestamps
    # without raising.
    await anon_service._rotation_tick_run()


@pytest.mark.asyncio
async def test_resign_pass_failure_does_not_break_rotation_tick(
    db_engine,
    monkeypatch,
    signing_key,
) -> None:
    """A throwing resign_fn must not abort the rotation timestamp
    write — the soft-stale path is the fallback."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_rotation_days",
        1,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_detection_key_rotation_min_interval_s",
        0,
    )

    def _raise(**_):
        raise RuntimeError("simulated resign failure")

    monkeypatch.setattr(
        anon_service,
        "_run_quote_cache_resign_pass",
        _raise,
    )

    # Should not raise.
    await anon_service._rotation_tick_run()
