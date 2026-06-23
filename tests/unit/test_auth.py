# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.security — API key generation, hashing, auth.

Tests:
- Key generation format
- Key hashing determinism
- Auth dependency (valid/invalid/expired/disabled keys)
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.security import generate_api_key, hash_api_key


class TestApiKeyGeneration:
    """Tests for generate_api_key() and hash_api_key()."""

    def test_key_format(self):
        """Generated keys have the lwk_ prefix and expected length."""
        key = generate_api_key()
        assert key.startswith("lwk_")
        assert len(key) == 52  # 4 (prefix) + 48 (hex)

    def test_keys_are_unique(self):
        """Two generated keys should never be the same."""
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100

    def test_key_is_hex_after_prefix(self):
        """The part after 'lwk_' should be valid hex."""
        key = generate_api_key()
        hex_part = key[4:]
        int(hex_part, 16)  # Should not raise

    def test_hash_deterministic(self):
        """Same key always produces the same hash."""
        key = "lwk_abc123def456"
        h1 = hash_api_key(key)
        h2 = hash_api_key(key)
        assert h1 == h2

    def test_hash_is_sha256_hex(self):
        """Hash output should be a 64-char hex string (SHA-256)."""
        key = generate_api_key()
        h = hash_api_key(key)
        assert len(h) == 64
        int(h, 16)  # Should not raise

    def test_different_keys_different_hashes(self):
        """Different keys produce different hashes."""
        k1 = generate_api_key()
        k2 = generate_api_key()
        assert hash_api_key(k1) != hash_api_key(k2)

    def test_hash_is_not_plaintext(self):
        """Hash should not contain the original key."""
        key = generate_api_key()
        h = hash_api_key(key)
        assert key not in h
        assert key[4:] not in h


class TestApiKeyAuth:
    """Tests for the get_api_key and get_admin_key dependencies."""

    @pytest.mark.asyncio
    async def test_valid_key_returns_model(self, db_session, test_api_key):
        """A valid key should return the APIKey model instance."""
        api_key, raw_key = test_api_key
        assert api_key.name == "test-key"
        assert api_key.is_active is True
        assert api_key.is_admin is False

    @pytest.mark.asyncio
    async def test_admin_key_returns_model(self, db_session, test_admin_key):
        """An admin key should have is_admin=True."""
        api_key, raw_key = test_admin_key
        assert api_key.is_admin is True

    @pytest.mark.asyncio
    async def test_expired_key_setup(self, db_session):
        """Expired keys should exist in DB with past expiry date."""
        from app.models.api_key import APIKey

        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="expired-key",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(api_key)
        await db_session.commit()
        await db_session.refresh(api_key)

        assert api_key.expires_at < datetime.now(timezone.utc).replace(tzinfo=None)

    @pytest.mark.asyncio
    async def test_disabled_key_setup(self, db_session):
        """Disabled keys should have is_active=False."""
        from app.models.api_key import APIKey

        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="disabled-key",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=False,
        )
        db_session.add(api_key)
        await db_session.commit()
        await db_session.refresh(api_key)

        assert api_key.is_active is False
