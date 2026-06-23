# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.security — get_api_key / get_admin_key dependencies.

Covers auth validation paths: valid key, invalid key, expired key, disabled key,
non-admin blocked from admin endpoints, and last_used_at update.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core.security import generate_api_key, get_admin_key, get_api_key, get_spend_key, hash_api_key
from app.models.api_key import APIKey


def _mock_request() -> MagicMock:
    """Create a mock Request with a client IP."""
    req = MagicMock()
    req.client.host = "127.0.0.1"
    return req


class TestGetApiKey:
    """Tests for the get_api_key FastAPI dependency."""

    @pytest.mark.asyncio
    async def test_valid_key_returns_model(self, db_session):
        """Valid active key returns the APIKey model."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="valid-key",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        result = await get_api_key(_mock_request(), creds, db_session)

        assert result.id == api_key.id
        assert result.name == "valid-key"

    @pytest.mark.asyncio
    async def test_invalid_key_raises_401(self, db_session):
        """Non-existent key hash raises 401."""
        creds = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="lwk_" + "a" * 48,
        )
        with pytest.raises(HTTPException) as exc_info:
            await get_api_key(_mock_request(), creds, db_session)
        assert exc_info.value.status_code == 401
        assert "Invalid" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_disabled_key_raises_401(self, db_session):
        """Disabled (is_active=False) key raises 401."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="disabled",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=False,
        )
        db_session.add(api_key)
        await db_session.commit()

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        with pytest.raises(HTTPException) as exc_info:
            await get_api_key(_mock_request(), creds, db_session)
        assert exc_info.value.status_code == 401
        assert "disabled" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_expired_key_raises_401(self, db_session):
        """Expired key raises 401."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="expired",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(api_key)
        await db_session.commit()

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        with pytest.raises(HTTPException) as exc_info:
            await get_api_key(_mock_request(), creds, db_session)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_valid_key_updates_last_used(self, db_session):
        """Successful auth updates last_used_at timestamp."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="tracked",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        assert api_key.last_used_at is None

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        result = await get_api_key(_mock_request(), creds, db_session)

        assert result.last_used_at is not None

    @pytest.mark.asyncio
    async def test_future_expiry_key_accepted(self, db_session):
        """Key with future expiry is accepted."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="future-expiry",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db_session.add(api_key)
        await db_session.commit()

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        result = await get_api_key(_mock_request(), creds, db_session)
        assert result.id == api_key.id


class TestGetAdminKey:
    """Tests for the get_admin_key FastAPI dependency."""

    @pytest.mark.asyncio
    async def test_admin_key_accepted(self, db_session):
        """Admin key passes the admin check."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="admin",
            key_hash=hash_api_key(raw_key),
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        result = await get_admin_key(api_key)
        assert result.is_admin is True

    @pytest.mark.asyncio
    async def test_non_admin_key_raises_403(self, db_session):
        """Non-admin key raises 403 from get_admin_key."""
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="reader",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        with pytest.raises(HTTPException) as exc_info:
            await get_admin_key(api_key)
        assert exc_info.value.status_code == 403
        assert "Admin" in exc_info.value.detail


class TestGetSpendKey:
    """Tests for the get_spend_key dependency — the middle tier that
    gates fund-moving endpoints (pay, keysend, cold-storage withdrawal).
    A ``spend`` *or* ``admin`` key passes; ``monitor`` is rejected."""

    @pytest.mark.asyncio
    async def test_spend_key_accepted(self):
        api_key = APIKey(id=uuid4(), name="agent", key_hash="a" * 64, scope="spend", is_active=True)
        result = await get_spend_key(api_key)
        assert result.can_spend is True
        assert result.is_admin is False

    @pytest.mark.asyncio
    async def test_admin_key_accepted(self):
        api_key = APIKey(id=uuid4(), name="admin", key_hash="b" * 64, scope="admin", is_active=True)
        result = await get_spend_key(api_key)
        assert result.can_spend is True

    @pytest.mark.asyncio
    async def test_monitor_key_raises_403(self):
        api_key = APIKey(id=uuid4(), name="reader", key_hash="c" * 64, scope="monitor", is_active=True)
        with pytest.raises(HTTPException) as exc_info:
            await get_spend_key(api_key)
        assert exc_info.value.status_code == 403
        assert "spend" in exc_info.value.detail.lower()


class TestScopeGatingAsymmetry:
    """A ``spend`` key must NOT satisfy the admin gate — the whole point
    of the tier is that an agent can move funds without god-mode over
    channels, signing, or key management."""

    @pytest.mark.asyncio
    async def test_spend_key_rejected_by_admin_gate(self):
        api_key = APIKey(id=uuid4(), name="agent", key_hash="d" * 64, scope="spend", is_active=True)
        with pytest.raises(HTTPException) as exc_info:
            await get_admin_key(api_key)
        assert exc_info.value.status_code == 403


class TestGenerateApiKey:
    """Tests for generate_api_key utility."""

    def test_starts_with_prefix(self):
        """Generated keys start with lwk_ prefix."""
        key = generate_api_key()
        assert key.startswith("lwk_")

    def test_correct_length(self):
        """Generated keys are 52 characters long."""
        key = generate_api_key()
        assert len(key) == 52

    def test_unique_keys(self):
        """Two generated keys are never identical."""
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100


class TestHashApiKey:
    """Tests for hash_api_key utility."""

    def test_deterministic(self):
        """Same input always produces the same hash."""
        key = "lwk_test123"
        assert hash_api_key(key) == hash_api_key(key)

    def test_hex_output(self):
        """Hash output is a 64-character hex string."""
        h = hash_api_key("lwk_test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_keys_different_hashes(self):
        """Different inputs produce different hashes."""
        h1 = hash_api_key("lwk_key1")
        h2 = hash_api_key("lwk_key2")
        assert h1 != h2


class TestSecretKeyRotation:
    """SECRET_KEY rotation: API keys hashed under the previous secret
    must keep authenticating until the operator clears
    SECRET_KEY_PREVIOUS."""

    @pytest.mark.asyncio
    async def test_old_secret_key_still_authenticates(self, db_session, monkeypatch):
        from app.core.security import hash_api_key_with

        raw_key = "lwk_" + "a" * 48
        old_secret = "old-secret-key-for-rotation-test-32-chars"
        old_hash = hash_api_key_with(old_secret, raw_key)

        api_key_row = APIKey(
            id=uuid4(),
            name="rotated-key",
            key_hash=old_hash,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key_row)
        await db_session.commit()

        from app.core import security as sec_mod

        monkeypatch.setattr(sec_mod.settings, "secret_key_previous", old_secret)

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        result = await get_api_key(_mock_request(), creds, db_session)
        assert result.id == api_key_row.id

    @pytest.mark.asyncio
    async def test_old_secret_rewrites_to_new_secret_on_use(self, db_session, monkeypatch):
        from app.core.security import hash_api_key, hash_api_key_with

        raw_key = "lwk_" + "b" * 48
        old_secret = "old-secret-key-for-rotation-test-32-chars"
        old_hash = hash_api_key_with(old_secret, raw_key)
        new_hash = hash_api_key(raw_key)
        assert old_hash != new_hash

        api_key_row = APIKey(
            id=uuid4(),
            name="rotated-key-2",
            key_hash=old_hash,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key_row)
        await db_session.commit()

        from app.core import security as sec_mod

        monkeypatch.setattr(sec_mod.settings, "secret_key_previous", old_secret)

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        await get_api_key(_mock_request(), creds, db_session)

        await db_session.refresh(api_key_row)
        assert api_key_row.key_hash == new_hash
        assert api_key_row.key_hash_prev == old_hash

    @pytest.mark.asyncio
    async def test_no_previous_secret_rejects_old_hash(self, db_session, monkeypatch):
        from app.core.security import hash_api_key_with

        raw_key = "lwk_" + "c" * 48
        old_secret = "old-secret-key-for-rotation-test-32-chars"
        old_hash = hash_api_key_with(old_secret, raw_key)

        api_key_row = APIKey(
            id=uuid4(),
            name="stale-key",
            key_hash=old_hash,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key_row)
        await db_session.commit()

        from app.core import security as sec_mod

        monkeypatch.setattr(sec_mod.settings, "secret_key_previous", "")

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        with pytest.raises(HTTPException) as exc:
            await get_api_key(_mock_request(), creds, db_session)
        assert exc.value.status_code == 401


# ──: constant-time digest compare on API-key auth ─────────────


class TestApiKeyConstantTimeCompare:
    """The post-DB
    digest comparison in ``get_api_key`` must route through
    ``hmac.compare_digest`` so an attacker cannot use response
    timing to distinguish "row matched current digest" from "row
    matched the rotation-window previous digest". The failure path
    must also perform a dummy ``compare_digest`` so a bare DB miss
    is indistinguishable from a hit-then-mismatch."""

    @pytest.mark.asyncio
    async def test_success_path_uses_compare_digest(self, db_session):
        from unittest.mock import patch

        from app.core import security as sec

        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="ct-success",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        calls: list[tuple[str, str]] = []
        real = sec.hmac.compare_digest

        def _spy(a, b):
            calls.append((str(a), str(b)))
            return real(a, b)

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        with patch.object(sec.hmac, "compare_digest", _spy):
            await get_api_key(_mock_request(), creds, db_session)
        assert calls, (
            "get_api_key did not invoke hmac.compare_digest on the "
            "success path \u2014 requires constant-time digest "
            "comparison."
        )

    @pytest.mark.asyncio
    async def test_failure_path_performs_dummy_compare(self, db_session):
        """A bare DB miss must still call ``compare_digest`` once to
        equalise timing with the success path."""
        from unittest.mock import patch

        from app.core import security as sec

        calls: list[tuple[str, str]] = []
        real = sec.hmac.compare_digest

        def _spy(a, b):
            calls.append((str(a), str(b)))
            return real(a, b)

        # Use a syntactically valid but non-existent key.
        creds = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=generate_api_key(),
        )
        with patch.object(sec.hmac, "compare_digest", _spy):
            with pytest.raises(HTTPException) as exc:
                await get_api_key(_mock_request(), creds, db_session)
        assert exc.value.status_code == 401
        assert calls, (
            "get_api_key skipped the dummy compare_digest on the "
            "DB-miss path \u2014 this re-introduces the timing "
            "oracle."
        )

    @pytest.mark.asyncio
    async def test_rotation_path_uses_compare_digest(self, db_session):
        """When a key authenticates under SECRET_KEY_PREVIOUS the
        rotation rewrite path must still use ``compare_digest`` to
        decide whether to overwrite ``key_hash``."""
        from unittest.mock import patch

        from app.core import security as sec
        from app.core.config import settings

        raw_key = generate_api_key()
        # Hash under "previous" secret, then mutate settings so the
        # current secret is different — the SELECT will find the
        # row via the previous-secret hash branch.
        original_prev = settings.secret_key_previous
        original_current = settings.secret_key
        settings.secret_key = "current-secret-for-rotation-test"
        settings.secret_key_previous = "previous-secret-for-rotation-test"
        try:
            from app.core.security import hash_api_key_with

            stored_hash = hash_api_key_with(settings.secret_key_previous, raw_key)
            api_key = APIKey(
                id=uuid4(),
                name="ct-rotation",
                key_hash=stored_hash,
                is_admin=False,
                is_active=True,
            )
            db_session.add(api_key)
            await db_session.commit()

            calls: list[tuple[str, str]] = []
            real = sec.hmac.compare_digest

            def _spy(a, b):
                calls.append((str(a), str(b)))
                return real(a, b)

            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
            with patch.object(sec.hmac, "compare_digest", _spy):
                result = await get_api_key(_mock_request(), creds, db_session)
            assert result.name == "ct-rotation"
            # At least one call must compare against the previous-secret
            # hash (i.e. the digest that's currently stored on the row).
            assert any(stored_hash in pair for pair in calls), (
                "Rotation path did not constant-time-compare against the previous-secret digest."
            )
        finally:
            settings.secret_key = original_current
            settings.secret_key_previous = original_prev


# ──: constant-time digest compare on API-key auth ─────────────


class TestApiKeyConstantTimeCompare:
    """The post-DB
    digest comparison in ``get_api_key`` must route through
    ``hmac.compare_digest`` so an attacker cannot use response
    timing to distinguish "row matched current digest" from "row
    matched the rotation-window previous digest". The failure path
    must also perform a dummy ``compare_digest`` so a bare DB miss
    is indistinguishable from a hit-then-mismatch."""

    @pytest.mark.asyncio
    async def test_success_path_uses_compare_digest(self, db_session):
        from unittest.mock import patch

        from app.core import security as sec

        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="ct-success",
            key_hash=hash_api_key(raw_key),
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        calls: list[tuple[str, str]] = []
        real = sec.hmac.compare_digest

        def _spy(a, b):
            calls.append((str(a), str(b)))
            return real(a, b)

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
        with patch.object(sec.hmac, "compare_digest", _spy):
            await get_api_key(_mock_request(), creds, db_session)
        assert calls, (
            "get_api_key did not invoke hmac.compare_digest on the "
            "success path \u2014 requires constant-time digest "
            "comparison."
        )

    @pytest.mark.asyncio
    async def test_failure_path_performs_dummy_compare(self, db_session):
        """A bare DB miss must still call ``compare_digest`` once to
        equalise timing with the success path."""
        from unittest.mock import patch

        from app.core import security as sec

        calls: list[tuple[str, str]] = []
        real = sec.hmac.compare_digest

        def _spy(a, b):
            calls.append((str(a), str(b)))
            return real(a, b)

        # Use a syntactically valid but non-existent key.
        creds = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=generate_api_key(),
        )
        with patch.object(sec.hmac, "compare_digest", _spy):
            with pytest.raises(HTTPException) as exc:
                await get_api_key(_mock_request(), creds, db_session)
        assert exc.value.status_code == 401
        assert calls, (
            "get_api_key skipped the dummy compare_digest on the "
            "DB-miss path \u2014 this re-introduces the timing "
            "oracle."
        )

    @pytest.mark.asyncio
    async def test_rotation_path_uses_compare_digest(self, db_session):
        """When a key authenticates under SECRET_KEY_PREVIOUS the
        rotation rewrite path must still use ``compare_digest`` to
        decide whether to overwrite ``key_hash``."""
        from unittest.mock import patch

        from app.core import security as sec
        from app.core.config import settings

        raw_key = generate_api_key()
        # Hash under "previous" secret, then mutate settings so the
        # current secret is different — the SELECT will find the
        # row via the previous-secret hash branch.
        original_prev = settings.secret_key_previous
        original_current = settings.secret_key
        settings.secret_key = "current-secret-for-rotation-test"
        settings.secret_key_previous = "previous-secret-for-rotation-test"
        try:
            from app.core.security import hash_api_key_with

            stored_hash = hash_api_key_with(settings.secret_key_previous, raw_key)
            api_key = APIKey(
                id=uuid4(),
                name="ct-rotation",
                key_hash=stored_hash,
                is_admin=False,
                is_active=True,
            )
            db_session.add(api_key)
            await db_session.commit()

            calls: list[tuple[str, str]] = []
            real = sec.hmac.compare_digest

            def _spy(a, b):
                calls.append((str(a), str(b)))
                return real(a, b)

            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw_key)
            with patch.object(sec.hmac, "compare_digest", _spy):
                result = await get_api_key(_mock_request(), creds, db_session)
            assert result.name == "ct-rotation"
            # At least one call must compare against the previous-secret
            # hash (i.e. the digest that's currently stored on the row).
            assert any(stored_hash in pair for pair in calls), (
                "Rotation path did not constant-time-compare against the previous-secret digest."
            )
        finally:
            settings.secret_key = original_current
            settings.secret_key_previous = original_prev
