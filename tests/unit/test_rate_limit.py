# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.rate_limit.

Tests:
- Spend limit enforcement (atomic Lua script)
- Velocity limit enforcement (atomic Lua script)
- Combined check_payment_limits
- Fail-open on Redis connection error
- Disabled limits (value set to 0)
"""

import logging
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest

import app.core.rate_limit as rate_limit_mod
from app.core.rate_limit import (
    check_payment_limits,
    check_spend_limit,
    check_velocity_limit,
    close_redis,
    reconcile_spend_limit,
    rollback_payment_limits,
)


@pytest.fixture(autouse=True)
async def _reset_redis_client():
    """Reset the module-level Redis client before and after each test."""
    rate_limit_mod._redis_client = None
    yield
    if rate_limit_mod._redis_client is not None:
        await rate_limit_mod._redis_client.aclose()
        rate_limit_mod._redis_client = None


@pytest.fixture
async def fake_redis():
    """Provide a fakeredis client and patch the module to use it."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    rate_limit_mod._redis_client = client
    yield client


class TestSpendLimit:
    """Tests for cumulative spend limit enforcement."""

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_spend_allowed_under_limit(self, fake_redis):
        allowed, error, member = await check_spend_limit(5_000, "key-1")
        assert allowed is True
        assert error is None
        assert member is not None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_spend_rejected_over_limit(self, fake_redis):
        # First spend — should be allowed
        allowed, _, _ = await check_spend_limit(6_000, "key-1")
        assert allowed is True

        # Second spend — exceeds 10k limit
        allowed, error, member = await check_spend_limit(5_000, "key-1")
        assert allowed is False
        assert "limit" in error.lower()
        assert member is None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_spend_exact_limit_allowed(self, fake_redis):
        """Payment exactly at the limit should be allowed."""
        allowed, _, _ = await check_spend_limit(10_000, "key-1")
        assert allowed is True

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_spend_one_over_limit_rejected(self, fake_redis):
        """Payment one sat over the limit should be rejected."""
        allowed, _, _ = await check_spend_limit(10_001, "key-1")
        assert allowed is False

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 0)
    async def test_spend_limit_disabled_when_zero(self, fake_redis):
        """When limit is 0, all payments are allowed."""
        allowed, error, _ = await check_spend_limit(999_999, "key-1")
        assert allowed is True
        assert error is None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_reconcile_lowers_window_total_to_settled_amount(self, fake_redis):
        """A worst-case reservation is replaced by the settled amount,
        freeing the difference back into the spend window."""
        allowed, _, reservation = await check_payment_limits(9_000, "key-1")
        assert allowed is True
        # Worst case consumed 9k; a second 5k would exceed the 10k cap.
        allowed, _, _ = await check_spend_limit(5_000, "key-1")
        assert allowed is False
        # Settle for only 2k and reconcile — the window now has headroom.
        await reconcile_spend_limit(reservation, 2_000)
        allowed, _, _ = await check_spend_limit(5_000, "key-1")
        assert allowed is True

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_reconcile_noop_without_reservation(self, fake_redis):
        """Reconciliation is a safe no-op when there is no reservation."""
        await reconcile_spend_limit(None, 1_000)
        await reconcile_spend_limit({"api_key_id": "key-1", "spend_member": None}, 1_000)

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    async def test_spend_per_key_isolation(self, fake_redis):
        """Different API keys have independent spend windows."""
        allowed, _, _ = await check_spend_limit(8_000, "key-1")
        assert allowed is True

        # Different key — should also be allowed
        allowed, _, _ = await check_spend_limit(8_000, "key-2")
        assert allowed is True


class TestVelocityLimit:
    """Tests for transaction velocity limit enforcement."""

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 3)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    async def test_velocity_allowed_under_limit(self, fake_redis):
        allowed, error, member = await check_velocity_limit("key-1")
        assert allowed is True
        assert error is None
        assert member is not None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 3)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    async def test_velocity_rejected_at_limit(self, fake_redis):
        # Three transactions
        for _ in range(3):
            allowed, _, _ = await check_velocity_limit("key-1")
            assert allowed is True

        # Fourth should be rejected
        allowed, error, member = await check_velocity_limit("key-1")
        assert allowed is False
        assert "velocity" in error.lower()
        assert member is None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 0)
    async def test_velocity_limit_disabled_when_zero(self, fake_redis):
        """When max_txns is 0, all transactions are allowed."""
        allowed, error, _ = await check_velocity_limit("key-1")
        assert allowed is True
        assert error is None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 2)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    async def test_velocity_per_key_isolation(self, fake_redis):
        """Different API keys have independent velocity windows."""
        for _ in range(2):
            await check_velocity_limit("key-1")

        # key-1 exhausted, key-2 should still work
        allowed, _, _ = await check_velocity_limit("key-2")
        assert allowed is True


class TestCheckPaymentLimits:
    """Tests for the combined check_payment_limits function."""

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 100_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 10)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    async def test_both_limits_pass(self, fake_redis):
        allowed, error, reservation = await check_payment_limits(1_000, "key-1")
        assert allowed is True
        assert error is None
        assert reservation is not None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 500)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 10)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    async def test_spend_limit_rejects_first(self, fake_redis):
        allowed, error, reservation = await check_payment_limits(1_000, "key-1")
        assert allowed is False
        assert "spend" in error.lower()
        assert reservation is None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 100_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 1)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    async def test_velocity_limit_rejects_after_spend_passes(self, fake_redis):
        # First payment OK (passes both)
        allowed, _, _ = await check_payment_limits(100, "key-1")
        assert allowed is True

        # Second payment fails velocity
        allowed, error, reservation = await check_payment_limits(100, "key-1")
        assert allowed is False
        assert "velocity" in error.lower()
        assert reservation is None


class TestFailPolicy:
    """Tests that rate limiting respects the fail policy when Redis is unavailable."""

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    @patch.object(rate_limit_mod.settings, "rate_limit_fail_policy", "closed")
    async def test_spend_limit_fails_closed_by_default(self):
        """If Redis is unreachable and policy is closed, the request is blocked."""
        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(side_effect=ConnectionError("Redis down"))
        rate_limit_mod._redis_client = mock_redis

        allowed, error, _ = await check_spend_limit(5_000, "key-1")
        assert allowed is False
        assert "unavailable" in error.lower()

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_sats", 10_000)
    @patch.object(rate_limit_mod.settings, "lnd_rate_limit_window_seconds", 3600)
    @patch.object(rate_limit_mod.settings, "rate_limit_fail_policy", "open")
    async def test_spend_limit_fails_open_when_configured(self):
        """If Redis is unreachable and policy is open, the request is allowed."""
        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(side_effect=ConnectionError("Redis down"))
        rate_limit_mod._redis_client = mock_redis

        allowed, error, _ = await check_spend_limit(5_000, "key-1")
        assert allowed is True
        assert error is None

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 5)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    @patch.object(rate_limit_mod.settings, "rate_limit_fail_policy", "closed")
    async def test_velocity_limit_fails_closed_by_default(self):
        """If Redis is unreachable and policy is closed, the request is blocked."""
        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(side_effect=ConnectionError("Redis down"))
        rate_limit_mod._redis_client = mock_redis

        allowed, error, _ = await check_velocity_limit("key-1")
        assert allowed is False
        assert "unavailable" in error.lower()

    @pytest.mark.asyncio
    @patch.object(rate_limit_mod.settings, "lnd_velocity_max_txns", 5)
    @patch.object(rate_limit_mod.settings, "lnd_velocity_window_seconds", 900)
    @patch.object(rate_limit_mod.settings, "rate_limit_fail_policy", "open")
    async def test_velocity_limit_fails_open_when_configured(self):
        """If Redis is unreachable and policy is open, the request is allowed."""
        mock_redis = AsyncMock()
        mock_redis.eval = AsyncMock(side_effect=ConnectionError("Redis down"))
        rate_limit_mod._redis_client = mock_redis

        allowed, error, _ = await check_velocity_limit("key-1")
        assert allowed is True
        assert error is None


class TestGetRedisClientConfig:
    """Regression guard: the shared async Redis client MUST be built with
    staleness protections, or a refresh after the dashboard sits idle
    hangs forever in verify_session() (half-open pooled connection,
    unbounded read). See app/core/rate_limit.get_redis."""

    @pytest.mark.asyncio
    async def test_get_redis_sets_staleness_protections(self):
        from unittest.mock import patch

        from app.core.rate_limit import get_redis

        captured: dict = {}

        def _fake_from_url(url, **kwargs):
            captured.update(kwargs)
            # AsyncMock so the autouse teardown's `await client.aclose()`
            # works.
            return AsyncMock()

        rate_limit_mod._redis_client = None
        with patch.object(rate_limit_mod.aioredis, "from_url", side_effect=_fake_from_url):
            await get_redis()

        # A bounded read so a half-open connection raises instead of
        # blocking forever.
        assert captured.get("socket_timeout"), "socket_timeout must be set"
        # Proactive idle-connection health check (the actual antidote to
        # the stale-after-idle hang).
        assert captured.get("health_check_interval"), "health_check_interval must be set"
        # Connect timeout retained.
        assert captured.get("socket_connect_timeout"), "socket_connect_timeout must be set"


class TestCloseRedis:
    """Tests for close_redis cleanup."""

    @pytest.mark.asyncio
    async def test_close_redis_cleans_up(self, fake_redis):
        assert rate_limit_mod._redis_client is not None
        await close_redis()
        assert rate_limit_mod._redis_client is None

    @pytest.mark.asyncio
    async def test_close_redis_noop_when_none(self):
        rate_limit_mod._redis_client = None
        await close_redis()  # should not raise
        assert rate_limit_mod._redis_client is None


class TestRollbackPaymentLimits:
    """Tests for rollback_payment_limits and _rollback_member."""

    @pytest.mark.asyncio
    async def test_rollback_removes_members(self, fake_redis):
        """rollback_payment_limits removes spend and velocity members from Redis."""
        # Add members to sorted sets
        await fake_redis.zadd("lwa:spend:key-1", {"spend_member_1": 1000})
        await fake_redis.zadd("lwa:velocity:key-1", {"velocity_member_1": 1})

        reservation = {
            "api_key_id": "key-1",
            "spend_member": "spend_member_1",
            "velocity_member": "velocity_member_1",
        }
        await rollback_payment_limits(reservation)

        assert await fake_redis.zcard("lwa:spend:key-1") == 0
        assert await fake_redis.zcard("lwa:velocity:key-1") == 0

    @pytest.mark.asyncio
    async def test_rollback_none_reservation_is_noop(self):
        """rollback_payment_limits with None reservation does nothing."""
        await rollback_payment_limits(None)  # should not raise

    @pytest.mark.asyncio
    async def test_rollback_empty_reservation_is_noop(self):
        """rollback_payment_limits with empty dict does nothing."""
        await rollback_payment_limits({})  # should not raise

    @pytest.mark.asyncio
    async def test_rollback_partial_reservation(self, fake_redis):
        """rollback_payment_limits handles reservation with only spend_member."""
        await fake_redis.zadd("lwa:spend:key-2", {"sm": 500})

        reservation = {
            "api_key_id": "key-2",
            "spend_member": "sm",
            "velocity_member": None,
        }
        await rollback_payment_limits(reservation)
        assert await fake_redis.zcard("lwa:spend:key-2") == 0

    @pytest.mark.asyncio
    async def test_rollback_handles_redis_error(self, caplog):
        """_rollback_member logs warning on Redis error."""
        mock_redis = AsyncMock()
        mock_redis.zrem = AsyncMock(side_effect=ConnectionError("Redis down"))
        rate_limit_mod._redis_client = mock_redis

        reservation = {
            "api_key_id": "key-3",
            "spend_member": "sm",
            "velocity_member": None,
        }
        with caplog.at_level(logging.WARNING):
            await rollback_payment_limits(reservation)
        assert any("rollback failed" in r.message for r in caplog.records)


class TestRedisUrlForDb:
    """`_redis_url_for_db` must preserve query string, userinfo, scheme."""

    def test_preserves_query_string_on_rediss(self):
        from app.core.rate_limit import _redis_url_for_db

        assert (
            _redis_url_for_db("rediss://:p@h:6380/0?ssl_cert_reqs=required", 1)
            == "rediss://:p@h:6380/1?ssl_cert_reqs=required"
        )

    def test_preserves_password_and_userinfo(self):
        from app.core.rate_limit import _redis_url_for_db

        assert _redis_url_for_db("redis://:secret@h/0", 1) == "redis://:secret@h/1"

    def test_handles_url_without_db(self):
        from app.core.rate_limit import _redis_url_for_db

        assert _redis_url_for_db("redis://h:6379", 1) == "redis://h:6379/1"

    def test_handles_url_with_db_and_fragment(self):
        from app.core.rate_limit import _redis_url_for_db

        assert _redis_url_for_db("redis://h:6379/0#frag", 1) == "redis://h:6379/1#frag"

    def test_handles_multiple_query_parameters(self):
        from app.core.rate_limit import _redis_url_for_db

        result = _redis_url_for_db(
            "rediss://:p@h:6380/0?ssl_cert_reqs=required&ssl_ca_certs=/etc/ca.pem",
            1,
        )
        assert result.startswith("rediss://:p@h:6380/1?")
        assert "ssl_cert_reqs=required" in result
        assert "ssl_ca_certs=%2Fetc%2Fca.pem" in result or "ssl_ca_certs=/etc/ca.pem" in result
