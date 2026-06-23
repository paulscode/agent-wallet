# SPDX-License-Identifier: MIT
"""Unit tests for `check_sign_rate_limit` in `app.core.rate_limit`.

Sign-rate enforcement must fail CLOSED on Redis errors so a transient
Redis outage cannot silently un-cap public-attestation issuance.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.core.rate_limit import check_sign_rate_limit


@pytest.mark.asyncio
async def test_zero_limit_disables_check():
    """`max_per_hour <= 0` short-circuits before touching Redis."""
    with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock) as g:
        allowed, err = await check_sign_rate_limit("anyone", 0)
    assert allowed is True
    assert err is None
    g.assert_not_called()


@pytest.mark.asyncio
async def test_negative_limit_disables_check():
    with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock) as g:
        allowed, _ = await check_sign_rate_limit("x", -1)
    assert allowed is True
    g.assert_not_called()


@pytest.mark.asyncio
async def test_allowed_when_under_limit():
    """Redis Lua returns [1, count] when allowed."""
    redis = AsyncMock()
    redis.eval = AsyncMock(return_value=[1, "5"])
    with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=redis):
        allowed, err = await check_sign_rate_limit("user-1", 30)
    assert allowed is True
    assert err is None
    redis.eval.assert_awaited_once()


@pytest.mark.asyncio
async def test_denied_with_count_message():
    """When limit reached, error message embeds the current count and limit."""
    redis = AsyncMock()
    redis.eval = AsyncMock(return_value=[0, "30"])
    with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=redis):
        allowed, err = await check_sign_rate_limit("user-2", 30)
    assert allowed is False
    assert err is not None
    assert "30" in err and "limit" in err.lower()


@pytest.mark.asyncio
async def test_fails_closed_on_get_redis_error():
    """Redis connection failure → deny, with a clear operator-facing message."""
    with patch(
        "app.core.rate_limit.get_redis",
        new_callable=AsyncMock,
        side_effect=ConnectionError("redis is down"),
    ):
        allowed, err = await check_sign_rate_limit("user-3", 30)
    assert allowed is False
    assert err is not None
    assert "blocked" in err.lower() or "unavailable" in err.lower()


@pytest.mark.asyncio
async def test_fails_closed_on_eval_error():
    """Redis Lua eval failure → deny (no silent un-capping)."""
    redis = AsyncMock()
    redis.eval = AsyncMock(side_effect=RuntimeError("script failed"))
    with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=redis):
        allowed, err = await check_sign_rate_limit("user-4", 30)
    assert allowed is False
    assert err is not None


@pytest.mark.asyncio
async def test_identity_scopes_the_bucket():
    """Different `identity` values must produce distinct Redis keys."""
    redis = AsyncMock()
    redis.eval = AsyncMock(return_value=[1, "1"])
    with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=redis):
        await check_sign_rate_limit("alice", 30)
        await check_sign_rate_limit("bob", 30)
    keys = [call.args[2] for call in redis.eval.await_args_list]
    assert keys[0] != keys[1]
    assert "alice" in keys[0]
    assert "bob" in keys[1]
