# SPDX-License-Identifier: MIT
"""global cross-IP brute-force counter for dashboard login."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.dashboard import auth


def _make_fake_redis(global_count: int, set_returns: bool | None = True):
    """Build a fake redis where pipeline() is sync and execute() is async.

    The real ``redis.asyncio.Redis.pipeline()`` returns a Pipeline
    synchronously (a context manager / object you queue ops onto);
    only the terminal ``.execute()`` is awaitable. Mirror that here.
    """
    pipe = MagicMock()
    pipe.incr = MagicMock(return_value=pipe)
    pipe.expire = MagicMock(return_value=pipe)
    pipe.execute = AsyncMock(return_value=[1, True, global_count, True])

    fake_redis = MagicMock()
    fake_redis.pipeline = MagicMock(return_value=pipe)
    fake_redis.set = AsyncMock(return_value=set_returns)
    fake_redis.get = AsyncMock(return_value=None)
    fake_redis.delete = AsyncMock()
    fake_redis.expire = AsyncMock()
    return fake_redis


@pytest.mark.asyncio
async def test_global_counter_emits_alert_above_threshold():
    fake_redis = _make_fake_redis(global_count=50, set_returns=True)
    with (
        patch("app.core.rate_limit.get_redis", new=AsyncMock(return_value=fake_redis)),
        patch("app.services.alert_service.send_alert", new=AsyncMock()) as send,
    ):
        await auth.record_login_failure("203.0.113.1")
        send.assert_awaited_once()
        args, _kwargs = send.await_args
        assert args[0] == "auth_brute_force"


@pytest.mark.asyncio
async def test_global_counter_below_threshold_no_alert():
    fake_redis = _make_fake_redis(global_count=5)
    with (
        patch("app.core.rate_limit.get_redis", new=AsyncMock(return_value=fake_redis)),
        patch("app.services.alert_service.send_alert", new=AsyncMock()) as send,
    ):
        await auth.record_login_failure("203.0.113.1")
        send.assert_not_awaited()


@pytest.mark.asyncio
async def test_global_counter_within_cooldown_no_alert():
    """Even above threshold, the alert is suppressed if cooldown is set
    (set NX returns None when the key already exists)."""
    fake_redis = _make_fake_redis(global_count=75, set_returns=None)
    with (
        patch("app.core.rate_limit.get_redis", new=AsyncMock(return_value=fake_redis)),
        patch("app.services.alert_service.send_alert", new=AsyncMock()) as send,
    ):
        await auth.record_login_failure("203.0.113.1")
        send.assert_not_awaited()


@pytest.mark.asyncio
async def test_redis_failure_does_not_raise():
    """record_login_failure is best-effort and must never raise."""
    with patch("app.core.rate_limit.get_redis", side_effect=RuntimeError("down")):
        await auth.record_login_failure("203.0.113.1")
