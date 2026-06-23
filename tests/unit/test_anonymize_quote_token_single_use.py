# SPDX-License-Identifier: MIT
"""Quote-token single-use.

A quote token authorizes exactly one session create; a replay within
its TTL must be rejected. Fails open when the single-use store is down.
"""

import pytest

import app.core.rate_limit as rate_limit
from app.services.anonymize.quote_token import consume_quote_token_single_use


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


@pytest.mark.asyncio
async def test_first_use_admitted_replay_rejected(monkeypatch):
    fake = _FakeRedis()

    async def _get_redis():
        return fake

    monkeypatch.setattr(rate_limit, "get_redis", _get_redis)

    token = "0.YWJj.deadbeefmac"
    assert await consume_quote_token_single_use(token, ttl_s=300) is True
    # Replay of the same token (same MAC) is rejected.
    assert await consume_quote_token_single_use(token, ttl_s=300) is False
    # A different token (different MAC) is independent.
    assert await consume_quote_token_single_use("0.YWJj.othermac", ttl_s=300) is True


@pytest.mark.asyncio
async def test_malformed_token_rejected(monkeypatch):
    async def _get_redis():
        return _FakeRedis()

    monkeypatch.setattr(rate_limit, "get_redis", _get_redis)
    assert await consume_quote_token_single_use("not-a-token", ttl_s=300) is False


@pytest.mark.asyncio
async def test_fails_open_when_store_unavailable(monkeypatch):
    async def _get_redis():
        raise RuntimeError("redis down")

    monkeypatch.setattr(rate_limit, "get_redis", _get_redis)
    # Fail open: the token stays MAC/TTL/cookie-bound and admission is serialized.
    assert await consume_quote_token_single_use("0.YWJj.mac", ttl_s=300) is True
