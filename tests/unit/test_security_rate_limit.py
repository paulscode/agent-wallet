# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.security rate-limit internals and the soft
``request_has_admin_key`` gate.

The failed-auth counter, the fail-open alert, and the global brute-force
alert are exercised against an in-memory fakeredis so the counter and
pipeline semantics run for real rather than being stubbed.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import app.core.security as sec
from app.core.security import (
    _check_auth_rate_limit,
    _clear_auth_failures,
    _maybe_alert_fail_open,
    _record_auth_failure,
    audit_chain_hmac,
    generate_api_key,
    hash_api_key,
    hash_api_key_with,
    request_has_admin_key,
)
from app.models.api_key import APIKey
from tests.helpers import make_api_key

_IP = "203.0.113.7"


class TestKeyedHashes:
    """Domain-separated keyed hashes derived from SECRET_KEY."""

    def test_api_key_hash_is_deterministic_and_keyed(self):
        token = generate_api_key()
        assert hash_api_key(token) == hash_api_key(token)
        # Different secrets yield different digests for the same token.
        assert hash_api_key_with("secret-one" + "1" * 32, token) != hash_api_key_with("secret-two" + "2" * 32, token)

    def test_api_key_and_audit_chain_are_domain_separated(self):
        """The same SECRET_KEY produces independent MACs for the API-key
        and audit-chain contexts — neither can be used to forge the other."""
        secret = "shared-secret-" + "s" * 32
        token = "lwk_" + "a" * 48
        assert hash_api_key_with(secret, token) != audit_chain_hmac(token, secret=secret)

    def test_audit_chain_hmac_is_deterministic_and_keyed(self):
        payload = "seq=1|action=test"
        assert audit_chain_hmac(payload, secret="k" * 40) == audit_chain_hmac(payload, secret="k" * 40)
        assert audit_chain_hmac(payload, secret="k" * 40) != audit_chain_hmac(payload, secret="j" * 40)


@pytest.fixture
def fake_redis(monkeypatch):
    """Patch ``get_redis`` to hand back a fresh in-memory fakeredis."""
    import fakeredis.aioredis as far

    client = far.FakeRedis()

    async def _get():
        return client

    monkeypatch.setattr("app.core.rate_limit.get_redis", _get)
    return client


@pytest.fixture
def redis_down(monkeypatch):
    """Patch ``get_redis`` to raise, simulating an unreachable backend."""

    async def _boom():
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr("app.core.rate_limit.get_redis", _boom)


@pytest.fixture
def capture_alerts(monkeypatch):
    """Record send_alert calls instead of dispatching them."""
    calls: list[tuple[str, str]] = []

    async def _fake_send_alert(kind, message, *args, **kwargs):
        calls.append((kind, message))

    monkeypatch.setattr("app.services.alert_service.send_alert", _fake_send_alert)
    return calls


class TestCheckAuthRateLimit:
    async def test_under_limit_allows(self, fake_redis):
        await fake_redis.set(f"{sec._AUTH_FAIL_PREFIX}{_IP}", sec._AUTH_FAIL_LIMIT - 1)
        # Does not raise.
        await _check_auth_rate_limit(_IP)

    async def test_at_limit_blocks_with_429(self, fake_redis):
        await fake_redis.set(f"{sec._AUTH_FAIL_PREFIX}{_IP}", sec._AUTH_FAIL_LIMIT)
        with pytest.raises(Exception) as exc:
            await _check_auth_rate_limit(_IP)
        assert getattr(exc.value, "status_code", None) == 429

    async def test_no_counter_allows(self, fake_redis):
        # No key set at all — count is None.
        await _check_auth_rate_limit(_IP)

    async def test_redis_down_fail_closed_raises_503(self, redis_down, monkeypatch):
        monkeypatch.setattr(sec.settings, "rate_limit_fail_policy", "closed")
        with pytest.raises(Exception) as exc:
            await _check_auth_rate_limit(_IP)
        assert getattr(exc.value, "status_code", None) == 503

    async def test_redis_down_fail_open_passes_and_alerts(self, redis_down, monkeypatch, capture_alerts):
        monkeypatch.setattr(sec.settings, "rate_limit_fail_policy", "open")
        monkeypatch.setattr(sec, "_last_fail_open_alert_at", 0.0)
        # Does not raise under fail-open.
        await _check_auth_rate_limit(_IP)
        await asyncio.sleep(0)  # let the fire-and-forget alert run
        assert capture_alerts and capture_alerts[0][0] == "rate_limit_bypass"


class TestRecordAuthFailure:
    async def test_increments_per_ip_counter(self, fake_redis):
        await _record_auth_failure(_IP)
        await _record_auth_failure(_IP)
        assert int(await fake_redis.get(f"{sec._AUTH_FAIL_PREFIX}{_IP}")) == 2

    async def test_global_threshold_fires_alert_once(self, fake_redis, capture_alerts):
        # Seed the global counter to one below the alert threshold so the
        # next failure lands exactly on it.
        await fake_redis.set(sec._GLOBAL_AUTH_FAIL_KEY, sec._GLOBAL_AUTH_FAIL_ALERT_THRESHOLD - 1)
        await _record_auth_failure(_IP)
        await asyncio.sleep(0)
        assert [c for c in capture_alerts if c[0] == "auth_brute_force"]

        # One past the threshold does not re-alert (equality check, not >=).
        capture_alerts.clear()
        await _record_auth_failure(_IP)
        await asyncio.sleep(0)
        assert not capture_alerts

    async def test_redis_error_is_swallowed(self, redis_down):
        # Best-effort: a backend error must not propagate.
        await _record_auth_failure(_IP)


class TestClearAuthFailures:
    async def test_clears_counter(self, fake_redis):
        await fake_redis.set(f"{sec._AUTH_FAIL_PREFIX}{_IP}", 5)
        await _clear_auth_failures(_IP)
        assert await fake_redis.get(f"{sec._AUTH_FAIL_PREFIX}{_IP}") is None

    async def test_redis_error_is_swallowed(self, redis_down):
        await _clear_auth_failures(_IP)


class TestMaybeAlertFailOpen:
    async def test_no_alert_when_policy_closed(self, monkeypatch, capture_alerts):
        monkeypatch.setattr(sec.settings, "rate_limit_fail_policy", "closed")
        monkeypatch.setattr(sec, "_last_fail_open_alert_at", 0.0)
        _maybe_alert_fail_open(_IP, "redis_unavailable")
        await asyncio.sleep(0)
        assert capture_alerts == []

    async def test_alert_fires_then_throttles(self, monkeypatch, capture_alerts):
        monkeypatch.setattr(sec.settings, "rate_limit_fail_policy", "open")
        monkeypatch.setattr(sec, "_last_fail_open_alert_at", 0.0)
        _maybe_alert_fail_open(_IP, "redis_unavailable")
        _maybe_alert_fail_open(_IP, "redis_unavailable")  # within throttle window
        await asyncio.sleep(0)
        assert len(capture_alerts) == 1


def _bearer(token: str):
    """Minimal Request stand-in carrying an Authorization header."""

    class _Req:
        headers = {"authorization": f"Bearer {token}"} if token is not None else {}

    return _Req()


async def _make_admin_key(db_session, *, is_admin=True, is_active=True, expires_at=None):
    """Persist an APIKey and return ``(raw_token, key)``.

    The caller must keep a reference to the returned ``key``: SQLAlchemy's
    identity map is weak, and a later same-session query that finds the row
    GC'd reloads it from SQLite, which drops the timezone on datetime
    columns (a harness artifact; production uses tz-aware Postgres).
    """
    key, raw = make_api_key(
        name="soft-gate-key",
        is_admin=is_admin,
        is_active=is_active,
        expires_at=expires_at,
    )
    db_session.add(key)
    await db_session.commit()
    return raw, key


class TestRequestHasAdminKey:
    async def test_true_for_active_admin_key(self, db_session):
        raw, _key = await _make_admin_key(db_session)
        assert await request_has_admin_key(_bearer(raw), db_session) is True

    async def test_false_without_bearer_header(self, db_session):
        class _NoAuth:
            headers: dict = {}

        assert await request_has_admin_key(_NoAuth(), db_session) is False

    async def test_false_for_empty_token(self, db_session):
        assert await request_has_admin_key(_bearer(""), db_session) is False

    async def test_false_for_non_admin_key(self, db_session):
        raw, _key = await _make_admin_key(db_session, is_admin=False)
        assert await request_has_admin_key(_bearer(raw), db_session) is False

    async def test_false_for_inactive_admin_key(self, db_session):
        raw, _key = await _make_admin_key(db_session, is_active=False)
        assert await request_has_admin_key(_bearer(raw), db_session) is False

    async def test_false_for_expired_admin_key(self, db_session):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        # Hold a reference to the key so the weak identity map keeps the
        # tz-aware in-memory instance (see _make_admin_key docstring).
        raw, _key = await _make_admin_key(db_session, expires_at=past)
        assert await request_has_admin_key(_bearer(raw), db_session) is False

    async def test_true_for_key_hashed_under_previous_secret(self, db_session, monkeypatch):
        """An admin key stored under the prior SECRET_KEY still gates true
        after rotation, via the previous-secret candidate hash."""
        old_secret = "old-secret-" + "o" * 32
        new_secret = "new-secret-" + "n" * 32
        raw = generate_api_key()
        key = APIKey(
            id=uuid4(),
            name="rotated-admin",
            key_hash=hash_api_key_with(old_secret, raw),
            is_admin=True,
            is_active=True,
        )
        db_session.add(key)
        await db_session.commit()
        assert key is not None  # keep the weak-identity-map entry alive

        monkeypatch.setattr(sec.settings, "secret_key", new_secret)
        monkeypatch.setattr(sec.settings, "secret_key_previous", old_secret)
        assert await request_has_admin_key(_bearer(raw), db_session) is True

    async def test_false_for_unknown_token(self, db_session):
        assert await request_has_admin_key(_bearer("lwk_" + "a" * 48), db_session) is False

    async def test_false_when_db_errors(self):
        class _BoomDB:
            async def execute(self, *args, **kwargs):
                raise RuntimeError("db down")

        assert await request_has_admin_key(_bearer("lwk_" + "b" * 48), _BoomDB()) is False
