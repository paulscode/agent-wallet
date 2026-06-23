# SPDX-License-Identifier: MIT
"""Unit tests for dashboard authentication module."""

import logging
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.config import settings
from app.dashboard.auth import (
    COOKIE_NAME,
    _sign,
    clear_session_cookie,
    create_session_cookie,
    ensure_token_ready,
    generate_login_nonce,
    revoke_session,
    verify_login_nonce,
    verify_session,
    verify_token,
)


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    """Ensure a known dashboard token is set for all tests."""
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token-xyz-0123456789"
    yield
    settings.dashboard_token = original


def _make_cookie(expires: int, session_id: str = "sess-test-abc") -> str:
    # Modern cookie format is ``session_id:expires`` — the legacy id-less
    # format is no longer accepted.
    payload = f"{session_id}:{expires}"
    return f"{payload}.{_sign(payload)}"


def _mock_request(cookie_value: str | None = None) -> MagicMock:
    req = MagicMock()
    req.cookies = {}
    if cookie_value is not None:
        req.cookies[COOKIE_NAME] = cookie_value
    return req


class TestVerifyToken:
    def test_correct_token(self):
        assert verify_token("test-dashboard-token-xyz-0123456789") is True

    def test_wrong_token(self):
        assert verify_token("wrong-token") is False

    def test_empty_token(self):
        assert verify_token("") is False


class TestVerifySession:
    @pytest.mark.asyncio
    async def test_valid_cookie(self):
        expires = int(time.time()) + 3600
        request = _mock_request(_make_cookie(expires))
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=True)
        mock_redis.get = AsyncMock(return_value=None)
        with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=mock_redis):
            assert await verify_session(request) is True

    @pytest.mark.asyncio
    async def test_no_cookie(self):
        request = _mock_request(None)
        assert await verify_session(request) is False

    @pytest.mark.asyncio
    async def test_expired_cookie(self):
        expires = int(time.time()) - 100
        request = _mock_request(_make_cookie(expires))
        assert await verify_session(request) is False

    @pytest.mark.asyncio
    async def test_bad_signature(self):
        expires = int(time.time()) + 3600
        request = _mock_request(f"{expires}.invalidsignature")
        assert await verify_session(request) is False

    @pytest.mark.asyncio
    async def test_malformed_cookie_no_dot(self):
        request = _mock_request("garbage")
        assert await verify_session(request) is False

    @pytest.mark.asyncio
    async def test_non_numeric_expiry(self):
        payload = "notanumber"
        request = _mock_request(f"{payload}.{_sign(payload)}")
        assert await verify_session(request) is False


class TestCreateSessionCookie:
    @pytest.mark.asyncio
    async def test_sets_cookie(self):
        response = MagicMock()
        await create_session_cookie(response)
        response.set_cookie.assert_called_once()
        kwargs = response.set_cookie.call_args
        assert kwargs.kwargs["key"] == COOKIE_NAME
        assert kwargs.kwargs["httponly"] is True
        assert kwargs.kwargs["samesite"] == "strict"
        assert kwargs.kwargs["path"] == "/dashboard"

    @pytest.mark.asyncio
    async def test_cookie_value_is_verifiable(self):
        response = MagicMock()
        await create_session_cookie(response)
        value = response.set_cookie.call_args.kwargs["value"]
        request = _mock_request(value)
        assert await verify_session(request) is True


class TestClearSessionCookie:
    def test_deletes_cookie(self):
        response = MagicMock()
        clear_session_cookie(response)
        response.delete_cookie.assert_called_once_with(key=COOKIE_NAME, path="/dashboard")


class TestGetToken:
    """Tests for _get_token() — the auto-generation logic."""

    def test_returns_configured_token(self):
        """When dashboard_token is set, returns it directly."""
        from app.dashboard.auth import _get_token

        original = settings.dashboard_token
        settings.dashboard_token = "my-configured-token"
        try:
            assert _get_token() == "my-configured-token"
        finally:
            settings.dashboard_token = original

    def test_auto_generates_when_empty(self, tmp_path):
        """When dashboard_token is empty, generates one and writes .env."""
        from app.dashboard.auth import _get_token

        original = settings.dashboard_token
        settings.dashboard_token = ""
        try:
            with patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)):
                token = _get_token()
            assert len(token) > 20
            # Should have persisted the token to settings
            assert settings.dashboard_token == token
            # Should have written to .env
            env_path = tmp_path / ".env"
            assert env_path.exists()
            assert f"DASHBOARD_TOKEN={token}" in env_path.read_text()
        finally:
            settings.dashboard_token = original

    def test_appends_to_existing_env(self, tmp_path):
        """Appends to .env without duplicating if file already exists."""
        from app.dashboard.auth import _get_token

        env_path = tmp_path / ".env"
        env_path.write_text("SECRET_KEY=something\n")

        original = settings.dashboard_token
        settings.dashboard_token = ""
        try:
            with patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)):
                token = _get_token()
            content = env_path.read_text()
            assert "SECRET_KEY=something" in content
            assert f"DASHBOARD_TOKEN={token}" in content
        finally:
            settings.dashboard_token = original

    def test_skips_write_if_already_in_env(self, tmp_path):
        """Does not duplicate DASHBOARD_TOKEN if already present in .env."""
        from app.dashboard.auth import _get_token

        env_path = tmp_path / ".env"
        env_path.write_text("DASHBOARD_TOKEN=existing-value\n")

        original = settings.dashboard_token
        settings.dashboard_token = ""
        try:
            with patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)):
                token = _get_token()
                assert token is not None
            content = env_path.read_text()
            # Should not have appended another DASHBOARD_TOKEN
            assert content.count("DASHBOARD_TOKEN=") == 1
        finally:
            settings.dashboard_token = original

    def test_handles_env_write_failure(self, tmp_path):
        """Gracefully handles OSError when writing .env (logs warning instead)."""
        from app.dashboard.auth import _get_token

        original = settings.dashboard_token
        settings.dashboard_token = ""
        try:
            with (
                patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)),
                patch("builtins.open", side_effect=OSError("permission denied")),
                patch("app.dashboard.auth.os.path.exists", return_value=False),
            ):
                token = _get_token()
            # Should still return a valid token
            assert len(token) > 20
            assert settings.dashboard_token == token
        finally:
            settings.dashboard_token = original


class TestGetTokenDockerBranch:
    def test_docker_env_logs_warning(self, caplog):
        """_get_token logs a warning when /.dockerenv exists."""
        from app.dashboard.auth import _get_token

        original = settings.dashboard_token
        settings.dashboard_token = ""
        try:
            with (
                patch("app.dashboard.auth.os.path.exists", side_effect=lambda p: p == "/.dockerenv"),
                caplog.at_level(logging.WARNING, logger="app.dashboard.auth"),
            ):
                token = _get_token()
            assert len(token) > 20
            assert any("DASHBOARD_TOKEN not set" in r.message for r in caplog.records)
        finally:
            settings.dashboard_token = original


class TestVerifySessionRedisBranches:
    @pytest.mark.asyncio
    async def test_session_revoked_in_redis(self):
        """verify_session returns False if session not in Redis."""
        session_id = "test-session-123"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=False)

        with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=mock_redis):
            result = await verify_session(request)
        assert result is False

    @pytest.mark.asyncio
    async def test_redis_unavailable_falls_back(self):
        """verify_session returns True when Redis raises but signature valid."""
        session_id = "test-session-456"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, side_effect=ConnectionError("down")):
            result = await verify_session(request)
        assert result is True

    @pytest.mark.asyncio
    async def test_redis_unavailable_fails_closed_when_policy_closed(self):
        """when ``RATE_LIMIT_FAIL_POLICY=closed`` (the
        production default), Redis being unreachable must fail the
        session check rather than silently degrade to signature-only
        validation. Falling back would suppress session revocation,
        idle timeout, and IP-binding enforcement.
        """
        from app.dashboard import auth as dashboard_auth

        session_id = "test-session-closed"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        original = dashboard_auth.settings.rate_limit_fail_policy
        dashboard_auth.settings.rate_limit_fail_policy = "closed"
        try:
            with patch(
                "app.core.rate_limit.get_redis",
                new_callable=AsyncMock,
                side_effect=ConnectionError("down"),
            ):
                result = await verify_session(request)
        finally:
            dashboard_auth.settings.rate_limit_fail_policy = original
        assert result is False

    @pytest.mark.asyncio
    async def test_legacy_format_no_session_id_is_rejected(self):
        """The legacy id-less cookie format is no longer accepted — it
        would skip server-side revocation, idle timeout, and IP binding.
        A correctly-signed but id-less payload must be rejected."""
        expires = int(time.time()) + 3600
        payload = str(expires)
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        result = await verify_session(request)
        assert result is False


class TestRevokeSession:
    @pytest.mark.asyncio
    async def test_revokes_redis_session(self):
        """revoke_session removes session from Redis."""
        session_id = "revoke-me-123"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        mock_redis = AsyncMock()
        with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=mock_redis):
            await revoke_session(request)
        mock_redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_cookie_is_noop(self):
        request = _mock_request(None)
        await revoke_session(request)  # should not raise

    @pytest.mark.asyncio
    async def test_invalid_cookie_is_noop(self):
        request = _mock_request("garbage")
        await revoke_session(request)  # should not raise

    @pytest.mark.asyncio
    async def test_bad_signature_is_noop(self):
        request = _mock_request("session:12345.badsig")
        await revoke_session(request)  # should not raise

    @pytest.mark.asyncio
    async def test_redis_error_during_revoke_is_noop(self):
        """revoke_session swallows Redis errors."""
        session_id = "revoke-fail-123"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        mock_redis = AsyncMock()
        mock_redis.delete = AsyncMock(side_effect=ConnectionError("down"))
        with patch("app.core.rate_limit.get_redis", new_callable=AsyncMock, return_value=mock_redis):
            await revoke_session(request)  # should not raise


class TestEnsureTokenReady:
    def test_returns_token(self):
        result = ensure_token_ready()
        assert isinstance(result, str)
        assert len(result) > 0


class TestCsrfErrorResponseCodes:
    """``check_csrf_token`` returns granular result codes; the dashboard
    write-side dependency must translate a real violation into 403 and
    a backend outage into 503, not let them collapse to the same
    status."""

    @pytest.mark.asyncio
    async def test_missing_header_returns_missing_header_code(self):
        from app.dashboard.auth import CSRF_MISSING_HEADER, check_csrf_token

        request = MagicMock()
        request.headers = {}
        result = await check_csrf_token(request)
        assert result == CSRF_MISSING_HEADER

    @pytest.mark.asyncio
    async def test_require_auth_csrf_returns_403_on_mismatch(self):
        from fastapi import HTTPException, Response

        from app.dashboard import api as dash_api
        from app.dashboard.auth import CSRF_MISMATCH

        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/dashboard/x"

        with patch.object(dash_api, "verify_session", new=AsyncMock(return_value=True)):
            with patch.object(dash_api, "check_csrf_token", new=AsyncMock(return_value=CSRF_MISMATCH)):
                with patch.object(dash_api, "send_alert", new=AsyncMock()):
                    with pytest.raises(HTTPException) as exc:
                        await dash_api._require_auth_csrf(request, Response())
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_auth_csrf_returns_503_on_backend_outage(self):
        from fastapi import HTTPException, Response

        from app.dashboard import api as dash_api
        from app.dashboard.auth import CSRF_BACKEND_UNAVAILABLE

        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/dashboard/x"

        with patch.object(dash_api, "verify_session", new=AsyncMock(return_value=True)):
            with patch.object(
                dash_api,
                "check_csrf_token",
                new=AsyncMock(return_value=CSRF_BACKEND_UNAVAILABLE),
            ):
                with pytest.raises(HTTPException) as exc:
                    await dash_api._require_auth_csrf(request, Response())
        assert exc.value.status_code == 503

    @pytest.mark.asyncio
    async def test_require_auth_csrf_emits_alert_on_real_violation(self):
        from fastapi import HTTPException, Response

        from app.dashboard import api as dash_api
        from app.dashboard.auth import CSRF_MISMATCH

        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "10.0.0.1"
        request.url.path = "/dashboard/payments"

        alert_mock = AsyncMock()
        with patch.object(dash_api, "verify_session", new=AsyncMock(return_value=True)):
            with patch.object(dash_api, "check_csrf_token", new=AsyncMock(return_value=CSRF_MISMATCH)):
                with patch.object(dash_api, "send_alert", new=alert_mock):
                    with pytest.raises(HTTPException):
                        await dash_api._require_auth_csrf(request, Response())
        alert_mock.assert_awaited_once()
        args, _ = alert_mock.call_args
        assert args[0] == "csrf_violation"


class TestSessionIdleTimeoutConfig:
    """The dashboard idle-timeout is configurable but must never exceed
    the absolute session lifetime, so an operator who lengthens the
    idle window above the session window cannot accidentally extend
    sessions past their hard expiry."""

    def test_idle_timeout_clamped_to_session_max(self, monkeypatch):
        import importlib

        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "dashboard_idle_timeout_minutes", 60)
        monkeypatch.setattr(cfg.settings, "dashboard_session_hours", 1)

        import app.dashboard.auth as auth

        importlib.reload(auth)
        try:
            assert auth._IDLE_TIMEOUT == 3600
        finally:
            monkeypatch.setattr(cfg.settings, "dashboard_idle_timeout_minutes", 30)
            monkeypatch.setattr(cfg.settings, "dashboard_session_hours", 4)
            importlib.reload(auth)

    def test_idle_timeout_default_is_30_minutes(self):
        import app.dashboard.auth as auth

        assert auth._IDLE_TIMEOUT == 1800


# ── Hardening tests ──────────────────────────────────────────────────


class TestExtractSessionIdSignatureVerification:
    """`_extract_session_id` must reject cookies with bad signatures."""

    def test_returns_none_for_tampered_signature(self):
        from app.dashboard.auth import _extract_session_id

        request = MagicMock()
        request.cookies = {COOKIE_NAME: "sid123:9999999999.deadbeef"}
        assert _extract_session_id(request) is None

    def test_returns_none_for_expired_cookie(self):
        from app.dashboard.auth import _extract_session_id

        payload = f"sid123:{int(time.time()) - 10}"
        sig = _sign(payload)
        request = MagicMock()
        request.cookies = {COOKIE_NAME: f"{payload}.{sig}"}
        assert _extract_session_id(request) is None

    def test_returns_session_id_for_valid_cookie(self):
        from app.dashboard.auth import _extract_session_id

        payload = f"sid123:{int(time.time()) + 3600}"
        sig = _sign(payload)
        request = MagicMock()
        request.cookies = {COOKIE_NAME: f"{payload}.{sig}"}
        assert _extract_session_id(request) == "sid123"

    def test_rejects_legacy_no_session_id_format(self):
        from app.dashboard.auth import _extract_session_id

        payload = str(int(time.time()) + 3600)
        sig = _sign(payload)
        request = MagicMock()
        request.cookies = {COOKIE_NAME: f"{payload}.{sig}"}
        assert _extract_session_id(request) is None


class TestLoginNonce:
    """Stateless signed login nonce defends against login-CSRF."""

    def test_generated_nonce_verifies(self):
        from app.dashboard.auth import generate_login_nonce, verify_login_nonce

        assert verify_login_nonce(generate_login_nonce()) is True

    def test_empty_nonce_rejected(self):
        from app.dashboard.auth import verify_login_nonce

        assert verify_login_nonce("") is False

    def test_tampered_nonce_rejected(self):
        from app.dashboard.auth import generate_login_nonce, verify_login_nonce

        nonce = generate_login_nonce()
        # Flip the last hex char of the signature.
        last = "0" if nonce[-1] != "0" else "1"
        tampered = nonce[:-1] + last
        assert verify_login_nonce(tampered) is False

    def test_expired_nonce_rejected(self):
        from app.dashboard.auth import _sign, verify_login_nonce

        payload = f"abc:{int(time.time()) - 10}"
        bad = f"{payload}.{_sign(payload)}"
        assert verify_login_nonce(bad) is False


class TestLoginOriginCheck:
    def test_no_origin_header_passes(self):
        from app.dashboard.auth import verify_login_origin

        request = MagicMock()
        request.headers = {}
        request.url.netloc = "test"
        assert verify_login_origin(request) is True

    def test_matching_origin_passes(self):
        from app.dashboard.auth import verify_login_origin

        request = MagicMock()
        request.headers = {"origin": "http://test"}
        request.url.netloc = "test"
        assert verify_login_origin(request) is True

    def test_cross_origin_rejected(self):
        from app.dashboard.auth import verify_login_origin

        request = MagicMock()
        request.headers = {"origin": "http://evil.example"}
        request.url.netloc = "test"
        assert verify_login_origin(request) is False

    def test_forwarded_host_is_ignored(self):
        """A client-suppliable ``X-Forwarded-Host`` must not be able to
        enrol an arbitrary origin into the accepted set, even when trusted
        proxies are configured. The accepted set is derived only from the
        request's own host and ``CORS_ORIGINS``."""
        from app.dashboard.auth import verify_login_origin

        request = MagicMock()
        request.headers = {
            "origin": "http://evil.example",
            "x-forwarded-host": "evil.example",
        }
        request.url.netloc = "test"
        with patch.object(settings, "trusted_proxies", "10.0.0.0/8"):
            assert verify_login_origin(request) is False


class TestCookieSecureFlag:
    """Cookie Secure flag must follow COOKIE_SECURE, not ENABLE_HSTS."""

    @pytest.mark.asyncio
    async def test_cookie_secure_true_when_setting_true(self):
        original_secure = settings.cookie_secure
        original_hsts = settings.enable_hsts
        try:
            settings.cookie_secure = True
            settings.enable_hsts = False
            response = MagicMock()
            with patch("app.core.rate_limit.get_redis", side_effect=Exception("no redis")):
                await create_session_cookie(response)
            kwargs = response.set_cookie.call_args.kwargs
            assert kwargs["secure"] is True
        finally:
            settings.cookie_secure = original_secure
            settings.enable_hsts = original_hsts

    @pytest.mark.asyncio
    async def test_cookie_secure_false_when_setting_false(self):
        original_secure = settings.cookie_secure
        original_hsts = settings.enable_hsts
        try:
            settings.cookie_secure = False
            settings.enable_hsts = True
            response = MagicMock()
            with patch("app.core.rate_limit.get_redis", side_effect=Exception("no redis")):
                await create_session_cookie(response)
            kwargs = response.set_cookie.call_args.kwargs
            assert kwargs["secure"] is False
        finally:
            settings.cookie_secure = original_secure
            settings.enable_hsts = original_hsts


# ──: CSRF token must not be in a JS-readable cookie ───────────


class TestCsrfCookieRemoval:
    """The
    dashboard must not mirror the CSRF token into a JavaScript-
    readable cookie. JS reads from the ``<meta name="csrf-token">``
    tag (and from the login JSON body) instead, so an XSS payload
    can no longer harvest the token with a single
    ``document.cookie`` read."""

    @pytest.mark.asyncio
    async def test_routes_login_response_does_not_set_csrf_cookie(self):
        """The HTML-form login at ``POST /dashboard/login`` must
        not emit a ``Set-Cookie: csrf_token=`` header. Asserted
        structurally by inspecting the routes module source."""
        import inspect

        from app.dashboard import routes as _routes

        source = inspect.getsource(_routes)
        assert 'key="csrf_token"' not in source, (
            "routes.py still writes a ``csrf_token`` cookie — requires the token to live in the meta tag only."
        )

    def test_api_login_module_does_not_write_csrf_cookie(self):
        import inspect

        from app.dashboard import api as _api

        source = inspect.getsource(_api)
        # The JSON ``/api/login`` endpoint is allowed to return the
        # token in the response **body** (look for the dict key,
        # which has different quoting), but must not set it as a
        # cookie.
        assert 'key="csrf_token"' not in source, (
            "api.py still writes a ``csrf_token`` cookie — "
            "requires the token to come from the JSON body / meta "
            "tag instead."
        )

    def test_api_login_returns_csrf_in_json_body(self):
        """The JSON login endpoint must surface the freshly-minted
        CSRF token in its response body so non-browser clients can
        wire it into their ``X-CSRF-Token`` header."""
        import inspect

        from app.dashboard import api as _api

        login_src = inspect.getsource(_api.login)
        assert '"csrf_token": csrf_token' in login_src or "'csrf_token': csrf_token" in login_src, (
            "POST /dashboard/api/login must include ``csrf_token`` in its JSON response body."
        )

    def test_base_template_renders_csrf_meta_tag(self):
        """``base.html`` must conditionally render the
        ``<meta name="csrf-token">`` tag so dashboard JS can read
        it. The conditional gating on ``csrf_token`` keeps the tag
        absent on the public login page where there is no
        session-bound token yet."""
        from pathlib import Path

        base = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates" / "base.html"
        text = base.read_text(encoding="utf-8")
        assert '<meta name="csrf-token"' in text
        # The conditional is what prevents an empty meta tag on
        # ``login.html`` (anonymous render, no session).
        assert "{% if csrf_token %}" in text

    def test_dashboard_js_reads_csrf_from_meta_not_cookie(self):
        """Dashboard JS must read the CSRF token from the meta
        tag. The previous ``document.cookie`` lookup is what made
        XSS able to mint authenticated writes — its absence is
        the structural part of."""
        from pathlib import Path

        js = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "static" / "dashboard.js"
        text = js.read_text(encoding="utf-8")
        assert 'meta[name="csrf-token"]' in text
        # No cookie-based read for csrf_token remains.
        assert "csrf_token=([^;]+)" not in text, (
            "dashboard.js still reads csrf_token from document.cookie —  forbids this read."
        )


# ──: CSRF rotate-on-use ───────────────────────────────────────


class TestCsrfRotation:
    """After a
    successful CSRF check on a state-changing request the server
    must rotate the session's CSRF token so a leaked token cannot
    be replayed for the full session lifetime."""

    @pytest.mark.asyncio
    async def test_rotate_csrf_token_returns_new_value_and_invalidates_old(
        self,
    ):
        """``rotate_csrf_token`` mints a fresh token, persists it,
        and the next ``check_csrf_token`` call against the OLD
        token returns mismatch."""
        from app.dashboard.auth import (
            CSRF_MISMATCH,
            CSRF_OK,
            check_csrf_token,
            get_csrf_token,
            rotate_csrf_token,
        )

        # Patch the underlying Redis client with an in-memory dict.
        store: dict[str, str] = {}

        class _FakeRedis:
            async def setex(self, k, ttl, v):
                store[k] = v

            async def get(self, k):
                return store.get(k)

        async def _get_redis():
            return _FakeRedis()

        with patch("app.core.rate_limit.get_redis", _get_redis):
            request_mint = MagicMock()
            request_mint.cookies = {COOKIE_NAME: ""}
            # Forge a signed session cookie so _extract_session_id
            # accepts it.
            sid = "fixed-session-id-for-rotation-test"
            payload = f"{sid}:{int(time.time()) + 3600}"
            sig = _sign(payload)
            request_mint.cookies = {COOKIE_NAME: f"{payload}.{sig}"}
            store[f"lwa:dash_session:{sid}:csrf"] = "old-token"
            store[f"lwa:dash_session:{sid}"] = "1"

            old = await get_csrf_token(request_mint)
            assert old == "old-token"

            new = await rotate_csrf_token(request_mint)
            assert new is not None
            assert new != old

            # New token verifies, old token does not.
            request_mint.headers = {"X-CSRF-Token": new}
            assert await check_csrf_token(request_mint) == CSRF_OK

            request_mint.headers = {"X-CSRF-Token": old}
            assert await check_csrf_token(request_mint) == CSRF_MISMATCH

    @pytest.mark.asyncio
    async def test_rotate_csrf_token_no_session_returns_none(self):
        """No active session → ``rotate_csrf_token`` returns
        ``None`` rather than raising. This guarantees the dependency
        chain can call it unconditionally on anonymous requests
        without surfacing 500s."""
        from app.dashboard.auth import rotate_csrf_token

        request = MagicMock()
        request.cookies = {}
        assert await rotate_csrf_token(request) is None

    @pytest.mark.asyncio
    async def test_require_auth_csrf_sets_next_token_header_on_success(
        self,
    ):
        """The dependency must populate ``X-CSRF-Token-Next`` on
        the response so the SPA can swap its in-memory token."""
        from fastapi import Response

        from app.dashboard import api as dash_api
        from app.dashboard.auth import CSRF_OK

        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/dashboard/payments"

        response = Response()
        with patch.object(dash_api, "verify_session", new=AsyncMock(return_value=True)):
            with patch.object(dash_api, "check_csrf_token", new=AsyncMock(return_value=CSRF_OK)):
                with patch.object(
                    dash_api,
                    "rotate_csrf_token",
                    new=AsyncMock(return_value="rotated-fresh-token"),
                ):
                    await dash_api._require_auth_csrf(request, response)

        assert response.headers.get("X-CSRF-Token-Next") == "rotated-fresh-token"

    @pytest.mark.asyncio
    async def test_require_auth_csrf_stashes_next_token_on_request_state(self):
        """The rotated token is also stashed on ``request.state`` so the
        security-headers middleware can attach it to the *final* response —
        critical for error paths where the handler returns its own Response
        and the dependency-set header would be dropped."""
        from types import SimpleNamespace

        from fastapi import Response

        from app.dashboard import api as dash_api
        from app.dashboard.auth import CSRF_OK

        request = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/dashboard/api/channel/close"
        request.state = SimpleNamespace()

        response = Response()
        with patch.object(dash_api, "verify_session", new=AsyncMock(return_value=True)):
            with patch.object(dash_api, "check_csrf_token", new=AsyncMock(return_value=CSRF_OK)):
                with patch.object(
                    dash_api,
                    "rotate_csrf_token",
                    new=AsyncMock(return_value="rotated-xyz"),
                ):
                    await dash_api._require_auth_csrf(request, response)

        assert request.state.csrf_next == "rotated-xyz"

    @pytest.mark.asyncio
    async def test_require_auth_csrf_omits_next_header_when_rotation_unavailable(
        self,
    ):
        """If Redis is down rotation may return ``None``. The
        dependency must still let the current request through (the
        CSRF check itself already succeeded) but must not emit a
        stale or empty ``X-CSRF-Token-Next`` header."""
        from fastapi import Response

        from app.dashboard import api as dash_api
        from app.dashboard.auth import CSRF_OK

        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.url.path = "/dashboard/payments"

        response = Response()
        with patch.object(dash_api, "verify_session", new=AsyncMock(return_value=True)):
            with patch.object(dash_api, "check_csrf_token", new=AsyncMock(return_value=CSRF_OK)):
                with patch.object(
                    dash_api,
                    "rotate_csrf_token",
                    new=AsyncMock(return_value=None),
                ):
                    await dash_api._require_auth_csrf(request, response)

        assert "X-CSRF-Token-Next" not in response.headers


class TestLocalRevocationCache:
    """Process-local
    LRU revocation cache lets ``verify_session`` keep rejecting
    explicitly-revoked sessions when Redis is unreachable, even
    under ``RATE_LIMIT_FAIL_POLICY=open``."""

    def _clear_cache(self):
        from app.dashboard import auth as dashboard_auth

        dashboard_auth._revocation_cache.clear()

    @pytest.mark.asyncio
    async def test_session_validation_uses_local_revocation_cache_when_redis_down(self):
        """When Redis is unreachable and the session ID is in the
        local cache, ``verify_session`` returns False regardless of
        ``RATE_LIMIT_FAIL_POLICY`` (this test uses ``open``, which
        would otherwise allow signature-only validation)."""
        from app.dashboard import auth as dashboard_auth

        self._clear_cache()
        session_id = "revoked-locally-abc"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        # Pre-populate the local revocation cache.
        dashboard_auth._revocation_cache_add(session_id)

        original = dashboard_auth.settings.rate_limit_fail_policy
        dashboard_auth.settings.rate_limit_fail_policy = "open"
        try:
            with patch(
                "app.core.rate_limit.get_redis",
                new_callable=AsyncMock,
                side_effect=ConnectionError("down"),
            ):
                result = await verify_session(request)
        finally:
            dashboard_auth.settings.rate_limit_fail_policy = original
            self._clear_cache()
        assert result is False

    @pytest.mark.asyncio
    async def test_session_validation_fail_open_without_local_cache_entry(self):
        """When Redis is down, no local cache entry for this session,
        and policy is ``open`` (dev-only), verification still falls
        through to signature-only acceptance — the local cache is a
        *positive* revocation check, not a fail-closed gate."""
        from app.dashboard import auth as dashboard_auth

        self._clear_cache()
        session_id = "not-in-cache-xyz"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        original = dashboard_auth.settings.rate_limit_fail_policy
        dashboard_auth.settings.rate_limit_fail_policy = "open"
        try:
            with patch(
                "app.core.rate_limit.get_redis",
                new_callable=AsyncMock,
                side_effect=ConnectionError("down"),
            ):
                result = await verify_session(request)
        finally:
            dashboard_auth.settings.rate_limit_fail_policy = original
        assert result is True

    @pytest.mark.asyncio
    async def test_session_validation_fail_closed_when_no_local_cache_entry(self):
        """With ``RATE_LIMIT_FAIL_POLICY=closed`` (production default)
        and an empty local cache, verification still fails closed when
        Redis is unreachable."""
        from app.dashboard import auth as dashboard_auth

        self._clear_cache()
        session_id = "missing-cache-entry"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        original = dashboard_auth.settings.rate_limit_fail_policy
        dashboard_auth.settings.rate_limit_fail_policy = "closed"
        try:
            with patch(
                "app.core.rate_limit.get_redis",
                new_callable=AsyncMock,
                side_effect=ConnectionError("down"),
            ):
                result = await verify_session(request)
        finally:
            dashboard_auth.settings.rate_limit_fail_policy = original
        assert result is False

    def test_revoke_session_populates_local_cache(self):
        """``revoke_session`` adds the session ID to the local cache
        so the next ``verify_session`` while Redis is down still
        rejects it."""
        import asyncio

        from app.dashboard import auth as dashboard_auth

        self._clear_cache()
        session_id = "to-be-revoked-123"
        expires = int(time.time()) + 3600
        payload = f"{session_id}:{expires}"
        cookie = f"{payload}.{_sign(payload)}"
        request = _mock_request(cookie)

        async def _run():
            with patch(
                "app.core.rate_limit.get_redis",
                new_callable=AsyncMock,
                side_effect=ConnectionError("down"),
            ):
                await dashboard_auth.revoke_session(request)

        asyncio.run(_run())
        assert dashboard_auth._revocation_cache_contains(session_id) is True
        self._clear_cache()

    def test_local_revocation_cache_respects_ttl(self):
        """Entries past their TTL are evicted on access."""
        from app.dashboard import auth as dashboard_auth

        self._clear_cache()
        dashboard_auth._revocation_cache_add("stale-id")
        # Force expiry by rewriting the stored deadline into the past.
        dashboard_auth._revocation_cache["stale-id"] = time.time() - 1
        assert dashboard_auth._revocation_cache_contains("stale-id") is False
        assert "stale-id" not in dashboard_auth._revocation_cache

    def test_local_revocation_cache_evicts_oldest_on_overflow(self):
        """LRU eviction prevents unbounded memory growth."""
        from app.dashboard import auth as dashboard_auth

        self._clear_cache()
        original_max = dashboard_auth._REVOCATION_CACHE_MAX_ENTRIES
        dashboard_auth._REVOCATION_CACHE_MAX_ENTRIES = 3
        try:
            for sid in ("a", "b", "c", "d"):
                dashboard_auth._revocation_cache_add(sid)
            assert "a" not in dashboard_auth._revocation_cache
            assert len(dashboard_auth._revocation_cache) == 3
        finally:
            dashboard_auth._REVOCATION_CACHE_MAX_ENTRIES = original_max
            self._clear_cache()


class TestTokenDomainSeparation:
    """The session cookie and the login nonce share an identical payload
    shape (``{random}:{expires}``) but are signed under distinct purpose
    labels, so one token class can never be presented as the other —
    independent of any Redis/side-channel state."""

    @pytest.mark.asyncio
    async def test_login_nonce_is_not_a_valid_session(self):
        nonce = generate_login_nonce()
        request = _mock_request(nonce)
        # Even on the Redis-unavailable fail-open path (where a genuine
        # session signature would be honoured), the nonce is rejected at
        # the MAC because it was signed for a different purpose.
        with patch(
            "app.core.rate_limit.get_redis",
            new_callable=AsyncMock,
            side_effect=ConnectionError("down"),
        ):
            assert await verify_session(request) is False

    @pytest.mark.asyncio
    async def test_login_nonce_rejected_even_if_redis_has_session(self):
        nonce = generate_login_nonce()
        # The random part of the nonce becomes the would-be session id.
        request = _mock_request(nonce)
        mock_redis = AsyncMock()
        mock_redis.exists = AsyncMock(return_value=True)
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.expire = AsyncMock(return_value=True)
        with patch(
            "app.core.rate_limit.get_redis",
            new_callable=AsyncMock,
            return_value=mock_redis,
        ):
            assert await verify_session(request) is False

    def test_session_cookie_is_not_a_valid_login_nonce(self):
        expires = int(time.time()) + 3600
        payload = f"sess-abc:{expires}"
        session_cookie = f"{payload}.{_sign(payload)}"
        assert verify_login_nonce(session_cookie) is False

    def test_login_nonce_verifies_for_its_own_purpose(self):
        assert verify_login_nonce(generate_login_nonce()) is True
