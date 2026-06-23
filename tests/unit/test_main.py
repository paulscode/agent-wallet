# SPDX-License-Identifier: MIT
"""
Unit tests for app.main — lifecycle, middleware, and helpers.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.core.limiter import _get_client_ip
from app.main import (
    _configure_logging,
    lifespan,
    rate_limit_handler,
    security_headers,
)

# ─── _get_client_ip ──────────────────────────────────────────────────


class TestGetClientIP:
    def test_returns_host_when_present(self):
        request = MagicMock(spec=Request)
        request.client.host = "192.168.1.1"
        assert _get_client_ip(request) == "192.168.1.1"

    def test_returns_unknown_when_no_client(self):
        request = MagicMock(spec=Request)
        request.client = None
        assert _get_client_ip(request) == "unknown"


# ─── rate_limit_handler ──────────────────────────────────────────────


class TestRateLimitHandler:
    @pytest.mark.asyncio
    async def test_returns_429_with_message(self):
        request = MagicMock(spec=Request)
        limit = MagicMock()
        limit.error_message = None
        exc = RateLimitExceeded(limit)
        resp = await rate_limit_handler(request, exc)
        assert isinstance(resp, JSONResponse)
        assert resp.status_code == 429


# ─── Dashboard confirm-modal placement ───────────────────────────────
class TestConfirmModalPlacement:
    """The app-wide askConfirm modal must sit at the top level of the
    dashboard root, not nested inside a page section. When nested, the
    section's stacking context traps its ``z-[60]`` *behind* an open
    ``z-50`` action dialog (e.g. Close Channels) and the confirm never
    shows, so the action button looks dead."""

    def _dashboard_html(self) -> str:
        from pathlib import Path

        path = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates" / "dashboard.html"
        return path.read_text(encoding="utf-8")

    def test_confirm_modal_is_top_level(self):
        import re

        html = self._dashboard_html()
        matches = re.findall(r'^(\s*)<div x-show="confirmOpen"', html, re.MULTILINE)
        assert len(matches) == 1, "expected exactly one confirmOpen modal"
        indent = len(matches[0])
        # Top-level dialogs in this template sit at 4-space indent; the
        # confirm modal must be at most that deep so its z-index isn't
        # trapped in a nested stacking context.
        assert indent <= 4, f"confirmOpen modal nested too deep (indent={indent}); must be top-level"

    def test_tor_health_modal_uses_backdrop_pattern(self):
        """The Tor Health modal must follow the working-dialog pattern (a
        backdrop div + @click to close) and must NOT use ``x-cloak`` or
        ``@click.outside``: x-cloak on an x-if-rendered element keeps it
        ``display:none`` in the CSP build (panel never shows), and
        @click.outside can swallow the opening click."""
        html = self._dashboard_html()
        # Grab the modal block from its template guard to the next dialog.
        start = html.index('x-if="showTorHealth"')
        block = html[start:start + 1200]
        assert '@click="showTorHealth = false"' in block, "Tor Health modal lost its backdrop close handler"
        assert "x-cloak" not in block, "Tor Health modal must not use x-cloak (x-if element stays display:none)"
        assert "click.outside" not in block, "Tor Health modal must not use @click.outside"


# ─── security_headers middleware ─────────────────────────────────────


class TestSecurityHeaders:
    @pytest.mark.asyncio
    async def test_adds_headers(self):
        request = MagicMock(spec=Request)
        base_response = JSONResponse(content={"ok": True})
        call_next = AsyncMock(return_value=base_response)

        resp = await security_headers(request, call_next)

        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
        assert resp.headers["Cache-Control"] == "no-store"

    @pytest.mark.asyncio
    async def test_hsts_header_when_enabled(self):
        request = MagicMock(spec=Request)
        base_response = JSONResponse(content={"ok": True})
        call_next = AsyncMock(return_value=base_response)

        with patch("app.main.settings") as mock_settings:
            mock_settings.enable_hsts = True
            resp = await security_headers(request, call_next)

        assert "Strict-Transport-Security" in resp.headers

    @pytest.mark.asyncio
    async def test_no_hsts_header_when_disabled(self):
        request = MagicMock(spec=Request)
        base_response = JSONResponse(content={"ok": True})
        call_next = AsyncMock(return_value=base_response)

        with patch("app.main.settings") as mock_settings:
            mock_settings.enable_hsts = False
            resp = await security_headers(request, call_next)

        assert "Strict-Transport-Security" not in resp.headers

    @pytest.mark.asyncio
    async def test_delivers_rotated_csrf_token_on_custom_response(self):
        """A handler that returns its own Response (e.g. an error
        JSONResponse) still gets the rotated CSRF token, sourced from
        ``request.state`` by this middleware. Without it, the
        dependency-set header is dropped on directly-returned Responses
        and the client wedges at 403 on its next write."""
        from types import SimpleNamespace

        request = SimpleNamespace(
            url=SimpleNamespace(path="/dashboard/api/channel/close"),
            state=SimpleNamespace(csrf_next="rotated-abc"),
        )

        async def call_next(_req):
            return JSONResponse(status_code=502, content={"detail": "LND error"})

        resp = await security_headers(request, call_next)

        assert resp.status_code == 502
        assert resp.headers["X-CSRF-Token-Next"] == "rotated-abc"

    @pytest.mark.asyncio
    async def test_no_csrf_token_header_when_state_unset(self):
        """Read-only routes never set ``csrf_next``, so the header is
        absent (no spurious rotation signal)."""
        from types import SimpleNamespace

        request = SimpleNamespace(
            url=SimpleNamespace(path="/healthz"),
            state=SimpleNamespace(),
        )

        async def call_next(_req):
            return JSONResponse(status_code=200, content={"ok": True})

        resp = await security_headers(request, call_next)

        assert "X-CSRF-Token-Next" not in resp.headers

    @pytest.mark.asyncio
    async def test_csp_header_on_dashboard_path(self):
        request = MagicMock(spec=Request)
        request.url.path = "/dashboard/login"
        request.state.csp_nonce = "test-nonce-value"
        base_response = JSONResponse(content={"ok": True})
        call_next = AsyncMock(return_value=base_response)

        with patch("app.main.settings") as mock_settings:
            mock_settings.enable_hsts = False
            resp = await security_headers(request, call_next)

        assert "Content-Security-Policy" in resp.headers

    @pytest.mark.asyncio
    async def test_api_path_gets_restrictive_csp(self):
        request = MagicMock(spec=Request)
        request.url.path = "/api/wallet"
        base_response = JSONResponse(content={"ok": True})
        call_next = AsyncMock(return_value=base_response)

        with patch("app.main.settings") as mock_settings:
            mock_settings.enable_hsts = False
            resp = await security_headers(request, call_next)

        assert "Content-Security-Policy" in resp.headers
        assert (
            resp.headers["Content-Security-Policy"]
            == "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )


# ─── _configure_logging ─────────────────────────────────────────────


class TestConfigureLogging:
    def test_text_format_calls_basic_config(self):
        with patch("app.main.settings") as mock_settings, patch("logging.basicConfig") as mock_basic:
            mock_settings.log_format = "text"
            mock_settings.log_level = "DEBUG"
            _configure_logging()

        mock_basic.assert_called_once()
        assert mock_basic.call_args.kwargs["level"] == logging.DEBUG

    def test_json_format_with_package_configures_json_handler(self):
        with patch("app.main.settings") as mock_settings:
            mock_settings.log_format = "json"
            mock_settings.log_level = "INFO"
            mock_formatter = MagicMock()
            mock_module = MagicMock()
            mock_module.JsonFormatter = mock_formatter
            with patch.dict("sys.modules", {"pythonjsonlogger": MagicMock(), "pythonjsonlogger.json": mock_module}):
                _configure_logging()
            mock_formatter.assert_called_once()

    def test_json_format_without_package_falls_back(self):
        with patch("app.main.settings") as mock_settings, patch("logging.basicConfig") as mock_basic:
            mock_settings.log_format = "json"
            mock_settings.log_level = "INFO"
            with patch.dict("sys.modules", {"pythonjsonlogger": None, "pythonjsonlogger.json": None}):
                _configure_logging()

        # Falls back to basicConfig when json logger package is missing
        mock_basic.assert_called()


# ─── lifespan ────────────────────────────────────────────────────────


class TestLifespan:
    @pytest.mark.asyncio
    async def test_insecure_secret_key_raises(self):
        """Lifespan should refuse startup with insecure SECRET_KEY."""
        mock_app = MagicMock()

        with patch("app.main.settings") as mock_settings:
            mock_settings.secret_key = "change-me-to-a-random-64-char-string"
            with pytest.raises(RuntimeError, match="SECRET_KEY is missing or insecure"):
                async with lifespan(mock_app):
                    pass

    @pytest.mark.asyncio
    async def test_short_secret_key_raises(self):
        """Lifespan should refuse startup with short SECRET_KEY."""
        mock_app = MagicMock()

        with patch("app.main.settings") as mock_settings:
            mock_settings.secret_key = "tooshort"
            with pytest.raises(RuntimeError, match="SECRET_KEY is missing or insecure"):
                async with lifespan(mock_app):
                    pass

    @pytest.mark.asyncio
    async def test_empty_secret_key_raises(self):
        mock_app = MagicMock()

        with patch("app.main.settings") as mock_settings:
            mock_settings.secret_key = ""
            with pytest.raises(RuntimeError, match="SECRET_KEY is missing or insecure"):
                async with lifespan(mock_app):
                    pass

    @pytest.mark.asyncio
    async def test_lifecycle_happy_path(self):
        """Lifespan runs startup and shutdown cleanly."""
        mock_app = MagicMock()

        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}) as _mock_engines,
            patch("app.tasks.boltz_tasks.recover_boltz_swaps") as mock_recover,
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock) as mock_redis,
        ):
            mock_settings.secret_key = "a" * 64
            mock_settings.bitcoin_network = "regtest"
            mock_settings.boltz_use_tor = False
            mock_settings.anonymize_enabled = False
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                mock_recover.delay.assert_called_once()

            mock_lnd.close.assert_awaited_once()
            mock_boltz.close.assert_awaited_once()
            mock_mempool.close.assert_awaited_once()
            mock_redis.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_lifecycle_disposes_engines(self):
        """Lifespan disposes engines on shutdown."""
        mock_app = MagicMock()
        mock_engine = AsyncMock()

        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {"default": mock_engine}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
        ):
            mock_settings.secret_key = "a" * 64
            mock_settings.bitcoin_network = "regtest"
            mock_settings.boltz_use_tor = False
            mock_settings.anonymize_enabled = False
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            mock_engine.dispose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_lifecycle_celery_unavailable(self):
        """Lifespan proceeds when Celery/Redis is unavailable."""
        mock_app = MagicMock()

        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}) as _mock_engines,
            patch("app.tasks.boltz_tasks.recover_boltz_swaps") as mock_recover,
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock) as _mock_redis,
        ):
            mock_settings.secret_key = "a" * 64
            mock_settings.bitcoin_network = "regtest"
            mock_settings.boltz_use_tor = False
            mock_settings.anonymize_enabled = False
            mock_recover.delay.side_effect = Exception("Redis unavailable")
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            # Should NOT raise
            async with lifespan(mock_app):
                pass


class TestCSPHardening:
    """The dashboard CSP must lock down the document base, form posts,
    and plugin embedding. Outside the dashboard the same directives
    are tightened to ``'none'`` because no API response should ever
    render an HTML form or a plugin."""

    @pytest.mark.asyncio
    async def test_dashboard_csp_has_no_unsafe_eval(self):
        from starlette.requests import Request as StarletteRequest

        request = MagicMock(spec=StarletteRequest)
        request.url.path = "/dashboard/home"
        request.state.csp_nonce = "test-nonce-123"
        base_response = JSONResponse(content={"ok": True})
        call_next = AsyncMock(return_value=base_response)

        with patch("app.main.settings") as mock_settings:
            mock_settings.enable_hsts = False
            resp = await security_headers(request, call_next)

        csp = resp.headers.get("Content-Security-Policy", "")
        assert "unsafe-eval" not in csp
        assert "'nonce-test-nonce-123'" in csp
        # The dashboard
        # now serves vendor assets locally, so the CSP must NOT
        # allow-list ``cdn.jsdelivr.net``.
        assert "cdn.jsdelivr.net" not in csp

    @pytest.mark.asyncio
    async def test_dashboard_csp_has_object_src_none(self):
        request = MagicMock()
        request.url.path = "/dashboard/home"
        request.state.csp_nonce = "n1"
        base = JSONResponse({"ok": True})
        call_next = AsyncMock(return_value=base)
        with patch("app.main.settings") as s:
            s.enable_hsts = False
            resp = await security_headers(request, call_next)
        csp = resp.headers["Content-Security-Policy"]
        assert "object-src 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp

    @pytest.mark.asyncio
    async def test_dashboard_csp_includes_upgrade_insecure_when_hsts_on(self):
        request = MagicMock()
        request.url.path = "/dashboard/home"
        request.state.csp_nonce = "n1"
        base = JSONResponse({"ok": True})
        call_next = AsyncMock(return_value=base)
        with patch("app.main.settings") as s:
            s.enable_hsts = True
            resp = await security_headers(request, call_next)
        csp = resp.headers["Content-Security-Policy"]
        assert "upgrade-insecure-requests" in csp

    @pytest.mark.asyncio
    async def test_non_dashboard_csp_locks_form_action(self):
        request = MagicMock()
        request.url.path = "/v1/wallet/balance"
        base = JSONResponse({"ok": True})
        call_next = AsyncMock(return_value=base)
        with patch("app.main.settings") as s:
            s.enable_hsts = False
            resp = await security_headers(request, call_next)
        csp = resp.headers["Content-Security-Policy"]
        assert "form-action 'none'" in csp
        assert "base-uri 'none'" in csp


class TestRequestBodySizeMiddleware:
    """The body-size middleware short-circuits an oversized
    Content-Length header and also enforces the limit while streaming
    a chunked body, so a client cannot bypass the cap by omitting the
    header."""

    @pytest.mark.asyncio
    async def test_chunked_body_exceeding_limit_returns_413(self):
        from app.main import MAX_BODY_SIZE, limit_body_size

        big_chunk = b"A" * (MAX_BODY_SIZE + 1024)

        class FakeRequest:
            def __init__(self):
                self.headers = {}
                self._chunks = [{"type": "http.request", "body": big_chunk, "more_body": False}]
                self._idx = 0

            async def _recv(self):
                if self._idx >= len(self._chunks):
                    return {"type": "http.disconnect"}
                msg = self._chunks[self._idx]
                self._idx += 1
                return msg

            @property
            def _receive(self):
                return self._recv

            @_receive.setter
            def _receive(self, value):
                self._recv = value

        req = FakeRequest()

        async def call_next(r):
            while True:
                msg = await r._receive()
                if msg["type"] == "http.disconnect":
                    break
                if not msg.get("more_body"):
                    break
            return JSONResponse({"ok": True})

        resp = await limit_body_size(req, call_next)  # type: ignore[arg-type]
        assert resp.status_code == 413

    @pytest.mark.asyncio
    async def test_chunked_body_overflow_short_circuits_before_handler(self):
        """when a chunked request exceeds the limit the
        handler must NOT run. The previous implementation drained the
        body, called the handler with empty input, then rewrote the
        response to 413 — letting any DB writes / side-effects from
        the handler land before being silently discarded.
        """
        from app.main import MAX_BODY_SIZE, limit_body_size

        big_chunk = b"A" * (MAX_BODY_SIZE + 1024)

        class FakeRequest:
            def __init__(self):
                self.headers = {}
                self._chunks = [{"type": "http.request", "body": big_chunk, "more_body": False}]
                self._idx = 0

            async def _recv(self):
                if self._idx >= len(self._chunks):
                    return {"type": "http.disconnect"}
                msg = self._chunks[self._idx]
                self._idx += 1
                return msg

            @property
            def _receive(self):
                return self._recv

            @_receive.setter
            def _receive(self, value):
                self._recv = value

        req = FakeRequest()
        call_next = AsyncMock()

        resp = await limit_body_size(req, call_next)  # type: ignore[arg-type]
        assert resp.status_code == 413
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_chunked_body_under_limit_replays_to_handler(self):
        """A within-limit chunked body must be re-readable by the
        handler — i.e. the buffered messages are replayed via
        ``request._receive``."""
        from app.main import limit_body_size

        body = b"hello world"

        class FakeRequest:
            def __init__(self):
                self.headers = {}
                self._chunks = [{"type": "http.request", "body": body, "more_body": False}]
                self._idx = 0

            async def _recv(self):
                if self._idx >= len(self._chunks):
                    return {"type": "http.disconnect"}
                msg = self._chunks[self._idx]
                self._idx += 1
                return msg

            @property
            def _receive(self):
                return self._recv

            @_receive.setter
            def _receive(self, value):
                self._recv = value

        req = FakeRequest()
        observed: list[bytes] = []

        async def call_next(r):
            msg = await r._receive()
            observed.append(msg.get("body", b""))
            return JSONResponse({"ok": True})

        resp = await limit_body_size(req, call_next)  # type: ignore[arg-type]
        assert resp.status_code == 200
        assert observed == [body]

    @pytest.mark.asyncio
    async def test_content_length_too_large_returns_413_immediately(self):
        from app.main import limit_body_size

        request = MagicMock()
        request.headers = {"content-length": str(99_999_999)}
        call_next = AsyncMock()
        resp = await limit_body_size(request, call_next)
        assert resp.status_code == 413
        call_next.assert_not_called()


class TestRedisTlsWarning:
    """Lifespan emits a startup warning when ``REDIS_URL`` points at a
    remote host but does not use ``rediss://``. The warning is
    suppressed for ``rediss://`` and for loopback addresses."""

    @pytest.mark.asyncio
    async def test_lifespan_warns_remote_redis_without_tls(self):
        mock_app = MagicMock()

        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.main.logger") as mock_logger,
        ):
            mock_settings.secret_key = "a" * 64
            mock_settings.bitcoin_network = "regtest"
            mock_settings.boltz_use_tor = False
            mock_settings.anonymize_enabled = False
            mock_settings.enable_hsts = True
            mock_settings.rate_limit_fail_policy = "closed"
            mock_settings.enable_dashboard = True
            mock_settings.dashboard_token = ""
            mock_settings.lnd_max_payment_sats = 10000
            mock_settings.database_url = "sqlite+aiosqlite://"
            mock_settings.database_require_ssl = False
            mock_settings.redis_url = "redis://redis.example.com:6379/0"
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert any("rediss://" in c for c in warning_calls)

    @pytest.mark.asyncio
    async def test_lifespan_no_warning_for_rediss(self):
        mock_app = MagicMock()

        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.main.logger") as mock_logger,
        ):
            mock_settings.secret_key = "a" * 64
            mock_settings.bitcoin_network = "regtest"
            mock_settings.boltz_use_tor = False
            mock_settings.anonymize_enabled = False
            mock_settings.enable_hsts = True
            mock_settings.rate_limit_fail_policy = "closed"
            mock_settings.enable_dashboard = True
            mock_settings.dashboard_token = ""
            mock_settings.lnd_max_payment_sats = 10000
            mock_settings.database_url = "sqlite+aiosqlite://"
            mock_settings.database_require_ssl = False
            mock_settings.redis_url = "rediss://redis.example.com:6379/0"
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert not any("rediss://" in c for c in warning_calls)


class TestTrustedProxiesWarning:
    """Lifespan emits a startup warning when the dashboard is exposed
    on a non-loopback ``API_HOST`` but no ``TRUSTED_PROXIES`` are
    configured. Without trusted proxies, dashboard session
    IP-binding silently degrades to the reverse proxy's address —
    identical for every client — providing no real protection."""

    def _make_settings(self, mock_settings, *, api_host, trusted, dashboard=True):
        mock_settings.secret_key = "a" * 64
        mock_settings.bitcoin_network = "regtest"
        mock_settings.boltz_use_tor = False
        mock_settings.anonymize_enabled = False
        mock_settings.enable_hsts = True
        mock_settings.rate_limit_fail_policy = "closed"
        mock_settings.enable_dashboard = dashboard
        mock_settings.dashboard_token = ""
        mock_settings.lnd_max_payment_sats = 10000
        mock_settings.database_url = "sqlite+aiosqlite://"
        mock_settings.database_require_ssl = False
        mock_settings.redis_url = "redis://localhost:6379/0"
        mock_settings.lnd_mempool_url = "https://mempool.space"
        mock_settings.mempool_allow_internal = True  # skip DNS in test
        mock_settings.api_host = api_host
        mock_settings.trusted_proxies_list = trusted

    @pytest.mark.asyncio
    async def test_warns_when_non_loopback_and_no_proxies(self):
        mock_app = MagicMock()
        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.main.logger") as mock_logger,
        ):
            self._make_settings(mock_settings, api_host="0.0.0.0", trusted=[])
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert any("TRUSTED_PROXIES" in c for c in warning_calls)

    @pytest.mark.asyncio
    async def test_no_warning_when_loopback(self):
        mock_app = MagicMock()
        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.main.logger") as mock_logger,
        ):
            self._make_settings(mock_settings, api_host="127.0.0.1", trusted=[])
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert not any("TRUSTED_PROXIES" in c for c in warning_calls)

    @pytest.mark.asyncio
    async def test_no_warning_when_proxies_configured(self):
        mock_app = MagicMock()
        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.main.logger") as mock_logger,
        ):
            self._make_settings(mock_settings, api_host="0.0.0.0", trusted=["172.16.0.0/12"])
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert not any("TRUSTED_PROXIES" in c for c in warning_calls)

    @pytest.mark.asyncio
    async def test_no_warning_when_dashboard_disabled(self):
        mock_app = MagicMock()
        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.main.logger") as mock_logger,
        ):
            self._make_settings(mock_settings, api_host="0.0.0.0", trusted=[], dashboard=False)
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert not any("TRUSTED_PROXIES" in c for c in warning_calls)
