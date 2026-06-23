# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.utils and app.main utility functions.

Tests:
- sanitize_upstream_error — no internal details leaked to clients
- _get_client_ip — proxy-aware IP extraction from X-Forwarded-For
"""

from unittest.mock import MagicMock

# ─── sanitize_upstream_error ──────────────────────────────────────────


class TestSanitizeUpstreamError:
    """The sanitize_upstream_error helper must never leak internals."""

    def test_returns_generic_message(self):
        from app.core.utils import sanitize_upstream_error

        result = sanitize_upstream_error("Connection refused: 10.0.0.5:8080", "LND")
        assert "LND service error" in result
        assert "10.0.0.5" not in result
        assert "Connection refused" not in result

    def test_logs_full_detail(self, caplog):
        from app.core.utils import sanitize_upstream_error

        with caplog.at_level("ERROR", logger="app.core.utils"):
            sanitize_upstream_error("some secret trace", "Boltz")
        assert "some secret trace" in caplog.text

    def test_different_service_names(self):
        from app.core.utils import sanitize_upstream_error

        assert "LND" in sanitize_upstream_error("err", "LND")
        assert "Boltz" in sanitize_upstream_error("err", "Boltz")


# ─── Client IP extraction ─────────────────────────────────────────────


class TestProxyAwareIP:
    """_get_client_ip always uses request.client.host (never trusts X-Forwarded-For directly)."""

    def test_no_forwarded_header(self):
        from app.core.limiter import _get_client_ip

        request = MagicMock()
        request.headers = {}
        request.client.host = "192.168.1.1"
        assert _get_client_ip(request) == "192.168.1.1"

    def test_single_forwarded_ip(self):
        """X-Forwarded-For is ignored — uses request.client.host."""
        from app.core.limiter import _get_client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "203.0.113.5"}
        request.client.host = "10.0.0.1"
        assert _get_client_ip(request) == "10.0.0.1"

    def test_multiple_forwarded_ips_returns_first(self):
        """X-Forwarded-For is ignored — uses request.client.host."""
        from app.core.limiter import _get_client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "203.0.113.5, 10.0.0.1, 172.16.0.1"}
        request.client.host = "172.16.0.1"
        assert _get_client_ip(request) == "172.16.0.1"

    def test_forwarded_with_whitespace(self):
        """X-Forwarded-For is ignored — uses request.client.host."""
        from app.core.limiter import _get_client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "  203.0.113.5 , 10.0.0.1 "}
        request.client.host = "172.16.0.1"
        assert _get_client_ip(request) == "172.16.0.1"

    def test_no_client_info(self):
        from app.core.limiter import _get_client_ip

        request = MagicMock()
        request.headers = {}
        request.client = None
        assert _get_client_ip(request) == "unknown"


# ─── b64_to_hex ───────────────────────────────────────────────────────


class TestB64ToHex:
    """Tests for the b64_to_hex utility function."""

    def test_valid_base64(self):
        import base64

        from app.core.utils import b64_to_hex

        data = b"\xde\xad\xbe\xef"
        encoded = base64.b64encode(data).decode()
        assert b64_to_hex(encoded) == "deadbeef"

    def test_empty_string(self):
        from app.core.utils import b64_to_hex

        assert b64_to_hex("") == ""

    def test_invalid_base64_returns_original(self):
        from app.core.utils import b64_to_hex

        result = b64_to_hex("!!!not-base64!!!")
        assert result == "!!!not-base64!!!"
