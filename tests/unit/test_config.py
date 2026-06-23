# SPDX-License-Identifier: MIT
"""Unit tests for app.core.config — parse helpers and validators."""

import warnings
from unittest.mock import patch

from app.core.config import _parse_str_list


class TestParseStrList:
    def test_empty_string(self):
        assert _parse_str_list("") == []

    def test_whitespace_only(self):
        assert _parse_str_list("   ") == []

    def test_comma_separated(self):
        assert _parse_str_list("http://a, http://b") == ["http://a", "http://b"]

    def test_json_array(self):
        assert _parse_str_list('["http://a", "http://b"]') == ["http://a", "http://b"]

    def test_single_value(self):
        assert _parse_str_list("http://localhost") == ["http://localhost"]

    def test_json_empty_array(self):
        assert _parse_str_list("[]") == []


class TestPlaceholderPasswordWarning:
    def test_warns_on_change_me_database_url(self, caplog):
        """Settings warns when database_url contains 'change-me'."""
        from app.core.config import Settings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with patch.dict(
                "os.environ",
                {
                    "SECRET_KEY": "a" * 64,
                    "LND_MACAROON_HEX": "0201036c6e640" + "a" * 100,
                    "LND_REST_URL": "https://localhost:8080",
                    "DATABASE_URL": "postgresql+asyncpg://user:change-me@localhost/db",
                    "REDIS_URL": "redis://localhost:6379/0",
                    "BITCOIN_NETWORK": "regtest",
                },
            ):
                s = Settings(_env_file=None)
                assert s is not None
            placeholder_warnings = [x for x in w if "change-me" in str(x.message).lower()]
            assert len(placeholder_warnings) >= 1


class TestChainBackendValidator:
    """``_validate_chain_backend`` rules for the electrs integration."""

    def _base_env(self) -> dict[str, str]:
        return {
            "SECRET_KEY": "a" * 64,
            "LND_MACAROON_HEX": "0201036c6e640" + "a" * 100,
            "LND_REST_URL": "https://localhost:8080",
            "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
            "REDIS_URL": "redis://localhost:6379/0",
            "BITCOIN_NETWORK": "regtest",
        }

    def test_default_auto_no_url_ok(self):
        from app.core.config import Settings

        with patch.dict("os.environ", self._base_env(), clear=True):
            s = Settings(_env_file=None)
            assert s.chain_backend == "auto"
            assert s.lnd_electrum_url == ""

    def test_strict_electrum_requires_url(self):
        from app.core.config import Settings

        env = self._base_env()
        env["CHAIN_BACKEND"] = "electrum"
        with patch.dict("os.environ", env, clear=True):
            try:
                Settings(_env_file=None)
                raise AssertionError("Expected ValueError")
            except ValueError as e:
                assert "LND_ELECTRUM_URL" in str(e)

    def test_url_must_use_tcp_or_ssl(self):
        from app.core.config import Settings

        env = self._base_env()
        env["LND_ELECTRUM_URL"] = "http://example.com:50001"
        with patch.dict("os.environ", env, clear=True):
            try:
                Settings(_env_file=None)
                raise AssertionError("Expected ValueError")
            except ValueError as e:
                assert "tcp://" in str(e) or "ssl://" in str(e)

    def test_onion_url_requires_tor_proxy(self):
        from app.core.config import Settings

        env = self._base_env()
        env["LND_ELECTRUM_URL"] = "tcp://abc.onion:50001"
        env["LND_TOR_PROXY"] = ""
        with patch.dict("os.environ", env, clear=True):
            try:
                Settings(_env_file=None)
                raise AssertionError("Expected ValueError")
            except ValueError as e:
                assert "LND_TOR_PROXY" in str(e)

    def test_onion_url_with_tor_proxy_ok(self):
        from app.core.config import Settings

        env = self._base_env()
        env["LND_ELECTRUM_URL"] = "tcp://abc.onion:50001"
        env["LND_TOR_PROXY"] = "socks5://tor-proxy:9050"
        with patch.dict("os.environ", env, clear=True):
            s = Settings(_env_file=None)
            assert s.lnd_electrum_url == "tcp://abc.onion:50001"

    def test_clearnet_ssl_url_ok(self):
        from app.core.config import Settings

        env = self._base_env()
        env["CHAIN_BACKEND"] = "electrum"
        env["LND_ELECTRUM_URL"] = "ssl://electrum.example.com:50002"
        with patch.dict("os.environ", env, clear=True):
            s = Settings(_env_file=None)
            assert s.chain_backend == "electrum"


class TestRateLimitFailPolicyValidator:
    """Refuse to boot
    with ``RATE_LIMIT_FAIL_POLICY=open`` in production."""

    def _base_env(self) -> dict[str, str]:
        return {
            "SECRET_KEY": "a" * 64,
            "LND_MACAROON_HEX": "0201036c6e640" + "a" * 100,
            "LND_REST_URL": "https://localhost:8080",
            "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
            "REDIS_URL": "redis://localhost:6379/0",
            "BITCOIN_NETWORK": "regtest",
        }

    def test_settings_rejects_rate_limit_fail_policy_open_in_production(self):
        import pytest

        from app.core.config import Settings

        env = self._base_env()
        env["DEBUG"] = "false"
        env["RATE_LIMIT_FAIL_POLICY"] = "open"
        with patch.dict("os.environ", env, clear=True):
            with pytest.raises(Exception) as exc_info:
                Settings(_env_file=None)
            assert "RATE_LIMIT_FAIL_POLICY=open" in str(exc_info.value)
            assert "production" in str(exc_info.value).lower()

    def test_settings_allows_rate_limit_fail_policy_open_when_debug_true(self):
        from app.core.config import Settings

        env = self._base_env()
        env["DEBUG"] = "true"
        env["RATE_LIMIT_FAIL_POLICY"] = "open"
        with patch.dict("os.environ", env, clear=True):
            s = Settings(_env_file=None)
            assert s.rate_limit_fail_policy == "open"
            assert s.debug is True

    def test_settings_allows_rate_limit_fail_policy_closed_in_production(self):
        from app.core.config import Settings

        env = self._base_env()
        env["DEBUG"] = "false"
        env["RATE_LIMIT_FAIL_POLICY"] = "closed"
        with patch.dict("os.environ", env, clear=True):
            s = Settings(_env_file=None)
            assert s.rate_limit_fail_policy == "closed"


class TestDatabaseSslValidator:
    """``_validate_database_ssl`` requires SSL for public database hosts."""

    def _base_env(self) -> dict[str, str]:
        return {
            "SECRET_KEY": "a" * 64,
            "LND_MACAROON_HEX": "0201036c6e640" + "a" * 100,
            "LND_REST_URL": "https://localhost:8080",
            "REDIS_URL": "redis://localhost:6379/0",
            "BITCOIN_NETWORK": "regtest",
        }

    def _settings(self, **overrides):
        from app.core.config import Settings

        env = self._base_env()
        env.update({k: str(v) for k, v in overrides.items()})
        with patch.dict("os.environ", env, clear=True):
            return Settings(_env_file=None)

    def test_public_fqdn_without_ssl_rejected(self):
        import pytest

        with pytest.raises(Exception) as exc_info:
            self._settings(DATABASE_URL="postgresql+asyncpg://u:p@db.example.com:5432/d")
        assert "DATABASE_REQUIRE_SSL" in str(exc_info.value)

    def test_public_ip_without_ssl_rejected(self):
        import pytest

        with pytest.raises(Exception):
            self._settings(DATABASE_URL="postgresql+asyncpg://u:p@8.8.8.8:5432/d")

    def test_public_host_with_ssl_allowed(self):
        s = self._settings(
            DATABASE_URL="postgresql+asyncpg://u:p@db.example.com:5432/d",
            DATABASE_REQUIRE_SSL="true",
        )
        assert s.database_require_ssl is True

    def test_public_host_in_debug_allowed(self):
        s = self._settings(
            DATABASE_URL="postgresql+asyncpg://u:p@db.example.com:5432/d",
            DEBUG="true",
        )
        assert s.debug is True

    def test_single_label_service_name_allowed(self):
        # The default compose deployment uses an internal "postgres" service.
        s = self._settings(DATABASE_URL="postgresql+asyncpg://u:p@postgres:5432/d")
        assert s.database_require_ssl is False

    def test_private_ip_allowed(self):
        s = self._settings(DATABASE_URL="postgresql+asyncpg://u:p@10.0.0.5:5432/d")
        assert s.database_require_ssl is False

    def test_localhost_allowed(self):
        s = self._settings(DATABASE_URL="postgresql+asyncpg://u:p@localhost:5432/d")
        assert s.database_require_ssl is False

    def test_internal_suffix_allowed(self):
        s = self._settings(DATABASE_URL="postgresql+asyncpg://u:p@db.internal:5432/d")
        assert s.database_require_ssl is False

    def test_sqlite_allowed(self):
        s = self._settings(DATABASE_URL="sqlite+aiosqlite://")
        assert s.database_require_ssl is False
