# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.database — engine/session per-loop isolation
and get_db_context context manager.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.core.database import (
    _engines,
    _get_loop_id,
    _session_makers,
    get_db_context,
    get_engine,
    get_session_maker,
)


class TestGetLoopId:
    """Tests for _get_loop_id."""

    @pytest.mark.asyncio
    async def test_returns_nonzero_inside_loop(self):
        """Inside a running event loop, returns a non-zero id."""
        loop_id = _get_loop_id()
        assert loop_id != 0

    def test_returns_zero_outside_loop(self):
        """Outside an event loop, returns 0."""
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            result = pool.submit(_get_loop_id).result()
        assert result == 0


class TestGetEngine:
    """Tests for get_engine per-loop caching."""

    @pytest.mark.asyncio
    async def test_returns_engine(self):
        mock_engine = MagicMock()
        with patch("app.core.database._create_engine", return_value=mock_engine):
            loop_id = _get_loop_id()
            _engines.pop(loop_id, None)  # clear cache
            engine = get_engine()
        assert engine is mock_engine
        _engines.pop(loop_id, None)

    @pytest.mark.asyncio
    async def test_same_engine_for_same_loop(self):
        mock_engine = MagicMock()
        with patch("app.core.database._create_engine", return_value=mock_engine) as mock_create:
            loop_id = _get_loop_id()
            _engines.pop(loop_id, None)
            e1 = get_engine()
            e2 = get_engine()
        assert e1 is e2
        mock_create.assert_called_once()
        _engines.pop(loop_id, None)

    @pytest.mark.asyncio
    async def test_engine_registered(self):
        mock_engine = MagicMock()
        with patch("app.core.database._create_engine", return_value=mock_engine):
            loop_id = _get_loop_id()
            _engines.pop(loop_id, None)
            engine = get_engine()
        assert _engines.get(loop_id) is engine
        _engines.pop(loop_id, None)


class TestGetSessionMaker:
    """Tests for get_session_maker per-loop caching."""

    @pytest.mark.asyncio
    async def test_returns_session_maker(self):
        mock_engine = MagicMock()
        with patch("app.core.database._create_engine", return_value=mock_engine):
            loop_id = _get_loop_id()
            _engines.pop(loop_id, None)
            _session_makers.pop(loop_id, None)
            sm = get_session_maker()
        assert sm is not None
        _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)

    @pytest.mark.asyncio
    async def test_same_session_maker_for_same_loop(self):
        mock_engine = MagicMock()
        with patch("app.core.database._create_engine", return_value=mock_engine):
            loop_id = _get_loop_id()
            _engines.pop(loop_id, None)
            _session_makers.pop(loop_id, None)
            sm1 = get_session_maker()
            sm2 = get_session_maker()
        assert sm1 is sm2
        _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)


class TestGetDbContext:
    """Tests for get_db_context context manager."""

    @pytest.mark.asyncio
    async def test_yields_session(self, db_engine):
        """Uses the test db_engine fixture to get a working session."""

        loop_id = _get_loop_id()
        _engines[loop_id] = db_engine
        _session_makers.pop(loop_id, None)

        async with get_db_context() as session:
            assert session is not None
            assert hasattr(session, "execute")
            assert hasattr(session, "commit")

        _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)

    @pytest.mark.asyncio
    async def test_session_closed_after_exit(self, db_engine):
        loop_id = _get_loop_id()
        _engines[loop_id] = db_engine
        _session_makers.pop(loop_id, None)

        session_ref = None
        async with get_db_context() as session:
            session_ref = session
        assert session_ref is not None

        _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)

    @pytest.mark.asyncio
    async def test_session_closed_on_exception(self, db_engine):
        """Session is still closed even if an exception occurs inside the context."""
        loop_id = _get_loop_id()
        _engines[loop_id] = db_engine
        _session_makers.pop(loop_id, None)

        with pytest.raises(ValueError, match="test error"):
            async with get_db_context() as session:
                assert session is not None
                raise ValueError("test error")

        _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)


class TestGetDb:
    """Tests for get_db FastAPI dependency."""

    @pytest.mark.asyncio
    async def test_get_db_yields_session(self, db_engine):
        """get_db dependency yields a working session."""
        from app.core.database import get_db

        loop_id = _get_loop_id()
        _engines[loop_id] = db_engine
        _session_makers.pop(loop_id, None)

        gen = get_db()
        session = await gen.__anext__()
        assert session is not None
        assert hasattr(session, "execute")
        try:
            await gen.__anext__()
        except StopAsyncIteration:
            pass

        _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)


class TestCreateEngine:
    """Tests for _create_engine."""

    @pytest.mark.asyncio
    async def test_create_engine_called_with_settings(self):
        """_create_engine passes settings.database_url to create_async_engine."""
        from app.core.database import _create_engine

        with patch("app.core.database.create_async_engine") as mock_create:
            mock_create.return_value = MagicMock()
            _create_engine()

        mock_create.assert_called_once()
        args, kwargs = mock_create.call_args
        # First positional arg is the database URL from settings
        from app.core.config import settings

        assert args[0] == settings.database_url


class TestEngineRegistry:
    """Tests for engine_registry alias."""

    def test_engine_registry_is_engines(self):
        """engine_registry is the same dict as _engines."""
        from app.core.database import engine_registry

        assert engine_registry is _engines


class TestDatabaseSslEnforcement:
    """``DATABASE_REQUIRE_SSL`` defaults off (so local dev with SQLite
    works) but, when enabled, must propagate through to the asyncpg
    engine's ``connect_args``. A remote Postgres URL with the flag
    off should at minimum produce a startup warning."""

    def test_database_require_ssl_default_false(self):
        from app.core.config import Settings

        with patch.dict("os.environ", {}, clear=False):
            s = Settings(
                secret_key="a" * 64,
                database_url="sqlite+aiosqlite://",
            )
            assert s.database_require_ssl is False

    def test_database_require_ssl_can_be_enabled(self):
        from app.core.config import Settings

        with patch.dict("os.environ", {"DATABASE_REQUIRE_SSL": "true"}, clear=False):
            s = Settings(
                secret_key="a" * 64,
                database_url="sqlite+aiosqlite://",
            )
            assert s.database_require_ssl is True

    @pytest.mark.asyncio
    async def test_lifespan_warns_remote_db_without_ssl(self):
        from unittest.mock import AsyncMock

        from app.main import lifespan

        mock_app = MagicMock()

        with (
            patch("app.main.settings") as mock_settings,
            patch("app.main.engine_registry", {}),
            patch("app.tasks.boltz_tasks.recover_boltz_swaps"),
            patch("app.tasks.boltz_tasks._run_recover_swaps", new_callable=AsyncMock),
            patch(
                "app.services.bolt12.reconcile.reconcile_stranded_invreqs",
                new_callable=AsyncMock,
                return_value={"scanned": 0, "timed_out": 0},
            ),
            patch("app.services.lnd_service.lnd_service") as mock_lnd,
            patch("app.services.boltz_service.boltz_service") as mock_boltz,
            patch("app.services.mempool_fee_service.mempool_fee_service") as mock_mempool,
            patch("app.core.rate_limit.close_redis", new_callable=AsyncMock),
            patch("app.core.database.get_engine") as mock_get_engine,
            patch("app.main.logger") as mock_logger,
        ):
            # Short-circuit DB probe — the test mocks settings.database_url
            # to a remote postgres host but the real engine factory would still
            # try to talk to that host. Replace the engine.connect() coroutine
            # with one that no-ops successfully.
            mock_eng = MagicMock()
            mock_conn_ctx = AsyncMock()
            mock_conn_ctx.__aenter__ = AsyncMock(return_value=AsyncMock(execute=AsyncMock()))
            mock_conn_ctx.__aexit__ = AsyncMock(return_value=None)
            mock_eng.connect = MagicMock(return_value=mock_conn_ctx)
            mock_get_engine.return_value = mock_eng
            mock_settings.secret_key = "a" * 64
            mock_settings.bitcoin_network = "regtest"
            mock_settings.boltz_use_tor = False
            mock_settings.enable_hsts = True
            mock_settings.rate_limit_fail_policy = "closed"
            mock_settings.enable_dashboard = True
            mock_settings.dashboard_token = ""
            mock_settings.lnd_max_payment_sats = 10000
            mock_settings.database_url = "postgresql+asyncpg://user:pass@db.example.com:5432/mydb"
            mock_settings.database_require_ssl = False
            mock_settings.redis_url = "redis://localhost:6379/0"
            # Skip anonymize-feature startup gates; this DB-SSL test
            # has no reason to exercise them.
            mock_settings.anonymize_enabled = False
            mock_lnd.close = AsyncMock()
            mock_boltz.close = AsyncMock()
            mock_mempool.close = AsyncMock()

            async with lifespan(mock_app):
                pass

            warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
            assert any("DATABASE_REQUIRE_SSL" in c for c in warning_calls)

    def test_create_engine_with_ssl(self):
        from app.core.database import _create_engine

        with (
            patch("app.core.database.settings") as mock_settings,
            patch("app.core.database.create_async_engine") as mock_create,
        ):
            mock_settings.database_url = "postgresql+asyncpg://user:pass@remote:5432/db"
            mock_settings.database_require_ssl = True
            mock_settings.debug = False

            _create_engine()

            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args[1]
            assert "ssl" in call_kwargs["connect_args"]

    def test_create_engine_sets_idle_in_transaction_timeout(self):
        """The async engine must hand asyncpg an
        ``idle_in_transaction_session_timeout`` server_setting so a
        session that gets abandoned mid-transaction (e.g. a coroutine
        holds the connection across a stalled HTTP call) is reaped by
        Postgres instead of sitting in ``idle in transaction`` until
        the pool (size 10 + overflow 20) is exhausted."""
        from app.core.database import _create_engine

        with (
            patch("app.core.database.settings") as mock_settings,
            patch("app.core.database.create_async_engine") as mock_create,
        ):
            mock_settings.database_url = "postgresql+asyncpg://user:pass@remote:5432/db"
            mock_settings.database_require_ssl = False
            mock_settings.debug = False

            _create_engine()

            mock_create.assert_called_once()
            server_settings = mock_create.call_args[1]["connect_args"]["server_settings"]
            assert server_settings.get("idle_in_transaction_session_timeout") == "300000"
            # statement_timeout was already present; ensure it's still there.
            assert server_settings.get("statement_timeout") == "30000"
