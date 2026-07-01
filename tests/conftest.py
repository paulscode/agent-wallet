# SPDX-License-Identifier: MIT
"""
Shared pytest fixtures for all tests.

Uses SQLite in-memory for fast, isolated testing.
Provides async DB sessions, FastAPI test client, and mock services.
"""

import asyncio
import atexit
import os
import warnings
from typing import AsyncGenerator
from uuid import uuid4

# ─── Warning filters that survive into interpreter shutdown ──────────
#
# wallycore (SWIG-wrapped libwally) emits this at Python 3.12+
# interpreter shutdown:
#
#   sys:1: DeprecationWarning: builtin type swigvarlink has no
#   __module__ attribute
#
# Upstream tracking: https://github.com/swig/swig/issues/2659.
#
# Neither the pyproject ``filterwarnings`` list nor pytest's ``-W``
# flag suppress it: pytest's session-end teardown resets
# ``warnings.filters`` before the wallycore C extension fires its
# shutdown warning. Registering a filter at module-import time here
# only works for warnings emitted during the test session; once
# pytest resets the filters at session end, we lose coverage of the
# actual shutdown moment.
#
# Strategy: register the filter both at import time (covers during-
# session) AND via an ``atexit`` handler (covers post-session +
# during interpreter shutdown). ``atexit`` callbacks run AFTER
# pytest's session teardown but BEFORE the C extension's module
# cleanup, so the filter is re-installed in time to suppress the
# shutdown warning.
_SWIG_FILTER_KWARGS: dict = {
    "action": "ignore",
    "message": "builtin type swigvarlink has no __module__ attribute",
    "category": DeprecationWarning,
}
warnings.filterwarnings(**_SWIG_FILTER_KWARGS)


def _reinstall_swig_filter() -> None:
    # ``simplefilter`` resets ``warnings.filters`` first, so this
    # forcefully removes any pytest-installed "error" filter that
    # would otherwise turn the wallycore shutdown warning into an
    # error trace. The filter is intentionally broader than
    # ``filterwarnings(message=...)``: at interpreter shutdown there
    # is no remaining test code to mask real DeprecationWarnings, so
    # an unconditional ``ignore`` is safe.
    warnings.simplefilter("ignore", DeprecationWarning)


atexit.register(_reinstall_swig_filter)


def _suppress_swigvarlink_stderr() -> None:
    # Belt-and-braces fallback: the warnings-filter approach above
    # works on focused test runs but pytest's session-end machinery
    # appears to re-arm warning-as-error on full-suite runs, so the
    # wallycore C extension's shutdown DeprecationWarning still leaks
    # to stderr. The warning's text arrives in fragments
    # ("sys:1: DeprecationWarning:" and the message body in separate
    # writes), so a simple substring check on a single write misses
    # part of it. Buffer writes until a newline, then drop the whole
    # line if it mentions the upstream-SWIG marker. Anything else
    # passes through unchanged.
    import sys

    real_write = sys.stderr.write
    buf: list[str] = []

    def _filtered_write(text: str) -> int:
        if "\n" not in text:
            buf.append(text)
            return len(text)
        head, _, tail = text.rpartition("\n")
        line = "".join(buf) + head + "\n"
        buf.clear()
        if tail:
            buf.append(tail)
        if "swigvarlink" in line or ("DeprecationWarning" in line and line.strip().endswith("DeprecationWarning:")):
            return len(text)
        real_write(line)
        return len(text)

    sys.stderr.write = _filtered_write  # type: ignore[method-assign]


atexit.register(_suppress_swigvarlink_stderr)

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import StaticPool
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ─── Hypothesis: deterministic, no per-example deadline ───────────────
# Property tests run with a fixed seed (derandomize) so a CI failure
# reproduces exactly, and with no deadline because some properties drive
# deliberately slow code (e.g. 600k-iteration PBKDF2 in field encryption)
# that would otherwise trip Hypothesis's timing health checks.
try:
    from hypothesis import HealthCheck
    from hypothesis import settings as _hyp_settings

    _hyp_settings.register_profile(
        "default",
        derandomize=True,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    _hyp_settings.load_profile("default")
except Exception:
    pass

# Override settings BEFORE any app imports
os.environ["TESTING"] = "true"  # Short-circuit long-lived background-task loops
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-for-unit-tests-only"
os.environ["LND_MACAROON_HEX"] = "0201036c6e640" + "a" * 100
os.environ["LND_REST_URL"] = "https://localhost:8080"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["RATE_LIMIT_FAIL_POLICY"] = "open"  # No Redis in tests — fail open to avoid 503s
os.environ.setdefault("DEBUG", "true")  # P5/: 'open' policy requires DEBUG=true
os.environ["BITCOIN_NETWORK"] = "regtest"
os.environ["ENABLE_DOCS"] = "false"
os.environ["ENABLE_DASHBOARD"] = "false"
# Ensure tests are not influenced by a developer's local .env that may
# turn BOLT 12 on; the integration suite assumes the runtime is OFF.
os.environ["BOLT12_ENABLED"] = "false"
os.environ["BOLT12_GATEWAY_GRPC"] = ""
# Keep ``start_bolt12_runtime`` from spawning the LND settlement /
# HTLC-event subscriber loops in unit tests. They reconnect on a
# 2 s ConnectError cadence and query the DB each cycle; if a test
# cancels the runtime while a query is in flight, the aiosqlite
# worker thread later signals the (now-closed) test event loop and
# pytest promotes that to a hard failure. Tests that specifically
# exercise the subscribers monkeypatch these flags back on.
os.environ["BOLT12_SETTLEMENT_SUBSCRIBER_ENABLED"] = "false"
os.environ["BOLT12_HTLC_EVENT_SUBSCRIBER_ENABLED"] = "false"
# Tests must not pick up a developer's local
# ``ANONYMIZE_LIQUID_ENABLED=true`` from .env — bootstrapping the
# Liquid hop deps requires an L-BTC asset id that has no built-in
# regtest value, and the orchestrator tests do not care about the
# Liquid path. Tests that exercise Liquid surfaces monkeypatch
# ``anonymize_liquid_enabled`` on locally.
os.environ["ANONYMIZE_LIQUID_ENABLED"] = "false"
os.environ["ANONYMIZE_LIQUID_INTEGRATION_VERIFIED"] = "false"

# ─── SQLite compatibility for PostgreSQL UUID columns ─────────────────
# Replace PGUUID columns with a string-backed UUID type when creating
# tables on SQLite, so model code can keep using
# sqlalchemy.dialects.postgresql.UUID in production.
import uuid as _uuid

import sqlalchemy.types as satypes
from sqlalchemy import event
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from app.core.database import Base, get_db
from app.core.security import generate_api_key, hash_api_key

# Register anonymize tables so SQLAlchemy create_all sees them.
from app.models.anonymize_session import (  # noqa: F401
    AnonymizeBinSetHistory,
    AnonymizeDecoyOutput,
    AnonymizeOperatorHealth,
    AnonymizeQuoteTokenKeyGeneration,
    AnonymizeRuntimeState,
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeSessionOutput,
    AnonymizeSettings,
    AnonymizeStepupState,
)
from app.models.api_key import APIKey
from app.models.audit_chain_state import AuditChainState  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.bolt12_invoice import (  # noqa: F401
    Bolt12Invoice,
    Bolt12InvoiceRequest,
)
from app.models.bolt12_offer import Bolt12Offer  # noqa: F401
from app.models.boltz_swap import BoltzSwap  # noqa: F401
from app.models.braiins_deposit_session import (  # noqa: F401
    BraiinsDepositSession,
    BraiinsDepositSourceKind,
    BraiinsDepositStatus,
)
from app.models.channel_mix_run import ChannelMixRun  # noqa: F401
from app.models.dashboard_setting import DashboardSetting  # noqa: F401
from app.models.utxo_label import AddressPurpose, UtxoLabel  # noqa: F401


class _StringUUID(satypes.TypeDecorator):
    """Store Python UUIDs as 36-char strings (for SQLite compatibility)."""

    impl = satypes.String(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            return str(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return _uuid.UUID(value)
        return value


from sqlalchemy.dialects.postgresql import JSONB as _PGJSONB


def _patch_columns_eagerly() -> None:
    """Patch PGUUID/JSONB/BigInteger-PK columns at conftest-import time.

    A ``before_create`` listener fires too late once a sync test (or
    other module-load codepath) has instantiated a mapped class and
    triggered SQLAlchemy to cache a bind processor for the *original*
    column type. Walking the metadata at import time ensures every
    mapper compiles against the patched type from the first use.
    """
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            if isinstance(col.type, PGUUID):
                col.type = _StringUUID()
            elif isinstance(col.type, _PGJSONB):
                col.type = satypes.JSON()
            elif col.primary_key and col.autoincrement is True and isinstance(col.type, satypes.BigInteger):
                col.type = satypes.Integer()


_patch_columns_eagerly()


@event.listens_for(Base.metadata, "before_create")
def _patch_pg_columns_for_sqlite(target, connection, **kw):
    # Re-run the patcher so a re-loaded model module (e.g., importlib
    # reload mid-test) still gets the patched types.
    if connection.dialect.name != "sqlite":
        return
    _patch_columns_eagerly()


# ─── Guardrail test marking ───────────────────────────────────────────
#
# A handful of test modules assert on *source structure* / supply-chain
# facts (forbidden call patterns, vendored-asset SRI hashes, migration
# shape) rather than runtime behavior. They are valuable regression
# fences but contribute no meaningful ``app/`` coverage, so they run as a
# distinct CI step and are excluded from the coverage-gated behavioral
# run (``pytest -m "not guardrail"``). Marking is centralized here so the
# set is discoverable in one place and new guardrail modules only need a
# filename entry.
_GUARDRAIL_MODULES = frozenset(
    {
        "test_anonymize_static_lints.py",
        "test_anonymize_test_robustness_lint.py",
        "test_anonymize_boltz_request_shape_lint.py",
        "test_anonymize_mpp_chan_id_lint.py",
        "test_anonymize_stepup_table_invariants.py",
        "test_dashboard_static_assets.py",
    }
)


def pytest_collection_modifyitems(config, items):
    guardrail = pytest.mark.guardrail
    for item in items:
        if item.path.name in _GUARDRAIL_MODULES:
            item.add_marker(guardrail)


# ─── Test Database ────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def db_engine():
    """Create an in-memory SQLite engine for testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a fresh database session for each test."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def test_api_key(db_session: AsyncSession) -> tuple[APIKey, str]:
    """Create a regular (non-admin) API key and return (model, raw_key)."""
    raw_key = generate_api_key()
    api_key = APIKey(
        id=uuid4(),
        name="test-key",
        key_hash=hash_api_key(raw_key),
        is_admin=False,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.commit()
    await db_session.refresh(api_key)
    return api_key, raw_key


@pytest_asyncio.fixture
async def test_admin_key(db_session: AsyncSession) -> tuple[APIKey, str]:
    """Create an admin API key and return (model, raw_key)."""
    raw_key = generate_api_key()
    api_key = APIKey(
        id=uuid4(),
        name="admin-key",
        key_hash=hash_api_key(raw_key),
        is_admin=True,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.commit()
    await db_session.refresh(api_key)
    return api_key, raw_key


# ─── FastAPI Test Client ──────────────────────────────────────────────


@pytest_asyncio.fixture
async def client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an async test client with overridden DB dependency."""
    from app.main import app

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authed_client(client: AsyncClient, db_engine) -> AsyncGenerator[tuple[AsyncClient, str, str], None]:
    """Provide an async test client with a pre-created admin API key.

    Returns (client, raw_key, key_id).
    """

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async with session_factory() as session:
        raw_key = generate_api_key()
        api_key = APIKey(
            id=uuid4(),
            name="test-admin",
            key_hash=hash_api_key(raw_key),
            is_admin=True,
            is_active=True,
        )
        session.add(api_key)
        await session.commit()
        key_id = str(api_key.id)

    client.headers["Authorization"] = f"Bearer {raw_key}"
    yield client, raw_key, key_id


# ─── Reset module-level resilience state between tests ─────────────────
# Circuit breakers and ServiceHealth singletons are module-level by
# design (one per process), but each test should start with a clean
# slate so a previous test's breaker-open / consecutive-failures
# counters don't bleed into the next test.


@pytest.fixture(scope="session", autouse=True)
def _configure_celery_for_tests():
    """Switch the Celery broker to an in-memory transport for the
    whole test session.

    Without this, every test that triggers a code path which calls
    ``some_task.delay(...)`` (e.g. ``process_boltz_swap.delay`` in
    the braiins deposit service) blocks for ~20 s while Celery
    retries to reach the real Redis broker that the application
    container would normally provide. The retry budget is hardcoded
    inside kombu/celery's connection logic; the only way to skip it
    is to point Celery at a broker that doesn't need a TCP
    connection.

    ``memory://`` is the standard in-process broker shipped with
    Celery. Combined with ``task_always_eager=False`` (the default)
    the ``.delay()`` call enqueues into an in-memory queue and
    returns immediately. Tests don't actually exercise the task
    body — they only care that the call doesn't hang.
    """
    try:
        from app.tasks.boltz_tasks import celery_app
    except Exception:
        yield
        return
    original_broker = celery_app.conf.broker_url
    original_backend = celery_app.conf.result_backend
    celery_app.conf.broker_url = "memory://"
    celery_app.conf.result_backend = "cache+memory://"
    # Belt-and-suspenders: cap broker connect retries so that even
    # if some test exercises a code path that doesn't use the memory
    # broker, the retry budget is small instead of the default 20.
    celery_app.conf.broker_connection_retry = False
    celery_app.conf.broker_connection_max_retries = 0
    try:
        yield
    finally:
        celery_app.conf.broker_url = original_broker
        celery_app.conf.result_backend = original_backend


@pytest.fixture(autouse=True)
def _reset_bolt12_module_state():
    """2026-06-12: reset in-memory state on the modules added in the
    inbound-supervisor / subscriber-metrics work so tests can't
    bleed state into each other. Each module exposes a
    ``_reset_for_tests`` helper; we drive them all from one place
    so any new module that lands later only has to add a single
    entry here (plus its own helper) to be cleaned up."""
    resets = []
    for mod_path in (
        "app.services.bolt12.runtime",
        "app.services.bolt12.sticky_peer_reconciler",
        "app.services.bolt12.subscriber_metrics",
        "app.services.bolt12.subscriber_recovery",
        "app.services.bolt12.onion_only_detect",
        "app.services.bolt12.inbound_supervisor",
        "app.services.lnd_hs_descriptor_age",
        "app.services.lnd_channel_uptime",
        "app.services.lnd_channel_flap_detector",
    ):
        try:
            import importlib

            mod = importlib.import_module(mod_path)
            for attr_name in (
                "_reset_for_tests",
                "_reset_throttle_for_tests",
                "reset_cache_for_tests",
            ):
                fn = getattr(mod, attr_name, None)
                if callable(fn):
                    resets.append(fn)
        except Exception:
            pass
    for fn in resets:
        try:
            fn()
        except Exception:
            pass
    yield
    for fn in resets:
        try:
            fn()
        except Exception:
            pass


@pytest_asyncio.fixture(autouse=True)
async def _cancel_orphan_asyncio_tasks_after_test():
    """Cancel any background task the just-completed test left running
    on its event loop.

    pytest-asyncio gives each test a fresh function-scoped loop. A
    test that spawns a task (directly or via ``lifespan`` /
    ``start_bolt12_runtime``) but doesn't await its shutdown leaves
    that task pending when the loop is torn down. The task often
    holds an aiosqlite ``Connection``; its ``__del__`` then fires
    during a *later* test and surfaces as a
    ``PytestUnraisableExceptionWarning`` attributed to the wrong
    test (the bolt12 runtime pool and the telemetry settle-watchdog
    pool are the usual culprits). Cancelling orphans here keeps the
    leak from crossing the test boundary.
    """
    yield
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    current = asyncio.current_task()
    pending = [t for t in asyncio.all_tasks(loop) if t is not current and not t.done()]
    if not pending:
        return
    for task in pending:
        task.cancel()
    # Give the cancellations one round-trip to propagate so the
    # tasks' ``finally`` blocks (which close clients / connections)
    # actually run before the loop is destroyed.
    try:
        await asyncio.gather(*pending, return_exceptions=True)
    except Exception:  # noqa: BLE001 — teardown best-effort
        pass


@pytest.fixture(autouse=True)
def _restore_app_main_logger():
    """Restore ``app.main.logger`` to the real logger before each test.

    ``lifespan`` resolves ``logger`` by name at call time, so a prior
    test whose ``patch("app.main.logger")`` context leaked (unclosed
    patch, or a manual start/stop that raised mid-way) would leave a
    stale mock bound to ``app.main.logger``. The next test's own
    ``patch`` would then replace that stale mock instead of the real
    logger, and its ``mock_logger.warning.call_args_list`` reads
    empty — exactly the ``test_lifespan_warns_remote_db_without_ssl``
    flake. Restoring before the test runs makes each test start from
    a known-good logger regardless of prior leaks.
    """
    import logging
    import sys

    # Only act when app.main is already imported — don't drag the full
    # FastAPI app into pure-unit tests that never touch it.
    app_main = sys.modules.get("app.main")
    if app_main is None:
        yield
        return
    saved = app_main.logger
    app_main.logger = logging.getLogger("app.main")
    try:
        yield
    finally:
        app_main.logger = saved


@pytest.fixture(autouse=True)
def _disable_bolt12_subscriber_lnd_probes(monkeypatch):
    """2026-06-12: the subscriber loops added two new pre-flight
    LND calls: the S4 warmup probe (``get_info`` before each stream
    open) and the S2 onion-only auto-detect (also ``get_info``).
    In a unit test where neither LND nor a mocked subscriber stops
    the loop, both probes hit a real ``get_info`` that has its own
    10 s timeout — combined with the heartbeat task that ALSO calls
    audit emit, the whole stack can hang the test for tens of
    seconds. Disable both by default for ALL unit tests; tests that
    specifically exercise these surfaces re-enable them via
    ``monkeypatch`` in their own setup."""
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_auto_detect",
        False,
    )
    # Also keep the heartbeat audit emit out of the picture by
    # default — its spawn loop in runtime.py would otherwise fire
    # _audit_inbound on every interval tick and the per-tick
    # try/except gets exercised on every unit test that touches
    # the runtime.
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_heartbeat_interval_s",
        0,
    )


@pytest.fixture(autouse=True)
def _reset_resilience_state():
    """Reset all registered ServiceHealth + their breakers before each test."""
    try:
        from app.services.health import all_health
    except Exception:
        yield
        return

    for h in all_health():
        h.last_success_at = None
        h.last_error = None
        h.consecutive_failures = 0
        h.extra.clear()
        if h.breaker is not None:
            h.breaker.state = "closed"
            h.breaker.consecutive_failures = 0
            h.breaker.opened_at = None
            h.breaker.last_error = None
            h.breaker.last_success_at = None
            h.breaker.last_failure_at = None
            if h.breaker._lock.locked():
                try:
                    h.breaker._lock.release()
                except RuntimeError:
                    pass
    # Reset module-level concurrency state too.
    try:
        from app.core.concurrency import _reset_for_tests as _reset_concurrency

        _reset_concurrency()
    except Exception:
        pass
    yield


@pytest_asyncio.fixture(autouse=True)
async def _dispose_app_engines_after_test():
    """Drop any per-event-loop engines populated during the test.

    ``app.core.database`` keeps a process-wide ``_engines`` map keyed
    by ``id(event_loop)`` so Celery workers and FastAPI handlers can
    share their own loops' engines. In tests, code paths that call
    ``get_engine()`` (notably the BOLT 12 responder's
    ``_audit_inbound`` via ``get_db_context``) populate this map on
    each test's loop. The loop dies with the test but the entry
    persists; the underlying aiosqlite engine keeps a non-daemon
    worker thread alive. Once enough tests stack up these orphan
    threads, the interpreter hangs at shutdown waiting for them to
    finish — and the next test that triggers any cross-loop database
    access can deadlock.

    Dispose-and-clear after every test keeps the map drained.
    """
    yield
    try:
        from app.core.database import _engines, _session_makers

        loop_id = id(asyncio.get_running_loop())
        engine = _engines.pop(loop_id, None)
        _session_makers.pop(loop_id, None)
        if engine is not None:
            try:
                await engine.dispose()
            except Exception:
                pass
    except Exception:
        pass
