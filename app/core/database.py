# SPDX-License-Identifier: MIT
"""
Database engine and session management.

Uses async SQLAlchemy with asyncpg for PostgreSQL.
Supports per-event-loop engine isolation for Celery workers.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = logging.getLogger(__name__)

# Per-event-loop engine isolation (needed for Celery workers)
_engines: dict[int, AsyncEngine] = {}
_session_makers: dict[int, async_sessionmaker] = {}

# Public alias so shutdown hooks (main.py lifespan) can dispose all engines
engine_registry = _engines


def _get_loop_id() -> int:
    """Get a unique id for the current event loop."""
    try:
        loop = asyncio.get_running_loop()
        return id(loop)
    except RuntimeError:
        return 0


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


def _create_engine() -> AsyncEngine:
    """Create a new async engine."""
    url = settings.database_url
    is_sqlite = url.startswith("sqlite")
    if is_sqlite:
        # SQLite's default StaticPool does not accept pool_size/
        # max_overflow; production-only knobs are skipped.
        return create_async_engine(url, echo=settings.debug)
    connect_args: dict = {
        "server_settings": {
            "statement_timeout": "30000",
            # Safety net for sessions that get abandoned mid-
            # transaction (e.g. a coroutine that holds the connection
            # across a blocking subprocess + then the event loop is
            # torn down, or an HTTP call that hangs past the SQLAlchemy
            # pool_timeout). Without this, the connection sits at
            # Postgres in ``idle in transaction`` forever — eventually
            # exhausting the pool (size 10 + overflow 20). 5 min is
            # long enough to outlast any legitimate awaited operation
            # (LND HTTP 30s + Boltz HTTP 30s + node subprocess 120s).
            "idle_in_transaction_session_timeout": "300000",
        }
    }
    if settings.database_require_ssl:
        import ssl as _ssl

        ctx = _ssl.create_default_context()
        connect_args["ssl"] = ctx
    return create_async_engine(
        url,
        echo=settings.debug,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=300,
        connect_args=connect_args,
    )


def get_engine() -> AsyncEngine:
    """Get or create engine for the current event loop."""
    loop_id = _get_loop_id()
    if loop_id not in _engines:
        _engines[loop_id] = _create_engine()
    return _engines[loop_id]


def get_session_maker() -> async_sessionmaker[AsyncSession]:
    """Get or create session maker for the current event loop."""
    loop_id = _get_loop_id()
    if loop_id not in _session_makers:
        engine = get_engine()
        _session_makers[loop_id] = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return _session_makers[loop_id]


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield an async database session."""
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for database sessions (used in Celery tasks)."""
    session_maker = get_session_maker()
    async with session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
