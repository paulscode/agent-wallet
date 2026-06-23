# SPDX-License-Identifier: MIT
"""
Alembic environment configuration for async SQLAlchemy.
"""

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from app.core.config import settings
from app.core.database import Base

# Import all models so Alembic sees them
from app.models.api_key import APIKey  # noqa: F401
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
from app.models.utxo_label import AddressPurpose, UtxoLabel  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — generates SQL script."""
    url = settings.database_url.replace("+asyncpg", "+psycopg2")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


_ALEMBIC_VERSION_COLUMN_WIDTH = 128


def _ensure_alembic_version_column_width(connection) -> None:
    # Alembic's default ``alembic_version.version_num`` is ``VARCHAR(32)``,
    # but several anonymize revision IDs exceed 32 chars (longest is 43).
    # Pre-create the table with the wider column for fresh databases, and
    # widen the column for existing deployments. Both statements are safe
    # to run on every migration pass.
    connection.execute(
        text(
            "CREATE TABLE IF NOT EXISTS alembic_version ("
            f"version_num VARCHAR({_ALEMBIC_VERSION_COLUMN_WIDTH}) NOT NULL, "
            "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
        )
    )
    connection.execute(
        text(f"ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR({_ALEMBIC_VERSION_COLUMN_WIDTH})")
    )


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        # Widen ``alembic_version.version_num`` inside Alembic's own
        # transaction so it commits with the rest of the upgrade. Running
        # this before ``begin_transaction`` autobegins a separate sync
        # transaction that the async wrapper rolls back on dispose,
        # silently undoing every migration that just ran.
        _ensure_alembic_version_column_width(connection)
        context.run_migrations()


async def run_async_migrations():
    """Run migrations in 'online' mode with async engine."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.database_url
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
