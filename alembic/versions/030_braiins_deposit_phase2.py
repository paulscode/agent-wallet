# SPDX-License-Identifier: MIT
"""Braiins Deposit: add submarine-swap (on-chain) source path.

Revision ID: 030_braiins_deposit_phase2
Revises: 029_braiins_deposit
Create Date: 2026-05-18 16:00:00.000000

Extends the Lightning self-source schema with on-chain source
support. Adds:

* ``source_kind`` enum column (``lightning`` | ``onchain``) with
  ``lightning`` default to keep existing Lightning rows valid.
* ``submarine_*`` columns tracking the leading submarine-swap leg.
* ``submarine_swapping`` value in the ``braiins_deposit_status`` enum.

The Postgres enum-value add must happen outside a transaction —
Alembic auto-enables transactional DDL by default, so we use
``op.execute("ALTER TYPE … ADD VALUE …")`` which is safe inside a
transaction starting with PG12+. (We target PG15+ in production.)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from alembic import op

revision: str = "030_braiins_deposit_phase2"
down_revision: Union[str, None] = "029_braiins_deposit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_SOURCE_KIND_VALUES = ("lightning", "onchain")


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"
    uuid_type: sa.types.TypeEngine = PGUUID(as_uuid=True) if is_pg else sa.String(36)

    # New status value. PG needs ALTER TYPE; SQLite recreates the
    # check constraint implicitly when the column's enum is rebuilt.
    if is_pg:
        # IF NOT EXISTS makes the migration idempotent across crash
        # recovery during deploys.
        op.execute("ALTER TYPE braiins_deposit_status ADD VALUE IF NOT EXISTS 'submarine_swapping'")

    # New source-kind enum type. PG creates a dedicated type; on
    # SQLite the column is a CHECK-constrained VARCHAR.
    source_kind_enum = sa.Enum(
        *_SOURCE_KIND_VALUES,
        name="braiins_deposit_source_kind",
        native_enum=is_pg,
    )
    if is_pg:
        source_kind_enum.create(bind, checkfirst=True)

    with op.batch_alter_table("braiins_deposit_sessions") as batch:
        batch.add_column(
            sa.Column(
                "source_kind",
                source_kind_enum,
                nullable=False,
                server_default="lightning",
            )
        )
        batch.add_column(
            sa.Column(
                "submarine_boltz_swap_id",
                uuid_type,
                sa.ForeignKey("boltz_swaps.id", ondelete="SET NULL"),
                nullable=True,
            )
        )
        batch.add_column(sa.Column("submarine_lockup_address", sa.String(128), nullable=True))
        batch.add_column(sa.Column("submarine_lockup_amount_sats", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("submarine_funding_txid", sa.String(64), nullable=True))
        batch.add_column(sa.Column("submarine_payment_hash_hex", sa.String(64), nullable=True))

    op.create_index(
        "ix_braiins_deposit_sessions_submarine_boltz_swap_id",
        "braiins_deposit_sessions",
        ["submarine_boltz_swap_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_braiins_deposit_sessions_submarine_boltz_swap_id",
        table_name="braiins_deposit_sessions",
    )
    with op.batch_alter_table("braiins_deposit_sessions") as batch:
        batch.drop_column("submarine_payment_hash_hex")
        batch.drop_column("submarine_funding_txid")
        batch.drop_column("submarine_lockup_amount_sats")
        batch.drop_column("submarine_lockup_address")
        batch.drop_column("submarine_boltz_swap_id")
        batch.drop_column("source_kind")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="braiins_deposit_source_kind").drop(bind, checkfirst=True)
    # NOTE: PostgreSQL does not support removing enum values without
    # rewriting the type. ``submarine_swapping`` stays in the enum
    # after downgrade — harmless since no row should reference it.
