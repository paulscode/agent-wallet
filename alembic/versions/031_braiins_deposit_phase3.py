# SPDX-License-Identifier: MIT
"""Braiins Deposit: external (user-funded) sources.

Revision ID: 031_braiins_deposit_phase3
Revises: 030_braiins_deposit_phase2
Create Date: 2026-05-18 18:00:00.000000

Extends the on-chain self-source schema with **external source**
support. Adds:

* Two new ``braiins_deposit_status`` enum values:
    - ``awaiting_ln_funds`` — Boltz reverse-swap invoice surfaced to the
      user; we are polling Boltz for invoice settlement.
    - ``awaiting_onchain_funds`` — fresh P2TR address surfaced to the
      user; we are polling LND for incoming deposits.

* Two new ``braiins_deposit_source_kind`` enum values:
    - ``ext_lightning`` — funds come from a Lightning wallet other than
      this Agent Wallet (user pays Boltz's invoice directly).
    - ``ext_onchain`` — funds come from a Bitcoin wallet other than
      this Agent Wallet (user sends to a fresh P2TR address).

* External-intake columns on ``braiins_deposit_sessions``:
    - ``ext_intake_address`` (ext-OC only)
    - ``ext_intake_amount_sats``
    - ``ext_intake_received_sats``
    - ``ext_intake_txids`` (JSON list)
    - ``ext_funds_received_at`` (UTC timestamp)
    - ``refund_address``
    - ``refund_txid``

All new columns are nullable so existing rows are unaffected. The
enum-value adds use ``ALTER TYPE ... ADD VALUE IF NOT EXISTS`` on
PostgreSQL (transaction-safe from PG12+) and are no-ops on SQLite
(check-constrained string columns are rebuilt on next attach).
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "031_braiins_deposit_phase3"
down_revision: Union[str, None] = "030_braiins_deposit_phase2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    if is_pg:
        # New status values. IF NOT EXISTS keeps the migration
        # idempotent across crash recovery during deploys.
        op.execute("ALTER TYPE braiins_deposit_status ADD VALUE IF NOT EXISTS 'awaiting_ln_funds'")
        op.execute("ALTER TYPE braiins_deposit_status ADD VALUE IF NOT EXISTS 'awaiting_onchain_funds'")
        # New source-kind values.
        op.execute("ALTER TYPE braiins_deposit_source_kind ADD VALUE IF NOT EXISTS 'ext_lightning'")
        op.execute("ALTER TYPE braiins_deposit_source_kind ADD VALUE IF NOT EXISTS 'ext_onchain'")

    with op.batch_alter_table("braiins_deposit_sessions") as batch:
        batch.add_column(sa.Column("ext_intake_address", sa.String(128), nullable=True))
        batch.add_column(sa.Column("ext_intake_amount_sats", sa.BigInteger(), nullable=True))
        batch.add_column(
            sa.Column(
                "ext_intake_received_sats",
                sa.BigInteger(),
                nullable=True,
                server_default="0",
            )
        )
        batch.add_column(sa.Column("ext_intake_txids", sa.JSON(), nullable=True))
        batch.add_column(
            sa.Column(
                "ext_funds_received_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )
        batch.add_column(sa.Column("refund_address", sa.String(128), nullable=True))
        batch.add_column(sa.Column("refund_txid", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("braiins_deposit_sessions") as batch:
        batch.drop_column("refund_txid")
        batch.drop_column("refund_address")
        batch.drop_column("ext_funds_received_at")
        batch.drop_column("ext_intake_txids")
        batch.drop_column("ext_intake_received_sats")
        batch.drop_column("ext_intake_amount_sats")
        batch.drop_column("ext_intake_address")
    # NOTE: PostgreSQL does not support removing enum values without
    # rewriting the type. ``awaiting_ln_funds``, ``awaiting_onchain_funds``,
    # ``ext_lightning``, and ``ext_onchain`` stay in the enum after
    # downgrade — harmless since the columns referencing them are gone.
