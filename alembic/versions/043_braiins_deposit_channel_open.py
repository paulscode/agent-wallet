# SPDX-License-Identifier: MIT
"""Braiins Deposit channel-open alternative (swap-bypass).

Revision ID: 043_braiins_deposit_channel_open
Revises: 042_bolt12_offer_min_real_hops_override
Create Date: 2026-06-16 12:00:00.000000

Adds the channel-open funding strategy for on-chain Braiins deposits:

* ``opening_channel`` value in the ``braiins_deposit_status`` enum.
* ``funding_strategy`` enum column (``swap`` | ``channel``) defaulting to
  ``swap`` so existing rows keep the submarine behaviour.
* ``channel_*`` columns tracking the freshly-opened channel.

All columns are nullable / safe-defaulted, so the migration is
backward-compatible and the swap path is untouched.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "043_braiins_deposit_channel_open"
down_revision: Union[str, None] = "042_bolt12_offer_min_real_hops_override"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_FUNDING_STRATEGY_VALUES = ("swap", "channel")


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    # New status value. PG needs ALTER TYPE; SQLite rebuilds the
    # CHECK constraint when the enum column is next recreated.
    if is_pg:
        op.execute("ALTER TYPE braiins_deposit_status ADD VALUE IF NOT EXISTS 'opening_channel'")

    # New funding-strategy enum type (PG) / CHECK-constrained VARCHAR (SQLite).
    funding_strategy_enum = sa.Enum(
        *_FUNDING_STRATEGY_VALUES,
        name="braiins_deposit_funding_strategy",
        native_enum=is_pg,
    )
    if is_pg:
        funding_strategy_enum.create(bind, checkfirst=True)

    with op.batch_alter_table("braiins_deposit_sessions") as batch:
        batch.add_column(
            sa.Column(
                "funding_strategy",
                funding_strategy_enum,
                nullable=False,
                server_default="swap",
            )
        )
        batch.add_column(sa.Column("channel_peer_pubkey", sa.String(66), nullable=True))
        batch.add_column(sa.Column("channel_open_txid", sa.String(64), nullable=True))
        batch.add_column(sa.Column("channel_open_output_index", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("channel_capacity_sats", sa.BigInteger(), nullable=True))

    # Reverse-swap first-hop pin (Braiins channel-open drains its new
    # channel). NULL for every other caller.
    op.add_column(
        "boltz_swaps",
        sa.Column("outgoing_chan_id", sa.String(32), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("boltz_swaps", "outgoing_chan_id")
    with op.batch_alter_table("braiins_deposit_sessions") as batch:
        batch.drop_column("channel_capacity_sats")
        batch.drop_column("channel_open_output_index")
        batch.drop_column("channel_open_txid")
        batch.drop_column("channel_peer_pubkey")
        batch.drop_column("funding_strategy")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="braiins_deposit_funding_strategy").drop(bind, checkfirst=True)
    # NOTE: PostgreSQL can't drop an enum value without rewriting the type.
    # ``opening_channel`` stays in ``braiins_deposit_status`` after downgrade
    # — harmless since no row should reference it.
