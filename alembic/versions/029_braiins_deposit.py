# SPDX-License-Identifier: MIT
"""Add braiins_deposit_sessions table.

Revision ID: 029_braiins_deposit
Revises: 028_audit_logs_api_key_id_nullable
Create Date: 2026-05-18 14:00:00.000000

Backs the Braiins Deposit feature. A session row drives the
3-leg pipeline: pay a Boltz reverse-swap invoice from our LN balance
→ receive a fresh on-chain UTXO at a freshly-minted P2TR address →
send the requested round amount from that UTXO to the user-supplied
Braiins destination.

Each row links to a ``boltz_swaps`` row via ``boltz_swap_id`` so the
state machine can read ``BoltzSwap.status`` and ``claim_txid``
without duplicating that data.

The destination address is public chain data and the round-amount /
fresh-UTXO outpoint are not sensitive, so columns are plaintext —
no Fernet field encryption on this table.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from alembic import op

revision: str = "029_braiins_deposit"
down_revision: Union[str, None] = "028_audit_logs_api_key_id_nullable"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_STATUS_VALUES = (
    "created",
    "swapping",
    "funded",
    "sending",
    "broadcast",
    "completed",
    "refunded",
    "failed",
    "cancelled",
)


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    uuid_type: sa.types.TypeEngine = PGUUID(as_uuid=True) if is_pg else sa.String(36)

    op.create_table(
        "braiins_deposit_sessions",
        sa.Column("id", uuid_type, primary_key=True),
        sa.Column("api_key_id", uuid_type, nullable=False),
        # User-facing parameters (frozen at create time).
        sa.Column("deposit_amount_sats", sa.BigInteger(), nullable=False),
        sa.Column("destination_address", sa.String(128), nullable=False),
        # Resources we mint as the session runs.
        sa.Column("fresh_address", sa.String(128), nullable=True),
        sa.Column(
            "boltz_swap_id",
            uuid_type,
            sa.ForeignKey("boltz_swaps.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("fresh_utxo_txid", sa.String(64), nullable=True),
        sa.Column("fresh_utxo_vout", sa.Integer(), nullable=True),
        sa.Column("fresh_utxo_amount_sats", sa.BigInteger(), nullable=True),
        sa.Column("send_txid", sa.String(64), nullable=True),
        sa.Column("send_confirmations", sa.Integer(), nullable=True),
        sa.Column("broadcast_block_height", sa.Integer(), nullable=True),
        # State machine.
        sa.Column(
            "status",
            sa.Enum(
                *_STATUS_VALUES,
                name="braiins_deposit_status",
                native_enum=is_pg,
            ),
            nullable=False,
            server_default="created",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("status_history", sa.JSON(), nullable=True),
        # Timestamps.
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_braiins_deposit_sessions_api_key_id_status",
        "braiins_deposit_sessions",
        ["api_key_id", "status"],
    )
    op.create_index(
        "ix_braiins_deposit_sessions_status",
        "braiins_deposit_sessions",
        ["status"],
    )
    op.create_index(
        "ix_braiins_deposit_sessions_boltz_swap_id",
        "braiins_deposit_sessions",
        ["boltz_swap_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_braiins_deposit_sessions_boltz_swap_id",
        table_name="braiins_deposit_sessions",
    )
    op.drop_index(
        "ix_braiins_deposit_sessions_status",
        table_name="braiins_deposit_sessions",
    )
    op.drop_index(
        "ix_braiins_deposit_sessions_api_key_id_status",
        table_name="braiins_deposit_sessions",
    )
    op.drop_table("braiins_deposit_sessions")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="braiins_deposit_status").drop(bind, checkfirst=True)
