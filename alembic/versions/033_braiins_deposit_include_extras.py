# SPDX-License-Identifier: MIT
"""Braiins Deposit per-session ``include_extras`` flag.

Revision ID: 033_braiins_deposit_include_extras
Revises: 032_braiins_deposit_dust_prevention
Create Date: 2026-05-22 12:00:00.000000

Adds ``include_extras`` to ``braiins_deposit_sessions``. When true
(default), the wallet broadcasts the dust-safe NO-CHANGE send tx
that absorbs any extras from the fresh UTXO into the deposit
output. When false, the wallet uses LND coin-selection to send
exactly ``deposit_amount_sats`` and return the remainder as a
change UTXO (which may be economically unspendable at high fees
— surfaced to the user via an info bubble in the wizard).

Column is NOT NULL with a server default of TRUE so existing rows
are backfilled to the dust-safe (pre-feature) behavior.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "033_braiins_deposit_include_extras"
down_revision: Union[str, None] = "032_braiins_deposit_dust_prevention"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "braiins_deposit_sessions",
        sa.Column(
            "include_extras",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("braiins_deposit_sessions", "include_extras")
