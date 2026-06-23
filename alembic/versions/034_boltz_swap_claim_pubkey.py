# SPDX-License-Identifier: MIT
"""Add boltz_claim_public_key_hex to boltz_swaps.

Revision ID: 034_boltz_swap_claim_pubkey
Revises: 033_braiins_deposit_include_extras
Create Date: 2026-05-23 00:00:00.000000

The cooperative submarine-refund flow requires Boltz's side of the
Musig2 key set (Boltz's claim public key). We weren't persisting it
on submarine swap creation, which left existing stuck swaps with no
way to perform a cooperative refund without re-fetching the swap
state from Boltz first. New column is NULLable; the refund flow
falls back to a live ``GET /swap/submarine/{id}`` lookup when the
column is empty (recovery path for swaps created before this
migration).
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "034_boltz_swap_claim_pubkey"
down_revision: Union[str, None] = "033_braiins_deposit_include_extras"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "boltz_swaps",
        sa.Column(
            "boltz_claim_public_key_hex",
            sa.String(length=66),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("boltz_swaps", "boltz_claim_public_key_hex")
