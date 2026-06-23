# SPDX-License-Identifier: MIT
"""Single-sweep guard for Liquid residual recovery.

Revision ID: 046_liquid_residual_recovered_swap_unique
Revises: 045_api_key_scope
Create Date: 2026-06-21 00:00:00.000000

A residual L-BTC output is swept by exactly one submarine swap. A
partial unique index on ``liquid_residual_outputs.recovered_swap_id``
(where non-NULL) makes a second stamp a hard database error rather than
a silent second lock spend of the same UTXO.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "046_liquid_residual_recovered_swap_unique"
down_revision: Union[str, None] = "045_api_key_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        "uq_liquid_residual_recovered_swap_id",
        "liquid_residual_outputs",
        ["recovered_swap_id"],
        unique=True,
        postgresql_where="recovered_swap_id IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_index(
        "uq_liquid_residual_recovered_swap_id",
        table_name="liquid_residual_outputs",
    )
