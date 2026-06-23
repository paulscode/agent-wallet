# SPDX-License-Identifier: MIT
"""Audit-chain signed high-water state.

Revision ID: 047_audit_chain_high_water
Revises: 046_liquid_residual_recovered_swap_unique
Create Date: 2026-06-21 00:00:00.000000

Adds a single-row ``audit_chain_state`` table holding the authorized
audit row count and head hash, signed with the SECRET_KEY-derived chain
key. The chain verifier compares the live row count against this recorded
count to detect removal of the newest rows (tail-truncation), which the
keyed row-hash walk alone cannot see.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "047_audit_chain_high_water"
down_revision: Union[str, None] = "046_liquid_residual_recovered_swap_unique"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.SmallInteger(), primary_key=True),
        sa.Column("entry_count", sa.BigInteger(), nullable=False),
        sa.Column("head_hash", sa.Text(), nullable=True),
        sa.Column("state_hmac", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_audit_chain_state_singleton"),
    )
    # The row is bootstrapped lazily on the next audit append (the
    # application computes the keyed signature from SECRET_KEY at that
    # point), so no seed row is inserted here.


def downgrade() -> None:
    op.drop_table("audit_chain_state")
