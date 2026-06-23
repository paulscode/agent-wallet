# SPDX-License-Identifier: MIT
"""Add lockup/claim broadcast timestamps to boltz_swaps.

Revision ID: 037_boltz_swap_broadcast_timestamps
Revises: 036_liquid_residual_outputs
Create Date: 2026-06-01 00:00:00.000000

The recovery classifier needs to know HOW LONG a tx has been in the
mempool before recommending a fee bump. We were stamping
``updated_at`` on every state transition, but that doesn't tell us
when the lockup / claim tx was first broadcast — it just tells us
when we last saw a status update. Two dedicated nullable columns:

* ``lockup_broadcast_at`` — stamped when the wallet broadcasts the
  submarine lockup OR when the reverse-swap observer first sees
  Boltz's lockup land in the mempool.
* ``claim_broadcast_at`` — stamped when the wallet broadcasts a
  reverse-swap claim (or Boltz broadcasts a submarine claim).

Both are nullable so existing rows survive without backfill; the
classifier's bump-fee recommendation is a strict opt-in (no
timestamp → no recommendation).
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "037_boltz_swap_broadcast_timestamps"
down_revision: Union[str, None] = "036_liquid_residual_outputs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "boltz_swaps",
        sa.Column("lockup_broadcast_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "boltz_swaps",
        sa.Column("claim_broadcast_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("boltz_swaps", "claim_broadcast_at")
    op.drop_column("boltz_swaps", "lockup_broadcast_at")
