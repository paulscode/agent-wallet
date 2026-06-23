# SPDX-License-Identifier: MIT
"""Add lockup_txid column to boltz_swaps.

Revision ID: 038_boltz_swap_lockup_txid
Revises: 037_boltz_swap_broadcast_timestamps
Create Date: 2026-05-26 00:00:00.000000

The submarine-direction fee-bump path (RBF on a wallet-broadcast
lockup tx) needs a stable handle on the lockup outpoint. We were
tracking the txid in ``BraiinsDepositSession.submarine_funding_txid``
only — invisible to the cold-storage / anonymize submarine flows
and not joinable to the swap row. One nullable column on the swap
row, stamped at every wallet broadcast site, makes the manual
fee-bump endpoint direction-aware without further plumbing.

Nullable so legacy rows survive — the endpoint validates presence
before invoking LND BumpFee.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "038_boltz_swap_lockup_txid"
down_revision: Union[str, None] = "037_boltz_swap_broadcast_timestamps"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "boltz_swaps",
        sa.Column("lockup_txid", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("boltz_swaps", "lockup_txid")
