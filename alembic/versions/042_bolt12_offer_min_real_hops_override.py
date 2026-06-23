# SPDX-License-Identifier: MIT
"""Add ``min_real_hops_override`` to ``bolt12_offers``.

Revision ID: 042_bolt12_offer_min_real_hops_override
Revises: 041_bolt12_blinded_paths_summary
Create Date: 2026-06-06 14:00:00.000000

Per-offer override for the global
``BOLT12_BLINDED_PATH_MIN_REAL_HOPS`` setting. ``NULL`` means
"use the global value". Set to ``1`` for offers where blinded-
path privacy isn't needed (Ocean payouts, B2B, LSP) so the
intermediate hop — where the 2026-06-06 Ocean failure occurred —
is eliminated in exchange for revealing our direct peer as the
reply intro.

Auto-set at offer-issuance time when the description matches a
well-known payer with ``requires_privacy=False`` (Ocean).
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "042_bolt12_offer_min_real_hops_override"
down_revision: Union[str, None] = "041_bolt12_blinded_paths_summary"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("bolt12_offers") as batch_op:
        batch_op.add_column(
            sa.Column(
                "min_real_hops_override",
                sa.Integer(),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("bolt12_offers") as batch_op:
        batch_op.drop_column("min_real_hops_override")
