# SPDX-License-Identifier: MIT
"""anonymize_session — liquid_blinding_seed_enc column.

Revision ID: 026_anonymize_liquid_blinding_seed
Revises: 025_anonymize_distinct_operator_ids_check
Create Date: 2026-05-11 00:00:00.000000

Per-session Liquid blinding-derivation index recorded as a
Fernet-encrypted blob so a DB-snapshot adversary cannot enumerate
Liquid hops by walking the derivation index.

The column is nullable and defaults to NULL: Lightning and on-chain self-source
sessions (no Liquid hop) leave the column unset.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "026_anonymize_liquid_blinding_seed"
down_revision: Union[str, None] = "025_anonymize_distinct_operator_ids_check"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "anonymize_session",
        sa.Column(
            "liquid_blinding_seed_enc",
            sa.LargeBinary(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("anonymize_session", "liquid_blinding_seed_enc")
