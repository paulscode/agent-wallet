# SPDX-License-Identifier: MIT
"""anonymize_session — persist claim_txid + confirmation/reorg counters.

Revision ID: 022_anonymize_session_claim_tx_columns
Revises: 021_anonymize_stepup_state
Create Date: 2026-05-10 00:00:06.000000

The reorg-aware completion path reads
``claim_tx_confirmations`` and ``claim_tx_reorg_observed_count`` from
the session row to decide the ``CONFIRMING → COMPLETED`` /
``CONFIRMING → COMPLETED_WITH_REORG_UNCERTAINTY`` transitions. Both
values were previously held as transient Python attributes and were
not durable across process restarts; this migration backs them with
real columns.

``claim_txid`` is added alongside so the chain-poll tick can identify
the on-chain tx without re-decoding the cached ``claim_tx_hex``
every tick. (The hex remains the source-of-truth for re-broadcast;
the txid is a derived index.)

All three columns default to NULL / 0; existing rows are not affected.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "022_anonymize_session_claim_tx_columns"
down_revision: Union[str, None] = "021_anonymize_stepup_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "anonymize_session",
        sa.Column("claim_txid", sa.String(64), nullable=True),
    )
    op.add_column(
        "anonymize_session",
        sa.Column(
            "claim_tx_confirmations",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "anonymize_session",
        sa.Column(
            "claim_tx_reorg_observed_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("anonymize_session", "claim_tx_reorg_observed_count")
    op.drop_column("anonymize_session", "claim_tx_confirmations")
    op.drop_column("anonymize_session", "claim_txid")
