# SPDX-License-Identifier: MIT
"""anonymize_session_output — multi-output session row (multi-output / external-source sessions).

Revision ID: 027_anonymize_session_output
Revises: 026_anonymize_liquid_blinding_seed
Create Date: 2026-05-11 00:00:01.000000

Multi-output sessions ("split into 3 outputs of varying
amounts") produce N base-layer outputs per session. The per-output
row carries its own ``destination_address_enc``, ``bin_amount_sat``,
``scheduled_at_unix_s`` (the randomized egress timestamp), and the
 reuse-detection hash so each output is independently
gc-redactable + audit-trackable.

Single-output sessions continue to populate the singular columns on
``anonymize_session``; multi-output sessions write the per-output
rows here and use the singular columns as the index-0 mirror so
existing read-paths stay compatible.

The unique ``(session_id, output_index)`` index prevents accidental
duplicate inserts mid-pipeline.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "027_anonymize_session_output"
down_revision: Union[str, None] = "026_anonymize_liquid_blinding_seed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "anonymize_session_output",
        sa.Column(
            "id",
            sa.BigInteger(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "session_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "anonymize_session.id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column("output_index", sa.Integer(), nullable=False),
        sa.Column(
            "destination_address_enc",
            sa.LargeBinary(),
            nullable=False,
        ),
        sa.Column(
            "destination_script_type",
            sa.Text(),
            nullable=False,
        ),
        sa.Column("bin_amount_sat", sa.BigInteger(), nullable=False),
        sa.Column("scheduled_at_unix_s", sa.Float(), nullable=True),
        sa.Column("output_txid", sa.Text(), nullable=True),
        sa.Column("output_vout", sa.Integer(), nullable=True),
        sa.Column(
            "destination_address_blake2b_keyed",
            sa.LargeBinary(),
            nullable=False,
        ),
        sa.Column(
            "destination_reuse_key_generation",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "destination_address_redacted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "session_id",
            "output_index",
            name="uq_anonymize_session_output_session_index",
        ),
        sa.CheckConstraint(
            "output_index >= 0",
            name="ck_anonymize_session_output_index_nonneg",
        ),
        sa.CheckConstraint(
            "bin_amount_sat > 0",
            name="ck_anonymize_session_output_bin_amount_positive",
        ),
    )
    op.create_index(
        "ix_anonymize_session_output_session_id",
        "anonymize_session_output",
        ["session_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_anonymize_session_output_session_id",
        table_name="anonymize_session_output",
    )
    op.drop_table("anonymize_session_output")
