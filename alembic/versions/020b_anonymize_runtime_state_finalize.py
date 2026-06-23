# SPDX-License-Identifier: MIT
"""anonymize_runtime_state — finalize encrypted value (step B of 2).

Revision ID: 020b_anonymize_runtime_state_finalize
Revises: 020a_anonymize_runtime_state_add_enc_column
Create Date: 2026-05-10 00:00:04.000000

Step B of the two-step migration. Runs *after* the application
has had time to re-write rows through the new ``value_enc`` path on
020a. This step:

1. Deletes any rows still cleartext (``value_enc IS NULL``). Every
   key in :data:`ANONYMIZE_RUNTIME_STATE_KEYS` is application state
   that the reader treats a missing row as the empty/initial state
   (HWMs default to 0, allow-lists default to empty, rotation
   timestamps to "never"). Dropping the stale cleartext rows is
   therefore equivalent to a no-op from the application's
   perspective and unblocks the column rename below.
2. Drops the legacy ``value`` column.
3. Renames ``value_enc`` → ``value`` so the application's stable
   read path survives the rename. Drops ``encrypted_at`` (the
   ``updated_at`` column already records last-write time).
4. Sets the new ``value`` column to NOT NULL.

If a downgrade is required, it re-adds the legacy
cleartext column. Operators are expected to have a separate path
(application-level decrypt + write) for restoring cleartext.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "020b_anonymize_runtime_state_finalize"
down_revision: Union[str, None] = "020a_anonymize_runtime_state_add_enc_column"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove any rows that never got encrypted. See module docstring:
    # all known runtime-state keys treat missing rows as the initial
    # state, so the delete is observationally equivalent to a no-op.
    op.execute(sa.text("DELETE FROM anonymize_runtime_state WHERE value_enc IS NULL"))

    op.drop_column("anonymize_runtime_state", "value")
    op.alter_column(
        "anonymize_runtime_state",
        "value_enc",
        new_column_name="value",
        existing_type=sa.LargeBinary(),
        nullable=False,
    )
    op.drop_column("anonymize_runtime_state", "encrypted_at")


def downgrade() -> None:
    # Restore the legacy cleartext column. The encrypted column keeps
    # its data; the cleartext column will be NULL until application-level
    # backfill runs.
    op.alter_column(
        "anonymize_runtime_state",
        "value",
        new_column_name="value_enc",
        existing_type=sa.LargeBinary(),
        nullable=True,
    )
    op.add_column(
        "anonymize_runtime_state",
        sa.Column(
            "value",
            sa.LargeBinary(),
            nullable=True,
        ),
    )
    op.add_column(
        "anonymize_runtime_state",
        sa.Column(
            "encrypted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
