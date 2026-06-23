# SPDX-License-Identifier: MIT
"""anonymize_runtime_state — add encrypted value column (step A of 2).

Revision ID: 020a_anonymize_runtime_state_add_enc_column
Revises: 019_anonymize_k_decrement_counter
Create Date: 2026-05-10 00:00:03.000000

Encrypt ``anonymize_runtime_state.value``
under ``MultiFernet(FERNET_KEYS)`` so a DB-snapshot adversary cannot
read circuit-rebuild bucket levels, decoy histograms, or the redactor
allow-list directly. The migration is split in two so a long-running
deployment can roll forward without a flag-day:

* **020a** (this file): adds ``value_enc BYTEA`` and ``encrypted_at``,
  leaves the legacy ``value`` column in place. Application code reads
  ``value_enc`` first and falls back to ``value`` on miss.
* **020b**: backfills ``value_enc`` for any remaining cleartext rows
  (the application is expected to have re-written most rows by then),
  refuses to start when cleartext rows are detected, then drops the
  legacy ``value`` column.

The single-step path is gated on ``ALLOW_OFFLINE_RUNTIME_STATE_MIGRATION=true``
and is not provided as a separate migration in this codebase — operators
who want the offline path should run 020a + 020b back-to-back during
a maintenance window.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "020a_anonymize_runtime_state_add_enc_column"
down_revision: Union[str, None] = "019_anonymize_k_decrement_counter"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "anonymize_runtime_state",
        sa.Column(
            "value_enc",
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


def downgrade() -> None:
    op.drop_column("anonymize_runtime_state", "encrypted_at")
    op.drop_column("anonymize_runtime_state", "value_enc")
