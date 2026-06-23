# SPDX-License-Identifier: MIT
"""Allow audit_logs.api_key_id to be NULL for system-emitted entries.

Revision ID: 028_audit_logs_api_key_id_nullable
Revises: 027_anonymize_session_output
Create Date: 2026-05-14 23:30:00.000000

The anonymize scheduler emits ``__system__`` audit rows for
``anonymize.bucket_summary`` and related background ticks. These rows
have no originating API key, so the prior NOT NULL constraint on
``api_key_id`` blocked every system insert. The FK to ``api_keys.id``
is kept (with ``ondelete=RESTRICT``) so API-key rows that *do* have
audit references still cannot be hard-deleted out from under them.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "028_audit_logs_api_key_id_nullable"
down_revision: Union[str, None] = "027_anonymize_session_output"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "audit_logs",
        "api_key_id",
        existing_nullable=False,
        nullable=True,
    )


def downgrade() -> None:
    # Refuses to downgrade if any rows still carry NULL api_key_id —
    # those rows would violate the restored constraint. Operators must
    # clean them up explicitly first.
    op.alter_column(
        "audit_logs",
        "api_key_id",
        existing_nullable=True,
        nullable=False,
    )
