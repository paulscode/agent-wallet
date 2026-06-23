# SPDX-License-Identifier: MIT
"""anonymize_session — CHECK on distinct operator IDs.

Revision ID: 025_anonymize_distinct_operator_ids_check
Revises: 024_anonymize_bin_set_history_seed
Create Date: 2026-05-11 00:00:02.000000

When both ``submarine_operator_id`` and ``reverse_operator_id``
are populated (multi-operator deployments), they MUST
differ. A single-operator session leaves ``submarine_operator_id``
NULL (LN sources only have a reverse leg); this CHECK guards the
multi-operator path.

Lightning self-source sessions written under the old code path may have either
column NULL — those rows pass the CHECK trivially.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "025_anonymize_distinct_operator_ids_check"
down_revision: Union[str, None] = "024_anonymize_bin_set_history_seed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Refuse a row that pairs the two legs with the same
# operator id. The CHECK passes when either column is NULL (single-
# operator path) or when the two strings differ.
_CHECK_SQL = (
    "submarine_operator_id IS NULL OR reverse_operator_id IS NULL OR submarine_operator_id <> reverse_operator_id"
)


def upgrade() -> None:
    # SQLite supports CHECK constraints via batch_alter_table; Postgres
    # supports them directly.
    with op.batch_alter_table("anonymize_session") as batch:
        batch.create_check_constraint(
            "ck_anonymize_session_distinct_operator_ids",
            _CHECK_SQL,
        )


def downgrade() -> None:
    with op.batch_alter_table("anonymize_session") as batch:
        batch.drop_constraint(
            "ck_anonymize_session_distinct_operator_ids",
            type_="check",
        )
