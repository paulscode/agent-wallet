# SPDX-License-Identifier: MIT
"""anonymize_bin_set_history — seeding + backfill.

Revision ID: 024_anonymize_bin_set_history_seed
Revises: 023_anonymize_quote_token_key_generations
Create Date: 2026-05-11 00:00:00.000000

Seed ``anonymize_bin_set_history`` with row
``id=1`` representing the frozen bin set, then backfill
every ``anonymize_session.bin_set_id`` that holds the
sentinel ``0`` to point at the new row.

The frozen bin set comes from the ``ANONYMIZE_AMOUNT_BINS``
setting at the time this migration runs. Operators who run multiple
deployments under different bin schedules must seed manually before
this migration runs.

Idempotent — re-running the upgrade is a no-op once the seed row
already exists (the INSERT guards on the row's absence).
"""

from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "024_anonymize_bin_set_history_seed"
down_revision: Union[str, None] = "023_anonymize_quote_token_key_generations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# The bin set the deployment froze. We pull from
# settings rather than hard-coding so a deployment with a customized
# bin schedule seeds correctly.
def _frozen_bin_set_json() -> str:
    import json

    from app.core.config import settings

    bins = sorted(int(b) for b in settings.anonymize_amount_bins_list)
    return json.dumps({"bins_sat": bins})


def upgrade() -> None:
    conn = op.get_bind()
    # 1. Seed the history table iff empty.
    existing = conn.execute(
        sa.text("SELECT id FROM anonymize_bin_set_history ORDER BY id ASC LIMIT 1")
    ).scalar_one_or_none()
    if existing is None:
        conn.execute(
            sa.text(
                "INSERT INTO anonymize_bin_set_history "
                "(activated_at, bin_set_json, schema_version) "
                "VALUES (:activated_at, :bin_set_json, 1)"
            ),
            {
                "activated_at": datetime.now(timezone.utc),
                "bin_set_json": _frozen_bin_set_json(),
            },
        )
        # The seeded row's id is 1 on a fresh autoincrement; SQLite +
        # Postgres both honor this for a fresh table. Subsequent
        # backfill points at id=1.
    # 2. Backfill sentinel rows. Any session whose
    # ``bin_set_id`` is still 0 gets rewritten to 1.
    conn.execute(sa.text("UPDATE anonymize_session SET bin_set_id = 1 WHERE bin_set_id = 0"))


def downgrade() -> None:
    conn = op.get_bind()
    # Reverse the backfill (sessions whose bin_set_id is 1 are the
    # only ones we touched — assume no other rows have written 1
    # between upgrade + downgrade; that's a documented constraint).
    conn.execute(sa.text("UPDATE anonymize_session SET bin_set_id = 0 WHERE bin_set_id = 1"))
    conn.execute(sa.text("DELETE FROM anonymize_bin_set_history WHERE id = 1"))
