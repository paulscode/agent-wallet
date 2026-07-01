# SPDX-License-Identifier: MIT
"""Drop the UNIQUE constraint on channel_mix_runs.plan_token_digest.

Revision ID: 051_mix_run_digest_not_unique
Revises: 050_dashboard_settings
Create Date: 2026-07-01 00:00:00.000000

The digest was UNIQUE to dedupe browser double-submits of an execute. But
that made it impossible to ever re-run an identical plan after the previous
run ended — retrying a failed build with the same target produced the same
digest, and the idempotency lookup returned the old *terminal* run forever
instead of starting fresh. Double-submit is now handled by scoping the
idempotency lookup to non-terminal runs, and two concurrent runs are already
prevented by the one-active-run guard + execute advisory lock, so the UNIQUE
constraint is dropped and replaced with a plain (non-unique) index for the
lookup.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "051_mix_run_digest_not_unique"
down_revision: Union[str, None] = "050_dashboard_settings"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "channel_mix_runs"
_UQ = "uq_channel_mix_runs_plan_token_digest"
_IX = "idx_channel_mix_runs_plan_token_digest"


def upgrade() -> None:
    # Drop the UNIQUE constraint (Postgres also drops its backing index), then
    # add a plain index so the digest lookup stays fast.
    op.drop_constraint(_UQ, _TABLE, type_="unique")
    op.create_index(_IX, _TABLE, ["plan_token_digest"])


def downgrade() -> None:
    op.drop_index(_IX, table_name=_TABLE)
    op.create_unique_constraint(_UQ, _TABLE, ["plan_token_digest"])
