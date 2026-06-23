# SPDX-License-Identifier: MIT
"""Anonymize K-decrement counter + refund-label backfill high-water-mark.

Revision ID: 019_anonymize_k_decrement_counter
Revises: 017_anonymize_feature_enabled_at_quantize
Create Date: 2026-05-10 00:00:02.000000

 brittleness A: persists the strict-mode K-fallback
counter so a session whose orchestrator restarts mid-fallback cannot
regress to a multi-step ratchet across the restart. The
``k_decrements_used`` column was created on ``anonymize_session`` by
migration 016 (with default ``0``); this migration adds the index that
the ``_resolve_executed_k`` read-site relies on for the
``mpp_k_floor_aborts_recent`` UI metric.

Replaces the prior plan's per-row
``boltz_swaps.refund_label_backfilled_at_ts`` marker (a per-row
anonymize-failure fingerprint) with a single ``anonymize_runtime_state``
row keyed ``refund_label_backfill_high_water_mark``. The row itself
is created lazily by the application on first write — :func:`read_high_water_mark`
returns :meth:`HighWaterMark.empty` when the row is missing, which
matches the previously-seeded ``{}`` payload behavior.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "019_anonymize_k_decrement_counter"
down_revision: Union[str, None] = "018_anonymize_decoy_seed"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Index over (status, k_decrements_used, completed_at) to support
    # metric-window scans for
    # ``mpp_k_floor_aborts_recent``.
    op.execute(
        """
        CREATE INDEX ix_anonymize_session_k_floor_metrics
            ON anonymize_session(status, k_decrements_used, completed_at)
            WHERE status IN ('failed', 'awaiting_reconciliation', 'completed')
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_anonymize_session_k_floor_metrics")
