# SPDX-License-Identifier: MIT
"""Quantize feature_enabled_at to UTC-day + add quantize trigger.

Revision ID: 017_anonymize_feature_enabled_at_quantize
Revises: 016_anonymize
Create Date: 2026-05-10 00:00:01.000000

Implements:

* The `feature_enabled_at_day` row in ``anonymize_settings`` stores a
  UTC-day-truncated date — second-precision storage was a per-second
  identifier across leaks (residual #26).
* The `set_at` column for any key in the registry constant
  ``ANONYMIZE_SETTINGS_QUANTIZE_KEYS`` is auto-truncated to UTC-day
  by trigger ``trg_anonymize_settings_quantize_set_at``. The trigger
  reads its quantize-key allow-list from the GUC
  ``anonymize.settings_quantize_keys`` (set by alembic env.py / app
  startup) and falls back to the in-DB ``anonymize_settings_quantize_allowlist``
  table when the GUC is unset.

The migration acquires an EXCLUSIVE lock on ``anonymize_settings``
 so no concurrent session-create writes can race the
day-quantization. Lightning self-source deployments will not yet have
rows in this table, so the lock is effectively free.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "017_anonymize_feature_enabled_at_quantize"
down_revision: Union[str, None] = "016_anonymize"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Default quantize-required keys. The GUC overrides this
# at runtime; the in-DB allow-list is the persistent fallback.
_INITIAL_QUANTIZE_KEYS = ("feature_enabled_at_day",)


def upgrade() -> None:
    # in-DB allow-list table.
    op.create_table(
        "anonymize_settings_quantize_allowlist",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    for key in _INITIAL_QUANTIZE_KEYS:
        op.execute(
            sa.text(
                "INSERT INTO anonymize_settings_quantize_allowlist(key) VALUES (:key) ON CONFLICT DO NOTHING"
            ).bindparams(key=key)
        )

    # EXCLUSIVE lock so an in-flight session-create cannot
    # write a second-precision row mid-migration.
    op.execute("LOCK TABLE anonymize_settings IN EXCLUSIVE MODE")

    # If a pre-quantization row exists (defensive — Lightning self-source
    # deployments writing the row in flight before this migration runs), truncate
    # the value AND set_at to UTC-day.
    op.execute(
        """
        UPDATE anonymize_settings
           SET value = to_jsonb(
                   to_char(
                       date_trunc('day', (value->>0)::timestamptz AT TIME ZONE 'UTC'),
                       'YYYY-MM-DD'
                   )
               ),
               set_at = date_trunc('day', set_at AT TIME ZONE 'UTC')
         WHERE key = 'feature_enabled_at_day'
           AND jsonb_typeof(value) = 'string'
           AND length(value->>0) > 10
        """
    )

    # Trigger function: when the row's key is in the quantize allow-list,
    # truncate set_at to UTC-day. Reads first from the session-local GUC
    # (set by app startup / alembic env.py) and falls back to the
    # `anonymize_settings_quantize_allowlist` table.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION trg_anonymize_settings_quantize_set_at()
        RETURNS trigger AS $$
        DECLARE
            guc_keys text;
            in_allowlist boolean;
        BEGIN
            guc_keys := COALESCE(
                current_setting('anonymize.settings_quantize_keys', true),
                ''
            );
            IF guc_keys != '' THEN
                IF position(',' || NEW.key || ',' IN ',' || guc_keys || ',') > 0 THEN
                    NEW.set_at := date_trunc('day', NEW.set_at AT TIME ZONE 'UTC');
                END IF;
            ELSE
                SELECT EXISTS (
                    SELECT 1 FROM anonymize_settings_quantize_allowlist
                     WHERE key = NEW.key
                ) INTO in_allowlist;
                IF in_allowlist THEN
                    NEW.set_at := date_trunc('day', NEW.set_at AT TIME ZONE 'UTC');
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_anonymize_settings_quantize_set_at
            BEFORE INSERT OR UPDATE ON anonymize_settings
            FOR EACH ROW EXECUTE FUNCTION
            trg_anonymize_settings_quantize_set_at()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_anonymize_settings_quantize_set_at ON anonymize_settings")
    op.execute("DROP FUNCTION IF EXISTS trg_anonymize_settings_quantize_set_at()")
    op.drop_table("anonymize_settings_quantize_allowlist")
