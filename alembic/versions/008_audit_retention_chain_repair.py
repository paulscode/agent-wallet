# SPDX-License-Identifier: MIT
"""Repair audit-log chain after past retention pruning.

Revision ID: 008_audit_retention_chain_repair
Revises: 007_api_key_prev_hash
Create Date: 2026-04-30 00:00:04.000000

The previous ``cleanup_audit_logs`` task deleted rows past the retention
window without rewriting the chain head. As a result, the oldest
surviving row's ``prev_hash`` references a row that no longer exists,
which causes ``verify_chain`` to report a chain break on its very
first walk step. This migration is a one-shot repair: walk every
surviving row in ``(created_at, id)`` order and rewrite each row's
``prev_hash`` and ``entry_hash`` so the chain is internally
consistent again.

Like migration 006, this is a one-time re-anchoring, not a
tamper-recovery mechanism: any pre-migration tampering is no longer
detectable; post-migration tampering remains detectable via
``verify_chain``.

Idempotent: if the chain is already self-consistent the migration
rewrites every row to the same value it already holds.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timezone
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "008_audit_retention_chain_repair"
down_revision: Union[str, None] = "007_api_key_prev_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _compute_hash(row: sa.engine.Row, prev_hash: str | None) -> str:
    created_at = row.created_at
    if created_at is None:
        created_at_iso = ""
    else:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        else:
            created_at = created_at.astimezone(timezone.utc)
        created_at_iso = created_at.isoformat()
    payload = json.dumps(
        {
            "id": str(row.id),
            "api_key_id": str(row.api_key_id),
            "api_key_name": row.api_key_name,
            "action": row.action,
            "resource": row.resource,
            "details": row.details,
            "amount_sats": row.amount_sats,
            "success": row.success,
            "error_message": row.error_message,
            "ip_address": row.ip_address,
            "prev_hash": prev_hash or "",
            "created_at": created_at_iso,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(
        sa.text(
            "SELECT id, api_key_id, api_key_name, action, resource, "
            "details, amount_sats, success, error_message, ip_address, "
            "created_at "
            "FROM audit_logs ORDER BY created_at ASC, id ASC"
        )
    ).fetchall()

    if not rows:
        print("008_audit_retention_chain_repair: no audit rows — skip")
        return

    prev_hash: str | None = None
    rewritten = 0
    for row in rows:
        entry_hash = _compute_hash(row, prev_hash)
        bind.execute(
            sa.text("UPDATE audit_logs SET prev_hash = :prev_hash, entry_hash = :entry_hash WHERE id = :id"),
            {"prev_hash": prev_hash, "entry_hash": entry_hash, "id": row.id},
        )
        prev_hash = entry_hash
        rewritten += 1

    print(f"008_audit_retention_chain_repair: re-anchored {rewritten} audit rows")


def downgrade() -> None:
    # No-op: the prior state is "broken chain", which has no value.
    pass
