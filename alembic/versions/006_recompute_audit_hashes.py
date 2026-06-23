# SPDX-License-Identifier: MIT
"""Recompute audit-log hash chain over existing rows.

Revision ID: 006_recompute_audit_hashes
Revises: 005_api_key_soft_delete
Create Date: 2026-04-30 00:00:02.000000

Re-anchors the audit-log hash chain to the on-disk state at migration
time. Earlier writes computed ``entry_hash`` before ``created_at`` was
populated, so the persisted hashes did not match a re-computation that
read ``created_at`` back from the row. This migration walks the table
in ``created_at`` order and rewrites ``prev_hash`` and ``entry_hash``
using the same payload format as ``AuditLog.compute_hash()``.

This is a one-time re-anchoring, not a tamper-recovery mechanism. Any
pre-migration tampering is no longer detectable; post-migration
tampering remains detectable via ``verify_chain``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import timezone
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "006_recompute_audit_hashes"
down_revision: Union[str, None] = "005_api_key_soft_delete"
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

    # Surface the row count in alembic's stdout for operator visibility.
    print(f"006_recompute_audit_hashes: re-anchored {rewritten} audit rows")


def downgrade() -> None:
    # No-op: this migration only rewrites hash columns to internally
    # consistent values. Reverting would leave the chain in its prior
    # broken state, which has no operational value.
    pass
