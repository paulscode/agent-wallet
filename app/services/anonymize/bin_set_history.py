# SPDX-License-Identifier: MIT
"""Bin-set history (/ items 66 + 90).

 refuses to use a pre-existing exact-bin UTXO as an anonymize
source unless the UTXO predates ``feature_enabled_at_day``. The naive
reading of the published bin set risks a *retroactive* reshape: a
migration that introduces a new bin (e.g., 750_000) would
suddenly admit pre-existing UTXOs of that value as "predates the
feature" without flagging them. The fix is to consult the bin set
that was *active at the UTXO's confirmation height*, not the live
bin set.

This module ships:
* :func:`seed_initial_bin_set_history` — migration helper that
  writes ``id=1`` from the originally frozen bin set.
* :func:`get_active_bin_set_for_height` — return the bin set active
  at a given chain height. Deployments with no history table
  rows fall back to the sentinel ``bin_set_id=0``; otherwise the
  appropriate row is read.
* :func:`record_bin_set_change` — append a new bin-set row when the
  operator updates ``ANONYMIZE_AMOUNT_BINS_SAT``.

The actual seeding writes happen in the migration that creates the
first ``anonymize_bin_set_history`` row.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeBinSetHistory

# Sentinel for ``anonymize_session.bin_set_id``.
# Rows with this value reference "the implicit frozen bin
# set"; the migration backfills them to id=1.
IMPLICIT_BIN_SET_SENTINEL: int = 0


async def seed_initial_bin_set_history(
    db: AsyncSession,
    *,
    bin_set: list[int] | None = None,
    schema_version: int = 1,
) -> AnonymizeBinSetHistory:
    """Write the first ``anonymize_bin_set_history`` row.

    Idempotent: if the table already has rows, returns the earliest
    one without writing. The migration calls this once with
    the originally frozen bin set.
    """
    existing = await db.execute(select(AnonymizeBinSetHistory).order_by(AnonymizeBinSetHistory.id.asc()).limit(1))
    row = existing.scalar_one_or_none()
    if row is not None:
        return row

    if bin_set is None:
        bin_set = list(settings.anonymize_amount_bins_list)

    seeded = AnonymizeBinSetHistory(
        activated_at=datetime.now(timezone.utc),
        bin_set_json={"bins_sat": [int(b) for b in bin_set]},
        schema_version=int(schema_version),
    )
    db.add(seeded)
    return seeded


async def record_bin_set_change(
    db: AsyncSession,
    *,
    bin_set: list[int],
    schema_version: int,
    activated_at: datetime | None = None,
) -> AnonymizeBinSetHistory:
    """Append a new bin-set row when the operator updates the published set.

    Invoked by an admin command when the operator rolls out a new
    bin schedule. The new row's ``id`` becomes the active
    ``bin_set_id`` for sessions created after ``activated_at``.
    """
    row = AnonymizeBinSetHistory(
        activated_at=activated_at or datetime.now(timezone.utc),
        bin_set_json={"bins_sat": [int(b) for b in bin_set]},
        schema_version=int(schema_version),
    )
    db.add(row)
    return row


async def get_bin_set_by_id(db: AsyncSession, bin_set_id: int) -> list[int] | None:
    """Resolve a ``bin_set_id`` to its bin list.

    The sentinel ``0`` returns the *current* configured bin
    set so sentinel rows decode cleanly. Any other id reads from the
    history table.
    """
    if bin_set_id == IMPLICIT_BIN_SET_SENTINEL:
        return list(settings.anonymize_amount_bins_list)
    row = await db.get(AnonymizeBinSetHistory, bin_set_id)
    if row is None:
        return None
    raw = row.bin_set_json
    if isinstance(raw, dict):
        bins = raw.get("bins_sat") or raw.get("bins") or []
    else:
        bins = raw or []
    try:
        return sorted(int(b) for b in bins)
    except (TypeError, ValueError):
        return None


async def get_active_bin_set_at_height(db: AsyncSession, *, confirmed_at: datetime) -> tuple[int, list[int]]:
    """Return ``(bin_set_id, bin_list)`` active at ``confirmed_at``.

    Selects the most-recent ``anonymize_bin_set_history`` row whose
    ``activated_at`` ≤ ``confirmed_at``. Deployments without
    any rows fall back to the sentinel ``(0, current_config_bins)``.
    """
    if confirmed_at.tzinfo is None:
        confirmed_at = confirmed_at.replace(tzinfo=timezone.utc)

    stmt = (
        select(AnonymizeBinSetHistory)
        .where(AnonymizeBinSetHistory.activated_at <= confirmed_at)
        .order_by(AnonymizeBinSetHistory.activated_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return IMPLICIT_BIN_SET_SENTINEL, list(settings.anonymize_amount_bins_list)
    raw = row.bin_set_json or {}
    bins = sorted(int(b) for b in (raw.get("bins_sat") or raw.get("bins") or []))
    return int(row.id), bins


__all__ = [
    "IMPLICIT_BIN_SET_SENTINEL",
    "seed_initial_bin_set_history",
    "record_bin_set_change",
    "get_bin_set_by_id",
    "get_active_bin_set_at_height",
]
