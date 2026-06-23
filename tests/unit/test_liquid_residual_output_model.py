# SPDX-License-Identifier: MIT
"""Unit tests for the ``LiquidResidualOutput`` ORM model.

These exercise the schema added by Alembic migration
``036_liquid_residual_outputs``: persistence round-trip, the
``UNIQUE(txid, vout)`` outpoint constraint, the ``value_sat > 0``
and ``vout >= 0`` CHECKs, and the dust-threshold helper-friendly
default state (``recovered_at`` + ``dust_acknowledged_at`` both
NULL on insert).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import LiquidResidualOutput


def _row(**overrides):
    base = dict(
        id=uuid4(),
        session_id=None,
        txid="aa" * 32,
        vout=0,
        asset_id="bb" * 32,
        value_sat=12_345,
        address="lq1qq0residual0addr",
        derivation_path="m/84h/1776h/0h/0/0",
    )
    base.update(overrides)
    return LiquidResidualOutput(**base)


@pytest.mark.asyncio
async def test_roundtrip_insert_defaults_pending(db_session: AsyncSession) -> None:
    row = _row()
    db_session.add(row)
    await db_session.commit()

    fetched = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert fetched.recovered_at is None
    assert fetched.recovered_swap_id is None
    assert fetched.dust_acknowledged_at is None
    assert fetched.discovered_at is not None
    assert fetched.value_sat == 12_345


@pytest.mark.asyncio
async def test_outpoint_unique_constraint(db_session: AsyncSession) -> None:
    db_session.add(_row(txid="cc" * 32, vout=2))
    await db_session.commit()
    db_session.add(_row(txid="cc" * 32, vout=2))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_same_txid_different_vout_allowed(
    db_session: AsyncSession,
) -> None:
    db_session.add(_row(txid="dd" * 32, vout=0))
    db_session.add(_row(txid="dd" * 32, vout=1))
    await db_session.commit()  # must not raise


@pytest.mark.asyncio
async def test_zero_value_rejected(db_session: AsyncSession) -> None:
    db_session.add(_row(value_sat=0))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_negative_vout_rejected(db_session: AsyncSession) -> None:
    db_session.add(_row(vout=-1))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_recovered_at_and_swap_id_set_together(
    db_session: AsyncSession,
) -> None:
    """Recovery stamps both columns. The schema doesn't enforce
    co-presence (NULL+NULL during scan, both set after sweep),
    but the recovery code does — this is a documentation test
    pinning the contract.
    """
    row = _row(txid="ee" * 32, vout=7)
    db_session.add(row)
    await db_session.commit()
    row.recovered_at = datetime.now(timezone.utc)
    row.recovered_swap_id = "boltz_swap_recovered"
    await db_session.commit()

    fetched = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert fetched.recovered_at is not None
    assert fetched.recovered_swap_id == "boltz_swap_recovered"


def test_dust_threshold_constant_present() -> None:
    """The 5 000-sat dust default must exist on settings as a single
    source of truth for the recovery banner."""
    assert hasattr(settings, "liquid_residual_dust_threshold_sat")
    assert settings.liquid_residual_dust_threshold_sat == 5000
    assert hasattr(settings, "liquid_residual_scan_interval_s")
    assert settings.liquid_residual_scan_interval_s > 0


@pytest.mark.asyncio
async def test_recovered_swap_id_unique_when_set(db_session: AsyncSession) -> None:
    """A residual UTXO is swept by exactly one swap: a second row stamping
    the same non-NULL ``recovered_swap_id`` is a hard error (the backstop
    behind the swap-out serialization)."""
    db_session.add(_row(txid="d1" * 32, vout=0, recovered_swap_id="swap-xyz"))
    await db_session.commit()

    db_session.add(_row(txid="d2" * 32, vout=1, recovered_swap_id="swap-xyz"))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_multiple_unrecovered_rows_allowed(db_session: AsyncSession) -> None:
    """The unique index is partial (non-NULL only): any number of
    un-recovered rows (``recovered_swap_id IS NULL``) coexist."""
    db_session.add(_row(txid="e1" * 32, vout=0))
    db_session.add(_row(txid="e2" * 32, vout=0))
    db_session.add(_row(txid="e3" * 32, vout=0))
    await db_session.commit()

    count = len(
        (
            await db_session.execute(
                select(LiquidResidualOutput).where(LiquidResidualOutput.recovered_swap_id.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert count >= 3
