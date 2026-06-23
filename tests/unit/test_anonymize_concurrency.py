# SPDX-License-Identifier: MIT
"""/ items 46, 47, 48 — concurrency + locking helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.concurrency import (
    can_create_session_at_tier,
    cap_for_proposed_tier,
    count_active_in_flight_sessions,
    count_reconciliation_queue,
    fetch_in_flight_session_tiers,
    highest_tier_in_flight,
    is_reconciliation_queue_full,
    lock_session_for_update,
)


def _row(
    *,
    status: str,
    tier: str = "weak",
    final_tier: str | None = None,
) -> AnonymizeSession:
    pipeline_json = {"tier": tier}
    final = {"tier": final_tier} if final_tier else None
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pipeline_json,
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=uuid4().bytes + uuid4().bytes,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        final_score_report_json=final,
    )


# ── item 46 — pure helpers ────────────────────────────────────────


def test_highest_tier_in_flight_returns_max() -> None:
    assert highest_tier_in_flight(["weak", "moderate", "weak"]) == "moderate"
    assert highest_tier_in_flight(["strong"]) == "strong"
    assert highest_tier_in_flight([]) is None


def test_highest_tier_in_flight_skips_unknown_values() -> None:
    assert highest_tier_in_flight(["weak", "garbage", "moderate"]) == "moderate"


def test_cap_for_proposed_tier_uses_settings_caps(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_tier_concurrency_cap", "weak=3,moderate=2,strong=1")
    # Empty in-flight + proposed=weak ⇒ cap=3.
    assert cap_for_proposed_tier(proposed_tier="weak", in_flight_tiers=[]) == 3
    # Proposed=strong ⇒ cap=1 regardless of in-flight set.
    assert cap_for_proposed_tier(proposed_tier="strong", in_flight_tiers=["weak"]) == 1
    # Proposed=weak but a moderate session is in flight ⇒ cap=2.
    assert cap_for_proposed_tier(proposed_tier="weak", in_flight_tiers=["moderate"]) == 2


# ── DB-backed cap tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_count_active_in_flight_excludes_terminal_and_reconciliation(
    db_session,
) -> None:
    # Active rows.
    db_session.add(_row(status=AnonymizeStatus.LN_HOLDING.value, tier="weak"))
    db_session.add(_row(status=AnonymizeStatus.EXITING.value, tier="moderate"))
    # Excluded.
    db_session.add(_row(status=AnonymizeStatus.COMPLETED.value, tier="weak"))
    db_session.add(_row(status=AnonymizeStatus.AWAITING_RECONCILIATION.value, tier="weak"))
    await db_session.commit()
    assert await count_active_in_flight_sessions(db_session) == 2


@pytest.mark.asyncio
async def test_fetch_in_flight_tiers_prefers_final_score_when_present(
    db_session,
) -> None:
    db_session.add(_row(status=AnonymizeStatus.EXITING.value, tier="moderate", final_tier="weak"))
    db_session.add(_row(status=AnonymizeStatus.LN_HOLDING.value, tier="strong"))
    await db_session.commit()
    tiers = await fetch_in_flight_session_tiers(db_session)
    assert sorted(tiers) == ["strong", "weak"]


@pytest.mark.asyncio
async def test_can_create_session_blocks_when_strong_is_in_flight(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_tier_concurrency_cap", "weak=3,moderate=2,strong=1")
    db_session.add(_row(status=AnonymizeStatus.HOPPING.value, tier="strong"))
    await db_session.commit()
    allowed, count, cap = await can_create_session_at_tier(db_session, proposed_tier="weak")
    assert allowed is False
    assert count == 1
    assert cap == 1


@pytest.mark.asyncio
async def test_can_create_session_allows_at_weak_cap(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_tier_concurrency_cap", "weak=3,moderate=2,strong=1")
    db_session.add(_row(status=AnonymizeStatus.LN_HOLDING.value, tier="weak"))
    db_session.add(_row(status=AnonymizeStatus.HOPPING.value, tier="weak"))
    await db_session.commit()
    allowed, count, cap = await can_create_session_at_tier(db_session, proposed_tier="weak")
    assert allowed is True  # 2 < 3
    assert count == 2
    assert cap == 3


# ── item 47 — reconciliation queue isolation ──────────────────────


@pytest.mark.asyncio
async def test_count_reconciliation_queue_excludes_active(db_session) -> None:
    db_session.add(_row(status=AnonymizeStatus.AWAITING_RECONCILIATION.value, tier="weak"))
    db_session.add(_row(status=AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value, tier="weak"))
    db_session.add(_row(status=AnonymizeStatus.LN_HOLDING.value, tier="weak"))  # active
    db_session.add(_row(status=AnonymizeStatus.COMPLETED.value, tier="weak"))  # terminal
    await db_session.commit()
    assert await count_reconciliation_queue(db_session) == 2


def test_is_reconciliation_queue_full(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_awaiting_reconciliation_cap", 5)
    assert is_reconciliation_queue_full(4) is False
    assert is_reconciliation_queue_full(5) is True
    assert is_reconciliation_queue_full(6) is True


# ── item 48 — row-level locking helper ────────────────────────────


def test_lock_session_for_update_returns_locked_statement() -> None:
    """The helper applies ``FOR UPDATE SKIP LOCKED`` when compiled for PostgreSQL.

    ``SKIP LOCKED`` is a PostgreSQL extension; SQLAlchemy silently
    drops it on dialects that don't support it (SQLite test runner).
    Compile against the PostgreSQL dialect explicitly so the test
    verifies what production sees.
    """
    from sqlalchemy import select
    from sqlalchemy.dialects import postgresql

    stmt = select(AnonymizeSession.id)
    locked = lock_session_for_update(stmt)
    compiled = str(
        locked.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )
    assert "FOR UPDATE" in compiled.upper()
    assert "SKIP LOCKED" in compiled.upper()
