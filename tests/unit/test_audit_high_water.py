# SPDX-License-Identifier: MIT
"""Audit-chain high-water reconciliation against row removal."""

import pytest
from sqlalchemy import delete, select

from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.services import audit_service as audit

pytestmark = pytest.mark.asyncio


async def _make_key(db_session) -> APIKey:
    key = APIKey(name="hw-key", key_hash="hw-hash", scope="admin")
    db_session.add(key)
    await db_session.commit()
    await db_session.refresh(key)
    return key


async def test_high_water_tracks_appends(db_session):
    key = await _make_key(db_session)
    for i in range(4):
        await audit.log_action(db_session, key, f"act{i}", "res")
    hw = await audit.check_high_water(db_session)
    assert hw["present"] and hw["ok"]
    assert hw["recorded_count"] == 4
    assert hw["live_count"] == 4


async def test_high_water_detects_tail_truncation(db_session):
    key = await _make_key(db_session)
    for i in range(5):
        await audit.log_action(db_session, key, f"act{i}", "res")
    assert (await audit.verify_chain(db_session))["ok"]

    # Remove the two newest rows out of band (an attacker without SECRET_KEY).
    newest = (
        (
            await db_session.execute(
                select(AuditLog.id).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(2)
            )
        )
        .scalars()
        .all()
    )
    await db_session.execute(delete(AuditLog).where(AuditLog.id.in_(newest)))
    await db_session.commit()

    hw = await audit.check_high_water(db_session)
    assert hw["present"] and not hw["ok"]
    assert "truncation" in hw["reason"]
    assert (await audit.verify_chain(db_session))["ok"] is False


async def test_high_water_signature_tamper_detected(db_session):
    key = await _make_key(db_session)
    await audit.log_action(db_session, key, "act", "res")
    state = await audit._load_high_water(db_session)
    # Forge a lower count without a valid signature.
    state.entry_count = 0
    await db_session.commit()
    hw = await audit.check_high_water(db_session)
    assert not hw["ok"]
    assert "signature" in hw["reason"]


async def test_high_water_signature_tamper_stays_latched_after_append(db_session):
    """A corrupted high-water signature is not healed by a later append."""
    key = await _make_key(db_session)
    await audit.log_action(db_session, key, "act0", "res")
    state = await audit._load_high_water(db_session)
    # Corrupt the signature in place (an attacker that can write the DB
    # but does not hold SECRET_KEY).
    state.state_hmac = "00" * 32
    await db_session.commit()
    # A subsequent legitimate append must NOT re-baseline / re-sign over
    # the tampered row — the mismatch stays detectable.
    await audit.log_action(db_session, key, "act1", "res")
    hw = await audit.check_high_water(db_session)
    assert not hw["ok"]
    assert "signature" in hw["reason"]


async def test_prune_lowers_high_water_consistently(db_session):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import update

    key = await _make_key(db_session)
    for i in range(5):
        await audit.log_action(db_session, key, f"act{i}", "res")

    # Backdate the oldest 3 rows past the cutoff. Editing created_at out of
    # band changes the hashed payload, so re-anchor to re-establish a
    # consistent baseline before the cut (mirrors an operator post-restore).
    old_ids = (
        (await db_session.execute(select(AuditLog.id).order_by(AuditLog.created_at.asc(), AuditLog.id.asc()).limit(3)))
        .scalars()
        .all()
    )
    old_ts = datetime.now(timezone.utc) - timedelta(days=10)
    await db_session.execute(update(AuditLog).where(AuditLog.id.in_(old_ids)).values(created_at=old_ts))
    await db_session.commit()
    await audit.reanchor_chain(db_session, key.id, key.name)

    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    result = await audit.prune_audit_log(db_session, cutoff, dashboard_key_id=key.id)
    assert result["deleted"] == 3 and not result["skipped"]

    # After an authorized prune the chain still verifies and the
    # high-water matches the live count (no false truncation flag).
    assert (await audit.verify_chain(db_session))["ok"]
    hw = await audit.check_high_water(db_session)
    assert hw["ok"]
    assert hw["recorded_count"] == hw["live_count"]
