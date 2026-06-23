# SPDX-License-Identifier: MIT
"""
Unit tests for ``app.services.api_key_service``.

The service is the single source of truth used by both the admin REST
router and the dashboard surface. These tests exercise it directly
(no HTTP layer) to lock in:

* validation / clamping behaviour
* self-protection (cannot delete or demote the actor's own key)
* retention-window gating on purge
* audit-log emission shape (one row per mutation, with the right
  actor id and details payload)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_api_key
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.services import api_key_service
from app.services.api_key_service import DashboardActor

_DASHBOARD_KEY_ID = UUID("00000000-0000-0000-0000-da5b0a4d0000")


async def _make_admin(db_session, *, name: str = "admin") -> APIKey:
    k = APIKey(
        id=uuid4(),
        name=name,
        key_hash=hash_api_key("dummy-" + name),
        is_admin=True,
        is_active=True,
    )
    db_session.add(k)
    await db_session.commit()
    await db_session.refresh(k)
    return k


async def _audit_rows(db_session) -> list[AuditLog]:
    res = await db_session.execute(select(AuditLog).order_by(AuditLog.created_at.asc()))
    return list(res.scalars().all())


# ── create_key ─────────────────────────────────────────────────────────


class TestCreateKey:
    @pytest.mark.asyncio
    async def test_returns_plaintext_and_persists_hash(self, db_session):
        admin = await _make_admin(db_session)
        before = len(await _audit_rows(db_session))

        key, raw = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="bot-1",
            is_admin=False,
            expires_in_days=30,
        )

        assert raw.startswith("lwk_")
        assert key.key_hash == hash_api_key(raw)
        assert key.is_admin is False
        assert key.expires_at is not None

        rows = await _audit_rows(db_session)
        assert len(rows) == before + 1
        new_row = rows[-1]
        assert new_row.action == "create_api_key"
        assert new_row.api_key_id == admin.id
        assert new_row.details["new_key_name"] == "bot-1"
        assert new_row.details["scope"] == "monitor"

    @pytest.mark.asyncio
    async def test_dashboard_actor_records_sentinel_id(self, db_session):
        actor = DashboardActor(_DASHBOARD_KEY_ID)
        key, _ = await api_key_service.create_key(
            db_session,
            actor=actor,
            name="dash-1",
            is_admin=False,
            expires_in_days=10,
        )
        rows = await _audit_rows(db_session)
        assert rows[-1].api_key_id == _DASHBOARD_KEY_ID
        assert rows[-1].api_key_name == "__dashboard__"

    @pytest.mark.asyncio
    async def test_expires_in_days_clamped_to_max(self, db_session):
        admin = await _make_admin(db_session)
        max_days = settings.api_key_max_ttl_days
        key, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="long-lived",
            is_admin=False,
            expires_in_days=max_days * 10,  # absurdly large
        )
        # Allow a small wall-clock skew window.
        expected = datetime.now(timezone.utc) + timedelta(days=max_days)
        got = key.expires_at
        if got.tzinfo is None:
            got = got.replace(tzinfo=timezone.utc)
        delta = abs((got - expected).total_seconds())
        assert delta < 5

    @pytest.mark.asyncio
    async def test_none_expires_uses_max_ttl(self, db_session):
        admin = await _make_admin(db_session)
        key, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="default-ttl",
            is_admin=False,
            expires_in_days=None,
        )
        expected = datetime.now(timezone.utc) + timedelta(days=settings.api_key_max_ttl_days)
        got = key.expires_at
        if got.tzinfo is None:
            got = got.replace(tzinfo=timezone.utc)
        delta = abs((got - expected).total_seconds())
        assert delta < 5

    @pytest.mark.asyncio
    async def test_empty_name_rejected(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.create_key(
                db_session,
                actor=admin,
                name="   ",
                is_admin=False,
                expires_in_days=10,
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_long_name_rejected(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.create_key(
                db_session,
                actor=admin,
                name="x" * 129,
                is_admin=False,
                expires_in_days=10,
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_negative_expiry_rejected(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException):
            await api_key_service.create_key(
                db_session,
                actor=admin,
                name="bad",
                is_admin=False,
                expires_in_days=0,
            )


# ── update_key ─────────────────────────────────────────────────────────


class TestUpdateKey:
    @pytest.mark.asyncio
    async def test_rename(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="orig",
            is_admin=False,
            expires_in_days=30,
        )
        before = len(await _audit_rows(db_session))

        updated, changes = await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            name="renamed",
        )
        assert updated.name == "renamed"
        assert changes == {"name": "renamed"}

        rows = await _audit_rows(db_session)
        assert len(rows) == before + 1
        assert rows[-1].action == "update_api_key"
        assert rows[-1].details["target_key_id"] == str(target.id)
        assert rows[-1].details["changes"] == {"name": "renamed"}

    @pytest.mark.asyncio
    async def test_combined_fields_update_atomically(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="combo",
            is_admin=False,
            expires_in_days=30,
        )
        updated, changes = await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            name="renamed",
            is_active=False,
            is_admin=True,
        )
        assert updated.name == "renamed"
        assert updated.is_active is False
        assert updated.is_admin is True
        assert changes == {
            "name": "renamed",
            "is_active": False,
            "scope": "admin",
        }

    @pytest.mark.asyncio
    async def test_no_op_update_still_emits_audit(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="noop",
            is_admin=False,
            expires_in_days=30,
        )
        before = len(await _audit_rows(db_session))
        _, changes = await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        assert changes == {}
        rows = await _audit_rows(db_session)
        # Decision: the service emits one row per update_key call so
        # the audit log records every operator intent, even no-ops.
        assert len(rows) == before + 1
        assert rows[-1].details["changes"] == {}

    @pytest.mark.asyncio
    async def test_promote_read_to_admin(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ro",
            is_admin=False,
            expires_in_days=30,
        )
        updated, changes = await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            is_admin=True,
        )
        assert updated.is_admin is True
        # The boolean ``is_admin`` alias resolves to the canonical scope,
        # and the change set is reported in scope terms.
        assert changes == {"scope": "admin"}

    @pytest.mark.asyncio
    async def test_rename_validation(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ok",
            is_admin=False,
            expires_in_days=30,
        )
        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id=str(target.id),
                name="   ",
            )
        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id=str(target.id),
                name="x" * 129,
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_self_demote_rejected_for_real_actor(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id=str(admin.id),
                is_admin=False,
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_self_rename_allowed_for_real_actor(self, db_session):
        # Self-protection only blocks demote, not other field updates.
        admin = await _make_admin(db_session)
        updated, changes = await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(admin.id),
            name="renamed",
        )
        assert updated.name == "renamed"
        assert changes == {"name": "renamed"}

    @pytest.mark.asyncio
    async def test_self_demote_allowed_for_dashboard_actor(self, db_session):
        # The dashboard actor is a sentinel, never a real APIKey row,
        # so the "cannot demote self" guard must not fire on it.
        actor = DashboardActor(_DASHBOARD_KEY_ID)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=actor,
            name="boot",
            is_admin=True,
            expires_in_days=30,
        )
        updated, changes = await api_key_service.update_key(
            db_session,
            actor=actor,
            key_id=str(target.id),
            is_admin=False,
        )
        assert updated.is_admin is False
        assert changes == {"scope": "monitor"}

    @pytest.mark.asyncio
    async def test_invalid_uuid_400(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id="not-a-uuid",
                name="x",
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_missing_key_404(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id=str(uuid4()),
                name="x",
            )
        assert exc.value.status_code == 404


# ── soft_delete_key ────────────────────────────────────────────────────


class TestSoftDelete:
    @pytest.mark.asyncio
    async def test_soft_delete_sets_inactive_and_deleted_at(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="bye",
            is_admin=False,
            expires_in_days=30,
        )
        before = len(await _audit_rows(db_session))

        result = await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        assert result.is_active is False
        assert result.deleted_at is not None

        rows = await _audit_rows(db_session)
        assert len(rows) == before + 1
        assert rows[-1].action == "delete_api_key"
        assert rows[-1].details["soft_delete"] is True
        assert rows[-1].details["deleted_key_name"] == "bye"

    @pytest.mark.asyncio
    async def test_soft_delete_is_idempotent_on_deleted_at(self, db_session):
        # Re-soft-deleting an already-deleted key must not bump
        # ``deleted_at`` (otherwise the retention window would
        # restart on every accidental re-delete).
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="twice",
            is_admin=False,
            expires_in_days=30,
        )
        first = await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        first_deleted_at = first.deleted_at
        second = await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        assert second.deleted_at == first_deleted_at

    @pytest.mark.asyncio
    async def test_self_delete_rejected_for_real_actor(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.soft_delete_key(
                db_session,
                actor=admin,
                key_id=str(admin.id),
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_dashboard_actor_can_delete_anything(self, db_session):
        # Dashboard actor never matches a real key id, so the
        # self-protection guard never triggers; the bootstrap-key
        # safeguard is purely client-side.
        actor = DashboardActor(_DASHBOARD_KEY_ID)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=actor,
            name="anything",
            is_admin=True,
            expires_in_days=30,
        )
        result = await api_key_service.soft_delete_key(
            db_session,
            actor=actor,
            key_id=str(target.id),
        )
        assert result.is_active is False


# ── purge_key ──────────────────────────────────────────────────────────


class TestPurge:
    @pytest.mark.asyncio
    async def test_purge_requires_soft_delete_first(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="alive",
            is_admin=False,
            expires_in_days=30,
        )
        with pytest.raises(HTTPException) as exc:
            await api_key_service.purge_key(
                db_session,
                actor=admin,
                key_id=str(target.id),
            )
        assert exc.value.status_code == 400
        assert "soft-deleted" in exc.value.detail

    @pytest.mark.asyncio
    async def test_purge_blocked_within_retention(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "audit_log_retention_days", 30)
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="recent",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        with pytest.raises(HTTPException) as exc:
            await api_key_service.purge_key(
                db_session,
                actor=admin,
                key_id=str(target.id),
            )
        assert exc.value.status_code == 400
        assert "retention" in exc.value.detail

    @pytest.mark.asyncio
    async def test_purge_allowed_after_retention(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "audit_log_retention_days", 7)
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="old",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        # Backdate deleted_at past the retention window.
        target.deleted_at = datetime.now(timezone.utc) - timedelta(days=30)
        await db_session.commit()

        before = len(await _audit_rows(db_session))
        await api_key_service.purge_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )

        # Row is gone.
        gone = await db_session.execute(select(APIKey).where(APIKey.id == target.id))
        assert gone.scalar_one_or_none() is None

        rows = await _audit_rows(db_session)
        assert len(rows) == before + 1
        assert rows[-1].action == "purge_api_key"
        assert rows[-1].details["purged_key_name"] == "old"

    @pytest.mark.asyncio
    async def test_purge_allowed_immediately_when_retention_zero(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "audit_log_retention_days", 0)
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ephemeral",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        await api_key_service.purge_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        gone = await db_session.execute(select(APIKey).where(APIKey.id == target.id))
        assert gone.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_self_purge_rejected_for_real_actor(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.purge_key(
                db_session,
                actor=admin,
                key_id=str(admin.id),
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_purge_missing_key_404(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.purge_key(
                db_session,
                actor=admin,
                key_id=str(uuid4()),
            )
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_purge_invalid_uuid_400(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.purge_key(
                db_session,
                actor=admin,
                key_id="not-a-uuid",
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_purge_blocked_does_not_emit_audit(
        self,
        db_session,
        monkeypatch,
    ):
        # If the operation refuses, no audit row should be written
        # — the audit log records what *happened*, not what was
        # attempted (failures of the same operation kind would
        # otherwise be indistinguishable from successes after the
        # fact).
        monkeypatch.setattr(settings, "audit_log_retention_days", 30)
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="too-soon",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        before_purge = await _audit_rows(db_session)
        with pytest.raises(HTTPException):
            await api_key_service.purge_key(
                db_session,
                actor=admin,
                key_id=str(target.id),
            )
        after = await _audit_rows(db_session)
        assert len(after) == len(before_purge)


# ── ip_address propagation ─────────────────────────────────────────────


class TestIpAddressPropagation:
    """Every audit-log emission point must thread ``ip_address``
    through to the row so an operator can correlate actions with
    network origin."""

    @pytest.mark.asyncio
    async def test_create_propagates_ip(self, db_session):
        admin = await _make_admin(db_session)
        await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ip-create",
            is_admin=False,
            expires_in_days=30,
            ip_address="203.0.113.7",
        )
        rows = await _audit_rows(db_session)
        assert rows[-1].ip_address == "203.0.113.7"

    @pytest.mark.asyncio
    async def test_update_propagates_ip(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ip-update",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            name="renamed",
            ip_address="203.0.113.8",
        )
        rows = await _audit_rows(db_session)
        assert rows[-1].action == "update_api_key"
        assert rows[-1].ip_address == "203.0.113.8"

    @pytest.mark.asyncio
    async def test_delete_propagates_ip(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ip-del",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            ip_address="203.0.113.9",
        )
        rows = await _audit_rows(db_session)
        assert rows[-1].action == "delete_api_key"
        assert rows[-1].ip_address == "203.0.113.9"

    @pytest.mark.asyncio
    async def test_purge_propagates_ip(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "audit_log_retention_days", 0)
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ip-purge",
            is_admin=False,
            expires_in_days=30,
        )
        await api_key_service.soft_delete_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
        )
        await api_key_service.purge_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            ip_address="203.0.113.10",
        )
        rows = await _audit_rows(db_session)
        assert rows[-1].action == "purge_api_key"
        assert rows[-1].ip_address == "203.0.113.10"


# ── list_keys + serialize_key ──────────────────────────────────────────


class TestListAndSerialize:
    @pytest.mark.asyncio
    async def test_list_returns_newest_first(self, db_session):
        admin = await _make_admin(db_session)
        # admin already created; mint two more.
        k1, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="first",
            is_admin=False,
            expires_in_days=30,
        )
        k2, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="second",
            is_admin=False,
            expires_in_days=30,
        )
        keys = await api_key_service.list_keys(db_session)
        names = [k.name for k in keys]
        # Newest first.
        assert names.index("second") < names.index("first")

    def test_serialize_omits_hash(self):
        k = APIKey(
            id=uuid4(),
            name="x",
            key_hash="secret-hash-must-not-leak",
            is_admin=False,
            is_active=True,
        )
        payload = api_key_service.serialize_key(k)
        assert "key_hash" not in payload
        assert "secret-hash-must-not-leak" not in str(payload)


class TestScopeHandling:
    """The three-tier scope model (monitor / spend / admin) and the
    boolean ``is_admin`` alias that maps onto it."""

    @pytest.mark.asyncio
    async def test_create_spend_key(self, db_session):
        admin = await _make_admin(db_session)
        key, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="agent",
            scope="spend",
            expires_in_days=30,
        )
        assert key.scope == "spend"
        assert key.can_spend is True
        assert key.is_admin is False

    @pytest.mark.asyncio
    async def test_create_defaults_to_monitor(self, db_session):
        admin = await _make_admin(db_session)
        key, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="bare",
            expires_in_days=30,
        )
        assert key.scope == "monitor"
        assert key.can_spend is False

    @pytest.mark.asyncio
    async def test_create_invalid_scope_rejected(self, db_session):
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.create_key(
                db_session,
                actor=admin,
                name="bad",
                scope="superuser",
                expires_in_days=30,
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_scope_takes_precedence_over_is_admin(self, db_session):
        # When both are passed, the canonical ``scope`` wins.
        admin = await _make_admin(db_session)
        key, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="both",
            scope="spend",
            is_admin=True,
            expires_in_days=30,
        )
        assert key.scope == "spend"

    @pytest.mark.asyncio
    async def test_update_scope_to_spend(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ro",
            expires_in_days=30,
        )
        updated, changes = await api_key_service.update_key(
            db_session,
            actor=admin,
            key_id=str(target.id),
            scope="spend",
        )
        assert updated.scope == "spend"
        assert changes == {"scope": "spend"}

    @pytest.mark.asyncio
    async def test_update_invalid_scope_rejected(self, db_session):
        admin = await _make_admin(db_session)
        target, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="ro",
            expires_in_days=30,
        )
        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id=str(target.id),
                scope="root",
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_self_scope_reduction_rejected_for_real_actor(self, db_session):
        # An admin actor cannot demote its own key to a lesser scope —
        # same lockout failure mode as self-delete.
        admin = await _make_admin(db_session)
        with pytest.raises(HTTPException) as exc:
            await api_key_service.update_key(
                db_session,
                actor=admin,
                key_id=str(admin.id),
                scope="spend",
            )
        assert exc.value.status_code == 400

    @pytest.mark.asyncio
    async def test_serialize_includes_scope_and_alias(self, db_session):
        admin = await _make_admin(db_session)
        key, _ = await api_key_service.create_key(
            db_session,
            actor=admin,
            name="agent",
            scope="spend",
            expires_in_days=30,
        )
        payload = api_key_service.serialize_key(key)
        assert payload["scope"] == "spend"
        assert payload["is_admin"] is False

    def test_is_admin_setter_maps_to_scope(self):
        # The ORM-level boolean alias: True → admin, False → monitor.
        k = APIKey(id=uuid4(), name="x", key_hash="h" * 64, is_admin=True, is_active=True)
        assert k.scope == "admin"
        k.is_admin = False
        assert k.scope == "monitor"
