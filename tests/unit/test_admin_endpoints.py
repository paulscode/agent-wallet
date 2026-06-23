# SPDX-License-Identifier: MIT
"""
Unit tests for app.api.admin endpoint functions.

Calls endpoint functions directly (not via ASGI transport) to ensure
coverage measurement works correctly with pytest-cov.

API-key *creation / update / deletion / purge* deliberately do **not**
live on this API-key-authed surface — they are operator-only and reached
through the dashboard's session-authed router. ``TestKeyMutationAbsent``
locks that invariant in; the lifecycle behaviour itself is covered by
``test_api_key_service.py`` and the dashboard tests.
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import Request

from app.api.admin import (
    get_audit_log,
    health_check,
    list_api_keys,
    reanchor_audit_log,
)
from app.models.api_key import APIKey


def _mock_request() -> MagicMock:
    req = MagicMock(spec=Request)
    req.client.host = "127.0.0.1"
    return req


def _make_admin_key() -> APIKey:
    return APIKey(
        id=uuid4(),
        name="admin",
        key_hash="a" * 64,
        scope="admin",
        is_active=True,
    )


class TestKeyMutationAbsent:
    """Regression guard: no API key — of any scope — can mint, promote,
    or revoke a key via the admin REST surface. Only the read-only
    inventory listing remains; mutation is dashboard-session-only."""

    def test_mutation_helpers_not_exported(self):
        import app.api.admin as admin_mod

        for name in (
            "create_api_key",
            "update_api_key",
            "delete_api_key",
            "purge_api_key",
            "CreateAPIKeyRequest",
            "UpdateAPIKeyRequest",
        ):
            assert not hasattr(admin_mod, name), f"admin surface unexpectedly exposes {name}"

    def test_router_has_no_key_mutation_routes(self):
        from app.api.admin import router

        for route in router.routes:
            path = getattr(route, "path", "")
            if "api-keys" in path:
                methods = getattr(route, "methods", set()) or set()
                assert methods <= {"GET", "HEAD"}, f"{path} exposes mutating methods {methods}"


class TestListAPIKeys:
    @pytest.mark.asyncio
    async def test_list_returns_keys(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        result = await list_api_keys(admin, db_session)
        assert "keys" in result
        assert len(result["keys"]) >= 1
        assert result["keys"][0]["name"] == "admin"
        # The list surfaces the canonical scope alongside the boolean alias.
        assert result["keys"][0]["scope"] == "admin"
        assert result["keys"][0]["is_admin"] is True


class TestGetAuditLog:
    @pytest.mark.asyncio
    async def test_audit_log_default(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        result = await get_audit_log(admin, db_session, limit=50, action=None)
        assert "entries" in result

    @pytest.mark.asyncio
    async def test_audit_log_with_action_filter(self, db_session):
        from app.services import api_key_service

        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        # Generate an audit entry via the service (the only key-mint path).
        await api_key_service.create_key(
            db_session,
            actor=admin,
            name="audit-trigger",
            expires_in_days=None,
            scope="monitor",
        )

        result = await get_audit_log(admin, db_session, limit=50, action="create_api_key")
        assert all(e["action"] == "create_api_key" for e in result["entries"])


class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy_when_lnd_reachable(self):
        admin = _make_admin_key()
        with patch("app.api.admin.lnd_service.get_info", new_callable=AsyncMock) as mock_info:
            mock_info.return_value = (
                {"alias": "test", "synced_to_chain": True, "block_height": 800000, "version": "0.18.0"},
                None,
            )
            result = await health_check(admin)
        assert result["status"] == "healthy"
        assert result["lnd_info"]["alias"] == "test"

    @pytest.mark.asyncio
    async def test_degraded_when_lnd_unreachable(self):
        admin = _make_admin_key()
        with patch("app.api.admin.lnd_service.get_info", new_callable=AsyncMock) as mock_info:
            mock_info.return_value = (None, "connection refused")
            result = await health_check(admin)
        assert result["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_degraded_when_lnd_raises(self):
        admin = _make_admin_key()
        with patch("app.api.admin.lnd_service.get_info", new_callable=AsyncMock) as mock_info:
            mock_info.side_effect = Exception("timeout")
            result = await health_check(admin)
        assert result["status"] == "degraded"


class TestAuditLogPurge:
    """The audit-log cleanup task removes entries older than
    ``AUDIT_LOG_RETENTION_DAYS`` and is a no-op when the retention is
    set to 0 (= keep forever)."""

    @pytest.mark.asyncio
    async def test_cleanup_deletes_old_entries(self, db_session):
        from datetime import datetime, timedelta, timezone

        from app.models.audit_log import AuditLog
        from app.tasks.boltz_tasks import _run_cleanup_audit_logs

        old_entry = AuditLog(
            api_key_id=uuid4(),
            api_key_name="test",
            action="test_action",
            resource="test",
            success=True,
        )
        old_entry.created_at = datetime.now(timezone.utc) - timedelta(days=100)
        db_session.add(old_entry)

        recent_entry = AuditLog(
            api_key_id=uuid4(),
            api_key_name="test",
            action="test_action",
            resource="test",
            success=True,
        )
        recent_entry.created_at = datetime.now(timezone.utc) - timedelta(days=10)
        db_session.add(recent_entry)
        await db_session.commit()

        # Anchor the directly-inserted rows into a valid chain so the
        # retention cut (which verifies before deleting) can run.
        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import reanchor_chain

        await reanchor_chain(db_session, DASHBOARD_KEY_ID, "__dashboard__")

        with (
            patch("app.tasks.boltz_tasks.settings") as mock_settings,
            patch("app.core.database.get_db_context") as mock_ctx,
        ):
            mock_settings.audit_log_retention_days = 90

            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def _fake_ctx():
                yield db_session

            mock_ctx.return_value = _fake_ctx()

            result = await _run_cleanup_audit_logs()

        assert result["deleted"] == 1
        assert result["retention_days"] == 90

    @pytest.mark.asyncio
    async def test_cleanup_disabled_when_zero(self):
        """Retention disabled does not prune but still emits a heartbeat
        anchor (so off-box truncation detection keeps working)."""
        from unittest.mock import MagicMock

        from app.tasks.boltz_tasks import _run_cleanup_audit_logs

        emitted: list[int] = []

        async def _emit(db, *, deleted=0):
            emitted.append(deleted)
            return {"count": 0, "deleted": deleted}

        class _Ctx:
            async def __aenter__(self):
                return MagicMock()

            async def __aexit__(self, *exc):
                return False

        with (
            patch("app.tasks.boltz_tasks.settings") as mock_settings,
            patch("app.core.database.get_db_context", return_value=_Ctx()),
            patch("app.services.audit_service.emit_audit_anchor", _emit),
        ):
            mock_settings.audit_log_retention_days = 0
            result = await _run_cleanup_audit_logs()

        assert result["deleted"] == 0
        assert "disabled" in result["detail"]
        assert emitted == [0]


class TestVerifyAuditLogEndpoint:
    """``GET /v1/admin/audit-log/verify`` is the operator-facing
    surface of the chain verifier. A clean, freshly-seeded log must
    return ``ok=true``; a row tampered after the fact must surface the
    offending id and a reason."""

    @pytest.mark.asyncio
    async def test_verify_endpoint_clean_after_inserts(self, db_session):
        from app.api.admin import verify_audit_log
        from app.services.audit_service import log_action

        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        for i in range(3):
            await log_action(
                db_session,
                api_key=admin,
                action=f"action_{i}",
                resource="test",
                success=True,
                ip_address="127.0.0.1",
            )

        result = await verify_audit_log(admin_key=admin, db=db_session, limit=1000, batch_size=1000)
        assert result["ok"] is True
        assert result["checked"] >= 3
        assert result.get("first_bad_id") in (None, "")

    @pytest.mark.asyncio
    async def test_verify_endpoint_after_tamper(self, db_session):
        from sqlalchemy import update

        from app.api.admin import verify_audit_log
        from app.models.audit_log import AuditLog
        from app.services.audit_service import log_action

        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        first = await log_action(
            db_session,
            api_key=admin,
            action="first",
            resource="test",
            success=True,
            ip_address="127.0.0.1",
        )
        await log_action(
            db_session,
            api_key=admin,
            action="second",
            resource="test",
            success=True,
            ip_address="127.0.0.1",
        )

        # Mutate a hashed column without rewriting entry_hash.
        await db_session.execute(update(AuditLog).where(AuditLog.id == first.id).values(details={"tampered": True}))
        await db_session.commit()
        db_session.expire_all()

        result = await verify_audit_log(admin_key=admin, db=db_session, limit=1000, batch_size=1000)
        assert result["ok"] is False
        assert result["first_bad_id"] == str(first.id)
        assert result["first_bad_reason"] == "entry_hash mismatch"


class TestReanchorEndpoint:
    """The admin re-anchor endpoint re-baselines the chain and attributes
    the recovery to the calling admin key."""

    @pytest.mark.asyncio
    async def test_reanchor_endpoint_records_actor(self, db_session):
        from sqlalchemy import select

        from app.models.audit_log import AuditLog
        from app.services.audit_service import log_action

        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        for i in range(2):
            await log_action(db_session, admin, f"a{i}", "r")

        result = await reanchor_audit_log(admin_key=admin, db=db_session)

        assert result["reanchored"] >= 2
        anchor = (
            await db_session.execute(select(AuditLog).where(AuditLog.action == "audit_chain_reanchor"))
        ).scalar_one()
        assert anchor.api_key_name == admin.name
