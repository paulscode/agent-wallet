# SPDX-License-Identifier: MIT
"""
Unit tests for app.services.audit_service — log_action.
"""

import logging
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, update

from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.services.audit_service import log_action, log_dashboard_action, verify_chain


class TestLogAction:
    """Tests for log_action audit recording."""

    @pytest.mark.asyncio
    async def test_creates_audit_entry(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="audit-test-key",
            key_hash="h" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        entry = await log_action(
            db_session,
            api_key,
            "test_action",
            "test_resource",
            details={"key": "value"},
            amount_sats=5000,
        )

        assert entry.id is not None
        assert entry.action == "test_action"
        assert entry.resource == "test_resource"
        assert entry.amount_sats == 5000
        assert entry.success is True
        assert entry.details == {"key": "value"}
        assert entry.api_key_name == "audit-test-key"

    @pytest.mark.asyncio
    async def test_records_failure(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="fail-key",
            key_hash="f" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        entry = await log_action(
            db_session,
            api_key,
            "pay_invoice",
            "lightning",
            amount_sats=1000,
            success=False,
            error_message="no route",
            ip_address="10.0.0.1",
        )

        assert entry.success is False
        assert entry.error_message == "no route"
        assert entry.ip_address == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_persisted_to_db(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="persist-key",
            key_hash="p" * 64,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        await log_action(db_session, api_key, "create_invoice", "lightning")

        result = await db_session.execute(select(AuditLog).where(AuditLog.action == "create_invoice"))
        entries = result.scalars().all()
        assert len(entries) == 1
        assert entries[0].api_key_name == "persist-key"

    @pytest.mark.asyncio
    async def test_optional_fields_default(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="minimal-key",
            key_hash="m" * 64,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        entry = await log_action(db_session, api_key, "get_balance", "wallet")

        assert entry.details is None
        assert entry.amount_sats is None
        assert entry.error_message is None
        assert entry.ip_address is None
        assert entry.success is True

    @pytest.mark.asyncio
    async def test_logs_warning_level_on_failure(self, db_session, caplog):
        """log_action should log at WARNING level when success=False."""
        api_key = APIKey(
            id=uuid4(),
            name="warn-key",
            key_hash="w" * 64,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        with caplog.at_level(logging.WARNING, logger="app.services.audit_service"):
            await log_action(
                db_session,
                api_key,
                "pay_invoice",
                "lightning",
                success=False,
                error_message="fail",
            )

        assert any("AUDIT" in r.message and "success=False" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_logs_info_level_on_success(self, db_session, caplog):
        """log_action should log at INFO level when success=True."""
        api_key = APIKey(
            id=uuid4(),
            name="info-key",
            key_hash="i" * 64,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        with caplog.at_level(logging.INFO, logger="app.services.audit_service"):
            await log_action(
                db_session,
                api_key,
                "get_balance",
                "wallet",
                success=True,
            )

        assert any("AUDIT" in r.message and "success=True" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_returns_audit_log_instance(self, db_session):
        """log_action should return the persisted AuditLog entry."""
        api_key = APIKey(
            id=uuid4(),
            name="return-key",
            key_hash="r" * 64,
            is_admin=False,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        entry = await log_action(db_session, api_key, "check", "system")

        assert isinstance(entry, AuditLog)
        assert entry.api_key_name == "return-key"


class TestLogDashboardAction:
    """Tests for log_dashboard_action."""

    @pytest.mark.asyncio
    async def test_persists_and_logs(self, db_session, caplog):
        """log_dashboard_action commits entry and emits structured log."""
        from app.dashboard import DASHBOARD_KEY_ID

        with caplog.at_level(logging.INFO, logger="app.services.audit_service"):
            entry = await log_dashboard_action(
                db_session,
                DASHBOARD_KEY_ID,
                "test_action",
                "test_resource",
                amount_sats=5000,
                ip_address="10.0.0.1",
            )

        assert isinstance(entry, AuditLog)
        assert entry.api_key_name == "__dashboard__"
        assert entry.action == "test_action"
        assert any("AUDIT" in r.message and "__dashboard__" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_failed_action_logs_warning(self, db_session, caplog):
        """log_dashboard_action logs at WARNING level for failed actions."""
        from app.dashboard import DASHBOARD_KEY_ID

        with caplog.at_level(logging.WARNING, logger="app.services.audit_service"):
            entry = await log_dashboard_action(
                db_session,
                DASHBOARD_KEY_ID,
                "failed_action",
                "auth",
                success=False,
                error_message="something went wrong",
            )

        assert entry.success is False
        assert any(r.levelno == logging.WARNING for r in caplog.records if "AUDIT" in r.message)


class TestHashChainConsistency:
    """The persisted entry_hash must match a re-computed hash after flush."""

    @pytest.mark.asyncio
    async def test_finalize_persists_consistent_hash(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="chain-key",
            key_hash="c" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        entry = await log_action(
            db_session,
            api_key,
            "pay_invoice",
            "lightning",
            details={"hint": "abc"},
            amount_sats=1234,
        )

        result = await db_session.execute(select(AuditLog).where(AuditLog.id == entry.id))
        row = result.scalar_one()
        assert row.entry_hash == row.compute_hash()

    @pytest.mark.asyncio
    async def test_verify_chain_clean_after_inserts(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="chain-key",
            key_hash="c" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        for i in range(3):
            await log_action(
                db_session,
                api_key,
                f"action_{i}",
                "test",
                details={"i": i},
                amount_sats=100 + i,
            )

        result = await verify_chain(db_session)
        assert result["ok"] is True
        assert result["checked"] == 3
        assert result["first_bad_id"] is None

    @pytest.mark.asyncio
    async def test_verify_chain_detects_field_tamper(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="chain-key",
            key_hash="c" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        first = await log_action(db_session, api_key, "a1", "r")
        await log_action(db_session, api_key, "a2", "r")

        # Tamper a column without rewriting entry_hash.
        await db_session.execute(update(AuditLog).where(AuditLog.id == first.id).values(details={"tampered": True}))
        await db_session.commit()
        db_session.expire_all()

        result = await verify_chain(db_session)
        assert result["ok"] is False
        assert result["first_bad_id"] == str(first.id)
        assert result["first_bad_reason"] == "entry_hash mismatch"

    @pytest.mark.asyncio
    async def test_verify_chain_detects_chain_break(self, db_session):
        api_key = APIKey(
            id=uuid4(),
            name="chain-key",
            key_hash="c" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        await log_action(db_session, api_key, "a1", "r")
        second = await log_action(db_session, api_key, "a2", "r")

        # Break the chain by clearing prev_hash on the second entry.
        await db_session.execute(update(AuditLog).where(AuditLog.id == second.id).values(prev_hash=None))
        await db_session.commit()
        # Discard cached ORM state so verify_chain reads the post-tamper row.
        db_session.expire_all()

        result = await verify_chain(db_session)
        assert result["ok"] is False
        assert result["first_bad_id"] == str(second.id)
        assert result["first_bad_reason"] == "prev_hash mismatch"

    @pytest.mark.asyncio
    async def test_verify_chain_after_retention_cleanup(self, db_session):
        """``prune_audit_log`` leaves the chain verifiable across a cut.

        After a retention delete the oldest surviving row's ``prev_hash``
        references a now-removed predecessor; ``verify_chain`` seeds its
        walk from the head's own back-link, so the chain still verifies
        without rewriting any surviving row's hash.
        """
        from datetime import datetime, timedelta, timezone

        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import prune_audit_log, reanchor_chain

        # Sentinel API key for the retention-anchor row's FK target.
        # In production this is created by alembic migration 002; the
        # SQLite test harness only runs Base.metadata.create_all.
        sentinel = APIKey(
            id=DASHBOARD_KEY_ID,
            name="__dashboard_sentinel__",
            key_hash="__dashboard_sentinel__",
            is_admin=True,
            is_active=True,
        )
        db_session.add(sentinel)

        api_key = APIKey(
            id=uuid4(),
            name="chain-key",
            key_hash="c" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        for i in range(5):
            await log_action(db_session, api_key, f"action_{i}", "r")

        # Backdate the oldest 3 rows so they fall outside the cutoff.
        old_ts = datetime.now(timezone.utc) - timedelta(days=10)
        old_ids = (
            (
                await db_session.execute(
                    select(AuditLog.id).order_by(AuditLog.created_at.asc(), AuditLog.id.asc()).limit(3)
                )
            )
            .scalars()
            .all()
        )
        await db_session.execute(update(AuditLog).where(AuditLog.id.in_(old_ids)).values(created_at=old_ts))
        await db_session.commit()
        # Backdating ``created_at`` out of band changes the hashed payload,
        # so re-anchor to re-establish a consistent baseline (the same
        # deliberate action an operator runs after a restore) before
        # exercising the retention cut.
        await reanchor_chain(db_session, api_key.id, api_key.name)

        cutoff = datetime.now(timezone.utc) - timedelta(days=1)
        result = await prune_audit_log(db_session, cutoff, DASHBOARD_KEY_ID)

        assert result["deleted"] == 3
        assert result["skipped"] is False
        assert result["anchor_id"] is not None

        db_session.expire_all()
        verify = await verify_chain(db_session)
        assert verify["ok"] is True, verify
        # 2 surviving original rows + reanchor entry + truncate anchor
        assert verify["checked"] == 4


class TestAuditLogHashCoverage:
    """Mutating any hashed attribute on an ``AuditLog`` row must change
    ``compute_hash()``. This locks in coverage of every column that
    feeds the chain so a future field addition that is missed in the
    digest is caught here instead of by an unverifiable production
    chain."""

    def _make_entry(self, **overrides):
        from datetime import datetime, timezone

        defaults = dict(
            id=uuid4(),
            api_key_id=uuid4(),
            api_key_name="key-1",
            action="pay_invoice",
            resource="lightning",
            details={"hint": "abc"},
            amount_sats=1000,
            success=True,
            error_message=None,
            ip_address="10.0.0.1",
            prev_hash="0" * 64,
            created_at=datetime(2026, 4, 30, 12, 0, tzinfo=timezone.utc),
        )
        defaults.update(overrides)
        return AuditLog(**defaults)

    def test_hash_changes_when_amount_mutated(self):
        entry = self._make_entry()
        h1 = entry.compute_hash()
        entry.amount_sats = 1001
        assert h1 != entry.compute_hash()

    def test_hash_changes_when_success_flag_mutated(self):
        entry = self._make_entry(success=True)
        h1 = entry.compute_hash()
        entry.success = False
        assert h1 != entry.compute_hash()

    def test_hash_changes_when_error_message_mutated(self):
        entry = self._make_entry(error_message=None)
        h1 = entry.compute_hash()
        entry.error_message = "tampered"
        assert h1 != entry.compute_hash()

    def test_hash_changes_when_details_mutated(self):
        entry = self._make_entry(details={"hint": "abc"})
        h1 = entry.compute_hash()
        entry.details = {"hint": "xyz"}
        assert h1 != entry.compute_hash()

    def test_hash_changes_when_ip_address_mutated(self):
        entry = self._make_entry(ip_address="10.0.0.1")
        h1 = entry.compute_hash()
        entry.ip_address = "10.0.0.2"
        assert h1 != entry.compute_hash()


class TestVerifyChainStreaming:
    """Streaming verifier walks the entire chain regardless of size."""

    @pytest.mark.asyncio
    async def test_verifies_more_than_legacy_cap(self, db_session):
        from uuid import uuid4

        from app.core.security import hash_api_key
        from app.models.api_key import APIKey
        from app.services.audit_service import log_action, verify_chain

        admin = APIKey(
            id=uuid4(),
            name="admin",
            key_hash=hash_api_key("test-key-streaming"),
            is_active=True,
            is_admin=True,
        )
        db_session.add(admin)
        await db_session.commit()

        # Insert more entries than the previous hard cap of 10_000 would
        # have allowed — kept small here for test speed; the cap removal
        # is what matters.
        N = 50
        for i in range(N):
            await log_action(
                db_session,
                api_key=admin,
                action=f"a_{i}",
                resource="r",
                success=True,
                ip_address="127.0.0.1",
            )

        # Default mode: limit=None walks everything via cursor pagination
        result = await verify_chain(db_session, batch_size=7)
        assert result["ok"] is True
        assert result["checked"] == N
        assert result["first_bad_id"] is None

    @pytest.mark.asyncio
    async def test_legacy_limit_still_caps_walk(self, db_session):
        from uuid import uuid4

        from app.core.security import hash_api_key
        from app.models.api_key import APIKey
        from app.services.audit_service import log_action, verify_chain

        admin = APIKey(
            id=uuid4(),
            name="admin2",
            key_hash=hash_api_key("test-key-legacy-cap"),
            is_active=True,
            is_admin=True,
        )
        db_session.add(admin)
        await db_session.commit()

        for i in range(20):
            await log_action(
                db_session,
                api_key=admin,
                action=f"b_{i}",
                resource="r",
                success=True,
                ip_address="127.0.0.1",
            )

        result = await verify_chain(db_session, limit=5, batch_size=3)
        assert result["ok"] is True
        assert result["checked"] == 5


class TestKeyedChain:
    """The hash chain is keyed by SECRET_KEY, and retention refuses to run
    on a chain that does not verify rather than rewriting over it."""

    def test_hash_depends_on_secret_key(self, monkeypatch):
        """Two different SECRET_KEYs produce different chain hashes for the
        same payload — the chain cannot be reproduced without the key."""
        from datetime import datetime, timezone

        from app.core import security

        entry = AuditLog(
            id=uuid4(),
            api_key_id=uuid4(),
            api_key_name="k",
            action="pay_invoice",
            resource="lightning",
            details={"x": 1},
            amount_sats=10,
            success=True,
            error_message=None,
            ip_address="1.2.3.4",
            prev_hash=None,
            created_at=datetime(2026, 6, 18, tzinfo=timezone.utc),
        )
        monkeypatch.setattr(security.settings, "secret_key", "a" * 64)
        h_a = entry.compute_hash()
        monkeypatch.setattr(security.settings, "secret_key", "b" * 64)
        h_b = entry.compute_hash()
        assert h_a != h_b

    @pytest.mark.asyncio
    async def test_prune_refuses_and_alerts_on_broken_chain(self, db_session, monkeypatch):
        """A chain that fails verification is left intact (no delete, no
        rewrite) and a security alert is raised."""
        from datetime import datetime, timedelta, timezone

        from app.dashboard import DASHBOARD_KEY_ID
        from app.services import audit_service
        from app.services.audit_service import prune_audit_log

        db_session.add(
            APIKey(
                id=DASHBOARD_KEY_ID,
                name="__dashboard_sentinel__",
                key_hash="__dashboard_sentinel__",
                is_admin=True,
                is_active=True,
            )
        )
        api_key = APIKey(id=uuid4(), name="k", key_hash="e" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()

        for i in range(4):
            await log_action(db_session, api_key, f"a{i}", "r")

        # Tamper a row's stored hash so the chain no longer verifies.
        first_id = (
            await db_session.execute(select(AuditLog.id).order_by(AuditLog.created_at.asc()).limit(1))
        ).scalar_one()
        await db_session.execute(update(AuditLog).where(AuditLog.id == first_id).values(entry_hash="0" * 64))
        await db_session.commit()

        alerts: list[tuple] = []

        async def _capture(event, message, details=None):
            alerts.append((event, message, details))

        monkeypatch.setattr(audit_service, "send_alert", _capture, raising=False)
        import app.services.alert_service as alert_mod

        monkeypatch.setattr(alert_mod, "send_alert", _capture)

        before = (await db_session.execute(select(AuditLog))).scalars().all()
        cutoff = datetime.now(timezone.utc) + timedelta(days=1)  # everything is "old"
        result = await prune_audit_log(db_session, cutoff, DASHBOARD_KEY_ID)

        assert result["skipped"] is True
        assert result["deleted"] == 0
        db_session.expire_all()
        after = (await db_session.execute(select(AuditLog))).scalars().all()
        assert len(after) == len(before)  # nothing deleted
        assert any(a[0] == "audit_chain_broken" for a in alerts)

    @pytest.mark.asyncio
    async def test_reanchor_recovers_after_key_rotation(self, db_session, monkeypatch):
        """Re-anchoring re-establishes a verifiable chain and records its
        own audited entry."""
        from app.core import security
        from app.services.audit_service import reanchor_chain

        api_key = APIKey(id=uuid4(), name="rot", key_hash="f" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()
        key_id, key_name = api_key.id, api_key.name

        monkeypatch.setattr(security.settings, "secret_key", "k" * 64)
        for i in range(3):
            await log_action(db_session, api_key, f"a{i}", "r")
        assert (await verify_chain(db_session))["ok"] is True

        # Rotating the key invalidates every stored hash.
        monkeypatch.setattr(security.settings, "secret_key", "z" * 64)
        assert (await verify_chain(db_session))["ok"] is False

        out = await reanchor_chain(db_session, key_id, key_name)
        assert out["reanchored"] == 3
        assert out["was_consistent"] is False
        db_session.expire_all()
        assert (await verify_chain(db_session))["ok"] is True
        anchor = (
            await db_session.execute(select(AuditLog).where(AuditLog.action == "audit_chain_reanchor"))
        ).scalar_one()
        assert anchor.api_key_name == "rot"

    @pytest.mark.asyncio
    async def test_verify_chain_survives_key_rotation_with_previous(self, db_session, monkeypatch):
        """A chain written under the old key still verifies after rotation
        when ``SECRET_KEY_PREVIOUS`` holds the old value — no destructive
        re-anchor required."""
        from app.core import security

        api_key = APIKey(id=uuid4(), name="rot2", key_hash="9" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()

        monkeypatch.setattr(security.settings, "secret_key", "k" * 64)
        monkeypatch.setattr(security.settings, "secret_key_previous", "")
        for i in range(3):
            await log_action(db_session, api_key, f"a{i}", "r")
        assert (await verify_chain(db_session))["ok"] is True

        # Rotate: old key moves to PREVIOUS, a fresh key becomes current.
        monkeypatch.setattr(security.settings, "secret_key", "z" * 64)
        monkeypatch.setattr(security.settings, "secret_key_previous", "k" * 64)
        db_session.expire_all()
        # Without the fallback this would be False; the previous-key fallback
        # keeps the rows written under the old key verifiable.
        assert (await verify_chain(db_session))["ok"] is True

        # A wrong previous key must NOT rescue a genuinely invalid chain.
        monkeypatch.setattr(security.settings, "secret_key_previous", "q" * 64)
        db_session.expire_all()
        assert (await verify_chain(db_session))["ok"] is False

    @pytest.mark.asyncio
    async def test_verify_chain_mixed_key_chain(self, db_session, monkeypatch):
        """A chain with OLD rows under the previous key and NEW rows under the
        current key — linked across the rotation boundary — verifies end-to-end,
        and post-rotation writes use the CURRENT key (verifiable without the
        previous key once it is retired)."""
        from app.core import security

        api_key = APIKey(id=uuid4(), name="mix", key_hash="5" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()

        # Rows 0–2 written under the old key.
        monkeypatch.setattr(security.settings, "secret_key", "k" * 64)
        monkeypatch.setattr(security.settings, "secret_key_previous", "")
        for i in range(3):
            await log_action(db_session, api_key, f"old{i}", "r")

        # Rotate: old → previous, fresh current. Then write rows 3–5 under the
        # new current key, linked onto the old tail.
        monkeypatch.setattr(security.settings, "secret_key", "z" * 64)
        monkeypatch.setattr(security.settings, "secret_key_previous", "k" * 64)
        for i in range(3):
            await log_action(db_session, api_key, f"new{i}", "r")

        db_session.expire_all()
        # Whole mixed-key chain (current+previous coexisting) verifies.
        assert (await verify_chain(db_session))["ok"] is True

        # Retire the previous key: the post-rotation rows must still verify
        # under the current key alone (proves _finalize_entry wrote them under
        # the CURRENT key, not the previous one). The first three rows now fail,
        # so the chain as a whole no longer fully verifies — but the failure is
        # in the OLD segment, confirming the NEW segment is current-keyed.
        monkeypatch.setattr(security.settings, "secret_key_previous", "")
        db_session.expire_all()
        result = await verify_chain(db_session)
        assert result["ok"] is False
        # The first inconsistent row is one of the OLD rows, not a new one.
        first_bad = (
            await db_session.execute(select(AuditLog).where(AuditLog.id == UUID(result["first_bad_id"])))
        ).scalar_one()
        assert first_bad.action.startswith("old")

    @pytest.mark.asyncio
    async def test_current_anchor_reports_head_and_count(self, db_session):
        """``current_anchor`` returns the row count and the newest row's
        keyed entry_hash as the externally-anchorable head."""
        from app.services.audit_service import current_anchor

        api_key = APIKey(id=uuid4(), name="anc", key_hash="8" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()

        for i in range(3):
            await log_action(db_session, api_key, f"a{i}", "r")

        head = (
            await db_session.execute(select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(1))
        ).scalar_one()

        anchor = await current_anchor(db_session)
        assert anchor["count"] == 3
        assert anchor["head_hash"] == head.entry_hash
        assert anchor["head_id"] == str(head.id)
        assert anchor["oldest_created_at"] is not None
        assert anchor["newest_created_at"] is not None

    @pytest.mark.asyncio
    async def test_emit_audit_anchor_sends_signed_event(self, db_session, monkeypatch):
        """``emit_audit_anchor`` ships an ``audit_anchor`` alert carrying the
        head/count snapshot so an off-box observer can detect truncation."""
        from app.services.audit_service import emit_audit_anchor

        api_key = APIKey(id=uuid4(), name="anc2", key_hash="7" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()
        for i in range(2):
            await log_action(db_session, api_key, f"a{i}", "r")

        sent: list[tuple] = []

        async def _capture(event, message, details=None):
            sent.append((event, message, details))

        monkeypatch.setattr("app.services.alert_service.send_alert", _capture)

        out = await emit_audit_anchor(db_session, deleted=3)
        assert out["count"] == 2
        assert out["deleted"] == 3
        assert len(sent) == 1
        event, _msg, details = sent[0]
        assert event == "audit_anchor"
        assert details["count"] == 2
        assert details["head_hash"] == out["head_hash"]
        # The in-process deletion count MUST be in the signed payload — it is
        # the datum the receiver uses to authenticate count deltas.
        assert details["deleted"] == 3

    @pytest.mark.asyncio
    async def test_prune_emits_anchor_with_post_prune_count_and_deleted(self, db_session, monkeypatch):
        """The anchor emitted by a real prune reflects the SURVIVING count and
        carries the number of rows that prune actually removed."""
        from datetime import datetime, timedelta, timezone

        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import prune_audit_log, reanchor_chain

        sentinel = APIKey(
            id=DASHBOARD_KEY_ID,
            name="__dashboard_sentinel__",
            key_hash="__dashboard_sentinel__",
            is_admin=True,
            is_active=True,
        )
        db_session.add(sentinel)
        api_key = APIKey(id=uuid4(), name="pk", key_hash="6" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()

        # Three old rows (will be pruned) + two recent rows (survive).
        old_ts = datetime.now(timezone.utc) - timedelta(days=10)
        for i in range(3):
            e = await log_action(db_session, api_key, f"old{i}", "r")
            await db_session.execute(update(AuditLog).where(AuditLog.id == e.id).values(created_at=old_ts))
        await db_session.commit()
        for i in range(2):
            await log_action(db_session, api_key, f"new{i}", "r")
        # Backdating created_at after finalisation invalidates the stored
        # hashes; re-anchor so the chain is valid with the new timestamps
        # (mirrors test_verify_chain_after_retention_cleanup).
        await reanchor_chain(db_session, api_key.id, api_key.name)
        db_session.expire_all()

        sent: list[tuple] = []

        async def _capture(event, message, details=None):
            sent.append((event, message, details))

        monkeypatch.setattr("app.services.alert_service.send_alert", _capture)

        cutoff = datetime.now(timezone.utc) - timedelta(days=1)
        result = await prune_audit_log(db_session, cutoff, DASHBOARD_KEY_ID)
        assert result["deleted"] == 3

        anchors = [d for (ev, _m, d) in sent if ev == "audit_anchor"]
        assert len(anchors) == 1
        anchor = anchors[0]
        # The signed anchor carries the in-process deletion count for this cycle
        assert anchor["deleted"] == 3
        # Survivors: 2 recent rows + 1 reanchor row + 1 audit_truncate anchor.
        assert anchor["count"] == 4
        # And it reflects POST-prune state, matching a fresh snapshot.
        from app.services.audit_service import current_anchor

        live = await current_anchor(db_session)
        assert anchor["count"] == live["count"]
        assert anchor["head_hash"] == live["head_hash"]

    def test_anchor_reconciliation_signals(self):
        """Lock in the two receiver-side checks SECURITY.md documents over the
        signed anchor stream."""

        # ── Check 2: ``count + Σdeleted`` ("rows that ever existed") is
        # non-decreasing; a decrease means rows vanished unreported. ──
        def ever_existed(count, cum_deleted):
            return count + cum_deleted

        # Legit growth + prune: 100 rows, then prune 10 (count 90, Σdel 10).
        assert ever_existed(90, 10) >= ever_existed(100, 0)
        # Legit heartbeat: rows only grow.
        assert ever_existed(120, 0) >= ever_existed(100, 0)
        # ATTACK: 4000 oldest rows deleted out of band; Σdeleted does NOT rise
        # to cover it, so "ever existed" drops — detected.
        assert not (ever_existed(6000, 0) >= ever_existed(10000, 0))

        # ── Check 1 (load-bearing for the oldest-rows threat): with retention
        # DISABLED nothing is legitimately deleted, so ``oldest_created_at``
        # must never move forward. Any advance — even one row — is tampering,
        # including slow drip that check 2 would miss. ──
        def front_truncation_detected(oldest_prev_iso, oldest_now_iso, retention_disabled):
            if retention_disabled:
                return oldest_now_iso > oldest_prev_iso  # must never advance
            return False  # retention mode: bounded check elsewhere (cutoff)

        assert front_truncation_detected("2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00", True)
        assert not front_truncation_detected("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", True)

    @pytest.mark.asyncio
    async def test_anchor_exposes_oldest_created_at_for_front_truncation_check(self, db_session):
        """The anchor must carry ``oldest_created_at`` — the field the receiver
        watches for the precise (drip-resistant) front-truncation signal."""
        from app.services.audit_service import current_anchor

        api_key = APIKey(id=uuid4(), name="oc", key_hash="4" * 64, is_admin=True, is_active=True)
        db_session.add(api_key)
        await db_session.commit()
        for i in range(2):
            await log_action(db_session, api_key, f"a{i}", "r")

        anchor = await current_anchor(db_session)
        assert anchor["oldest_created_at"] is not None
        assert anchor["newest_created_at"] is not None
        assert anchor["oldest_created_at"] <= anchor["newest_created_at"]
