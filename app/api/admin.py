# SPDX-License-Identifier: MIT
"""
Admin API endpoints — API key management, audit logs, system health.

All endpoints require an admin API key.
"""

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import API_V1_PREFIX, settings
from app.core.database import get_db
from app.core.security import get_admin_key
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.services import api_key_service
from app.services.audit_service import current_anchor, reanchor_chain, verify_chain
from app.services.lnd_service import lnd_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix=f"{API_V1_PREFIX}/admin", tags=["admin"])


# API-key creation, update, deletion, and purge are operator-only and
# live on the dashboard's session-authed endpoints. They are deliberately
# absent from this API-key-authed surface so that no API key — of any
# scope — can mint, promote, or revoke a key. This list view stays
# (read-only key inventory for operator tooling).
@router.get("/api-keys")
async def list_api_keys(
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List all API keys (without hashes)."""
    keys = await api_key_service.list_keys(db)
    return {
        "keys": [
            {
                "id": str(k.id),
                "name": k.name,
                "scope": k.scope,
                "is_admin": k.is_admin,
                "is_active": k.is_active,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "created_at": k.created_at.isoformat(),
            }
            for k in keys
        ]
    }


@router.get("/audit-log")
async def get_audit_log(
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    action: Optional[str] = Query(default=None, max_length=50, pattern=r"^[a-zA-Z_]+$"),
) -> Any:
    """Get recent audit log entries."""
    query = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        query = query.where(AuditLog.action == action)
    result = await db.execute(query)
    entries = result.scalars().all()
    return {
        "entries": [
            {
                "id": str(e.id),
                "api_key_name": e.api_key_name,
                "action": e.action,
                "resource": e.resource,
                "details": e.details,
                "amount_sats": e.amount_sats,
                "success": e.success,
                "error_message": e.error_message,
                "ip_address": e.ip_address,
                "created_at": e.created_at.isoformat(),
            }
            for e in entries
        ]
    }


@router.get("/audit-log/verify")
async def verify_audit_log(
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
    limit: int | None = Query(
        default=None,
        ge=1,
        description=("Maximum number of entries to verify. Omit to verify the entire chain in batches (recommended)."),
    ),
    batch_size: int = Query(default=1000, ge=100, le=10000),
) -> Any:
    """Walk the audit log and verify every entry's hash chain.

    By default the entire chain is verified end-to-end using cursor
    pagination so memory usage stays bounded regardless of audit-log
    size. Pass ``limit`` to cap the walk for quick spot checks.

    Returns the count of entries checked, an ``ok`` flag, and — on
    failure — the id and reason of the first inconsistent entry.
    """
    # Clamp batch_size defensively; this endpoint is admin-only but
    # bad values would still degrade query plans.
    bs = max(100, min(int(batch_size), 10000))
    result = await verify_chain(db, limit=limit, batch_size=bs)
    # Surface the current externally-anchorable head/count so operators can
    # reconcile it against the signed ``audit_anchor`` events their webhook
    # receiver has retained (front-truncation detection).
    result["anchor"] = await current_anchor(db)
    return result


@router.post("/audit-log/reanchor")
async def reanchor_audit_log(
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Re-anchor the audit hash chain under the current key.

    Verification fails legitimately after a database restore or a
    SECRET_KEY rotation, and retention pruning then refuses to run until
    the chain verifies. This deliberate, admin-only action recomputes the
    chain from its genesis and records its own ``audit_chain_reanchor``
    entry (actor + the pre-re-anchor verdict) so the recovery is part of
    the tamper-evident record.

    Returns the number of rows re-anchored, whether the chain verified
    beforehand, and — if not — the first inconsistent entry id.
    """
    return await reanchor_chain(db, admin_key.id, admin_key.name)


@router.get("/health")
async def health_check(admin_key: APIKey = Depends(get_admin_key)) -> Any:
    """System health check — verifies LND connectivity.

    For a per-service breakdown (LND, Boltz, mempool, BOLT 12),
    see :http:get:`/v1/admin/services`.
    """
    lnd_ok = False
    lnd_info = None
    try:
        info, _err = await lnd_service.get_info()
        if info:
            lnd_ok = True
            lnd_info = {
                "alias": info.get("alias"),
                "synced_to_chain": info.get("synced_to_chain"),
                "block_height": info.get("block_height"),
                "version": info.get("version"),
            }
    except Exception:
        pass

    # Surface whether rate-limiting is currently active so an operator
    # who set RATE_LIMIT_FAIL_POLICY=closed can verify Redis is up
    # without staring at logs.
    rate_limiting_active = False
    try:
        from app.core.rate_limit import get_redis

        redis = await get_redis()
        await redis.ping()  # type: ignore[misc]  # redis.asyncio ping() typed as Awaitable[bool]|bool (ResponseT); async client always returns awaitable
        rate_limiting_active = True
    except Exception:
        rate_limiting_active = False

    return {
        "status": "healthy" if lnd_ok else "degraded",
        "lnd_connected": lnd_ok,
        "lnd_info": lnd_info,
        "rate_limiting_active": rate_limiting_active,
        "rate_limit_fail_policy": settings.rate_limit_fail_policy,
    }


@router.get("/services")
async def services_health(admin_key: APIKey = Depends(get_admin_key)) -> Any:
    """Unified per-service health snapshot for operator dashboards.

    Returns one entry per registered external dependency (LND,
    Boltz, mempool, BOLT 12 gateway). Each entry includes a
    breaker state, last-success timestamp, last-error message, and
    service-specific ``extra`` fields. The endpoint never blocks on
    upstream calls — values are read from in-process state updated
    by the retry wrappers.
    """
    from app.services.health import all_health

    return {"services": [h.snapshot() for h in all_health()]}


@router.post("/tor/reload")
async def reload_tor_config(
    admin_key: APIKey = Depends(get_admin_key),
) -> Any:
    """Graceful Tor config reload via ``SIGNAL HUP``.

    Reloads ``torrc`` without restarting the process or tearing
    down existing circuits. Useful for runtime tuning (guard
    knobs SafeLogging level, etc.) without taking the
    wallet down. A bad torrc → Tor refuses to reload but stays
    running on the prior config; the helper returns ``ok=False``
    so the caller can surface the rejection."""
    from app.services.anonymize.tor import signal_reload

    ok, err = await signal_reload()
    return {"ok": ok, "error": err}


@router.get("/tasks/status")
async def tasks_status(admin_key: APIKey = Depends(get_admin_key)) -> Any:
    """Per-Celery-task observability snapshot.

    Reports last_run_at, last_success_at, last_error, and
    consecutive_failures for each known task. Backed by Redis with
    a 30-day TTL. If Redis is unreachable, ``available`` is False
    on each entry.
    """
    from app.tasks.observability import get_all_task_status

    return {"tasks": get_all_task_status()}


@router.get("/migrations/status")
async def migrations_status(
    admin_key: APIKey = Depends(get_admin_key),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Report Alembic migration state.

    Reads the script directory's head revision and the
    ``alembic_version`` row in the live DB, then computes whether
    they match. Useful for pre-flight checks before traffic is
    routed to a freshly-deployed instance.
    """
    from sqlalchemy import text as _text

    head_revision: str | None = None
    current_revision: str | None = None
    error: str | None = None
    unapplied: list[str] = []

    try:
        from pathlib import Path

        from alembic.config import Config
        from alembic.script import ScriptDirectory

        # Resolve alembic.ini relative to repo root (parent of app/).
        repo_root = Path(__file__).resolve().parents[2]
        cfg = Config(str(repo_root / "alembic.ini"))
        script_dir = ScriptDirectory.from_config(cfg)
        head_revision = script_dir.get_current_head()

        try:
            row = await db.execute(_text("SELECT version_num FROM alembic_version"))
            current_revision = row.scalar()
        except Exception as e:  # noqa: BLE001
            current_revision = None
            error = f"alembic_version table unreadable: {e}"

        if head_revision and current_revision and head_revision != current_revision:
            walk: list[str] = []
            for rev in script_dir.walk_revisions(base="base", head=head_revision):
                if rev.revision == current_revision:
                    break
                walk.append(rev.revision)
            unapplied = list(reversed(walk))
    except Exception as e:  # noqa: BLE001
        error = f"alembic introspection failed: {e}"

    up_to_date = head_revision is not None and current_revision is not None and head_revision == current_revision

    return {
        "head_revision": head_revision,
        "current_revision": current_revision,
        "up_to_date": up_to_date,
        "unapplied": unapplied,
        "error": error,
    }
