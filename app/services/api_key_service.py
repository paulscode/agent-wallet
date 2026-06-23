# SPDX-License-Identifier: MIT
"""
API key management service — single source of truth for create / list /
update / soft-delete / purge of API keys, plus the audit-log emission
that goes with each mutation.

Both the admin REST router (``/api/v1/admin/api-keys``) and the
dashboard router (``/dashboard/api/api-keys``) call into this module
so that validation, self-protection, retention-window gating, and
audit-log emission stay byte-identical across both surfaces. With
real funds at stake this is a security-critical invariant — every key
mint or revoke must leave an audit trail and apply the same caps
regardless of whether the actor is a scripted admin caller or a
human dashboard session.

Actors
------

Each mutation takes an ``actor`` argument that is either a real
:class:`APIKey` row (admin REST path) or the dashboard sentinel UUID
(dashboard session path). The audit-log helper is dispatched
accordingly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Union
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import generate_api_key, hash_api_key
from app.models.api_key import (
    API_KEY_SCOPES,
    SCOPE_ADMIN,
    SCOPE_MONITOR,
    APIKey,
)
from app.services.audit_service import log_action, log_dashboard_action

# ── Actor abstraction ────────────────────────────────────────────────────


@dataclass(frozen=True)
class DashboardActor:
    """Sentinel actor used by the dashboard session router."""

    dashboard_key_id: UUID

    @property
    def id(self) -> UUID:
        return self.dashboard_key_id


Actor = Union[APIKey, DashboardActor]


def _actor_id(actor: Actor) -> UUID:
    return actor.id


async def _audit(
    db: AsyncSession,
    actor: Actor,
    action: str,
    *,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    if isinstance(actor, APIKey):
        await log_action(
            db,
            actor,
            action,
            "admin",
            details=details,
            ip_address=ip_address,
        )
    else:
        await log_dashboard_action(
            db,
            actor.dashboard_key_id,
            action,
            "admin",
            details=details,
            ip_address=ip_address,
        )


# ── Helpers ──────────────────────────────────────────────────────────────


def _parse_uuid(key_id: str) -> UUID:
    try:
        return UUID(key_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid key ID")


async def _get_key(db: AsyncSession, key_uuid: UUID) -> APIKey:
    result = await db.execute(select(APIKey).where(APIKey.id == key_uuid))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="API key not found")
    return target


def _resolve_scope(scope: Optional[str], is_admin: Optional[bool]) -> Optional[str]:
    """Normalise the caller's intent into a scope string.

    ``scope`` is canonical when provided; otherwise the boolean
    ``is_admin`` alias maps to ``admin``/``monitor``. Returns ``None``
    when neither was supplied (caller decides the default / no change).
    """
    if scope is not None:
        if scope not in API_KEY_SCOPES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scope (must be one of: {', '.join(API_KEY_SCOPES)})",
            )
        return scope
    if is_admin is not None:
        return SCOPE_ADMIN if is_admin else SCOPE_MONITOR
    return None


def serialize_key(k: APIKey) -> dict[str, Any]:
    """JSON-safe representation of an API key (never includes the hash)."""
    return {
        "id": str(k.id),
        "name": k.name,
        "scope": k.scope,
        "is_admin": k.is_admin,
        "is_active": k.is_active,
        "expires_at": k.expires_at.isoformat() if k.expires_at else None,
        "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        "created_at": k.created_at.isoformat() if k.created_at else None,
        "deleted_at": k.deleted_at.isoformat() if k.deleted_at else None,
    }


# ── Operations ───────────────────────────────────────────────────────────


async def list_keys(db: AsyncSession) -> list[APIKey]:
    """Return every API key, newest first."""
    result = await db.execute(select(APIKey).order_by(APIKey.created_at.desc()))
    return list(result.scalars().all())


async def create_key(
    db: AsyncSession,
    *,
    actor: Actor,
    name: str,
    expires_in_days: Optional[int],
    scope: Optional[str] = None,
    is_admin: Optional[bool] = None,
    ip_address: Optional[str] = None,
) -> tuple[APIKey, str]:
    """Mint a new API key.

    Returns ``(api_key_row, plaintext_key)``. The plaintext is the
    only time the secret is in memory — callers must hand it back to
    the user immediately and never persist it.

    ``expires_in_days`` is clamped to ``settings.api_key_max_ttl_days``
    in addition to the usual Pydantic validation on the request layer
    (defence in depth — this service must never mint a key that lives
    longer than the configured ceiling).
    """
    # Pydantic already constrains name length on both routers, but the
    # service is the single source of truth — re-validate here so a
    # future caller that bypasses the request model still gets the
    # same protection.
    if not name or not name.strip():
        raise HTTPException(status_code=400, detail="Name must not be empty")
    if len(name) > 128:
        raise HTTPException(status_code=400, detail="Name too long (max 128)")
    # Reject control characters (CR/LF/NUL/etc.): the name is
    # interpolated into application log lines and outbound alert text, so
    # an embedded newline could forge log entries or split a webhook
    # payload.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        raise HTTPException(status_code=400, detail="Name must not contain control characters")

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)

    max_days = settings.api_key_max_ttl_days
    if expires_in_days is None:
        days = max_days
    else:
        if expires_in_days < 1:
            raise HTTPException(status_code=400, detail="expires_in_days must be ≥ 1")
        days = min(expires_in_days, max_days)
    expires_at = datetime.now(timezone.utc) + timedelta(days=days)

    resolved_scope = _resolve_scope(scope, is_admin) or SCOPE_MONITOR

    api_key = APIKey(
        name=name,
        key_hash=key_hash,
        scope=resolved_scope,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    await _audit(
        db,
        actor,
        "create_api_key",
        details={"new_key_name": name, "scope": resolved_scope},
        ip_address=ip_address,
    )

    return api_key, raw_key


async def update_key(
    db: AsyncSession,
    *,
    actor: Actor,
    key_id: str,
    name: Optional[str] = None,
    is_active: Optional[bool] = None,
    scope: Optional[str] = None,
    is_admin: Optional[bool] = None,
    ip_address: Optional[str] = None,
) -> tuple[APIKey, dict[str, Any]]:
    """Patch an API key's mutable fields.

    Returns the updated row and the dict of changes that were
    actually applied (subset of the inputs, with normalised types).
    """
    key_uuid = _parse_uuid(key_id)
    target = await _get_key(db, key_uuid)

    changes: dict[str, Any] = {}

    if name is not None:
        if not name.strip():
            raise HTTPException(status_code=400, detail="Name must not be empty")
        if len(name) > 128:
            raise HTTPException(status_code=400, detail="Name too long (max 128)")
        # Same control-character guard as the create path: the name is
        # interpolated into log lines / alert text.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
            raise HTTPException(status_code=400, detail="Name must not contain control characters")
        target.name = name
        changes["name"] = name

    if is_active is not None:
        target.is_active = is_active
        changes["is_active"] = is_active

    new_scope = _resolve_scope(scope, is_admin)
    if new_scope is not None:
        # Defence in depth: prevent the actor from reducing the scope of
        # the key they are currently authenticated with — "demote myself"
        # has the same lockout failure mode as self-delete.
        if isinstance(actor, APIKey) and key_uuid == actor.id and new_scope != SCOPE_ADMIN:
            raise HTTPException(
                status_code=400,
                detail="Cannot reduce your own API key's scope",
            )
        target.scope = new_scope
        changes["scope"] = new_scope

    await db.commit()
    await db.refresh(target)

    await _audit(
        db,
        actor,
        "update_api_key",
        details={"target_key_id": key_id, "changes": changes},
        ip_address=ip_address,
    )

    return target, changes


async def soft_delete_key(
    db: AsyncSession,
    *,
    actor: Actor,
    key_id: str,
    ip_address: Optional[str] = None,
) -> APIKey:
    """Soft-delete an API key (sets ``is_active=False`` and ``deleted_at``).

    Refuses to soft-delete the actor's own key when the actor is a
    real :class:`APIKey` (would lock the actor out of the system).
    Audit-log rows continue to reference the key by id and name.
    """
    key_uuid = _parse_uuid(key_id)
    if isinstance(actor, APIKey) and key_uuid == actor.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own API key",
        )

    target = await _get_key(db, key_uuid)
    target.is_active = False
    if target.deleted_at is None:
        target.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(target)

    await _audit(
        db,
        actor,
        "delete_api_key",
        details={"deleted_key_name": target.name, "soft_delete": True},
        ip_address=ip_address,
    )

    return target


async def purge_key(
    db: AsyncSession,
    *,
    actor: Actor,
    key_id: str,
    ip_address: Optional[str] = None,
) -> None:
    """Hard-delete a previously soft-deleted key.

    Refuses unless the audit-log retention window has elapsed since
    ``deleted_at`` (or retention is disabled with
    ``AUDIT_LOG_RETENTION_DAYS=0``). This guarantees the audit trail
    survives at least as long as the configured retention.
    """
    key_uuid = _parse_uuid(key_id)
    if isinstance(actor, APIKey) and key_uuid == actor.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot purge your own API key",
        )

    target = await _get_key(db, key_uuid)

    if target.deleted_at is None:
        raise HTTPException(
            status_code=400,
            detail="Key must be soft-deleted (DELETE /api-keys/{id}) before purge.",
        )

    retention_days = settings.audit_log_retention_days
    if retention_days > 0:
        deleted_at = target.deleted_at
        if deleted_at.tzinfo is None:
            deleted_at = deleted_at.replace(tzinfo=timezone.utc)
        elapsed = datetime.now(timezone.utc) - deleted_at
        if elapsed < timedelta(days=retention_days):
            remaining = timedelta(days=retention_days) - elapsed
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Cannot purge yet — audit retention is {retention_days} days, ~{remaining.days} day(s) remaining."
                ),
            )

    purged_name = target.name
    await db.delete(target)
    await db.commit()

    await _audit(
        db,
        actor,
        "purge_api_key",
        details={"purged_key_name": purged_name, "key_id": key_id},
        ip_address=ip_address,
    )
