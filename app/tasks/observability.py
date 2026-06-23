# SPDX-License-Identifier: MIT
"""Celery task observability.

Records last-run / last-success / last-error / consecutive-failure
metadata in Redis so operators can tell at a glance whether the
beat schedule is actually firing and whether tasks are succeeding.

Designed to be used as a small wrapper inside synchronous Celery
task bodies (the surrounding ``celery_app.task`` decorator is left
intact). All functions are best-effort: a missing or unreachable
Redis must never break a task.

Storage layout::

    agent_wallet:task_status:<task_name>  →  JSON blob, 30-day TTL

Read-side helper :func:`get_all_task_status` is used by the admin
endpoint ``/v1/admin/tasks/status``.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, cast

logger = logging.getLogger(__name__)

_KEY_PREFIX = "agent_wallet:task_status:"
_KEY_INDEX = "agent_wallet:task_status:_index"
_TTL_SECONDS = 60 * 60 * 24 * 30  # 30 days

# Tasks that have been observed running at least once in this
# process. Lets the admin endpoint enumerate without SCAN.
_known_tasks: set[str] = set()


def _get_redis() -> Any | None:
    """Return a synchronous Redis client, or None if unavailable.

    Imports lazily so the rest of the task module loads even when
    redis-py isn't installed (e.g. in a stripped-down test env).
    """
    try:
        import redis  # type: ignore[import-untyped]

        from app.core.config import settings

        return redis.Redis.from_url(settings.redis_url, socket_timeout=2.0)
    except Exception:  # noqa: BLE001
        return None


def _read(client: Any, name: str) -> dict[str, Any]:
    try:
        raw = client.get(_KEY_PREFIX + name)
        if not raw:
            return {}
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return cast("dict[str, Any]", json.loads(raw))
    except Exception:  # noqa: BLE001
        return {}


def _write(client: Any, name: str, blob: dict[str, Any]) -> None:
    try:
        client.set(_KEY_PREFIX + name, json.dumps(blob), ex=_TTL_SECONDS)
        client.sadd(_KEY_INDEX, name)
        client.expire(_KEY_INDEX, _TTL_SECONDS)
    except Exception:  # noqa: BLE001
        pass


def record_task_run(name: str) -> None:
    """Record that a task started. Best-effort."""
    _known_tasks.add(name)
    client = _get_redis()
    if client is None:
        return
    blob = _read(client, name)
    blob["name"] = name
    blob["last_run_at"] = time.time()
    _write(client, name, blob)


def record_task_success(name: str, *, result: Any = None) -> None:
    """Record a successful completion. Best-effort."""
    _known_tasks.add(name)
    client = _get_redis()
    if client is None:
        return
    blob = _read(client, name)
    blob["name"] = name
    now = time.time()
    blob["last_run_at"] = blob.get("last_run_at", now)
    blob["last_success_at"] = now
    blob["last_error"] = None
    blob["consecutive_failures"] = 0
    if isinstance(result, dict):
        # Persist a *small* result preview only — bound the size.
        try:
            preview = {k: v for k, v in result.items() if isinstance(v, (str, int, float, bool, type(None)))}
            blob["last_result_preview"] = preview
        except Exception:  # noqa: BLE001
            pass
    _write(client, name, blob)


def record_task_failure(name: str, error: BaseException) -> None:
    """Record a failed run. Best-effort."""
    _known_tasks.add(name)
    client = _get_redis()
    if client is None:
        return
    blob = _read(client, name)
    blob["name"] = name
    now = time.time()
    blob["last_run_at"] = blob.get("last_run_at", now)
    blob["last_failure_at"] = now
    # Keep the error message bounded — don't store stack traces here.
    msg = f"{type(error).__name__}: {error}"
    blob["last_error"] = msg[:500]
    blob["consecutive_failures"] = int(blob.get("consecutive_failures", 0)) + 1
    _write(client, name, blob)


def track_task(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: wrap a task body with run/success/failure recording.

    Wraps a *synchronous* function (the Celery task body). Re-raises
    on failure so Celery's retry logic still sees the exception.
    """

    def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            record_task_run(name)
            try:
                result = fn(*args, **kwargs)
            except BaseException as e:  # noqa: BLE001 — Celery may raise Retry
                record_task_failure(name, e)
                raise
            else:
                record_task_success(name, result=result)
                return result

        _wrapped.__wrapped__ = fn  # type: ignore[attr-defined]
        _wrapped.__name__ = getattr(fn, "__name__", name)
        return _wrapped

    return _decorator


def get_all_task_status() -> list[dict[str, Any]]:
    """Read-side: return one snapshot dict per known task.

    Best-effort. Returns empty list if Redis is unavailable.
    """
    client = _get_redis()
    if client is None:
        return [{"name": n, "available": False} for n in sorted(_known_tasks)]
    out: list[dict[str, Any]] = []
    try:
        members = client.smembers(_KEY_INDEX) or set()
        names = sorted({(m.decode() if isinstance(m, bytes) else m) for m in members} | _known_tasks)
        for name in names:
            blob = _read(client, name)
            if not blob:
                out.append({"name": name, "available": False})
                continue
            blob["available"] = True
            out.append(blob)
    except Exception as e:  # noqa: BLE001
        logger.debug("task status read failed: %s", e)
        return [{"name": n, "available": False} for n in sorted(_known_tasks)]
    return out
