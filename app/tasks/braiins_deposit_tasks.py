# SPDX-License-Identifier: MIT
"""
Celery tasks for the Braiins Deposit pipeline.

Two roles:

1. ``advance_braiins_deposit_sessions`` — periodic ticker that drives
   any non-terminal session forward one step. Acts as the safety net
   when the dashboard isn't open + the upstream Boltz Celery task has
   advanced the linked swap but our state machine hasn't observed it.

2. ``_run_recover_braiins_deposits`` — synchronous recovery hook
   called from FastAPI lifespan on startup. Matches the BoltzSwap
   pattern in ``app/tasks/boltz_tasks.py``.
"""

from __future__ import annotations

import logging
from typing import Any

from app.tasks.boltz_tasks import _run_async, celery_app
from app.tasks.observability import track_task

logger = logging.getLogger(__name__)


async def _run_advance_braiins_deposits() -> dict[str, Any]:
    """Tick every non-terminal Braiins-Deposit session once."""
    from app.core.database import get_db_context
    from app.services.braiins_deposit_service import braiins_deposit_service

    async with get_db_context() as db:
        try:
            results = await braiins_deposit_service.recover_pending_sessions(db)
            if results:
                logger.info(
                    "braiins_deposit: ticked %d non-terminal session(s)",
                    len(results),
                )
            return {"ticked": len(results), "results": results}
        except Exception as exc:  # noqa: BLE001
            logger.exception("braiins_deposit: tick failed: %s", exc)
            return {"error": str(exc)}


@celery_app.task(name="advance_braiins_deposit_sessions")
@track_task("advance_braiins_deposit_sessions")
def advance_braiins_deposit_sessions() -> dict[str, Any]:
    """Periodic task: drive every non-terminal session forward one step."""
    result: dict[str, Any] = _run_async(_run_advance_braiins_deposits())
    return result


async def _run_recover_braiins_deposits() -> dict[str, Any]:
    """Startup recovery — same shape as ``_run_recover_swaps``."""
    return await _run_advance_braiins_deposits()
