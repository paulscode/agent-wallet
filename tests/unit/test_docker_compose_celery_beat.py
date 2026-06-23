# SPDX-License-Identifier: MIT
"""Regression guard: the celery-worker service in docker-compose.yml
must run Celery Beat embedded (``-B`` flag).

Background: ``app/tasks/boltz_tasks.py`` defines a ``beat_schedule``
with five periodic tasks (recover_boltz_swaps every 5 min,
advance_braiins_deposit_sessions every 30 s, cleanup_audit_logs
daily, bolt12_reconcile_invoices every minute,
reconcile_utxo_labels every 5 min). Without Beat running, that
schedule is dead code — the periodic recovery the rest of the
codebase counts on never fires.

The 2026-05-21 incident caught this: a wedged Boltz swap had no
scheduled reconciliation and had to be recovered manually.

This test catches a future compose rewrite that drops the flag.
"""

from __future__ import annotations

from pathlib import Path

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"


def test_celery_worker_runs_embedded_beat() -> None:
    """The celery-worker command must include ``-B`` (or
    ``--beat``) so the in-process Beat scheduler fires the periodic
    tasks defined in ``app.tasks.boltz_tasks.celery_app``."""
    text = _COMPOSE.read_text(encoding="utf-8")
    # Locate the celery-worker service block.
    service_start = text.find("celery-worker:")
    assert service_start != -1, "celery-worker service missing from docker-compose.yml"
    # The next top-level service (deindented) marks the end of the block.
    # Simplest delimiter for this file: the trailing ``volumes:`` section.
    volumes_start = text.find("\nvolumes:", service_start)
    assert volumes_start != -1, "compose file structure changed unexpectedly"
    service_block = text[service_start:volumes_start]
    assert "celery -A app.tasks.boltz_tasks.celery_app worker" in service_block, (
        "celery-worker command must invoke the boltz_tasks.celery_app worker"
    )
    # Accept either short or long form of the beat flag.
    has_beat = " -B" in service_block or "--beat" in service_block
    assert has_beat, (
        "celery-worker command must include ``-B`` (or ``--beat``) so "
        "the embedded scheduler fires the beat_schedule defined in "
        "app/tasks/boltz_tasks.py. Without this, periodic tasks "
        "(recover-boltz-swaps, advance-braiins-deposit-sessions, "
        "cleanup-audit-logs, bolt12-reconcile-invoices, "
        "reconcile-utxo-labels) are dead code. See the 2026-05-21 "
        "incident in the recovery notes."
    )
