# SPDX-License-Identifier: MIT
"""Audit-log emission tests for operator-assignment, covering the
three actions:

- ``anonymize_submarine_operator_selected`` (per-session, at session-create)
- ``anonymize_reverse_operator_selected`` (per-session, at session-create)
- ``anonymize_reverse_probe_failed`` (per-quote-attempt, at quote-build)

Uses the standard ``db_session`` fixture from conftest so the tests
exercise the real ``_finalize_entry`` hash-chain helper end-to-end
(not a mock).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.audit_log import AuditLog
from app.services.anonymize.operator_selection import (
    emit_operator_selection_audit_events,
    emit_reverse_probe_failed_audit,
)


async def _all_audit_rows(db_session) -> list[AuditLog]:
    res = await db_session.execute(select(AuditLog).order_by(AuditLog.created_at, AuditLog.id))
    return list(res.scalars().all())


@pytest.mark.asyncio
async def test_session_create_emits_submarine_operator_selected(
    db_session,
) -> None:
    """At session-create the helper emits an audit row with
    ``action=anonymize_submarine_operator_selected`` and a body
    carrying the bound ``operator_id`` + ``selection_source``."""
    await emit_operator_selection_audit_events(
        db_session,
        submarine_operator_id="middleway",
        reverse_operator_id="boltz-canonical",
        selection_source="primary",
    )
    rows = await _all_audit_rows(db_session)
    sub_row = next(
        (r for r in rows if r.action == "anonymize_submarine_operator_selected"),
        None,
    )
    assert sub_row is not None
    assert sub_row.details["operator_id"] == "middleway"
    assert sub_row.details["selection_source"] == "primary"


@pytest.mark.asyncio
async def test_session_create_emits_reverse_operator_selected(
    db_session,
) -> None:
    """Symmetric: the reverse-leg audit row carries only
    ``operator_id`` (no selection_source — the reverse leg has no
    fallback chain in v1)."""
    await emit_operator_selection_audit_events(
        db_session,
        submarine_operator_id="middleway",
        reverse_operator_id="boltz-canonical",
        selection_source="primary",
    )
    rows = await _all_audit_rows(db_session)
    rev_row = next(
        (r for r in rows if r.action == "anonymize_reverse_operator_selected"),
        None,
    )
    assert rev_row is not None
    assert rev_row.details["operator_id"] == "boltz-canonical"


@pytest.mark.asyncio
async def test_selection_source_carries_correct_discriminator(
    db_session,
) -> None:
    """``selection_source`` field discriminates between
    primary / secondary_after_primary_failed /
    single_operator_after_chain_exhausted, so the v2-trigger metric
    can compute the per-class distribution."""
    await emit_operator_selection_audit_events(
        db_session,
        submarine_operator_id="boltz-canonical",
        reverse_operator_id="boltz-canonical",
        selection_source="single_operator_after_chain_exhausted",
    )
    rows = await _all_audit_rows(db_session)
    sub_row = next(
        (r for r in rows if r.action == "anonymize_submarine_operator_selected"),
        None,
    )
    assert sub_row is not None
    assert sub_row.details["selection_source"] == "single_operator_after_chain_exhausted"


@pytest.mark.asyncio
async def test_emit_skips_when_submarine_operator_id_is_none(
    db_session,
) -> None:
    """LN-only sessions and URL-pin bypass sessions land at
    the helper with ``submarine_operator_id=None``. The helper MUST
    NOT emit a submarine row in that case (the field would be
    semantically meaningless)."""
    await emit_operator_selection_audit_events(
        db_session,
        submarine_operator_id=None,
        reverse_operator_id="boltz-canonical",
        selection_source="primary",
    )
    rows = await _all_audit_rows(db_session)
    actions = [r.action for r in rows]
    assert "anonymize_submarine_operator_selected" not in actions
    # Reverse row still fires.
    assert "anonymize_reverse_operator_selected" in actions


@pytest.mark.asyncio
async def test_emit_skips_when_both_operator_ids_are_none(
    db_session,
) -> None:
    """URL-pin bypass: both operator_ids are None → no audit rows
    emitted at all. Releases the legacy single-operator-deployment
    behavior."""
    await emit_operator_selection_audit_events(
        db_session,
        submarine_operator_id=None,
        reverse_operator_id=None,
        selection_source="",
    )
    rows = await _all_audit_rows(db_session)
    actions = [r.action for r in rows]
    assert "anonymize_submarine_operator_selected" not in actions
    assert "anonymize_reverse_operator_selected" not in actions


@pytest.mark.asyncio
async def test_quote_emits_reverse_probe_failed_at_quote_time(
    db_session,
) -> None:
    """``anonymize_reverse_probe_failed`` is emitted at
    quote-build time (NOT session-create) with a body carrying the
    reverse operator's ``operator_id`` + ``status`` enum value.
    Feeds the v2-trigger metric."""
    await emit_reverse_probe_failed_audit(
        db_session,
        operator_id="boltz-canonical",
        status="unreachable",
    )
    rows = await _all_audit_rows(db_session)
    row = next(
        (r for r in rows if r.action == "anonymize_reverse_probe_failed"),
        None,
    )
    assert row is not None
    assert row.details["operator_id"] == "boltz-canonical"
    assert row.details["status"] == "unreachable"
    # success=False because this records a failure event.
    assert row.success is False


@pytest.mark.asyncio
async def test_reverse_probe_failed_emitted_per_attempt(db_session) -> None:
    """Emission is per-quote-attempt, NOT per-session. Three
    back-to-back failing quotes emit three audit rows so the
    v2-trigger metric's denominator is correct."""
    for _ in range(3):
        await emit_reverse_probe_failed_audit(
            db_session,
            operator_id="boltz-canonical",
            status="unreachable",
        )
    rows = await _all_audit_rows(db_session)
    failures = [r for r in rows if r.action == "anonymize_reverse_probe_failed"]
    assert len(failures) == 3


@pytest.mark.asyncio
async def test_reverse_probe_failed_status_enum_restricted(db_session) -> None:
    """Body's ``status`` field is one of
    ``{unreachable, degraded}``. The wider ``ProbeStatus`` enum's
    selected / skipped_* values never appear here (they apply only
    to submarine-side chain attempts)."""
    await emit_reverse_probe_failed_audit(
        db_session,
        operator_id="boltz-canonical",
        status="degraded",
    )
    rows = await _all_audit_rows(db_session)
    row = next(
        (r for r in rows if r.action == "anonymize_reverse_probe_failed"),
        None,
    )
    assert row is not None
    assert row.details["status"] in {"unreachable", "degraded"}
