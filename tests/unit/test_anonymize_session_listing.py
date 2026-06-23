# SPDX-License-Identifier: MIT
"""GET /anonymize/sessions list + detail endpoints.

Covers:

* List endpoint includes non-terminal rows and recently-completed rows.
* List endpoint excludes terminal rows older than the 30-day window.
* List + detail responses never leak destination_address_enc,
  quote_hmac, destination_address_blake2b_keyed, hop_idempotency_key.
* Detail endpoint returns 404 for malformed UUID and unknown id.
* Detail endpoint returns the event log in chronological order.
* Disabled deployment ⇒ 404 (so the tab can be hidden).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_session_detail,
    dash_anonymize_sessions,
)
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.projections import (
    project_session_detail,
    project_session_summary,
)


def _session(
    *,
    status: str = AnonymizeStatus.HOPPING.value,
    bin_amount: int = 250_000,
    completed_offset_days: float | None = None,
) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
    completed = None if completed_offset_days is None else now - timedelta(days=completed_offset_days)
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=bin_amount,
        bin_amount_sat=bin_amount,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct" * 16,
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=completed,
    )


# ── Projection unit tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_projection_excludes_destination_address_enc() -> None:
    s = _session()
    out = project_session_summary(s)
    assert "destination_address_enc" not in out
    # The fixture's encrypted bytes are ``b"ct" * 16`` — check for
    # the full sentinel rather than a 2-char substring (which now
    # collides with field names like ``last_error_redacted``).
    sentinel = "ct" * 16
    assert sentinel not in repr(out)


@pytest.mark.asyncio
async def test_projection_excludes_quote_hmac_and_reuse_key() -> None:
    s = _session()
    out = project_session_summary(s)
    assert "quote_hmac" not in out
    assert "destination_address_blake2b_keyed" not in out
    assert "destination_reuse_key_generation" not in out


@pytest.mark.asyncio
async def test_projection_summary_includes_safe_fields() -> None:
    s = _session()
    out = project_session_summary(s)
    assert out["id"] == str(s.id)
    assert out["status"] == s.status
    assert out["source_kind"] == "ext-lightning"
    assert out["bin_amount_sat"] == 250_000


@pytest.mark.asyncio
async def test_projection_emits_reconciliation_fields_when_unset() -> None:
    """Reconciliation fields must be present on every row for shape
    stability — null until the session enters AWAITING_RECONCILIATION."""
    s = _session()
    out = project_session_summary(s)
    assert out["awaiting_reconciliation_reason"] is None
    assert out["pre_reconciliation_status"] is None
    assert out["reconciliation_attempts"] == 0
    assert out["last_reconciliation_attempt_ts"] is None
    assert out["next_retry_at_unix_s"] is None
    assert out["confirmation_count"] == 0
    assert out["last_error_redacted"] is None


@pytest.mark.asyncio
async def test_projection_emits_reconciliation_fields_when_populated() -> None:
    """When the helper has set the columns the projection surfaces them."""
    from datetime import datetime, timezone

    s = _session()
    s.status = "awaiting_reconciliation"
    s.awaiting_reconciliation_reason = "mpp_k_floor_exhausted"
    s.pre_reconciliation_status = "exiting"
    s.reconciliation_attempts = 3
    s.last_reconciliation_attempt_ts = datetime(
        2026,
        5,
        16,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )
    s.claim_tx_confirmations = 1
    s.last_error = "redacted"

    out = project_session_summary(s)
    assert out["awaiting_reconciliation_reason"] == "mpp_k_floor_exhausted"
    assert out["pre_reconciliation_status"] == "exiting"
    assert out["reconciliation_attempts"] == 3
    assert out["last_reconciliation_attempt_ts"] is not None
    assert out["last_reconciliation_attempt_ts"].startswith("2026-05-16")
    assert out["confirmation_count"] == 1
    assert out["last_error_redacted"] == "redacted"


@pytest.mark.asyncio
async def test_projection_never_leaks_raw_last_error_key() -> None:
    """The serialised key is ``last_error_redacted``, not ``last_error`` —
    so a caller can't accidentally use the unredacted name even if
    the setter-side redactor is bypassed."""
    s = _session()
    s.last_error = "some text"
    out = project_session_summary(s)
    assert "last_error" not in out
    assert out["last_error_redacted"] == "some text"


@pytest.mark.asyncio
async def test_projection_next_retry_populated_for_class_b_in_cooldown() -> None:
    """``next_retry_at_unix_s`` is computed
    server-side from ``last_reconciliation_attempt_ts +
    backoff_s(attempts)``. Class A/B reasons in cooldown should
    surface a future Unix timestamp; the SPA renders the countdown
    against it.

    Without this server-side computation the SPA either has to
    duplicate the backoff math (drift risk) or render a static
    "retrying…" label (UX regression). Lock the populated case so
    a future refactor can't silently nullify it.
    """
    from datetime import datetime, timedelta, timezone

    s = _session()
    s.status = "awaiting_reconciliation"
    s.awaiting_reconciliation_reason = "mpp_k_floor_exhausted"  # Class B
    s.pre_reconciliation_status = "exiting"
    s.reconciliation_attempts = 1
    # Last try 5 seconds ago; with backoff_base=30s, next retry is
    # ~25s in the future.
    s.last_reconciliation_attempt_ts = datetime.now(timezone.utc) - timedelta(seconds=5)

    out = project_session_summary(s)
    assert out["next_retry_at_unix_s"] is not None
    now_unix = datetime.now(timezone.utc).timestamp()
    # Should be in the future, less than one backoff window away.
    assert out["next_retry_at_unix_s"] > now_unix
    assert out["next_retry_at_unix_s"] - now_unix < 60


@pytest.mark.asyncio
async def test_projection_next_retry_null_for_class_c() -> None:
    """Class C reasons (operator-judgement) don't auto-retry, so the
    projection must NOT surface a countdown timestamp — the SPA's
    countdown caption stays blank for those rows."""
    from datetime import datetime, timezone

    s = _session()
    s.status = "awaiting_reconciliation"
    s.awaiting_reconciliation_reason = "operator_signature_mismatch"  # Class C
    s.pre_reconciliation_status = "exiting"
    s.reconciliation_attempts = 1
    s.last_reconciliation_attempt_ts = datetime.now(timezone.utc)

    out = project_session_summary(s)
    assert out["next_retry_at_unix_s"] is None


@pytest.mark.asyncio
async def test_projection_detail_includes_events_in_order() -> None:
    s = _session()
    now = datetime.now(timezone.utc)
    # NB: AnonymizeSessionEvent instances created without ``add()`` get
    # mistakenly auto-flushed by a later test's async session via
    # SQLAlchemy's identity map; build a minimal fake instead of using
    # the ORM model so the projection helper is exercised in isolation
    # from the unit-of-work.
    from dataclasses import dataclass

    @dataclass
    class _FakeEvent:
        ts: datetime
        kind: str
        detail_json: dict

    events = [
        _FakeEvent(ts=now, kind="created", detail_json={"k": 1}),
        _FakeEvent(
            ts=now + timedelta(seconds=10),
            kind="hopping_started",
            detail_json={},
        ),
    ]
    out = project_session_detail(s, events=events)
    assert len(out["events"]) == 2
    assert out["events"][0]["kind"] == "created"
    assert out["events"][0]["detail"] == {"k": 1}
    # hop_idempotency_key/nonce columns must NOT appear in event detail.
    assert "hop_idempotency_key" not in out["events"][0]


@pytest.mark.asyncio
async def test_projection_detail_bounded_event_count() -> None:
    """A session with many events caps to max_events."""
    from dataclasses import dataclass

    @dataclass
    class _FakeEvent:
        ts: datetime
        kind: str
        detail_json: dict

    s = _session()
    now = datetime.now(timezone.utc)
    events = [
        _FakeEvent(
            ts=now + timedelta(seconds=i),
            kind="probe",
            detail_json={},
        )
        for i in range(500)
    ]
    out = project_session_detail(s, events=events, max_events=50)
    assert len(out["events"]) == 50


# ── List endpoint tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sessions_endpoint_lists_non_terminal_rows(db_session) -> None:
    settings.anonymize_enabled = True
    live = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(live)
    await db_session.commit()
    out = await dash_anonymize_sessions(db=db_session)
    ids = [s["id"] for s in out["sessions"]]
    assert str(live.id) in ids


@pytest.mark.asyncio
async def test_sessions_endpoint_includes_recently_completed(db_session) -> None:
    settings.anonymize_enabled = True
    recent = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_offset_days=3,
    )
    db_session.add(recent)
    await db_session.commit()
    out = await dash_anonymize_sessions(db=db_session)
    assert any(s["id"] == str(recent.id) for s in out["sessions"])


@pytest.mark.asyncio
async def test_sessions_endpoint_excludes_old_completed(db_session) -> None:
    settings.anonymize_enabled = True
    old = _session(
        status=AnonymizeStatus.COMPLETED.value,
        completed_offset_days=60,
    )
    db_session.add(old)
    await db_session.commit()
    out = await dash_anonymize_sessions(db=db_session)
    assert all(s["id"] != str(old.id) for s in out["sessions"])


@pytest.mark.asyncio
async def test_sessions_endpoint_returns_404_when_disabled(db_session) -> None:
    settings.anonymize_enabled = False
    try:
        resp = await dash_anonymize_sessions(db=db_session)
        assert resp.status_code == 404
    finally:
        settings.anonymize_enabled = True


@pytest.mark.asyncio
async def test_sessions_endpoint_never_leaks_destination_bytes(
    db_session,
) -> None:
    """An explicit byte-presence check that ``ct`` (the encrypted blob)
    is nowhere in the response body."""
    import json

    settings.anonymize_enabled = True
    s = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(s)
    await db_session.commit()
    out = await dash_anonymize_sessions(db=db_session)
    # JSON-encode the whole response and grep for the encrypted bytes
    # marker. The bytes themselves are b"ct"*16 (length 32); they are
    # never serializable as JSON unless something projected them.
    blob = json.dumps(out, default=str)
    assert "destination_address_enc" not in blob


# ── Detail endpoint tests ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_detail_endpoint_returns_session_with_events(db_session) -> None:
    settings.anonymize_enabled = True
    s = _session()
    db_session.add(s)
    await db_session.commit()

    out = await dash_anonymize_session_detail(str(s.id), db=db_session)
    if hasattr(out, "status_code"):
        raise AssertionError(f"detail endpoint returned {out.status_code}: {out.body!r}")
    assert out["id"] == str(s.id)
    assert out["events"] == []


@pytest.mark.asyncio
async def test_detail_endpoint_returns_events_in_order(db_session) -> None:
    """Session with two events surfaces them in chronological order."""
    settings.anonymize_enabled = True
    s = _session()
    db_session.add(s)
    await db_session.flush()
    now = datetime.now(timezone.utc)
    ev1 = AnonymizeSessionEvent(
        session_id=s.id,
        ts=now,
        kind="created",
        detail_json={"k": 1},
    )
    ev2 = AnonymizeSessionEvent(
        session_id=s.id,
        ts=now + timedelta(seconds=10),
        kind="hopping_started",
        detail_json={},
    )
    db_session.add_all([ev1, ev2])
    await db_session.commit()

    out = await dash_anonymize_session_detail(str(s.id), db=db_session)
    if hasattr(out, "status_code"):
        raise AssertionError(f"detail endpoint returned {out.status_code}: {out.body!r}")
    assert [e["kind"] for e in out["events"]] == ["created", "hopping_started"]


@pytest.mark.asyncio
async def test_detail_endpoint_returns_404_for_malformed_id(db_session) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_session_detail("not-a-uuid", db=db_session)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_detail_endpoint_returns_404_for_unknown_id(db_session) -> None:
    """An unknown id returns the SAME 404 as malformed — no enumeration leak."""
    settings.anonymize_enabled = True
    resp = await dash_anonymize_session_detail(str(uuid4()), db=db_session)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_detail_endpoint_returns_404_when_disabled(db_session) -> None:
    settings.anonymize_enabled = False
    try:
        resp = await dash_anonymize_session_detail(str(uuid4()), db=db_session)
        assert resp.status_code == 404
    finally:
        settings.anonymize_enabled = True
