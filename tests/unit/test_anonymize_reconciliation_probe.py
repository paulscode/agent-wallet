# SPDX-License-Identifier: MIT
"""Auto-retry probe + wedge detector + startup heuristic tests.

Covers ``app/services/anonymize/reconciliation_probe.py``:

* Backoff math + cooldown predicate (pure).
* Per-session ``attempt_reconciliation`` decision tree.
* ``apply_wedge_detector`` flips wedged actives into AR.
* ``apply_startup_pre_status_heuristic`` backfills legacy rows.
* ``compute_next_retry_at_unix_s`` projection helper.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.reconciliation_classify import MAX_RETRIES_SEMI
from app.services.anonymize.reconciliation_probe import (
    apply_startup_pre_status_heuristic,
    apply_wedge_detector,
    attempt_reconciliation,
    compute_backoff_s,
    compute_next_retry_at_unix_s,
    heuristic_pre_status_for,
    is_in_cooldown,
    max_retries_for_class,
)
from app.services.anonymize.service import (
    get_anonymize_service,
    reset_anonymize_service,
)


@pytest_asyncio.fixture(autouse=True)
async def _reset_service():
    reset_anonymize_service()
    yield
    # Stop any service the test started before dropping the
    # singleton — otherwise background tasks linger as
    # unclosed-event-loop ResourceWarnings that pytest's
    # ``filterwarnings = ["error"]`` setting elevates to test
    # failures during the next test's collection. Pre-existing
    # test-isolation bug surfaced once grpc/wallycore deps were
    # installed.
    from app.services.anonymize import service as _svc_mod

    if _svc_mod.anonymize_service is not None:
        try:
            await _svc_mod.anonymize_service.stop()
        except Exception:  # noqa: BLE001
            pass
    reset_anonymize_service()


def _session(
    *,
    status: str = AnonymizeStatus.AWAITING_RECONCILIATION.value,
    reason: str | None = None,
    pre_status: str | None = AnonymizeStatus.EXITING.value,
    attempts: int = 0,
    last_attempt: datetime | None = None,
    updated_at: datetime | None = None,
) -> AnonymizeSession:
    s = AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct" * 16,
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        awaiting_reconciliation_reason=reason,
        pre_reconciliation_status=pre_status,
        reconciliation_attempts=attempts,
        last_reconciliation_attempt_ts=last_attempt,
    )
    if updated_at is not None:
        s.updated_at = updated_at
    return s


# ── Backoff math ─────────────────────────────────────────────────────


def test_backoff_attempts_zero_is_immediate() -> None:
    """A freshly-parked row (no attempts) can be tried immediately."""
    assert compute_backoff_s(0, base_s=30, max_s=3600) == 0.0


def test_backoff_grows_exponentially() -> None:
    """attempts=1 → base; attempts=2 → 2*base; attempts=3 → 4*base."""
    assert compute_backoff_s(1, base_s=30, max_s=3600) == 30.0
    assert compute_backoff_s(2, base_s=30, max_s=3600) == 60.0
    assert compute_backoff_s(3, base_s=30, max_s=3600) == 120.0


def test_backoff_clamped_at_max() -> None:
    """Doubling stops at the configured ceiling."""
    out = compute_backoff_s(20, base_s=30, max_s=3600)
    assert out == 3600.0


def test_backoff_exp_overflow_clamped() -> None:
    """A pathologically high attempts value doesn't overflow."""
    out = compute_backoff_s(10_000, base_s=30, max_s=3600)
    assert out == 3600.0


# ── Cooldown ─────────────────────────────────────────────────────────


def test_cooldown_false_when_never_attempted() -> None:
    s = _session(attempts=0, last_attempt=None)
    now = datetime.now(timezone.utc)
    assert is_in_cooldown(s, now=now) is False


def test_cooldown_true_just_after_attempt() -> None:
    """attempts=1, last try 5s ago, base=30 → still in cooldown."""
    now = datetime.now(timezone.utc)
    s = _session(attempts=1, last_attempt=now - timedelta(seconds=5))
    assert is_in_cooldown(s, now=now, base_s=30, max_s=3600) is True


def test_cooldown_false_after_window_elapses() -> None:
    """attempts=1, last try 60s ago, base=30 → past cooldown."""
    now = datetime.now(timezone.utc)
    s = _session(attempts=1, last_attempt=now - timedelta(seconds=60))
    assert is_in_cooldown(s, now=now, base_s=30, max_s=3600) is False


def test_cooldown_handles_naive_timestamps() -> None:
    """A naive ``last_attempt_ts`` (no tzinfo) is treated as UTC."""
    now = datetime.now(timezone.utc)
    naive = (now - timedelta(seconds=5)).replace(tzinfo=None)
    s = _session(attempts=1, last_attempt=naive)
    assert is_in_cooldown(s, now=now, base_s=30, max_s=3600) is True


# ── Per-class budget ─────────────────────────────────────────────────


def test_class_a_budget_from_settings() -> None:
    """Class A is configurable."""
    assert max_retries_for_class("A") == int(
        settings.anonymize_reconciliation_max_retries_transient,
    )


def test_class_b_budget_is_constant() -> None:
    """Class B is the code constant from reconciliation_classify."""
    assert max_retries_for_class("B") == MAX_RETRIES_SEMI


def test_class_c_budget_is_zero() -> None:
    """Class C never auto-retries."""
    assert max_retries_for_class("C") == 0


# ── attempt_reconciliation ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_attempt_class_a_resumes_to_pre_status(db_session) -> None:
    """Class A reason with attempts < budget and a legal pre_status →
    resume."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    s = _session(
        reason="circuit_rebuild_throttled",
        pre_status=AnonymizeStatus.EXITING.value,
        attempts=0,
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    out = await attempt_reconciliation(
        db_session,
        s,
        service=svc,
        now=now,
    )
    await db_session.commit()

    assert out.kind == "retried"
    assert out.target_status == AnonymizeStatus.EXITING.value
    await db_session.refresh(s)
    assert s.status == AnonymizeStatus.EXITING.value
    assert s.reconciliation_attempts == 1
    assert s.last_reconciliation_attempt_ts is not None


@pytest.mark.asyncio
async def test_attempt_class_c_defers_without_consuming_budget(
    db_session,
) -> None:
    """Class C touches the timestamp but doesn't bump attempts so
    operator-state UI can still surface 'last seen'."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    s = _session(
        reason="operator_signature_mismatch",  # Class C
        pre_status=AnonymizeStatus.EXITING.value,
        attempts=0,
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    out = await attempt_reconciliation(
        db_session,
        s,
        service=svc,
        now=now,
    )
    await db_session.commit()

    assert out.kind == "deferred"
    await db_session.refresh(s)
    assert s.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert s.reconciliation_attempts == 0  # not consumed
    assert s.last_reconciliation_attempt_ts is not None


@pytest.mark.asyncio
async def test_attempt_class_b_escalates_when_budget_exhausted(
    db_session,
) -> None:
    """Class B with attempts already at the constant budget escalates
    to FAILED on the next attempt."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    s = _session(
        reason="mpp_k_floor_exhausted",
        pre_status=AnonymizeStatus.EXITING.value,
        attempts=MAX_RETRIES_SEMI,  # next attempt = MAX_RETRIES_SEMI+1 > budget
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    out = await attempt_reconciliation(
        db_session,
        s,
        service=svc,
        now=now,
    )
    await db_session.commit()

    assert out.kind == "escalated"
    assert out.target_status == AnonymizeStatus.FAILED.value
    await db_session.refresh(s)
    assert s.status == AnonymizeStatus.FAILED.value
    # Audit event emitted.
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    kinds = [e.kind for e in events]
    assert "reconciliation_escalated" in kinds


@pytest.mark.asyncio
async def test_full_class_b_lifecycle_e2e(db_session) -> None:
    """integration: a session lands in AR via the helper, the
    probe attempts MAX_RETRIES_SEMI Class B retries (each followed
    by a fresh AR re-entry simulating a failing resume), and on the
    (N+1)th tick escalates to FAILED.

    Pins the recovery lifetime-accumulation invariant —
    attempts persist across AR cycles so the budget bounds total
    retries, not per-cycle retries."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()

    # Build a session in EXITING.
    s = _session(status=AnonymizeStatus.EXITING.value, reason=None, pre_status=None)
    db_session.add(s)
    await db_session.commit()

    # Reverse-hop emits the reason via the helper.
    await svc.transition_to_awaiting_reconciliation(
        db_session,
        s,
        reason="mpp_k_floor_exhausted",
    )
    await db_session.commit()
    assert s.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert s.pre_reconciliation_status == AnonymizeStatus.EXITING.value
    assert s.reconciliation_attempts == 0

    # Drive MAX_RETRIES_SEMI cycles: each tick resumes to EXITING,
    # then a simulated hop failure routes us back to AR. The
    # attempt counter accumulates across cycles.
    for cycle in range(MAX_RETRIES_SEMI):
        now = datetime.now(timezone.utc) + timedelta(seconds=10 + cycle * 100)
        out = await attempt_reconciliation(
            db_session,
            s,
            service=svc,
            now=now,
        )
        await db_session.commit()
        assert out.kind == "retried"
        assert s.status == AnonymizeStatus.EXITING.value
        assert s.reconciliation_attempts == cycle + 1
        # Simulate a fresh hop failure cycling us back to AR. The
        # helper preserves attempts.
        await svc.transition_to_awaiting_reconciliation(
            db_session,
            s,
            reason="mpp_k_floor_exhausted",
        )
        await db_session.commit()
        assert s.reconciliation_attempts == cycle + 1
        assert s.status == AnonymizeStatus.AWAITING_RECONCILIATION.value

    # One more tick: counter would bump to MAX_RETRIES_SEMI+1 which
    # exceeds the budget → escalate to FAILED.
    now = datetime.now(timezone.utc) + timedelta(hours=1)
    out = await attempt_reconciliation(
        db_session,
        s,
        service=svc,
        now=now,
    )
    await db_session.commit()
    assert out.kind == "escalated"
    assert s.status == AnonymizeStatus.FAILED.value

    # Audit event sequence: at least MAX_RETRIES_SEMI attempt_started
    # events plus the final escalated event.
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent)
                .where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
                .order_by(AnonymizeSessionEvent.id.asc())
            )
        )
        .scalars()
        .all()
    )
    kinds = [e.kind for e in events]
    assert kinds.count("reconciliation_attempt_started") == MAX_RETRIES_SEMI + 1
    assert kinds.count("reconciliation_attempt_completed") == MAX_RETRIES_SEMI + 1
    assert kinds.count("reconciliation_escalated") == 1

    # schema lock — verify every emitted event matches the
    # documented detail_json shape. A future schema drift (renamed
    # key, dropped field) will fail this test loudly.
    started_events = [e for e in events if e.kind == "reconciliation_attempt_started"]
    for e in started_events:
        d = e.detail_json
        assert set(d.keys()) >= {"attempts", "reason", "class", "target_status"}
        assert d["reason"] == "mpp_k_floor_exhausted"
        assert d["class"] in ("A", "B", "C")
        assert isinstance(d["attempts"], int)

    completed_events = [e for e in events if e.kind == "reconciliation_attempt_completed"]
    for e in completed_events:
        d = e.detail_json
        assert set(d.keys()) >= {"attempts", "outcome"}
        assert d["outcome"] in ("retried", "escalated", "deferred")

    escalated = [e for e in events if e.kind == "reconciliation_escalated"]
    assert len(escalated) == 1
    d = escalated[0].detail_json
    assert set(d.keys()) >= {"final_attempts", "from_class", "to_status"}
    assert d["from_class"] == "B"  # mpp_k_floor_exhausted is Class B
    assert d["to_status"] == AnonymizeStatus.FAILED.value
    assert isinstance(d["final_attempts"], int)
    await svc.stop()


@pytest.mark.asyncio
async def test_attempt_escalates_when_pre_status_missing(
    db_session,
) -> None:
    """Legacy AR rows with no pre_status (and no heuristic match)
    escalate cleanly rather than wedging the probe."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    s = _session(
        reason="circuit_rebuild_throttled",
        pre_status=None,
        attempts=0,
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    out = await attempt_reconciliation(
        db_session,
        s,
        service=svc,
        now=now,
    )
    await db_session.commit()

    assert out.kind == "escalated"
    assert out.target_status == AnonymizeStatus.FAILED.value


@pytest.mark.asyncio
async def test_attempt_class_a_retries_multiple_times(db_session) -> None:
    """Class A with attempts < budget keeps retrying."""
    settings.anonymize_enabled = True
    settings.anonymize_reconciliation_max_retries_transient = 5
    svc = get_anonymize_service()
    await svc.start()
    s = _session(
        reason="circuit_rebuild_throttled",
        pre_status=AnonymizeStatus.EXITING.value,
        attempts=2,  # 2 done, 3rd attempt next → still within budget=5
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    out = await attempt_reconciliation(
        db_session,
        s,
        service=svc,
        now=now,
    )
    await db_session.commit()

    assert out.kind == "retried"
    await db_session.refresh(s)
    assert s.reconciliation_attempts == 3


# ── Wedge detector ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wedge_detector_flips_idle_active_session(
    db_session,
) -> None:
    """An EXITING row whose updated_at is past the budget flips to AR
    with reason ``wall_clock_budget_exceeded``."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    now = datetime.now(timezone.utc)
    s = _session(
        status=AnonymizeStatus.EXITING.value,
        pre_status=None,
        reason=None,
        updated_at=now - timedelta(hours=10),
    )
    db_session.add(s)
    await db_session.commit()

    n = await apply_wedge_detector(
        db_session,
        service=svc,
        now=now,
        budget_s=3600.0,
    )
    await db_session.commit()

    assert n == 1
    await db_session.refresh(s)
    assert s.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert s.awaiting_reconciliation_reason == "wall_clock_budget_exceeded"
    # Audit event with the detail_json schema.
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    wall_clock_events = [e for e in events if e.kind == "reconciliation_wall_clock_flipped"]
    assert len(wall_clock_events) == 1
    detail = wall_clock_events[0].detail_json
    # schema: {"from_status": "...", "idle_s": N}
    assert detail["from_status"] == AnonymizeStatus.EXITING.value
    assert isinstance(detail["idle_s"], int)
    assert detail["idle_s"] >= 10 * 3600  # we set updated_at 10h ago


@pytest.mark.asyncio
async def test_wedge_detector_skips_recently_updated(db_session) -> None:
    """A row updated 5 minutes ago is not wedged for a 1-hour budget."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    now = datetime.now(timezone.utc)
    s = _session(
        status=AnonymizeStatus.EXITING.value,
        pre_status=None,
        reason=None,
        updated_at=now - timedelta(minutes=5),
    )
    db_session.add(s)
    await db_session.commit()

    n = await apply_wedge_detector(
        db_session,
        service=svc,
        now=now,
        budget_s=3600.0,
    )
    assert n == 0
    await db_session.refresh(s)
    assert s.status == AnonymizeStatus.EXITING.value


@pytest.mark.asyncio
async def test_wedge_detector_skips_ar_rows(db_session) -> None:
    """An AR row idle past the budget is left alone — the auto-retry
    sweep owns those."""
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    now = datetime.now(timezone.utc)
    s = _session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        reason="mpp_k_floor_exhausted",
        updated_at=now - timedelta(hours=10),
    )
    db_session.add(s)
    await db_session.commit()

    n = await apply_wedge_detector(
        db_session,
        service=svc,
        now=now,
        budget_s=3600.0,
    )
    assert n == 0


@pytest.mark.asyncio
async def test_wedge_detector_skips_terminal_rows(db_session) -> None:
    settings.anonymize_enabled = True
    svc = get_anonymize_service()
    await svc.start()
    now = datetime.now(timezone.utc)
    s = _session(
        status=AnonymizeStatus.COMPLETED.value,
        pre_status=None,
        reason=None,
        updated_at=now - timedelta(hours=10),
    )
    db_session.add(s)
    await db_session.commit()

    n = await apply_wedge_detector(
        db_session,
        service=svc,
        now=now,
        budget_s=3600.0,
    )
    assert n == 0


# ── Startup heuristic ────────────────────────────────────────────────


def test_heuristic_mpp_k_floor_exhausted_maps_to_exiting() -> None:
    """The 5a0da707-class legacy row case: infer EXITING."""
    assert heuristic_pre_status_for("mpp_k_floor_exhausted") == (AnonymizeStatus.EXITING.value)


def test_heuristic_unknown_reasons_return_none() -> None:
    """Reasons whose emit-site could be in many states are NOT
    inferred — the probe falls back to operator-fail."""
    assert heuristic_pre_status_for("circuit_rebuild_throttled") is None
    assert heuristic_pre_status_for("bounded_retry_exhausted") is None
    assert heuristic_pre_status_for(None) is None
    assert heuristic_pre_status_for("") is None
    assert heuristic_pre_status_for("totally_made_up") is None


@pytest.mark.asyncio
async def test_startup_heuristic_backfills_mpp_k_floor_row(
    db_session,
) -> None:
    """A legacy AR row with reason=mpp_k_floor_exhausted and NULL
    pre_status gets EXITING written + the audit event emitted."""
    settings.anonymize_enabled = True
    s = _session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        reason="mpp_k_floor_exhausted",
        pre_status=None,
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    n = await apply_startup_pre_status_heuristic(db_session, now=now)
    await db_session.commit()

    assert n == 1
    await db_session.refresh(s)
    assert s.pre_reconciliation_status == AnonymizeStatus.EXITING.value
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    )
    heur_events = [e for e in events if e.kind == "reconciliation_pre_status_heuristic_applied"]
    assert len(heur_events) == 1
    # schema: {"reason": "...", "inferred_pre_status": "..."}
    detail = heur_events[0].detail_json
    assert detail["reason"] == "mpp_k_floor_exhausted"
    assert detail["inferred_pre_status"] == AnonymizeStatus.EXITING.value


@pytest.mark.asyncio
async def test_startup_heuristic_skips_rows_without_known_mapping(
    db_session,
) -> None:
    """A legacy row whose reason isn't in the heuristic stays NULL —
    the probe's missing-target branch handles it via escalate."""
    settings.anonymize_enabled = True
    s = _session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        reason="circuit_rebuild_throttled",
        pre_status=None,
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    n = await apply_startup_pre_status_heuristic(db_session, now=now)
    await db_session.commit()

    assert n == 0
    await db_session.refresh(s)
    assert s.pre_reconciliation_status is None


@pytest.mark.asyncio
async def test_startup_heuristic_skips_rows_with_populated_pre_status(
    db_session,
) -> None:
    """Idempotency: rows that already have pre_status are skipped."""
    settings.anonymize_enabled = True
    s = _session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        reason="mpp_k_floor_exhausted",
        pre_status=AnonymizeStatus.HOPPING.value,  # already set
    )
    db_session.add(s)
    await db_session.commit()

    now = datetime.now(timezone.utc)
    n = await apply_startup_pre_status_heuristic(db_session, now=now)
    assert n == 0
    await db_session.refresh(s)
    # Unchanged.
    assert s.pre_reconciliation_status == AnonymizeStatus.HOPPING.value


# ── compute_next_retry_at_unix_s ─────────────────────────────────────


def test_next_retry_returns_none_when_not_in_ar() -> None:
    s = _session(status=AnonymizeStatus.EXITING.value)
    assert compute_next_retry_at_unix_s(s) is None


def test_next_retry_returns_none_for_class_c_reason() -> None:
    s = _session(
        reason="operator_signature_mismatch",
        attempts=1,
        last_attempt=datetime.now(timezone.utc),
    )
    assert compute_next_retry_at_unix_s(s) is None


def test_next_retry_returns_none_when_never_attempted() -> None:
    s = _session(reason="mpp_k_floor_exhausted", attempts=0, last_attempt=None)
    assert compute_next_retry_at_unix_s(s) is None


def test_next_retry_returns_future_timestamp_for_class_a() -> None:
    """Class A in cooldown returns a future Unix timestamp."""
    now = datetime.now(timezone.utc)
    s = _session(
        reason="circuit_rebuild_throttled",
        attempts=1,
        last_attempt=now,
    )
    out = compute_next_retry_at_unix_s(s, base_s=30, max_s=3600)
    assert out is not None
    assert out > now.timestamp()


def test_next_retry_returns_none_when_already_past() -> None:
    """Cooldown elapsed → returns None so the SPA stops showing
    'Next try in...' captions."""
    s = _session(
        reason="circuit_rebuild_throttled",
        attempts=1,
        last_attempt=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    # base=30, max=3600. Even at attempts=1 the backoff is 30s, well
    # under the 2-hour gap.
    out = compute_next_retry_at_unix_s(s, base_s=30, max_s=3600)
    assert out is None


# ── Probe runner — jitter ─────────────────────────────────────


@pytest.fixture
def _quote_keyset(monkeypatch):
    """Seed a Fernet quote-token key so the bootstrap canary passes.

    Mirrors the fixture in test_anonymize_orchestrator_bootstrap.py.
    """
    from cryptography.fernet import Fernet

    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.mark.asyncio
async def test_probe_runner_sleeps_jitter_before_work(
    db_engine,
    monkeypatch,
) -> None:
    """Each tick sleeps a random 0..interval*jitter_frac before
    running so the absolute cadence is jittered (fingerprint
    defense). Verified by injecting a deterministic ``rng`` + a
    sleep recorder and asserting sleep_fn was called with the
    expected value."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.tick_runners import (
        make_reconciliation_probe_run_fn,
    )

    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_interval_s",
        300,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_jitter_frac",
        0.20,
    )

    sleeps: list[float] = []

    async def _record_sleep(delay: float) -> None:
        sleeps.append(float(delay))

    # Deterministic "random" — always pick the midpoint of the
    # requested range so the test is reproducible.
    def _midpoint(lo: float, hi: float) -> float:
        return (lo + hi) / 2.0

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    svc = get_anonymize_service()
    await svc.start()
    try:
        run = make_reconciliation_probe_run_fn(
            service=svc,
            session_factory=factory,
            sleep_fn=_record_sleep,
            rng=_midpoint,
        )
        await run()
    finally:
        await svc.stop()

    # Exactly one jitter sleep should have fired at the start of
    # the tick. Expected value: midpoint of [0, 300*0.20] = 30s.
    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(30.0)


@pytest.mark.asyncio
async def test_probe_runner_skips_jitter_when_disabled(
    db_engine,
    monkeypatch,
) -> None:
    """A deployment that pins ``jitter_frac=0`` should NOT sleep."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.tick_runners import (
        make_reconciliation_probe_run_fn,
    )

    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_jitter_frac",
        0.0,
    )

    sleeps: list[float] = []

    async def _record_sleep(delay: float) -> None:
        sleeps.append(float(delay))

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    svc = get_anonymize_service()
    await svc.start()
    try:
        run = make_reconciliation_probe_run_fn(
            service=svc,
            session_factory=factory,
            sleep_fn=_record_sleep,
            rng=lambda _lo, _hi: 0.0,
        )
        await run()
    finally:
        await svc.stop()

    # No jitter sleep when frac=0 (the rng returns 0 anyway, but the
    # implementation should also short-circuit before calling sleep).
    assert sleeps == []


@pytest.mark.asyncio
async def test_probe_runner_clamps_jitter_frac_to_half(
    db_engine,
    monkeypatch,
) -> None:
    """A pathologically-large ``jitter_frac`` is clamped to 0.5 so
    two consecutive ticks can't compound into a full-interval skip.
    Without the clamp a frac of 1.5 would mean each tick could sleep
    longer than the interval, breaking the cadence contract."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.tick_runners import (
        make_reconciliation_probe_run_fn,
    )

    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_interval_s",
        100,
    )
    # Operator misconfigures to 1.5 (150% jitter — nonsensical).
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_jitter_frac",
        1.5,
    )

    sleeps: list[float] = []

    async def _record_sleep(delay: float) -> None:
        sleeps.append(float(delay))

    # rng that always returns the upper bound of its range.
    def _max_rng(_lo: float, hi: float) -> float:
        return float(hi)

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    svc = get_anonymize_service()
    await svc.start()
    try:
        run = make_reconciliation_probe_run_fn(
            service=svc,
            session_factory=factory,
            sleep_fn=_record_sleep,
            rng=_max_rng,
        )
        await run()
    finally:
        await svc.stop()

    # Clamped at 0.5 → max sleep = 100 * 0.5 = 50.0, NOT 150.0.
    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(50.0)


# ── Probe runner — boot delay ────────────────────────────────


@pytest.mark.asyncio
async def test_bootstrap_reconciliation_probe_has_boot_delay(
    db_engine,
    monkeypatch,
    _quote_keyset,
) -> None:
    """The orchestrator's first probe tick fires at least
    ``ANONYMIZE_RECONCILIATION_PROBE_BOOT_DELAY_S`` seconds after
    bootstrap. Implemented by setting the task's
    ``cooldown_until_unix_s`` to ``now + boot_delay``."""
    import time as _time

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.service import (
        bootstrap_anonymize_orchestrator,
    )

    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_boot_delay_s",
        60,
    )

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    reset_anonymize_service()
    before = _time.time()
    svc = await bootstrap_anonymize_orchestrator()
    after = _time.time()
    try:
        tasks = list(svc._state.scheduler.tasks())  # type: ignore[attr-defined]
        probe = next(t for t in tasks if t.name == "reconciliation_probe")
        # Cooldown should bracket ``boot_time + 60`` to within the
        # bootstrap's own wall-clock cost.
        assert probe.cooldown_until_unix_s is not None
        assert probe.cooldown_until_unix_s >= before + 50
        assert probe.cooldown_until_unix_s <= after + 70
    finally:
        await svc.stop()


# ── Probe runner — per-row exception isolation (commit-per-row) ─


@pytest.mark.asyncio
async def test_probe_runner_isolates_per_row_exceptions(
    db_engine,
    monkeypatch,
) -> None:
    """commit-per-row contract: one row raising mid-attempt
    must NOT prevent subsequent rows from being processed. The probe
    catches the exception, rolls back the partial work, and continues
    to the next row's fresh attempt.

    Builds three AR rows: row 0 succeeds, row 1 raises during
    attempt_reconciliation, row 2 succeeds. Asserts both rows 0
    and 2 transitioned out of AR (proving row 1's exception didn't
    poison the session)."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize import reconciliation_probe
    from app.services.anonymize.service import get_anonymize_service
    from app.services.anonymize.tick_runners import (
        make_reconciliation_probe_run_fn,
    )

    monkeypatch.setattr(settings, "anonymize_enabled", True)
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_jitter_frac",
        0.0,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_reconciliation_probe_batch_size",
        50,
    )

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    svc = get_anonymize_service()
    await svc.start()

    # Build 3 AR rows via the helper so they're in the right state.
    row_ids: list = []
    async with factory() as setup_db:
        for i in range(3):
            row = _session(
                status=AnonymizeStatus.EXITING.value,
                reason=None,
                pre_status=None,
            )
            setup_db.add(row)
            await setup_db.flush()
            await svc.transition_to_awaiting_reconciliation(
                setup_db,
                row,
                reason="mpp_k_floor_exhausted",
            )
            row_ids.append(row.id)
        await setup_db.commit()

    # Patch attempt_reconciliation to raise on the second call only.
    call_count = {"n": 0}
    real_attempt = reconciliation_probe.attempt_reconciliation

    async def _attempt_with_one_failure(db, sess, *, service, now):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("simulated mid-attempt failure")
        return await real_attempt(db, sess, service=service, now=now)

    monkeypatch.setattr(
        reconciliation_probe,
        "attempt_reconciliation",
        _attempt_with_one_failure,
    )
    # Also patch the import the tick_runners module took at import time.
    # tick_runners imports attempt_reconciliation INSIDE the closure,
    # not at module scope — so monkeypatching the probe module is
    # sufficient. Verify by inspection.

    try:
        run = make_reconciliation_probe_run_fn(
            service=svc,
            session_factory=factory,
            sleep_fn=lambda _s: _noop_coro(),
            rng=lambda _lo, _hi: 0.0,
        )
        await run()
    finally:
        await svc.stop()

    # Verify: 3 attempts were called.
    assert call_count["n"] == 3

    # Verify: rows 0 and 2 transitioned out of AR (success path).
    # Row 1's attempt raised so it stays in AR.
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSession

    async with factory() as fresh:
        rows = (
            (
                await fresh.execute(
                    select(AnonymizeSession)
                    .where(AnonymizeSession.id.in_(row_ids))
                    .order_by(AnonymizeSession.created_at.asc())
                )
            )
            .scalars()
            .all()
        )
    statuses = [r.status for r in rows]
    # Row 0 (first attempt) transitioned to EXITING (the resume target).
    assert statuses[0] == AnonymizeStatus.EXITING.value, f"row 0 should have resumed; got {statuses[0]!r}"
    # Row 1 (raised) stayed in AR.
    assert statuses[1] == AnonymizeStatus.AWAITING_RECONCILIATION.value, (
        f"row 1 should have stayed in AR after the failure; got {statuses[1]!r}"
    )
    # Row 2 (third attempt) ALSO transitioned out — this is the test's
    # critical assertion. Without per-row commits + rollback, row 1's
    # exception could leave the session in a state that blocks row 2.
    assert statuses[2] == AnonymizeStatus.EXITING.value, (
        f"row 2 should have resumed despite row 1's failure; got "
        f"{statuses[2]!r}. The per-row commit + rollback contract from "
        f" isn't holding."
    )


async def _noop_coro() -> None:
    return None
