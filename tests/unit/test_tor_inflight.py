# SPDX-License-Identifier: MIT
"""In-flight detection inventory.

The watchdog gates NEWNYM on `check_in_flight() → in_flight=False`.
These tests pin each surface's wiring + the fail-safe defer behaviour
on probe failure.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest

from app.services.tor_inflight import InFlightResult, check_in_flight


def _factory_for(session) -> object:
    """Wrap a mock session in a ``check_in_flight``-shaped factory.

    Production passes :func:`app.core.database.get_db_context`; tests
    pass a thunk that returns an async context manager yielding the
    mock session each time it's called. The mock is shared across
    concurrent probes — that's fine because ``MagicMock.execute`` is
    a plain async method without SQLAlchemy's connection-state
    machine, so it doesn't hit ISCE.
    """

    @asynccontextmanager
    async def _ctx():
        yield session

    return _ctx


@pytest.fixture
def db_session() -> MagicMock:
    """Return a MagicMock that masquerades as an AsyncSession.

    The in-flight helper calls ``db.execute(stmt)`` and reads
    ``.first()``. We use a MagicMock that returns
    ``no-row-found`` (== closed/empty) by default; individual tests
    override per-surface by recording the SQL fragment they expect."""
    session = MagicMock()

    async def _execute(stmt):
        result = MagicMock()
        result.first.return_value = None  # no rows by default
        return result

    session.execute = _execute
    return session


# ── No in-flight: all surfaces clean → in_flight=False ─────────────


@pytest.mark.asyncio
async def test_no_in_flight_returns_false(db_session, monkeypatch) -> None:
    """When every surface is empty (and the LND probe says no in-flight
    HTLCs), the result is in_flight=False with no surfaces listed."""

    # Mock LND list-payments → empty.
    async def _lnd_probe() -> bool:
        return False

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    # Mock anonymize service.
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=0)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory_for(db_session))
    assert isinstance(result, InFlightResult)
    assert result.in_flight is False
    assert result.surfaces == []


# ── LND probe failure → fail-safe defer ─────────────────────────────


@pytest.mark.asyncio
async def test_lnd_probe_failure_defers(db_session, monkeypatch) -> None:
    """If the LND probe raises / times out, the helper must
    fail-safe to in_flight=True. Cause: an open Tor breaker IS
    the scenario the watchdog is meant to recover from, so the
    LND probe will routinely fail during that window. We must NOT
    fire NEWNYM during the window in which we can't know whether
    HTLCs are in flight."""

    async def _lnd_probe() -> bool:
        return True  # mock returns True on failure (fail-safe)

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=0)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory_for(db_session))
    assert result.in_flight is True
    assert "lnd_htlc" in result.surfaces


# ── Step-up nonce in flight → defer + surface labelled ──────────────


@pytest.mark.asyncio
async def test_stepup_nonce_blocks_newnym(monkeypatch) -> None:
    """A pending step-up nonce must block NEWNYM. Drives
    the surface label so the audit-log records 'anonymize_stepup'."""

    # Mock DB session that returns a row for the step-up query and
    # nothing for the others.
    db = MagicMock()
    call_count = {"n": 0}

    async def _execute(stmt):
        call_count["n"] += 1
        result = MagicMock()
        # Step-up query is in position ~5 (after lnd_htlc/boltz/braiins/
        # anonymize_session — but check_in_flight runs DB probes in
        # parallel so we can't rely on order). Inspect the statement.
        s = str(stmt).lower()
        if "anonymize_stepup_state" in s:
            result.first.return_value = (1,)
        else:
            result.first.return_value = None
        return result

    db.execute = _execute

    # No-op LND probe.
    async def _lnd_probe() -> bool:
        return False

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=0)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory_for(db))
    assert result.in_flight is True
    assert "anonymize_stepup" in result.surfaces


# ── Anonymize session in flight → defer ─────────────────────────────


@pytest.mark.asyncio
async def test_anonymize_session_in_flight_blocks_newnym(
    db_session,
    monkeypatch,
) -> None:
    """If AnonymizeService.in_flight_count() returns > 0, the
    watchdog defers."""

    async def _lnd_probe() -> bool:
        return False

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=2)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory_for(db_session))
    assert result.in_flight is True
    assert "anonymize_session" in result.surfaces


# ── Multiple surfaces: every hitting label appears ──────────────────


@pytest.mark.asyncio
async def test_multiple_surfaces_all_reported(monkeypatch) -> None:
    """When multiple surfaces are in-flight, the audit-log must
    record EACH of them so operators can diagnose deferral causes."""
    db = MagicMock()

    async def _execute(stmt):
        result = MagicMock()
        s = str(stmt).lower()
        # Match Boltz + Braiins; rest empty.
        if "boltz_swap" in s or "braiins_deposit" in s:
            result.first.return_value = (1,)
        else:
            result.first.return_value = None
        return result

    db.execute = _execute

    async def _lnd_probe() -> bool:
        return True  # also in-flight

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=0)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory_for(db))
    assert result.in_flight is True
    assert "lnd_htlc" in result.surfaces
    assert "boltz_swap" in result.surfaces
    assert "braiins_deposit" in result.surfaces


# ── Probe raising an exception → fail-safe ──────────────────────────


@pytest.mark.asyncio
async def test_individual_probe_raises_treated_as_in_flight(
    monkeypatch,
) -> None:
    """If a single DB probe raises (e.g. a connection blip), the
    helper must NOT propagate — treat the surface as in-flight and
    keep going."""
    db = MagicMock()

    async def _execute(stmt):
        s = str(stmt).lower()
        if "boltz_swap" in s:
            raise RuntimeError("synthetic db blip")
        result = MagicMock()
        result.first.return_value = None
        return result

    db.execute = _execute

    async def _lnd_probe() -> bool:
        return False

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=0)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory_for(db))
    assert result.in_flight is True
    assert "boltz_swap" in result.surfaces


# ── Concurrency: each DB probe must get its own session ────────────


@pytest.mark.asyncio
async def test_each_db_probe_gets_its_own_session(monkeypatch) -> None:
    """Regression: 2026-06-02 incident — ``check_in_flight`` used to
    share one ``AsyncSession`` across 4 concurrent probes, and
    SQLAlchemy's ISCE guard ("session is provisioning a new
    connection; concurrent operations are not permitted") fired on
    every probe. Every surface fail-safed to in-flight, and the
    watchdog deferred NEWNYM forever. Pin: the factory must be
    invoked once per DB-touching probe."""
    from contextlib import asynccontextmanager

    sessions_handed_out: list = []

    @asynccontextmanager
    async def _factory():
        session = MagicMock()

        async def _execute(stmt):
            result = MagicMock()
            result.first.return_value = None
            return result

        session.execute = _execute
        sessions_handed_out.append(session)
        yield session

    async def _lnd_probe() -> bool:
        return False

    monkeypatch.setattr("app.services.tor_inflight._lnd_htlc_in_flight", _lnd_probe)
    fake_svc = MagicMock()
    fake_svc.in_flight_count = MagicMock(return_value=0)
    with patch(
        "app.services.anonymize.service.get_anonymize_service",
        return_value=fake_svc,
    ):
        result = await check_in_flight(_factory)

    assert result.in_flight is False
    # Four DB-touching probes: boltz_swap, braiins_deposit,
    # anonymize_stepup, bolt12_invoice_request.
    assert len(sessions_handed_out) == 4


# ── LND HTLC probe internals ───────────────────────────────────────


@pytest.mark.asyncio
async def test_lnd_htlc_probe_detects_in_flight_payment(monkeypatch) -> None:
    """A payment with status IN_FLIGHT makes the LND probe report
    in-flight=True directly (not via the fail-safe path)."""
    from app.services import tor_inflight as tif

    class _Svc:
        async def list_payments_raw(self, **kwargs):
            return {"payments": [{"status": "IN_FLIGHT"}]}, None

    monkeypatch.setattr("app.services.lnd_service.lnd_service", _Svc())
    assert await tif._lnd_htlc_in_flight() is True


@pytest.mark.asyncio
async def test_lnd_htlc_probe_clean_when_no_in_flight(monkeypatch) -> None:
    """Completed/failed payments only → probe returns False (nothing
    blocking NEWNYM from the LN side)."""
    from app.services import tor_inflight as tif

    class _Svc:
        async def list_payments_raw(self, **kwargs):
            return {"payments": [{"status": "SUCCEEDED"}, {"status": "FAILED"}]}, None

    monkeypatch.setattr("app.services.lnd_service.lnd_service", _Svc())
    assert await tif._lnd_htlc_in_flight() is False


@pytest.mark.asyncio
async def test_lnd_htlc_probe_failsafe_on_error_field(monkeypatch) -> None:
    """When LND returns an error (breaker open — the very state the
    watchdog recovers from), the probe can't tell, so it fail-safes
    to in-flight=True and defers NEWNYM."""
    from app.services import tor_inflight as tif

    class _Svc:
        async def list_payments_raw(self, **kwargs):
            return None, "breaker open"

    monkeypatch.setattr("app.services.lnd_service.lnd_service", _Svc())
    assert await tif._lnd_htlc_in_flight() is True


@pytest.mark.asyncio
async def test_lnd_htlc_probe_failsafe_on_timeout(monkeypatch) -> None:
    """A probe that exceeds the tight timeout fail-safes to defer —
    a wedged LND must not lead to interrupting in-flight HTLCs."""
    import asyncio

    from app.services import tor_inflight as tif

    class _Svc:
        async def list_payments_raw(self, **kwargs):
            await asyncio.sleep(10)
            return {"payments": []}, None

    monkeypatch.setattr("app.services.lnd_service.lnd_service", _Svc())
    monkeypatch.setattr(tif, "_LND_PROBE_TIMEOUT_S", 0.01)
    assert await tif._lnd_htlc_in_flight() is True


@pytest.mark.asyncio
async def test_lnd_htlc_probe_uses_fallback_when_no_raw_method(monkeypatch) -> None:
    """If ``lnd_service`` lacks ``list_payments_raw``, the probe
    routes through ``_list_payments_fallback`` which hits ``_request``
    against the payments endpoint and surfaces the same shape."""
    from app.services import tor_inflight as tif

    class _Svc:
        async def _request(self, method, path, params=None):
            assert path == "/v1/payments"
            return {"payments": [{"status": "IN_FLIGHT"}]}, None

    monkeypatch.setattr("app.services.lnd_service.lnd_service", _Svc())
    assert await tif._lnd_htlc_in_flight() is True


@pytest.mark.asyncio
async def test_list_payments_fallback_wraps_request_exception(monkeypatch) -> None:
    """The fallback returns ``(None, error_str)`` when ``_request``
    raises, so the caller treats it as the can't-tell fail-safe case
    rather than crashing."""
    from app.services import tor_inflight as tif

    class _Svc:
        async def _request(self, *a, **k):
            raise RuntimeError("transport blew up")

    monkeypatch.setattr("app.services.lnd_service.lnd_service", _Svc())
    data, err = await tif._list_payments_fallback()
    assert data is None
    assert "transport blew up" in err


@pytest.mark.asyncio
async def test_anonymize_probe_failsafe_when_service_raises(monkeypatch) -> None:
    """If the anonymize service lookup raises, the count probe
    fail-safes to 1 (treat as in-flight) so a broken anonymize
    subsystem can't green-light a disruptive NEWNYM."""
    from app.services import tor_inflight as tif

    def _boom():
        raise RuntimeError("anonymize service unavailable")

    monkeypatch.setattr(
        "app.services.anonymize.service.get_anonymize_service",
        _boom,
    )
    assert await tif._anonymize_session_in_flight_count() == 1


@pytest.mark.asyncio
async def test_cold_storage_and_inbound_liquidity_probes_return_zero() -> None:
    """These two surfaces are covered transitively by the BoltzSwap
    probe; their standalone helpers return 0 (kept only for audit-log
    label clarity)."""
    from unittest.mock import MagicMock

    from app.services import tor_inflight as tif

    db = MagicMock()
    assert await tif._cold_storage_swap_in_flight_count(db) == 0
    assert await tif._inbound_liquidity_swap_in_flight_count(db) == 0
