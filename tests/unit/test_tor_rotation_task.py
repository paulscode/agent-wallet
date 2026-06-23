# SPDX-License-Identifier: MIT
"""Preventive Tor age rotation task tests.

Pins the in-flight gate (defer when anything is live) + the SIGHUP
issuance path. The task itself runs inside Celery; we exercise the
async impl ``_run_rotate_tor_age`` directly.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.tor_inflight import InFlightResult
from app.tasks.boltz_tasks import _run_rotate_tor_age


def _async_null_db():
    """Context manager whose ``__aenter__`` yields a MagicMock. The
    in-flight check is the only consumer of the session in this
    path; we patch the check itself."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        yield MagicMock()

    return _ctx


@pytest.mark.asyncio
async def test_defers_when_in_flight() -> None:
    """If anything looks live (LN HTLCs, swaps, etc.), SIGHUP must
    NOT fire — the operator-facing audit row records the deferral."""
    sh = AsyncMock(return_value=(True, None))
    audit = AsyncMock()
    with (
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(
                return_value=InFlightResult(
                    in_flight=True,
                    surfaces=["lnd_htlc"],
                )
            ),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
        patch(
            "app.services.anonymize.tor.signal_reload",
            sh,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            audit,
        ),
    ):
        result = await _run_rotate_tor_age()

    sh.assert_not_called()
    assert result["status"] == "deferred"
    assert result["surfaces"] == ["lnd_htlc"]
    audit.assert_any_call(
        "tor_age_rotation_deferred",
        details={"surfaces": ["lnd_htlc"]},
    )


@pytest.mark.asyncio
async def test_defers_when_in_flight_check_raises() -> None:
    """A failed in-flight check defers (fail-closed) so a probe
    error doesn't accidentally interrupt a live payment."""
    sh = AsyncMock(return_value=(True, None))
    with (
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(side_effect=RuntimeError("DB unreachable")),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
        patch(
            "app.services.anonymize.tor.signal_reload",
            sh,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            AsyncMock(),
        ),
    ):
        result = await _run_rotate_tor_age()

    sh.assert_not_called()
    assert result["status"] == "deferred"
    assert result["reason"] == "in_flight_check_raised"


@pytest.mark.asyncio
async def test_fires_sighup_when_nothing_in_flight() -> None:
    """All-clear path: SIGHUP fires once, audit row records the
    rotation, no NEWNYM (rotation uses HUP, not NEWNYM)."""
    sh = AsyncMock(return_value=(True, None))
    nn = AsyncMock()  # NEWNYM must NOT be called
    audit = AsyncMock()
    with (
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(return_value=InFlightResult(in_flight=False, surfaces=[])),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
        patch(
            "app.services.anonymize.tor.signal_reload",
            sh,
        ),
        patch(
            "app.services.anonymize.tor.signal_newnym",
            nn,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            audit,
        ),
    ):
        result = await _run_rotate_tor_age()

    sh.assert_awaited_once()
    nn.assert_not_called()
    assert result["status"] == "fired"
    audit.assert_any_call("tor_age_rotation_fired", details={})


@pytest.mark.asyncio
async def test_audits_failure_when_sighup_fails() -> None:
    """A SIGHUP that returns (False, err) must NOT raise — the
    rotation simply records the failure for the operator and the
    next tick retries."""
    sh = AsyncMock(return_value=(False, "control port closed"))
    audit = AsyncMock()
    with (
        patch(
            "app.services.tor_inflight.check_in_flight",
            AsyncMock(return_value=InFlightResult(in_flight=False, surfaces=[])),
        ),
        patch(
            "app.core.database.get_db_context",
            _async_null_db(),
        ),
        patch(
            "app.services.anonymize.tor.signal_reload",
            sh,
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            audit,
        ),
    ):
        result = await _run_rotate_tor_age()

    assert result["status"] == "error"
    audit.assert_any_call(
        "tor_age_rotation_failed",
        details={"error": "control port closed"},
    )
