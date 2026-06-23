# SPDX-License-Identifier: MIT
"""Startup exit-relay diversity smoke test cases.

Three behavioural contracts to pin:
  - Skipped (no failure) when Tor isn't bootstrapped.
  - Hard-fail (raise) on observed circuit collision — broken
    listener isolation is a security regression.
  - Soft-fail (no raise) when some probes time out but no collision
    is observed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.anonymize.tor import CircuitExitInfo
from app.services.tor_diversity_smoke import (
    DiversitySmokeFailureError,
    run_diversity_smoke,
)


def _circuit(cid: str) -> CircuitExitInfo:
    """Build a minimal CircuitExitInfo for the smoke test's
    GETINFO circuit-status responses."""
    return CircuitExitInfo(
        circuit_id=cid,
        exit_fingerprint="$FAKE",
        exit_ip="0.0.0.0",
    )


class _BootStub:
    """Stub stand-in for ``TorBootstrapStatus``. Only the
    ``circuit_established`` attribute matters for the smoke test."""

    def __init__(self, established: bool) -> None:
        self.circuit_established = established


@pytest.fixture(autouse=True)
def _tor_proxy_set(monkeypatch) -> None:
    """The smoke test short-circuits when ``lnd_tor_proxy`` is
    empty (test/CI default). Set it for these cases so the inner
    behaviour we want to pin actually runs."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_tor_proxy",
        "socks5h://tor-proxy:9050",
    )


@pytest.mark.asyncio
async def test_skips_when_tor_not_bootstrapped() -> None:
    """Cold-boot path: probe says circuit not established → result
    has ``skipped=True``, no exceptions, no probes attempted."""
    with patch(
        "app.services.anonymize.tor.probe_tor_bootstrap_status",
        AsyncMock(return_value=_BootStub(False)),
    ):
        result = await run_diversity_smoke()

    assert result.skipped is True
    assert result.ok is True  # not failed, just skipped
    assert result.listeners_probed == 0


@pytest.mark.asyncio
async def test_skips_when_no_listeners_configured(monkeypatch) -> None:
    """Empty SOCKS port dict → skipped (operator running their own
    Tor outside the compose stack)."""
    monkeypatch.setattr(
        "app.core.config.settings.anonymize_tor_socks_ports",
        "",
    )
    result = await run_diversity_smoke()
    assert result.skipped is True


@pytest.mark.asyncio
async def test_hard_fails_on_circuit_collision() -> None:
    """When N>=2 listener probes succeed but post-probe
    circuit-status shows fewer NEW distinct circuits than ok
    probes → DiversitySmokeFailureError raised. This is the security-
    regression path we test for."""
    # Before/after circuit-status: probes succeed but only one new
    # circuit shows up post-probe → collision.
    before = [_circuit("0")]  # pre-existing
    after = [_circuit("0"), _circuit("1")]  # one new circuit total

    with (
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(return_value=_BootStub(True)),
        ),
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(side_effect=[(before, None), (after, None)]),
        ),
        patch(
            "app.services.tor_diversity_smoke._hold_one_probe",
            AsyncMock(return_value=True),  # every probe succeeds
        ),
    ):
        with pytest.raises(DiversitySmokeFailureError) as excinfo:
            await run_diversity_smoke()

    msg = str(excinfo.value)
    assert "diversity smoke FAILED" in msg or "diversity" in msg.lower()


@pytest.mark.asyncio
async def test_soft_fail_on_probe_timeouts() -> None:
    """Some probes time out → soft-fail (ok=False, no exception)
    so a network blip at startup doesn't refuse to serve."""
    before = []
    after = [_circuit(str(i)) for i in range(8)]

    async def mixed_probe(_port, _hold):
        # Half the probes "succeed", half "fail".
        return _port % 2 == 0

    with (
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(return_value=_BootStub(True)),
        ),
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(side_effect=[(before, None), (after, None)]),
        ),
        patch(
            "app.services.tor_diversity_smoke._hold_one_probe",
            side_effect=mixed_probe,
        ),
    ):
        # Must not raise — partial probe failures are soft.
        result = await run_diversity_smoke()

    assert result.ok is False
    assert result.skipped is False
    assert result.listeners_ok > 0
    assert result.error is not None


@pytest.mark.asyncio
async def test_ok_when_every_listener_gets_distinct_circuit() -> None:
    """All probes succeed AND distinct_circuits >= probes → ok=True."""
    before = []
    after = [_circuit(str(i)) for i in range(8)]

    with (
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(return_value=_BootStub(True)),
        ),
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(side_effect=[(before, None), (after, None)]),
        ),
        patch(
            "app.services.tor_diversity_smoke._hold_one_probe",
            AsyncMock(return_value=True),
        ),
    ):
        result = await run_diversity_smoke()

    assert result.ok is True
    assert result.skipped is False
    assert result.listeners_ok == result.listeners_probed
    assert result.distinct_circuits >= result.listeners_ok
