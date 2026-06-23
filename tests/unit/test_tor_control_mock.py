# SPDX-License-Identifier: MIT
"""Validate the Tor control-port mock against the existing
``probe_tor_bootstrap_status`` so we know later tests can rely on
it. If this fails after a real-Tor protocol change, the mock needs
to be updated to match.
"""

from __future__ import annotations

import pytest

from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control


@pytest.mark.asyncio
async def test_mock_drives_bootstrap_probe_ready(monkeypatch) -> None:
    """Mock returns a fully-bootstrapped status; probe must agree."""
    from app.services.anonymize.tor import probe_tor_bootstrap_status

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO status/bootstrap-phase",
        '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n250 OK\r\n',
    )
    mock.set_response(
        "GETINFO status/circuit-established",
        "250-status/circuit-established=1\r\n250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        status = await probe_tor_bootstrap_status(
            host="127.0.0.1",
            port=9100,
        )
    assert status.control_port_reachable is True
    assert status.bootstrap_phase_progress == 100
    assert status.circuit_established is True
    assert status.fully_bootstrapped
    # Protocol order: AUTHENTICATE → 2 GETINFOs → QUIT.
    assert mock.commands[0].startswith("AUTHENTICATE")
    assert mock.commands[1] == "GETINFO status/bootstrap-phase"
    assert mock.commands[2] == "GETINFO status/circuit-established"
    assert mock.commands[3] == "QUIT"


@pytest.mark.asyncio
async def test_mock_drives_bootstrap_probe_not_ready(monkeypatch) -> None:
    """Mock returns mid-bootstrap; probe reports not-fully-ready."""
    from app.services.anonymize.tor import probe_tor_bootstrap_status

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO status/bootstrap-phase",
        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=conn "
        'SUMMARY="Connecting to a relay"\r\n250 OK\r\n',
    )
    mock.set_response(
        "GETINFO status/circuit-established",
        "250-status/circuit-established=0\r\n250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        status = await probe_tor_bootstrap_status(host="127.0.0.1", port=9100)
    assert status.control_port_reachable is True
    assert status.bootstrap_phase_progress == 45
    assert status.circuit_established is False
    assert not status.fully_bootstrapped


@pytest.mark.asyncio
async def test_mock_authenticates_with_password(monkeypatch) -> None:
    """Pass a password; mock records it verbatim in the AUTH command."""
    from app.services.anonymize.tor import probe_tor_bootstrap_status

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO status/bootstrap-phase",
        "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100\r\n250 OK\r\n",
    )
    mock.set_response(
        "GETINFO status/circuit-established",
        "250-status/circuit-established=1\r\n250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        await probe_tor_bootstrap_status(
            host="127.0.0.1",
            port=9100,
            password="hunter2",
        )
    assert mock.commands[0] == 'AUTHENTICATE "hunter2"'
