# SPDX-License-Identifier: MIT
"""Probe_entry_guards() + probe_network_liveness() unit tests.

These probes are diagnostic surfaces for the dashboard Tor-health
panel. They read Tor's own assessment of guard reachability +
overall network status via the control port.
"""

from __future__ import annotations

import pytest

from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control

# ── probe_entry_guards ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_entry_guards_parses_multi_guard_response(
    monkeypatch,
) -> None:
    from app.services.anonymize.tor import probe_entry_guards

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO entry-guards",
        "250+entry-guards=\r\n"
        "$ABCD1234ABCD1234~Guard1 up\r\n"
        "$EF56EF56EF56EF56~Guard2 down\r\n"
        "$0011002200110022~Guard3 unlisted\r\n"
        ".\r\n"
        "250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        guards, err = await probe_entry_guards(host="127.0.0.1", port=9100)
    assert err is None
    assert len(guards) == 3
    assert guards[0].fingerprint == "abcd1234abcd1234"
    assert guards[0].nickname == "Guard1"
    assert guards[0].status == "up"
    assert guards[1].status == "down"
    assert guards[2].status == "unlisted"


@pytest.mark.asyncio
async def test_probe_entry_guards_handles_missing_nickname(monkeypatch) -> None:
    """Some Tor versions/configurations omit the ~Nickname token."""
    from app.services.anonymize.tor import probe_entry_guards

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO entry-guards",
        "250+entry-guards=\r\n$ABCD1234ABCD1234 up\r\n.\r\n250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        guards, err = await probe_entry_guards(host="127.0.0.1", port=9100)
    assert err is None
    assert len(guards) == 1
    assert guards[0].nickname == ""
    assert guards[0].status == "up"


@pytest.mark.asyncio
async def test_probe_entry_guards_connect_failure(monkeypatch) -> None:
    """Unreachable control port → empty list + descriptive error."""
    import asyncio

    async def _refuse(*args, **kwargs):
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(asyncio, "open_connection", _refuse)
    from app.services.anonymize.tor import probe_entry_guards

    guards, err = await probe_entry_guards(host="127.0.0.1", port=9100)
    assert guards == []
    assert err is not None
    assert "connect failed" in err.lower()


# ── probe_network_liveness ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_network_liveness_up(monkeypatch) -> None:
    from app.services.anonymize.tor import probe_network_liveness

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO network-liveness",
        "250-network-liveness=up\r\n250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        is_live, err = await probe_network_liveness(host="127.0.0.1", port=9100)
    assert err is None
    assert is_live is True


@pytest.mark.asyncio
async def test_probe_network_liveness_down(monkeypatch) -> None:
    from app.services.anonymize.tor import probe_network_liveness

    mock = TorControlPortMock()
    mock.set_response(
        "GETINFO network-liveness",
        "250-network-liveness=down\r\n250 OK\r\n",
    )
    with mock_tor_control(monkeypatch, mock):
        is_live, err = await probe_network_liveness(host="127.0.0.1", port=9100)
    assert err is None
    assert is_live is False


@pytest.mark.asyncio
async def test_probe_network_liveness_unparseable(monkeypatch) -> None:
    """Garbage response → False + descriptive error (not a crash)."""
    from app.services.anonymize.tor import probe_network_liveness

    mock = TorControlPortMock()
    mock.set_response("GETINFO network-liveness", "550 Unknown command\r\n")
    with mock_tor_control(monkeypatch, mock):
        is_live, err = await probe_network_liveness(host="127.0.0.1", port=9100)
    assert is_live is False
    assert err is not None
    assert "unparseable" in err.lower()
