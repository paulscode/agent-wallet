# SPDX-License-Identifier: MIT
"""Mock Tor control-port protocol for unit tests.

The wallet's Tor probes / signals talk to Tor over a text-based TCP
control protocol (``AUTHENTICATE … / GETINFO … / SIGNAL … / QUIT``).
Spinning up a real Tor process for every unit test is too slow + too
flaky; this module gives tests a programmable mock that speaks the
protocol over an asyncio stream pair.

Usage:

    from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control

    @pytest.mark.asyncio
    async def test_thing(monkeypatch):
        mock = TorControlPortMock()
        mock.set_response("GETINFO status/bootstrap-phase",
                          "250-status/bootstrap-phase=NOTICE … PROGRESS=100\\r\\n250 OK\\r\\n")
        with mock_tor_control(monkeypatch, mock):
            from app.services.anonymize.tor import probe_tor_bootstrap_status
            status = await probe_tor_bootstrap_status()
            assert status.fully_bootstrapped

The mock records every command sent so tests can assert exact
protocol expectations.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Iterator

# Canned responses keyed by exact command string (without trailing \r\n).
# Tests configure via :meth:`set_response`; un-configured commands get
# a default ``250 OK\\r\\n``.
_DEFAULT_REPLY = "250 OK\r\n"


class TorControlPortMock:
    """Programmable mock of the Tor control-port protocol.

    Holds a per-instance command log + a response map. Test fixtures
    instantiate one mock per test, configure the responses the wallet
    code expects, and assert against ``commands`` after the call.
    """

    def __init__(self, *, accept_auth: bool = True) -> None:
        self.commands: list[str] = []
        self._responses: dict[str, str] = {}
        # Whether AUTHENTICATE succeeds. Tests that exercise the
        # "password required but wrong / missing" path flip this.
        self.accept_auth = accept_auth
        # Track teardown so tests can assert ``QUIT`` was sent.
        self.closed = False

    def set_response(self, command: str, reply: str) -> None:
        """Configure the canned reply for ``command``. The reply
        string is sent verbatim; callers are responsible for the
        ``250-…\\r\\n250 OK\\r\\n`` envelope shape Tor uses."""
        self._responses[command.strip()] = reply

    def reply_for(self, command: str) -> str:
        """Resolve the reply for ``command``. Always-on AUTHENTICATE
        success/failure shape; otherwise look up the configured
        response or fall back to ``250 OK\\r\\n``."""
        cmd = command.strip()
        if cmd.startswith("AUTHENTICATE"):
            if self.accept_auth:
                return "250 OK\r\n"
            return "515 Authentication failed\r\n"
        if cmd == "QUIT":
            return "250 closing connection\r\n"
        return self._responses.get(cmd, _DEFAULT_REPLY)


class _MockStreamReader:
    """Minimal subset of ``asyncio.StreamReader`` the wallet code uses."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._closed = False
        self._waiters: list[asyncio.Event] = []

    def feed(self, data: bytes) -> None:
        self._buffer.extend(data)
        for ev in self._waiters:
            ev.set()
        self._waiters.clear()

    def close_eof(self) -> None:
        self._closed = True
        for ev in self._waiters:
            ev.set()
        self._waiters.clear()

    async def readline(self) -> bytes:
        while True:
            idx = self._buffer.find(b"\n")
            if idx >= 0:
                line = bytes(self._buffer[: idx + 1])
                del self._buffer[: idx + 1]
                return line
            if self._closed:
                if self._buffer:
                    rest = bytes(self._buffer)
                    self._buffer.clear()
                    return rest
                return b""
            ev = asyncio.Event()
            self._waiters.append(ev)
            await ev.wait()


class _MockStreamWriter:
    """Minimal subset of ``asyncio.StreamWriter`` the wallet uses."""

    def __init__(self, mock: TorControlPortMock, reader: _MockStreamReader) -> None:
        self._mock = mock
        self._reader = reader
        self._pending = bytearray()
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        self._pending.extend(data)
        # The wallet sends complete lines terminated by \r\n; reply
        # immediately so the reader can pick up the response on its
        # next readline.
        while b"\r\n" in self._pending:
            idx = self._pending.find(b"\r\n")
            line = bytes(self._pending[:idx])
            del self._pending[: idx + 2]
            cmd = line.decode("ascii", errors="replace")
            self._mock.commands.append(cmd)
            reply = self._mock.reply_for(cmd)
            self._reader.feed(reply.encode("ascii"))

    async def drain(self) -> None:
        return

    def close(self) -> None:
        self._closed = True
        self._mock.closed = True
        self._reader.close_eof()

    async def wait_closed(self) -> None:
        return


@contextlib.contextmanager
def mock_tor_control(
    monkeypatch,
    mock: TorControlPortMock,
) -> Iterator[TorControlPortMock]:
    """Patch ``asyncio.open_connection`` to return a stream pair
    backed by ``mock``. Yields the mock so the test body can keep a
    handle to ``mock.commands``."""

    async def _fake_open_connection(host, port, *args, **kwargs):
        reader = _MockStreamReader()
        writer = _MockStreamWriter(mock, reader)
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", _fake_open_connection)
    try:
        yield mock
    finally:
        # No teardown required — monkeypatch reverts on context exit.
        pass


__all__ = ["TorControlPortMock", "mock_tor_control"]
