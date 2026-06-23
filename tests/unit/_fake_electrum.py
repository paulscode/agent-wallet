# SPDX-License-Identifier: MIT
"""Fake in-process Electrum server for unit & integration tests.

Speaks newline-delimited JSON-RPC over plain TCP on
``127.0.0.1:<ephemeral>``. Provides scripted responses for any
method name; supports notification dispatch and forced disconnects so
reconnect logic can be exercised.

Usage::

    async with FakeElectrumServer() as server:
        server.set_response("server.version", ["ElectrumX 1.16.0", "1.4"])
        server.set_response("blockchain.headers.subscribe",
                            {"height": 800_000, "hex": "00" * 80})
        client = ElectrumClient(server.url, ...)
        await client.start()
        result = await client.request("blockchain.estimatefee", [6])
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable, Optional

_Handler = Callable[[list[Any]], Awaitable[Any]]


class FakeElectrumServer:
    """Async context-managed fake server."""

    def __init__(self) -> None:
        self._server: Optional[asyncio.base_events.Server] = None
        self.host = "127.0.0.1"
        self.port: int = 0
        # method → static response, callable, or list of responses (queue).
        self._responses: dict[str, Any] = {}
        # Live writers (for notifications + forced disconnects).
        self._writers: list[asyncio.StreamWriter] = []
        # Method call log (method, params).
        self.calls: list[tuple[str, list[Any]]] = []
        # Counters for connection events.
        self.connection_count = 0

        # Defaults that satisfy a basic handshake.
        self.set_response("server.version", ["FakeElectrum 0.0.1", "1.4"])
        self.set_response(
            "blockchain.headers.subscribe",
            {"height": 800_000, "hex": "00" * 80},
        )
        self.set_response("server.ping", None)

    @property
    def url(self) -> str:
        return f"tcp://{self.host}:{self.port}"

    async def __aenter__(self) -> "FakeElectrumServer":
        self._server = await asyncio.start_server(self._handle, host=self.host, port=0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        for w in list(self._writers):
            try:
                w.close()
            except Exception:
                pass
        self._writers.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # ── Scripting ───────────────────────────────────────────────────

    def set_response(self, method: str, value: Any) -> None:
        """Set a static response for ``method``."""
        self._responses[method] = ("static", value)

    def set_handler(self, method: str, handler: _Handler) -> None:
        """Set a coroutine handler called with the method's params."""
        self._responses[method] = ("handler", handler)

    def queue_response(self, method: str, value: Any) -> None:
        """Queue a one-shot response (consumed in FIFO order)."""
        entry = self._responses.get(method)
        if entry is None or entry[0] != "queue":
            self._responses[method] = ("queue", [])
            entry = self._responses[method]
        entry[1].append(value)

    def set_error(self, method: str, code: int, message: str) -> None:
        """Make ``method`` return a JSON-RPC error."""
        self._responses[method] = ("error", (code, message))

    async def disconnect_all(self) -> None:
        for w in list(self._writers):
            try:
                w.close()
            except Exception:
                pass

    async def notify_headers(self, height: int, hex_header: str = "00" * 80) -> None:
        """Push a ``blockchain.headers.subscribe`` notification."""
        await self._broadcast(
            {
                "jsonrpc": "2.0",
                "method": "blockchain.headers.subscribe",
                "params": [{"height": height, "hex": hex_header}],
            }
        )

    async def notify_scripthash(self, scripthash: str, status: Optional[str]) -> None:
        await self._broadcast(
            {
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [scripthash, status],
            }
        )

    async def _broadcast(self, message: dict[str, Any]) -> None:
        payload = (json.dumps(message) + "\n").encode()
        for w in list(self._writers):
            try:
                w.write(payload)
                await w.drain()
            except Exception:
                pass

    # ── Connection handler ──────────────────────────────────────────

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connection_count += 1
        self._writers.append(writer)
        try:
            while True:
                try:
                    line = await reader.readuntil(b"\n")
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                try:
                    msg = json.loads(line.decode())
                except Exception:
                    continue
                method = msg.get("method")
                params = msg.get("params") or []
                rid = msg.get("id")
                self.calls.append((method, params))
                response = await self._make_response(method, params, rid)
                if response is not None:
                    writer.write((json.dumps(response) + "\n").encode())
                    try:
                        await writer.drain()
                    except ConnectionError:
                        return
        finally:
            try:
                self._writers.remove(writer)
            except ValueError:
                pass
            try:
                writer.close()
            except Exception:
                pass

    async def _make_response(self, method: str, params: list[Any], rid: Any) -> Optional[dict[str, Any]]:
        entry = self._responses.get(method)
        if entry is None:
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
        kind, value = entry
        if kind == "static":
            return {"jsonrpc": "2.0", "id": rid, "result": value}
        if kind == "queue":
            if value:
                return {"jsonrpc": "2.0", "id": rid, "result": value.pop(0)}
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {"code": -1, "message": "queue empty"},
            }
        if kind == "handler":
            result = await value(params)  # type: ignore[misc]
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        if kind == "error":
            code, message = value
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "error": {"code": code, "message": message},
            }
        return None
