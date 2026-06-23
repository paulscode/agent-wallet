# SPDX-License-Identifier: MIT
"""Unit tests for the bounded-body outbound HTTP read helper."""

from __future__ import annotations

import httpx
import pytest

from app.core.http_limits import ResponseTooLargeError, request_capped


def _client_streaming(body: bytes, *, status_code: int = 200, chunk: int = 4):
    """Build an httpx client whose responses stream ``body`` in chunks."""

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, content=body)

    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport)


@pytest.mark.asyncio
async def test_body_within_cap_is_returned():
    async with _client_streaming(b'{"ok": true}') as client:
        resp = await request_capped(client, "GET", "https://example.test/x", max_bytes=1000)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


@pytest.mark.asyncio
async def test_body_over_cap_is_refused():
    async with _client_streaming(b"x" * 5000) as client:
        with pytest.raises(ResponseTooLargeError):
            await request_capped(client, "GET", "https://example.test/x", max_bytes=1024)


@pytest.mark.asyncio
async def test_zero_cap_disables_limit():
    async with _client_streaming(b"y" * 5000) as client:
        resp = await request_capped(client, "GET", "https://example.test/x", max_bytes=0)
    assert len(resp.content) == 5000


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
@pytest.mark.asyncio
async def test_compressed_body_is_decoded_once(encoding):
    import gzip
    import zlib

    payload = b'{"hello": "world"}'
    body = gzip.compress(payload) if encoding == "gzip" else zlib.compress(payload)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Encoding": encoding, "Content-Type": "application/json"},
            content=body,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await request_capped(client, "GET", "https://example.test/x", max_bytes=10000)
    # The body must decode exactly once: rebuilding the response must not
    # re-run the Content-Encoding decoder over already-decoded bytes.
    assert resp.json() == {"hello": "world"}
    assert resp.headers.get("content-type") == "application/json"


@pytest.mark.asyncio
async def test_default_cap_from_settings(monkeypatch):
    from app.core import http_limits

    monkeypatch.setattr(http_limits.settings, "outbound_max_response_bytes", 16, raising=False)
    async with _client_streaming(b"z" * 64) as client:
        with pytest.raises(ResponseTooLargeError):
            await request_capped(client, "GET", "https://example.test/x")
