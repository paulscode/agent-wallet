# SPDX-License-Identifier: MIT
"""Bounded-body HTTP reads for outbound requests.

``httpx`` buffers a response body in full with no size limit. For outbound
calls to operator-configured or signed-registry endpoints (Boltz, the DoH
resolver, the chain backend) the body is read straight into memory, so a
misbehaving or compromised upstream can stream an arbitrarily large response.

``request_capped`` streams the response and stops once the accumulated body
exceeds a byte ceiling, then returns a fully-materialised ``httpx.Response``
so call sites use ``.status_code`` / ``.json()`` / ``.text`` /
``.raise_for_status()`` exactly as they would with a normal request.
"""

import httpx

from app.core.config import settings

__all__ = ["ResponseTooLargeError", "request_capped"]


class ResponseTooLargeError(Exception):
    """Raised when a response body exceeds the configured byte ceiling."""


async def request_capped(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_bytes: int | None = None,
    **kwargs: object,
) -> httpx.Response:
    """Issue a request and read the body under a hard byte ceiling.

    Streams the response so an oversized body is refused mid-read rather
    than buffered whole. ``max_bytes`` defaults to
    ``settings.outbound_max_response_bytes``; a ceiling of 0 disables the
    cap. Returns a materialised ``httpx.Response`` whose ``.content`` holds
    the bytes read.
    """
    cap = settings.outbound_max_response_bytes if max_bytes is None else max_bytes
    async with client.stream(method, url, **kwargs) as resp:  # type: ignore[arg-type]
        buf = bytearray()
        async for chunk in resp.aiter_bytes():
            buf.extend(chunk)
            if cap and len(buf) > cap:
                raise ResponseTooLargeError(f"response body exceeded {cap}-byte cap")
        # ``aiter_bytes`` has already decoded any Content-Encoding (gzip /
        # br / deflate), so ``buf`` holds the plaintext body. Drop the
        # framing headers that describe the encoded form — keeping
        # ``Content-Encoding`` would make the rebuilt response decode the
        # body a second time, and ``Content-Length`` / ``Transfer-Encoding``
        # no longer match the decoded length.
        headers = httpx.Headers(resp.headers)
        for stale in ("content-encoding", "content-length", "transfer-encoding"):
            if stale in headers:
                del headers[stale]
        return httpx.Response(
            status_code=resp.status_code,
            headers=headers,
            content=bytes(buf),
            request=resp.request,
        )
