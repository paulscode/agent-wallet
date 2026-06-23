# SPDX-License-Identifier: MIT
"""Response-floor middleware for the anonymize endpoints.

Every ``POST /anonymize/quote``
response (success or any 422) waits until at least
``ANONYMIZE_QUOTE_RESPONSE_FLOOR_MS`` (default 250 ms) has elapsed
since request entry, defeating the timing-channel oracle that
otherwise distinguishes reuse-match vs malformed-script vs success.

Every ``POST /anonymize/sessions``
response also has a floor (``ANONYMIZE_CREATE_RESPONSE_FLOOR_MS``,
default 350 ms) plus per-request jitter. Cap-rejection branches
execute the would-be insert's ballast under a savepoint so the cost
shape matches the success path; that ballast lives in the create
endpoint, not here.

The middleware is registered as the *first* middleware on the
``/anonymize/*`` router so 401 / 403 / 422 fast-fail
paths from auth / CSRF / body validation are also floor-covered.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings


class AnonymizeTimingMiddleware(BaseHTTPMiddleware):
    """Floors response time on ``/anonymize/*`` write paths."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Only interfere with anonymize-prefixed paths; passing
        # everything through the floor would burden unrelated
        # dashboard traffic and could cause user-visible latency.
        path = request.url.path
        if not path.startswith("/dashboard/api/anonymize/"):
            return await call_next(request)

        start = time.monotonic()
        response = await call_next(request)
        # Resolve the floor for this method/path tuple.
        floor_ms = self._resolve_floor_ms(request.method, path)
        if floor_ms <= 0:
            return response
        elapsed_ms = (time.monotonic() - start) * 1000.0
        # jitter on top of the floor so the floor itself
        # does not become a uniform-distribution fingerprint.
        jitter_ms = self._sample_jitter_ms(path)
        target_ms = floor_ms + jitter_ms
        if elapsed_ms < target_ms:
            await asyncio.sleep((target_ms - elapsed_ms) / 1000.0)
        return response

    @staticmethod
    def _is_quote_path(path: str) -> bool:
        """True for the quote family, including the ``/quote/multi`` variant."""
        return "/anonymize/quote" in path

    @staticmethod
    def _resolve_floor_ms(method: str, path: str) -> float:
        """Return the configured floor for the (method, path) tuple.

        Every anonymize state-changing POST is floored: the quote family
        (``/quote`` and ``/quote/multi``) shares the quote floor; every other
        anonymize POST — ``sessions``, ``sessions/multi``, ``cancel``,
        ``refund``, ``reconciliation/*``, ``spend-override``,
        ``liquid-recovery/*`` — shares the (larger) create floor. Flooring
        only the two exact original paths left the reuse-match vs malformed vs
        success timing oracle open on every other write route.
        """
        if method != "POST":
            return 0.0
        if AnonymizeTimingMiddleware._is_quote_path(path):
            return float(settings.anonymize_quote_response_floor_ms)
        return float(settings.anonymize_create_response_floor_ms)

    @staticmethod
    def _sample_jitter_ms(path: str) -> float:
        """Uniform jitter on top of the floor so it is not a flat line."""
        if AnonymizeTimingMiddleware._is_quote_path(path):
            cap = settings.anonymize_quote_response_floor_jitter_ms
        else:
            cap = settings.anonymize_create_response_floor_jitter_ms
        if cap <= 0:
            return 0.0
        return secrets.SystemRandom().uniform(0.0, float(cap))


__all__ = ["AnonymizeTimingMiddleware"]
