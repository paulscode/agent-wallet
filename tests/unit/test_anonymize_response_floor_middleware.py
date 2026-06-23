# SPDX-License-Identifier: MIT
"""Quote response floor middleware.

The floor must be applied to ``POST /anonymize/quote`` and
``POST /anonymize/sessions``. Other routes pass through. The
middleware must defeat the timing oracle that would otherwise
distinguish reuse-match vs malformed-script vs success.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import settings
from app.services.anonymize.middleware import AnonymizeTimingMiddleware


def _make_request(method: str, path: str) -> MagicMock:
    req = MagicMock()
    req.method = method
    req.url.path = path
    return req


@pytest.mark.asyncio
async def test_quote_post_is_floored(monkeypatch) -> None:
    """A response that returns instantly is delayed to the floor."""
    monkeypatch.setattr(settings, "anonymize_quote_response_floor_ms", 80)
    mw = AnonymizeTimingMiddleware(app=MagicMock())
    call_next = AsyncMock(return_value=MagicMock())
    req = _make_request("POST", "/dashboard/api/anonymize/quote")

    start = time.monotonic()
    await mw.dispatch(req, call_next)
    elapsed_ms = (time.monotonic() - start) * 1000.0
    # Allow some scheduler slack; the floor must be at least met.
    assert elapsed_ms >= 75, f"floor not enforced (elapsed={elapsed_ms} ms)"


@pytest.mark.asyncio
async def test_sessions_post_is_floored(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_create_response_floor_ms", 60)
    monkeypatch.setattr(settings, "anonymize_create_response_floor_jitter_ms", 0)
    mw = AnonymizeTimingMiddleware(app=MagicMock())
    call_next = AsyncMock(return_value=MagicMock())
    req = _make_request("POST", "/dashboard/api/anonymize/sessions")

    start = time.monotonic()
    await mw.dispatch(req, call_next)
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert elapsed_ms >= 55, f"floor not enforced (elapsed={elapsed_ms} ms)"


@pytest.mark.asyncio
async def test_get_request_passes_through(monkeypatch) -> None:
    """No floor on GET requests."""
    monkeypatch.setattr(settings, "anonymize_quote_response_floor_ms", 500)
    mw = AnonymizeTimingMiddleware(app=MagicMock())
    call_next = AsyncMock(return_value=MagicMock())
    req = _make_request("GET", "/dashboard/api/anonymize/policy")
    start = time.monotonic()
    await mw.dispatch(req, call_next)
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert elapsed_ms < 100  # passed through


@pytest.mark.asyncio
async def test_non_anonymize_path_passes_through(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_response_floor_ms", 500)
    mw = AnonymizeTimingMiddleware(app=MagicMock())
    call_next = AsyncMock(return_value=MagicMock())
    req = _make_request("POST", "/dashboard/api/payments/send")
    start = time.monotonic()
    await mw.dispatch(req, call_next)
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert elapsed_ms < 100


@pytest.mark.asyncio
async def test_cancel_refund_are_floored(monkeypatch) -> None:
    """Cancel/refund are floored like every other anonymize write so they do
    not re-open the reuse-match vs malformed vs success timing oracle."""
    monkeypatch.setattr(settings, "anonymize_create_response_floor_ms", 200)
    monkeypatch.setattr(settings, "anonymize_create_response_floor_jitter_ms", 0)
    mw = AnonymizeTimingMiddleware(app=MagicMock())
    call_next = AsyncMock(return_value=MagicMock())
    req = _make_request("POST", "/dashboard/api/anonymize/sessions/abc/cancel")
    start = time.monotonic()
    await mw.dispatch(req, call_next)
    elapsed_ms = (time.monotonic() - start) * 1000.0
    assert elapsed_ms >= 200


def test_floor_resolver() -> None:
    """Direct unit-level check on the floor resolver helper."""
    assert (
        AnonymizeTimingMiddleware._resolve_floor_ms("POST", "/dashboard/api/anonymize/quote")
        == settings.anonymize_quote_response_floor_ms
    )
    assert (
        AnonymizeTimingMiddleware._resolve_floor_ms("POST", "/dashboard/api/anonymize/sessions")
        == settings.anonymize_create_response_floor_ms
    )
    assert AnonymizeTimingMiddleware._resolve_floor_ms("GET", "/dashboard/api/anonymize/quote") == 0
    # Every other anonymize state-changing POST shares the create floor so the
    # timing oracle is closed on cancel / refund / reconciliation / multi too.
    assert (
        AnonymizeTimingMiddleware._resolve_floor_ms("POST", "/dashboard/api/anonymize/sessions/x/cancel")
        == settings.anonymize_create_response_floor_ms
    )
    assert (
        AnonymizeTimingMiddleware._resolve_floor_ms("POST", "/dashboard/api/anonymize/quote/multi")
        == settings.anonymize_quote_response_floor_ms
    )
