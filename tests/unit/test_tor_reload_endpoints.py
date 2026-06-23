# SPDX-License-Identifier: MIT
"""Tor SIGHUP reload endpoint tests.

Two endpoints to cover:
  - ``POST /v1/admin/tor/reload`` (admin auth).
  - ``POST /dashboard/api/tor-reload`` (dashboard cookie + CSRF).

Both must:
  - Be POST-only (avoid CSRF on a GET).
  - Call ``signal_reload()`` and return its (ok, error) shape.
  - Surface a torrc-rejection (ok=False) as a 200 with ``ok: false``
    so the operator UI can show the error string.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.api import admin as admin_module
from app.dashboard import api as dashboard_api_module


@pytest.mark.asyncio
async def test_admin_reload_returns_ok_true_on_success() -> None:
    """signal_reload returns (True, None) → endpoint returns ok=True."""
    with patch(
        "app.services.anonymize.tor.signal_reload",
        AsyncMock(return_value=(True, None)),
    ):
        # Call the route handler directly; bypassing the auth
        # dependency is fine because the dependency injection layer
        # is exercised in the dashboard auth integration tests.
        result = await admin_module.reload_tor_config(admin_key=None)  # type: ignore[arg-type]
    assert result == {"ok": True, "error": None}


@pytest.mark.asyncio
async def test_admin_reload_surfaces_torrc_rejection() -> None:
    """A bad torrc → Tor refuses to reload but stays running.
    The endpoint returns ok=False + the error so the UI shows it."""
    with patch(
        "app.services.anonymize.tor.signal_reload",
        AsyncMock(return_value=(False, "torrc syntax error")),
    ):
        result = await admin_module.reload_tor_config(admin_key=None)  # type: ignore[arg-type]
    assert result["ok"] is False
    assert "torrc" in result["error"]


@pytest.mark.asyncio
async def test_dashboard_reload_returns_ok_true_on_success() -> None:
    with patch(
        "app.services.anonymize.tor.signal_reload",
        AsyncMock(return_value=(True, None)),
    ):
        result = await dashboard_api_module.post_tor_reload()
    assert result == {"ok": True, "error": None}


@pytest.mark.asyncio
async def test_dashboard_reload_surfaces_error() -> None:
    with patch(
        "app.services.anonymize.tor.signal_reload",
        AsyncMock(return_value=(False, "control port unreachable")),
    ):
        result = await dashboard_api_module.post_tor_reload()
    assert result["ok"] is False
    assert "control port" in result["error"]
