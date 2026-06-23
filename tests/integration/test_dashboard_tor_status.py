# SPDX-License-Identifier: MIT
"""Dashboard ``/dashboard/api/tor-status`` endpoint tests.

The endpoint backs the SPA's Tor Health panel. It must:
  - Require dashboard cookie auth (anonymous → 401/403, not 200).
  - Return a flat JSON shape the @alpinejs/csp build can consume
    without dotted-chain short-circuiting.
  - Surface ``None`` for probes that failed rather than raising 500
    (the panel renders "unknown" client-side).
"""

from __future__ import annotations

import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME


def _make_session_cookie() -> str:
    expires = int(time.time()) + 86400
    # Modern cookie format: ``session_id:expires`` (the legacy id-less
    # format is rejected). Use a UNIQUE session id per cookie so a
    # revoke/logout test can't poison the process-local revocation
    # cache for other tests sharing this helper.
    import secrets as _secrets

    payload = f"sess-itest-{_secrets.token_urlsafe(8)}:{expires}"
    from app.dashboard.auth import _sign  # production (domain-separated) signer

    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dashboard_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    from fastapi import FastAPI

    from app.dashboard.api import router as dashboard_api
    from app.dashboard.routes import router as dashboard_routes

    app = FastAPI()
    app.include_router(dashboard_routes)
    app.include_router(dashboard_api)

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


@pytest.fixture
def auth_cookies(dashboard_client):
    dashboard_client.cookies.set(COOKIE_NAME, _make_session_cookie())
    return {COOKIE_NAME: _make_session_cookie()}


def _patch_all_tor_probes(boot=None, circuits=None, guards=None, net_live=None, used_mb=None):
    """Returns a tuple of context managers patching every probe the
    /tor-status endpoint calls so a test can compose them with a
    single nested with-block (or contextlib.ExitStack)."""
    from contextlib import ExitStack

    stack = ExitStack()
    stack.enter_context(
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(return_value=boot),
        )
    )
    stack.enter_context(
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(return_value=(circuits or [], None)),
        )
    )
    stack.enter_context(
        patch(
            "app.services.anonymize.tor.probe_entry_guards",
            AsyncMock(return_value=(guards or [], None)),
        )
    )
    stack.enter_context(
        patch(
            "app.services.anonymize.tor.probe_network_liveness",
            AsyncMock(return_value=(net_live, None)),
        )
    )
    stack.enter_context(
        patch(
            "app.services.tor_watchdog._data_dir_used_mb",
            AsyncMock(return_value=used_mb),
        )
    )
    return stack


# ── Auth ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tor_status_requires_auth(dashboard_client):
    """Anonymous → 401/403, never a 200 with Tor internals."""
    resp = await dashboard_client.get("/dashboard/api/tor-status")
    assert resp.status_code in (401, 403)


# ── Shape: flat JSON, no nested chains ─────────────────────────────


@pytest.mark.asyncio
async def test_tor_status_returns_flat_shape(dashboard_client, auth_cookies):
    """The @alpinejs/csp build can't short-circuit ``a && a.b`` chains
    reliably. The dashboard endpoint must keep the response shape
    flat — every key resolves to a single number/string/bool, with
    nested arrays only where the SPA explicitly iterates."""

    class _BootStub:
        bootstrap_phase_progress = 100
        circuit_established = True
        control_port_reachable = True

    with _patch_all_tor_probes(boot=_BootStub(), used_mb=42):
        resp = await dashboard_client.get("/dashboard/api/tor-status")

    assert resp.status_code == 200
    body = resp.json()
    # Top-level keys the SPA template references directly.
    expected_keys = {
        "bootstrap_progress",
        "circuit_established",
        "control_port_reachable",
        "active_circuits",
        "guards_total",
        "guards_up",
        "guards",
        "network_liveness",
        "tor_breaker_state",
        "tor_breaker_failures",
        "tor_breaker_last_error",
        "lnd_breaker_state",
        "watchdog_alive",
        "watchdog_last_tick_age_s",
        "watchdog_last_newnym_age_s",
        "event_stream_connected",
        "event_stream_circ_failed",
        "event_stream_hs_desc_failed",
        "event_stream_guard_down",
        "data_dir_used_mb",
    }
    missing = expected_keys - body.keys()
    assert not missing, f"flat shape missing keys: {missing}"
    # Each top-level value (except ``guards`` which is a list) is a
    # primitive — no nested dicts.
    for k, v in body.items():
        if k == "guards":
            assert isinstance(v, list)
            continue
        assert not isinstance(v, dict), f"key {k!r} must be a primitive for @alpinejs/csp consumption, got dict: {v!r}"


@pytest.mark.asyncio
async def test_tor_status_surfaces_unknown_when_probes_fail(
    dashboard_client,
    auth_cookies,
):
    """If every probe raises, the endpoint still returns 200 with
    None / empty defaults — the panel renders "unknown" rather than
    a 500."""
    with (
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
        patch(
            "app.services.anonymize.tor.probe_entry_guards",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
        patch(
            "app.services.anonymize.tor.probe_network_liveness",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
        patch(
            "app.services.tor_watchdog._data_dir_used_mb",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
    ):
        resp = await dashboard_client.get("/dashboard/api/tor-status")

    assert resp.status_code == 200
    body = resp.json()
    assert body["bootstrap_progress"] is None
    assert body["circuit_established"] is None
    assert body["control_port_reachable"] is False
    assert body["active_circuits"] == 0
    assert body["guards"] == []
    assert body["network_liveness"] == "unknown"
    assert body["data_dir_used_mb"] is None


@pytest.mark.asyncio
async def test_tor_status_surfaces_guard_status_for_each_entry(
    dashboard_client,
    auth_cookies,
):
    """The panel renders one row per guard with its status; the
    endpoint flattens EntryGuardInfo → dicts."""
    from app.services.anonymize.tor import EntryGuardInfo

    guards = [
        EntryGuardInfo(fingerprint="$AAA", nickname="guard-1", status="up"),
        EntryGuardInfo(fingerprint="$BBB", nickname="", status="down"),
    ]

    class _BootStub:
        bootstrap_phase_progress = 100
        circuit_established = True
        control_port_reachable = True

    with _patch_all_tor_probes(boot=_BootStub(), guards=guards):
        resp = await dashboard_client.get("/dashboard/api/tor-status")

    body = resp.json()
    assert body["guards_total"] == 2
    assert body["guards_up"] == 1
    assert body["guards"][0]["status"] == "up"
    assert body["guards"][1]["status"] == "down"
    assert body["guards"][1]["nickname"] == ""
