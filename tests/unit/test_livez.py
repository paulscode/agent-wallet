# SPDX-License-Identifier: MIT
"""Tests for the ``/livez`` Docker healthcheck endpoint.

Pins the 200/503 boundary across:
  * keepalive disabled (skip check)
  * keepalive warming up (grace period)
  * keepalive recently successful (healthy)
  * keepalive last-success stale (unhealthy)
  * DB probe failing / timing out (unhealthy)
  * both healthy ⇒ 200
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from app.api.livez import router as livez_router


@pytest.fixture
def app_with_livez() -> FastAPI:
    app = FastAPI()
    app.include_router(livez_router)
    return app


@pytest.fixture(autouse=True)
def _reset_keepalive_state():
    from app.services import lnd_keepalive

    lnd_keepalive._STATE = lnd_keepalive._KeepaliveState()
    yield
    lnd_keepalive._STATE = lnd_keepalive._KeepaliveState()


def _ok_db_ctx():
    @asynccontextmanager
    async def _ctx():
        db = MagicMock()

        async def _execute(stmt):
            return MagicMock()

        db.execute = _execute
        yield db

    return _ctx


def _broken_db_ctx(exc):
    @asynccontextmanager
    async def _ctx():
        db = MagicMock()

        async def _execute(stmt):
            raise exc

        db.execute = _execute
        yield db

    return _ctx


def _slow_db_ctx():
    @asynccontextmanager
    async def _ctx():
        db = MagicMock()

        async def _execute(stmt):
            # Longer than the livez DB-probe timeout.
            await asyncio.sleep(10.0)

        db.execute = _execute
        yield db

    return _ctx


async def _get(app, path: str):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        return await ac.get(path)


# ── Healthy: keepalive disabled + DB ok → 200 ─────────────────────


@pytest.mark.asyncio
async def test_keepalive_disabled_is_healthy(app_with_livez) -> None:
    """Operators may disable the keepalive (``interval<=0``); livez
    must still report healthy on the strength of the DB probe."""
    fake_settings = MagicMock(lnd_keepalive_interval_s=0)
    with patch("app.core.config.settings", fake_settings), patch("app.core.database.get_db_context", _ok_db_ctx()):
        r = await _get(app_with_livez, "/livez")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["checks"]["keepalive"]["reason"] == "keepalive_disabled"


# ── Warming up: pre-first-success but within grace ─────────────────


@pytest.mark.asyncio
async def test_keepalive_warming_within_grace_is_healthy(
    app_with_livez,
) -> None:
    """During the warm-up grace window (started_at < grace_s ago),
    a still-pending first success must NOT mark unhealthy."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    lnd_keepalive._STATE.last_success_at = None

    fake_settings = MagicMock(lnd_keepalive_interval_s=60)
    with patch("app.core.config.settings", fake_settings), patch("app.core.database.get_db_context", _ok_db_ctx()):
        r = await _get(app_with_livez, "/livez")
    assert r.status_code == 200
    assert r.json()["checks"]["keepalive"]["status"] == "warming"


# ── Past grace + no first success → 503 ───────────────────────────


@pytest.mark.asyncio
async def test_keepalive_no_first_success_past_grace_is_unhealthy(
    app_with_livez,
) -> None:
    """If the task has been running well past the grace window but
    never had a single success, treat as unhealthy."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=600)
    lnd_keepalive._STATE.last_success_at = None
    lnd_keepalive._STATE.last_error = "timeout after 20s"

    fake_settings = MagicMock(lnd_keepalive_interval_s=60)
    with patch("app.core.config.settings", fake_settings), patch("app.core.database.get_db_context", _ok_db_ctx()):
        r = await _get(app_with_livez, "/livez")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "unhealthy"
    assert body["checks"]["keepalive"]["reason"] == "no_first_success"


# ── Stale last success → 503 ───────────────────────────────────────


@pytest.mark.asyncio
async def test_keepalive_stale_last_success_is_unhealthy(
    app_with_livez,
) -> None:
    """Last success older than the max age (the LND-wedge scenario
    from 2026-06-02): healthcheck must trip to 503 so Docker bounces
    the container under its restart policy."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=3600)
    lnd_keepalive._STATE.last_success_at = datetime.now(timezone.utc) - timedelta(seconds=600)
    lnd_keepalive._STATE.last_error = "timeout after 20s"

    fake_settings = MagicMock(lnd_keepalive_interval_s=60)
    with patch("app.core.config.settings", fake_settings), patch("app.core.database.get_db_context", _ok_db_ctx()):
        r = await _get(app_with_livez, "/livez")
    assert r.status_code == 503
    assert r.json()["checks"]["keepalive"]["reason"] == "last_success_stale"


# ── Recent last success → 200 ──────────────────────────────────────


@pytest.mark.asyncio
async def test_keepalive_recent_success_is_healthy(app_with_livez) -> None:
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=600)
    lnd_keepalive._STATE.last_success_at = datetime.now(timezone.utc) - timedelta(seconds=30)

    fake_settings = MagicMock(lnd_keepalive_interval_s=60)
    with patch("app.core.config.settings", fake_settings), patch("app.core.database.get_db_context", _ok_db_ctx()):
        r = await _get(app_with_livez, "/livez")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── DB probe failure → 503 even if keepalive is fine ──────────────


@pytest.mark.asyncio
async def test_db_probe_raising_is_unhealthy(app_with_livez) -> None:
    """DB connection-pool exhaustion (the ISCE-cascade symptom from
    the 2026-06-02 wedge) must trip livez to 503 even when
    keepalive is healthy."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=600)
    lnd_keepalive._STATE.last_success_at = datetime.now(timezone.utc) - timedelta(seconds=30)

    fake_settings = MagicMock(lnd_keepalive_interval_s=60)
    with (
        patch("app.core.config.settings", fake_settings),
        patch(
            "app.core.database.get_db_context",
            _broken_db_ctx(RuntimeError("synthetic ISCE")),
        ),
    ):
        r = await _get(app_with_livez, "/livez")
    assert r.status_code == 503
    body = r.json()
    assert body["checks"]["db"]["reason"] == "db_probe_raised"


@pytest.mark.asyncio
async def test_db_probe_timeout_is_unhealthy(app_with_livez) -> None:
    """A DB probe that exceeds the livez timeout (e.g. DB blocked
    on a stuck transaction) must mark unhealthy rather than letting
    the healthcheck hang."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=600)
    lnd_keepalive._STATE.last_success_at = datetime.now(timezone.utc) - timedelta(seconds=30)

    # Shrink the probe timeout so the test doesn't wait 5s.
    with patch("app.api.livez._LIVENESS_DB_PROBE_TIMEOUT_S", 0.05):
        fake_settings = MagicMock(lnd_keepalive_interval_s=60)
        with (
            patch("app.core.config.settings", fake_settings),
            patch("app.core.database.get_db_context", _slow_db_ctx()),
        ):
            r = await _get(app_with_livez, "/livez")
    assert r.status_code == 503
    assert r.json()["checks"]["db"]["reason"] == "db_probe_timeout"


# ── Error redaction strips host/onion identifiers ──


def test_redact_sensitive_strips_onion_and_host_and_ip():
    from app.api.livez import _redact_sensitive

    raw = (
        "ConnectError: failed to connect to "
        "abcdefghij234567abcdefghij234567abcdefghij234567abcdef.onion:8080 "
        "via proxy 10.0.0.5:9050 (host lnd.internal:10009)"
    )
    out = _redact_sensitive(raw)
    assert ".onion" not in out
    assert "10.0.0.5" not in out
    assert "lnd.internal" not in out
    assert "[redacted-onion]" in out
    assert "[redacted-ip]" in out


def test_redact_sensitive_handles_empty():
    from app.api.livez import _redact_sensitive

    assert _redact_sensitive("") == ""


# ── Unauthenticated body carries no peer identity / Tor telemetry ──


@pytest.mark.asyncio
async def test_livez_body_omits_peer_identity_and_tor_telemetry(
    app_with_livez,
) -> None:
    """``/livez`` is unauthenticated, so its body restricts itself to a
    coarse liveness verdict. Channel peer pubkeys/aliases and
    fine-grained Tor/HS timing telemetry are served only from the
    admin-gated ``/v1/status/tor`` snapshot."""
    from app.services import lnd_keepalive

    lnd_keepalive._STATE.started_at = datetime.now(timezone.utc) - timedelta(seconds=600)
    lnd_keepalive._STATE.last_success_at = datetime.now(timezone.utc) - timedelta(seconds=30)
    lnd_keepalive._STATE.consecutive_failures = 3

    fake_settings = MagicMock(lnd_keepalive_interval_s=60)
    with patch("app.core.config.settings", fake_settings), patch("app.core.database.get_db_context", _ok_db_ctx()):
        r = await _get(app_with_livez, "/livez")

    assert r.status_code == 200
    keepalive = r.json()["checks"]["keepalive"]
    for leaked in (
        "channel_uptime",
        "hs_descriptor",
        "subscriber_lifetimes",
        "inbound_supervisor",
        "consecutive_failures",
        "recoveries_attempted_total",
        "inbound_burst_newnyms_total",
    ):
        assert leaked not in keepalive, f"/livez must not expose {leaked!r}"
    # The whole serialized body must be free of the peer-identity field
    # names regardless of nesting.
    assert "peer_pubkey" not in r.text
    assert "peer_alias" not in r.text
