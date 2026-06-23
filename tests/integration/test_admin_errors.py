# SPDX-License-Identifier: MIT
"""Auth + error-contract tests for the admin REST surface.

Every endpoint under ``/v1/admin`` is gated behind the admin API key.
These integration tests drive the live FastAPI app to pin the
request->response contract that the function-level unit tests in
``tests/unit/test_admin_endpoints.py`` cannot observe: the exact status
code for an unauthenticated caller (401), for an authenticated but
non-admin caller (403), and the Pydantic/Query validation rejections
(422) on the audit-log filters. The read-only diagnostic endpoints
(``/services``, ``/tasks/status``, ``/migrations/status``,
``/tor/reload``, ``/health``) are exercised through an authenticated
admin client so their response shape is asserted end-to-end without
depending on any live upstream.
"""

from __future__ import annotations

import pytest

# Read endpoints that must reject anonymous + non-admin callers
# identically. Kept as data so the auth contract is asserted uniformly
# across the whole surface.
_ADMIN_GET_ENDPOINTS = (
    "/v1/admin/api-keys",
    "/v1/admin/audit-log",
    "/v1/admin/audit-log/verify",
    "/v1/admin/health",
    "/v1/admin/services",
    "/v1/admin/tasks/status",
    "/v1/admin/migrations/status",
)

_ADMIN_POST_ENDPOINTS = (
    "/v1/admin/audit-log/reanchor",
    "/v1/admin/tor/reload",
)


# ── Auth contract ────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _ADMIN_GET_ENDPOINTS)
async def test_admin_get_requires_authentication(client, path) -> None:
    """An anonymous GET against any admin read endpoint is refused
    with 401 — no admin surface is reachable without a key."""
    resp = await client.get(path)
    assert resp.status_code == 401
    # No bearer credentials at all → the HTTPBearer scheme rejects
    # before key lookup with FastAPI's default "Not authenticated".
    assert resp.json()["detail"] == "Not authenticated"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _ADMIN_POST_ENDPOINTS)
async def test_admin_post_requires_authentication(client, path) -> None:
    """An anonymous POST against an admin mutation endpoint is refused
    with 401."""
    resp = await client.post(path)
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Not authenticated"


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _ADMIN_GET_ENDPOINTS)
async def test_admin_get_rejects_non_admin_key(client, test_api_key, path) -> None:
    """A valid but non-admin key is authenticated yet unauthorised:
    the admin-key dependency rejects it with 403 and the documented
    detail string."""
    _api_key, raw_key = test_api_key
    resp = await client.get(path, headers={"Authorization": f"Bearer {raw_key}"})
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin API key required for this operation"


@pytest.mark.asyncio
async def test_admin_invalid_bearer_token_is_rejected(client) -> None:
    """A well-formed but unknown bearer token resolves no key row and
    is rejected with 401 (not 403) — the key never authenticated."""
    resp = await client.get(
        "/v1/admin/services",
        headers={"Authorization": "Bearer lwk_deadbeefdeadbeefdeadbeefdeadbeef0000"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid API key"


# ── Audit-log query validation (422) ───────────────────────────────


@pytest.mark.asyncio
async def test_audit_log_rejects_non_alpha_action_filter(authed_client) -> None:
    """The ``action`` filter is constrained to ``^[a-zA-Z_]+$``; a
    value containing punctuation fails request validation with 422
    before any DB query runs."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/audit-log", params={"action": "bad-action!"})
    assert resp.status_code == 422
    body = resp.json()
    assert any(err["loc"][-1] == "action" for err in body["detail"])


@pytest.mark.asyncio
async def test_audit_log_rejects_limit_below_minimum(authed_client) -> None:
    """``limit`` is bounded ``ge=1``; zero is rejected with 422."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/audit-log", params={"limit": 0})
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "limit" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_audit_log_rejects_limit_above_maximum(authed_client) -> None:
    """``limit`` is bounded ``le=200``; an oversized value is rejected
    with 422 so a caller cannot widen the scan past the cap."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/audit-log", params={"limit": 5000})
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "limit" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_audit_log_verify_rejects_batch_size_below_minimum(authed_client) -> None:
    """``batch_size`` is bounded ``ge=100``; a too-small value is
    rejected with 422 at the request layer."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/audit-log/verify", params={"batch_size": 1})
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "batch_size" for err in resp.json()["detail"])


# ── Authenticated diagnostic reads ─────────────────────────────────


@pytest.mark.asyncio
async def test_services_health_returns_snapshot_list(authed_client) -> None:
    """``/services`` reads in-process health state (never blocks on an
    upstream) and returns one entry per registered dependency."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/services")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["services"], list)


@pytest.mark.asyncio
async def test_tasks_status_returns_task_map(authed_client) -> None:
    """``/tasks/status`` returns the per-task observability map; with
    no Redis the entries degrade to ``available=False`` rather than
    erroring."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/tasks/status")
    assert resp.status_code == 200
    assert "tasks" in resp.json()


@pytest.mark.asyncio
async def test_migrations_status_reports_revisions(authed_client) -> None:
    """``/migrations/status`` introspects Alembic + the live DB. The
    in-memory SQLite test DB has no ``alembic_version`` row, so the
    endpoint reports ``up_to_date=False`` and surfaces a non-null
    ``error`` without raising."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/migrations/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["up_to_date"] is False
    # No alembic_version table in the test DB → an explanatory error.
    assert body["error"] is not None


@pytest.mark.asyncio
async def test_tor_reload_surfaces_control_port_failure(authed_client) -> None:
    """``POST /tor/reload`` issues a SIGNAL HUP via the Tor control
    port. With no Tor running in the test environment the helper
    returns ``ok=False`` plus the control-port error rather than
    raising a 5xx — the operator sees the rejection inline."""
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/admin/tor/reload")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["error"]


@pytest.mark.asyncio
async def test_health_reports_degraded_without_lnd(authed_client) -> None:
    """``/health`` never raises on an unreachable LND: it returns
    ``status=degraded`` with ``lnd_connected=False`` and surfaces the
    active rate-limit policy."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/admin/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["lnd_connected"] is False
    assert body["rate_limiting_active"] is False
    assert "rate_limit_fail_policy" in body
