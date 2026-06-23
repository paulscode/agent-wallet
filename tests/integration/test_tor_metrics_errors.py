# SPDX-License-Identifier: MIT
"""Auth + error-contract tests for the Tor metrics/status HTTP surface.

Both ``/v1/status/tor`` (JSON) and ``/v1/status/tor/metrics``
(Prometheus text) gate on the admin API key. These tests pin the
request->response contract: the precise status code for an
unauthenticated caller, the precise status code for an authenticated
but non-admin caller, and that an authenticated admin scrape returns a
well-formed body even when Tor is entirely unreachable (every probe
fails and degrades to the documented sentinel/empty values rather than
raising). The probe helpers themselves are covered as units in
``tests/unit/test_tor_metrics_endpoint.py``; here the value is the
live FastAPI routing + dependency wiring.
"""

from __future__ import annotations

import pytest

# ── /v1/status/tor/metrics — Prometheus text endpoint ───────────────


@pytest.mark.asyncio
async def test_metrics_unauthenticated_is_rejected(client) -> None:
    """An anonymous scrape of the Prometheus endpoint must be refused
    with 401 — fine-grained Tor timing telemetry is never exposed
    without the admin key."""
    resp = await client.get("/v1/status/tor/metrics")
    assert resp.status_code == 401
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_metrics_non_admin_key_is_forbidden(client, test_api_key) -> None:
    """A valid but non-admin API key carries no scope for the metrics
    surface; the dependency rejects it with 403 (authenticated, not
    authorised) rather than 401."""
    _api_key, raw_key = test_api_key
    resp = await client.get(
        "/v1/status/tor/metrics",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_metrics_admin_renders_sentinels_when_tor_unreachable(
    authed_client,
) -> None:
    """With no live Tor control port (the unit-test environment), an
    authenticated admin scrape must still return 200 and a
    well-formed Prometheus body: the bootstrap gauge degrades to its
    documented value and the always-present ``# TYPE`` lines are
    emitted so the label set stays stable across scrapes."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/status/tor/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Stable metric surface — these are emitted on every scrape
    # regardless of Tor reachability.
    assert "# TYPE tor_bootstrap_progress gauge" in body
    assert "# TYPE tor_newnym_total counter" in body
    assert "# TYPE tor_breaker_state gauge" in body
    # Exposition format requires a trailing newline.
    assert body.endswith("\n")


# ── /v1/status/tor — JSON dashboard snapshot ────────────────────────


@pytest.mark.asyncio
async def test_status_json_unauthenticated_is_rejected(client) -> None:
    """The JSON snapshot carries host-identifying guard fingerprints,
    so an unauthenticated caller is refused with 401."""
    resp = await client.get("/v1/status/tor")
    assert resp.status_code == 401
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_status_json_non_admin_key_is_forbidden(client, test_api_key) -> None:
    """A non-admin key cannot read the Tor JSON snapshot; the
    admin-key dependency rejects it with 403."""
    _api_key, raw_key = test_api_key
    resp = await client.get(
        "/v1/status/tor",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_status_json_admin_returns_flat_snapshot_when_tor_down(
    authed_client,
) -> None:
    """An authenticated admin read returns 200 with the documented
    flat shape: each top-level key is present and the
    breaker/watchdog sub-dicts always carry their nested fields so
    the dashboard's CSP getters never traverse a missing key."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/status/tor")
    assert resp.status_code == 200
    body = resp.json()
    # Flat-shape invariant: top-level probe-derived keys always exist
    # (their values degrade when Tor is down, but the key set is
    # stable so the Alpine/CSP getters can read them directly).
    for key in (
        "bootstrap_progress",
        "control_port_reachable",
        "active_circuits",
        "guards",
        "network_liveness",
    ):
        assert key in body
    assert isinstance(body["guards"], list)
    # Sub-dicts are always present with their nested fields.
    assert "state" in body["tor_breaker"]
    assert "alive" in body["watchdog"]
