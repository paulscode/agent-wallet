# SPDX-License-Identifier: MIT
"""Tests for the LND BOLT 12 outbound REST helpers (J2).

Covers:

* :meth:`lnd_service.query_routes_with_blinded_paths` — body shape,
  amount validation, route extraction.
* :meth:`lnd_service.send_to_route_v2` — payment-hash encoding,
  body shape, error propagation.

The underlying ``_request`` is monkeypatched so no real LND is hit.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from app.services.lnd_service import lnd_service

# ── query_routes_with_blinded_paths ────────────────────────────────


@pytest.mark.asyncio
async def test_query_routes_rejects_zero_amount(monkeypatch) -> None:
    routes, err = await lnd_service.query_routes_with_blinded_paths(
        amount_msat=0,
        blinded_payment_paths=[{"blinded_path": {}}],
    )
    assert routes is None
    assert "amount_msat must be positive" in (err or "")


@pytest.mark.asyncio
async def test_query_routes_rejects_empty_paths(monkeypatch) -> None:
    routes, err = await lnd_service.query_routes_with_blinded_paths(
        amount_msat=1000,
        blinded_payment_paths=[],
    )
    assert routes is None
    assert "blinded_payment_paths must be non-empty" in (err or "")


@pytest.mark.asyncio
async def test_query_routes_sends_correct_body(monkeypatch) -> None:
    """The REST request body must carry amt_msat (string) +
    blinded_payment_paths verbatim. The URL path receives placeholder
    pubkey + amount (LND ignores both when blinded paths are present)."""
    captured: dict[str, Any] = {}

    async def fake_request(method, path, *, idempotent=None, **kwargs):
        captured["method"] = method
        captured["path"] = path
        captured["json"] = kwargs.get("json")
        captured["idempotent"] = idempotent
        return {"routes": [{"hops": []}], "success_prob": 0.9}, None

    monkeypatch.setattr(lnd_service, "_request", fake_request)
    paths = [{"blinded_path": {"introduction_node": "AA=="}}]
    data, err = await lnd_service.query_routes_with_blinded_paths(
        amount_msat=15_000_000,
        blinded_payment_paths=paths,
        fee_limit_msat=500_000,
        cltv_limit=400,
    )
    assert err is None
    assert data == {"routes": [{"hops": []}], "success_prob": 0.9}
    assert captured["method"] == "POST"
    assert "/v1/graph/routes/" in captured["path"]
    # 15_000_000 msat = 15_000 sat → URL placeholder
    assert captured["path"].endswith("/15000")
    body = captured["json"]
    assert body["amt_msat"] == "15000000"
    assert body["blinded_payment_paths"] == paths
    assert body["fee_limit"] == {"fixed_msat": "500000"}
    assert body["cltv_limit"] == 400
    # final_cltv_delta MUST NOT be set by default — blinded paths
    # carry their own aggregate.
    assert "final_cltv_delta" not in body
    # GET semantics: idempotent (route query is read-only).
    assert captured["idempotent"] is True


@pytest.mark.asyncio
async def test_query_routes_propagates_lnd_error(monkeypatch) -> None:
    async def fake_request(*_args, **_kwargs):
        return None, "lnd 404 routes/...: route not found"

    monkeypatch.setattr(lnd_service, "_request", fake_request)
    data, err = await lnd_service.query_routes_with_blinded_paths(
        amount_msat=1000,
        blinded_payment_paths=[{"blinded_path": {}}],
    )
    assert data is None
    assert "route not found" in (err or "")


# ── send_to_route_v2 ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_to_route_rejects_missing_payment_hash() -> None:
    out, err = await lnd_service.send_to_route_v2(
        payment_hash_hex="",
        route={},
    )
    assert out is None
    assert "payment_hash_hex must be non-empty" in (err or "")


@pytest.mark.asyncio
async def test_send_to_route_rejects_bad_hex() -> None:
    out, err = await lnd_service.send_to_route_v2(
        payment_hash_hex="not-a-hex-string",
        route={},
    )
    assert out is None
    assert "valid hex" in (err or "")


@pytest.mark.asyncio
async def test_send_to_route_rejects_wrong_length() -> None:
    # 16 bytes instead of 32 → rejected before any LND call.
    out, err = await lnd_service.send_to_route_v2(
        payment_hash_hex="ab" * 16,
        route={},
    )
    assert out is None
    assert "32 bytes" in (err or "")


@pytest.mark.asyncio
async def test_send_to_route_sends_base64_payment_hash(monkeypatch) -> None:
    """LND expects payment_hash as base64-encoded bytes in REST."""
    captured: dict[str, Any] = {}

    async def fake_request(method, path, *, idempotent=None, **kwargs):
        captured["method"] = method
        captured["path"] = path
        captured["json"] = kwargs.get("json")
        return {"status": "SUCCEEDED", "preimage": "cc" * 32}, None

    monkeypatch.setattr(lnd_service, "_request", fake_request)
    route = {"hops": [{"chan_id": "1"}], "total_amt_msat": "1500000"}
    htlc, err = await lnd_service.send_to_route_v2(
        payment_hash_hex="ab" * 32,
        route=route,
    )
    assert err is None
    assert htlc and htlc["status"] == "SUCCEEDED"
    assert captured["method"] == "POST"
    assert captured["path"] == "/v2/router/route/send"
    body = captured["json"]
    assert body["route"] == route
    # 32 bytes of 0xab base64-encoded.
    expected_b64 = base64.b64encode(b"\xab" * 32).decode("ascii")
    assert body["payment_hash"] == expected_b64


@pytest.mark.asyncio
async def test_send_to_route_propagates_failure(monkeypatch) -> None:
    async def fake_request(*_args, **_kwargs):
        return {
            "status": "FAILED",
            "failure": {"code": "NO_ROUTE"},
        }, None

    monkeypatch.setattr(lnd_service, "_request", fake_request)
    htlc, err = await lnd_service.send_to_route_v2(
        payment_hash_hex="dd" * 32,
        route={"hops": []},
    )
    assert err is None
    # A FAILED HTLC is still a *successful* RPC; the caller
    # interprets the structured status field, not the wire error.
    assert htlc and htlc["status"] == "FAILED"
    assert htlc["failure"]["code"] == "NO_ROUTE"
